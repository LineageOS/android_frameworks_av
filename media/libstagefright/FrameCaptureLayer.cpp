/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "FrameCaptureLayer"

#include <include/FrameCaptureLayer.h>
#include <media/stagefright/FrameCaptureProcessor.h>
#include <gui/BufferQueue.h>
#include <gui/GLConsumer.h>
#include <gui/IGraphicBufferConsumer.h>
#include <gui/Surface.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/MediaErrors.h>
#include <renderengine/RenderEngine.h>
#include <utils/Log.h>

namespace android {

static const int64_t kAcquireBufferTimeoutNs = 100000000LL;
static constexpr float kDefaultMaxMasteringLuminance = 1000.0;
static constexpr float kDefaultMaxContentLuminance = 1000.0;

ui::Dataspace translateDataspace(ui::Dataspace dataspace) {
    ui::Dataspace updatedDataspace = dataspace;
    // translate legacy dataspaces to modern dataspaces
    switch (dataspace) {
        case ui::Dataspace::SRGB:
            updatedDataspace = ui::Dataspace::V0_SRGB;
            break;
        case ui::Dataspace::SRGB_LINEAR:
            updatedDataspace = ui::Dataspace::V0_SRGB_LINEAR;
            break;
        case ui::Dataspace::JFIF:
            updatedDataspace = ui::Dataspace::V0_JFIF;
            break;
        case ui::Dataspace::BT601_625:
            updatedDataspace = ui::Dataspace::V0_BT601_625;
            break;
        case ui::Dataspace::BT601_525:
            updatedDataspace = ui::Dataspace::V0_BT601_525;
            break;
        case ui::Dataspace::BT709:
            updatedDataspace = ui::Dataspace::V0_BT709;
            break;
        default:
            break;
    }

    return updatedDataspace;
}

bool isHdrY410(const BufferItem &bi) {
    ui::Dataspace dataspace = translateDataspace(static_cast<ui::Dataspace>(bi.mDataSpace));
    // pixel format is HDR Y410 masquerading as RGBA_1010102
    return ((dataspace == ui::Dataspace::BT2020_ITU_PQ ||
            dataspace == ui::Dataspace::BT2020_ITU_HLG) &&
            bi.mGraphicBuffer->getPixelFormat() == HAL_PIXEL_FORMAT_RGBA_1010102);
}

struct FrameCaptureLayer::BufferLayer : public FrameCaptureProcessor::Layer {
    BufferLayer(const BufferItem &bi) : mBufferItem(bi) {}
    void getLayerSettings(
            const Rect &sourceCrop, uint32_t textureName,
            renderengine::LayerSettings *layerSettings) override;
    BufferItem mBufferItem;
};

void FrameCaptureLayer::BufferLayer::getLayerSettings(
        const Rect &sourceCrop, uint32_t textureName,
        renderengine::LayerSettings *layerSettings) {
    layerSettings->geometry.boundaries = sourceCrop.toFloatRect();
    layerSettings->alpha = 1.0f;

    layerSettings->sourceDataspace = translateDataspace(
            static_cast<ui::Dataspace>(mBufferItem.mDataSpace));

    // from BufferLayer
    layerSettings->source.buffer.buffer = mBufferItem.mGraphicBuffer;
    layerSettings->source.buffer.isOpaque = true;
    layerSettings->source.buffer.fence = mBufferItem.mFence;
    layerSettings->source.buffer.textureName = textureName;
    layerSettings->source.buffer.usePremultipliedAlpha = false;
    layerSettings->source.buffer.isY410BT2020 = isHdrY410(mBufferItem);
    bool hasSmpte2086 = mBufferItem.mHdrMetadata.validTypes & HdrMetadata::SMPTE2086;
    bool hasCta861_3 = mBufferItem.mHdrMetadata.validTypes & HdrMetadata::CTA861_3;
    layerSettings->source.buffer.maxMasteringLuminance = hasSmpte2086
            ? mBufferItem.mHdrMetadata.smpte2086.maxLuminance
                    : kDefaultMaxMasteringLuminance;
    layerSettings->source.buffer.maxContentLuminance = hasCta861_3
            ? mBufferItem.mHdrMetadata.cta8613.maxContentLightLevel
                    : kDefaultMaxContentLuminance;

    // Set filtering to false since the capture itself doesn't involve
    // any scaling, metadata retriever JNI is scaling the bitmap if
    // display size is different from decoded size. If that scaling
    // needs to be handled by server side, consider enable this based
    // display size vs decoded size.
    const bool useFiltering = false;
    layerSettings->source.buffer.useTextureFiltering = useFiltering;

    float textureMatrix[16];
    GLConsumer::computeTransformMatrix(
            textureMatrix, mBufferItem.mGraphicBuffer,
            mBufferItem.mCrop, mBufferItem.mTransform, useFiltering);

    // Flip y-coordinates because GLConsumer expects OpenGL convention.
    mat4 tr = mat4::translate(vec4(.5, .5, 0, 1)) * mat4::scale(vec4(1, -1, 1, 1)) *
            mat4::translate(vec4(-.5, -.5, 0, 1));

    layerSettings->source.buffer.textureTransform =
            mat4(static_cast<const float*>(textureMatrix)) * tr;
}

status_t FrameCaptureLayer::init() {
    if (FrameCaptureProcessor::getInstance() == nullptr) {
        ALOGE("failed to get capture processor");
        return ERROR_UNSUPPORTED;
    }

    // Mimic surfaceflinger's BufferQueueLayer::onFirstRef() to create a
    // BufferQueue for encoder output
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;

    BufferQueue::createBufferQueue(&producer, &consumer);
    // We don't need HW_COMPOSER usage since we're not using hwc to compose.
    // The buffer is only used as a GL texture.
    consumer->setConsumerUsageBits(GraphicBuffer::USAGE_HW_TEXTURE);
    consumer->setConsumerName(String8("FrameDecoder"));

    status_t err = consumer->consumerConnect(
            new BufferQueue::ProxyConsumerListener(this), false);
    if (NO_ERROR != err) {
        ALOGE("Error connecting to BufferQueue: %s (%d)", strerror(-err), err);
        return err;
    }

    mConsumer = consumer;
    mSurface = new Surface(producer);

    return OK;
}

status_t FrameCaptureLayer::capture(const ui::PixelFormat reqPixelFormat,
        const Rect &sourceCrop, sp<GraphicBuffer> *outBuffer) {
    ALOGV("capture: reqPixelFormat %d, crop {%d, %d, %d, %d}", reqPixelFormat,
            sourceCrop.left, sourceCrop.top, sourceCrop.right, sourceCrop.bottom);

    BufferItem bi;
    status_t err = acquireBuffer(&bi);
    if (err != OK) {
        return err;
    }

    // create out buffer
    const uint32_t usage =
            GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN |
            GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_HW_TEXTURE;
    sp<GraphicBuffer> buffer = new GraphicBuffer(
            sourceCrop.getWidth(), sourceCrop.getHeight(),
            static_cast<android_pixel_format>(reqPixelFormat),
            1, usage, std::string("thumbnail"));

    err = FrameCaptureProcessor::getInstance()->capture(
            new BufferLayer(bi), sourceCrop, buffer);
    if (err == OK) {
        *outBuffer = buffer;
    }

    (void)releaseBuffer(bi);
    return err;
}

FrameCaptureLayer::FrameCaptureLayer() : mFrameAvailable(false) {}

void FrameCaptureLayer::onFrameAvailable(const BufferItem& /*item*/) {
    ALOGV("onFrameAvailable");
    Mutex::Autolock _lock(mLock);

    mFrameAvailable = true;
    mCondition.signal();
}

void FrameCaptureLayer::onBuffersReleased() {
    ALOGV("onBuffersReleased");
    Mutex::Autolock _lock(mLock);

    uint64_t mask = 0;
    mConsumer->getReleasedBuffers(&mask);
    for (int i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
        if (mask & (1ULL << i)) {
            mSlotToBufferMap[i] = nullptr;
        }
    }
}

void FrameCaptureLayer::onSidebandStreamChanged() {
    ALOGV("onSidebandStreamChanged");
}

status_t FrameCaptureLayer::acquireBuffer(BufferItem *bi) {
    ALOGV("acquireBuffer");
    Mutex::Autolock _lock(mLock);

    if (!mFrameAvailable) {
        // The output buffer is already released to the codec at this point.
        // Use a small timeout of 100ms in case the buffer hasn't arrived
        // at the consumer end of the output surface yet.
        if (mCondition.waitRelative(mLock, kAcquireBufferTimeoutNs) != OK) {
            ALOGE("wait for buffer timed out");
            return TIMED_OUT;
        }
    }
    mFrameAvailable = false;

    status_t err = mConsumer->acquireBuffer(bi, 0);
    if (err != OK) {
        ALOGE("failed to acquire buffer!");
        return err;
    }

    if (bi->mGraphicBuffer != nullptr) {
        mSlotToBufferMap[bi->mSlot] = bi->mGraphicBuffer;
    } else {
        bi->mGraphicBuffer = mSlotToBufferMap[bi->mSlot];
    }

    if (bi->mGraphicBuffer == nullptr) {
        ALOGE("acquired null buffer!");
        return BAD_VALUE;
    }
    return OK;
}

status_t FrameCaptureLayer::releaseBuffer(const BufferItem &bi) {
    ALOGV("releaseBuffer");
    Mutex::Autolock _lock(mLock);

    return mConsumer->releaseBuffer(bi.mSlot, bi.mFrameNumber,
            EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, bi.mFence);
}

}  // namespace android
