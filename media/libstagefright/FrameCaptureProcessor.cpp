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
#define LOG_TAG "FrameCaptureProcessor"

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/FrameCaptureProcessor.h>
#include <media/stagefright/MediaErrors.h>
#include <renderengine/RenderEngine.h>
#include <ui/Fence.h>
#include <ui/PixelFormat.h>
#include <utils/Log.h>

namespace android {

//static
Mutex FrameCaptureProcessor::sLock;
//static
sp<FrameCaptureProcessor> FrameCaptureProcessor::sInstance;

//static
sp<FrameCaptureProcessor> FrameCaptureProcessor::getInstance() {
    Mutex::Autolock _l(sLock);
    if (sInstance == nullptr) {
        sInstance = new FrameCaptureProcessor();
        sInstance->createRenderEngine();
    }
    // init only once, if failed nullptr will be returned afterwards.
    return (sInstance->initCheck() == OK) ? sInstance : nullptr;
}

//static
status_t FrameCaptureProcessor::PostAndAwaitResponse(
        const sp<AMessage> &msg, sp<AMessage> *response) {
    status_t err = msg->postAndAwaitResponse(response);

    if (err != OK) {
        return err;
    }

    if (!(*response)->findInt32("err", &err)) {
        err = OK;
    }

    return err;
}

//static
void FrameCaptureProcessor::PostReplyWithError(
        const sp<AReplyToken> &replyID, status_t err) {
    sp<AMessage> response = new AMessage;
    if (err != OK) {
        response->setInt32("err", err);
    }
    response->postReply(replyID);
}

FrameCaptureProcessor::FrameCaptureProcessor()
    : mInitStatus(NO_INIT), mTextureName(0) {}

FrameCaptureProcessor::~FrameCaptureProcessor() {
    if (mLooper != nullptr) {
        mLooper->unregisterHandler(id());
        mLooper->stop();
    }
}

void FrameCaptureProcessor::createRenderEngine() {
    // this method should only be called once, immediately after ctor
    CHECK(mInitStatus == NO_INIT);

    mLooper = new ALooper();
    mLooper->setName("capture_looper");
    mLooper->start(); // default priority
    mLooper->registerHandler(this);

    sp<AMessage> response;
    status_t err = PostAndAwaitResponse(new AMessage(kWhatCreate, this), &response);
    if (err != OK) {
        mInitStatus = ERROR_UNSUPPORTED;

        mLooper->unregisterHandler(id());
        mLooper->stop();
        mLooper.clear();
        return;
    }

    // only need one texture name
    mRE->genTextures(1, &mTextureName);

    mInitStatus = OK;
}

status_t FrameCaptureProcessor::capture(
        const sp<Layer> &layer, const Rect &sourceCrop, const sp<GraphicBuffer> &buffer) {
    sp<AMessage> msg = new AMessage(kWhatCapture, this);
    msg->setObject("layer", layer);
    msg->setRect("crop", sourceCrop.left, sourceCrop.top, sourceCrop.right, sourceCrop.bottom);
    msg->setObject("buffer", buffer);
    sp<AMessage> response;
    return PostAndAwaitResponse(msg, &response);
}

status_t FrameCaptureProcessor::onCreate() {
    mRE = renderengine::RenderEngine::create(
            renderengine::RenderEngineCreationArgs::Builder()
                .setPixelFormat(static_cast<int>(ui::PixelFormat::RGBA_8888))
                .setImageCacheSize(2 /*maxFrameBufferAcquiredBuffers*/)
                .setUseColorManagerment(true)
                .setEnableProtectedContext(false)
                .setPrecacheToneMapperShaderOnly(true)
                .setContextPriority(renderengine::RenderEngine::ContextPriority::LOW)
                .build());

    if (mRE == nullptr) {
        return ERROR_UNSUPPORTED;
    }
    return OK;
}

status_t FrameCaptureProcessor::onCapture(const sp<Layer> &layer,
        const Rect &sourceCrop, const sp<GraphicBuffer> &buffer) {
    renderengine::DisplaySettings clientCompositionDisplay;
    std::vector<const renderengine::LayerSettings*> clientCompositionLayers;

    clientCompositionDisplay.physicalDisplay = sourceCrop;
    clientCompositionDisplay.clip = sourceCrop;

    clientCompositionDisplay.outputDataspace = ui::Dataspace::V0_SRGB;
    clientCompositionDisplay.maxLuminance = sDefaultMaxLumiance;
    clientCompositionDisplay.clearRegion = Region::INVALID_REGION;

    // from Layer && BufferLayer
    renderengine::LayerSettings layerSettings;

    layer->getLayerSettings(sourceCrop, mTextureName, &layerSettings);

    clientCompositionLayers.push_back(&layerSettings);

    // Use an empty fence for the buffer fence, since we just created the buffer so
    // there is no need for synchronization with the GPU.
    base::unique_fd bufferFence;
    base::unique_fd drawFence;
    mRE->useProtectedContext(false);
    status_t err = mRE->drawLayers(clientCompositionDisplay, clientCompositionLayers, buffer.get(),
            /*useFramebufferCache=*/false, std::move(bufferFence), &drawFence);

    sp<Fence> fence = new Fence(std::move(drawFence));

    if (err != OK) {
        ALOGE("drawLayers returned err %d", err);
        return err;
    }

    err = fence->wait(500);
    if (err != OK) {
        ALOGW("wait for fence returned err %d", err);
    }

    mRE->cleanupPostRender(renderengine::RenderEngine::CleanupMode::CLEAN_ALL);
    return OK;
}

void FrameCaptureProcessor::onMessageReceived(const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatCreate:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            status_t err = onCreate();

            PostReplyWithError(replyID, err);
            break;
        }
        case kWhatCapture:
        {
            sp<AReplyToken> replyID;
            CHECK(msg->senderAwaitsResponse(&replyID));

            sp<RefBase> layerObj, bufferObj;
            int32_t left, top, right, bottom;
            CHECK(msg->findObject("layer", &layerObj));
            CHECK(msg->findRect("crop", &left, &top, &right, &bottom));
            CHECK(msg->findObject("buffer", &bufferObj));

            sp<GraphicBuffer> buffer = static_cast<GraphicBuffer*>(bufferObj.get());
            sp<Layer> layer = static_cast<Layer*>(layerObj.get());

            PostReplyWithError(replyID,
                    onCapture(layer, Rect(left, top, right, bottom), buffer));

            break;
        }
        default:
            TRESPASS();
    }
}

}  // namespace android
