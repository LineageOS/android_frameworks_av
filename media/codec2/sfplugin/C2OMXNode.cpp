/*
 * Copyright 2018, The Android Open Source Project
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

#ifdef __LP64__
#define OMX_ANDROID_COMPILE_AS_32BIT_ON_64BIT_PLATFORMS
#endif

//#define LOG_NDEBUG 0
#define LOG_TAG "C2OMXNode"
#include <log/log.h>

#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Component.h>
#include <C2PlatformSupport.h>

#include <OMX_Component.h>
#include <OMX_Index.h>
#include <OMX_IndexExt.h>

#include <media/stagefright/omx/OMXUtils.h>
#include <media/stagefright/MediaErrors.h>
#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>

#include "C2OMXNode.h"

namespace android {

namespace {

class Buffer2D : public C2Buffer {
public:
    explicit Buffer2D(C2ConstGraphicBlock block) : C2Buffer({ block }) {}
};

}  // namespace

C2OMXNode::C2OMXNode(const std::shared_ptr<Codec2Client::Component> &comp)
    : mComp(comp), mFrameIndex(0), mWidth(0), mHeight(0),
      mAdjustTimestampGapUs(0), mFirstInputFrame(true) {
    // TODO: read from intf()
    if (!strncmp(comp->getName().c_str(), "c2.android.", 11)) {
        mUsage = GRALLOC_USAGE_SW_READ_OFTEN;
    } else {
        mUsage = GRALLOC_USAGE_HW_VIDEO_ENCODER;
    }
}

status_t C2OMXNode::freeNode() {
    mComp.reset();
    return OK;
}

status_t C2OMXNode::sendCommand(OMX_COMMANDTYPE cmd, OMX_S32 param) {
    if (cmd == OMX_CommandStateSet && param == OMX_StateLoaded) {
        // Reset first input frame so if C2OMXNode is recycled, the timestamp does not become
        // negative. This is a workaround for HW codecs that do not handle timestamp rollover.
        mFirstInputFrame = true;
    }
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::getParameter(OMX_INDEXTYPE index, void *params, size_t size) {
    status_t err = ERROR_UNSUPPORTED;
    switch ((uint32_t)index) {
        case OMX_IndexParamConsumerUsageBits: {
            OMX_U32 *usage = (OMX_U32 *)params;
            *usage = mUsage;
            err = OK;
            break;
        }
        case OMX_IndexParamPortDefinition: {
            if (size < sizeof(OMX_PARAM_PORTDEFINITIONTYPE)) {
                return BAD_VALUE;
            }
            OMX_PARAM_PORTDEFINITIONTYPE *pDef = (OMX_PARAM_PORTDEFINITIONTYPE *)params;
            // TODO: read these from intf()
            pDef->nBufferCountActual = 16;
            pDef->eDomain = OMX_PortDomainVideo;
            pDef->format.video.nFrameWidth = mWidth;
            pDef->format.video.nFrameHeight = mHeight;
            err = OK;
            break;
        }
        default:
            break;
    }
    return err;
}

status_t C2OMXNode::setParameter(OMX_INDEXTYPE index, const void *params, size_t size) {
    // handle max/fixed frame duration control
    if (index == (OMX_INDEXTYPE)OMX_IndexParamMaxFrameDurationForBitrateControl
            && params != NULL
            && size == sizeof(OMX_PARAM_U32TYPE)) {
        // The incoming number is an int32_t contained in OMX_U32.
        mAdjustTimestampGapUs = (int32_t)((OMX_PARAM_U32TYPE*)params)->nU32;
        return OK;
    }
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::getConfig(OMX_INDEXTYPE index, void *config, size_t size) {
    (void)index;
    (void)config;
    (void)size;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::setConfig(OMX_INDEXTYPE index, const void *config, size_t size) {
    (void)index;
    (void)config;
    (void)size;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::setPortMode(OMX_U32 portIndex, IOMX::PortMode mode) {
    (void)portIndex;
    (void)mode;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::prepareForAdaptivePlayback(
        OMX_U32 portIndex, OMX_BOOL enable,
        OMX_U32 maxFrameWidth, OMX_U32 maxFrameHeight) {
    (void)portIndex;
    (void)enable;
    (void)maxFrameWidth;
    (void)maxFrameHeight;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::configureVideoTunnelMode(
        OMX_U32 portIndex, OMX_BOOL tunneled,
        OMX_U32 audioHwSync, native_handle_t **sidebandHandle) {
    (void)portIndex;
    (void)tunneled;
    (void)audioHwSync;
    *sidebandHandle = nullptr;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::getGraphicBufferUsage(OMX_U32 portIndex, OMX_U32* usage) {
    (void)portIndex;
    *usage = 0;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::setInputSurface(const sp<IOMXBufferSource> &bufferSource) {
    c2_status_t err = GetCodec2PlatformAllocatorStore()->fetchAllocator(
            C2PlatformAllocatorStore::GRALLOC,
            &mAllocator);
    if (err != OK) {
        return UNKNOWN_ERROR;
    }
    mBufferSource = bufferSource;
    return OK;
}

status_t C2OMXNode::allocateSecureBuffer(
        OMX_U32 portIndex, size_t size, buffer_id *buffer,
        void **bufferData, sp<NativeHandle> *nativeHandle) {
    (void)portIndex;
    (void)size;
    (void)nativeHandle;
    *buffer = 0;
    *bufferData = nullptr;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::useBuffer(
        OMX_U32 portIndex, const OMXBuffer &omxBuf, buffer_id *buffer) {
    (void)portIndex;
    (void)omxBuf;
    *buffer = 0;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::freeBuffer(OMX_U32 portIndex, buffer_id buffer) {
    (void)portIndex;
    (void)buffer;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::fillBuffer(
        buffer_id buffer, const OMXBuffer &omxBuf, int fenceFd) {
    (void)buffer;
    (void)omxBuf;
    (void)fenceFd;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::emptyBuffer(
        buffer_id buffer, const OMXBuffer &omxBuf,
        OMX_U32 flags, OMX_TICKS timestamp, int fenceFd) {
    // TODO: better fence handling
    if (fenceFd >= 0) {
        sp<Fence> fence = new Fence(fenceFd);
        fence->waitForever(LOG_TAG);
    }
    std::shared_ptr<Codec2Client::Component> comp = mComp.lock();
    if (!comp) {
        return NO_INIT;
    }

    uint32_t c2Flags = (flags & OMX_BUFFERFLAG_EOS)
            ? C2FrameData::FLAG_END_OF_STREAM : 0;
    std::shared_ptr<C2GraphicBlock> block;

    C2Handle *handle = nullptr;
    if (omxBuf.mBufferType == OMXBuffer::kBufferTypeANWBuffer
            && omxBuf.mGraphicBuffer != nullptr) {
        std::shared_ptr<C2GraphicAllocation> alloc;
        handle = WrapNativeCodec2GrallocHandle(
                omxBuf.mGraphicBuffer->handle,
                omxBuf.mGraphicBuffer->width,
                omxBuf.mGraphicBuffer->height,
                omxBuf.mGraphicBuffer->format,
                omxBuf.mGraphicBuffer->usage,
                omxBuf.mGraphicBuffer->stride);
        c2_status_t err = mAllocator->priorGraphicAllocation(handle, &alloc);
        if (err != OK) {
            return UNKNOWN_ERROR;
        }
        block = _C2BlockFactory::CreateGraphicBlock(alloc);
    } else if (!(flags & OMX_BUFFERFLAG_EOS)) {
        return BAD_VALUE;
    }

    std::unique_ptr<C2Work> work(new C2Work);
    work->input.flags = (C2FrameData::flags_t)c2Flags;
    work->input.ordinal.timestamp = timestamp;

    // WORKAROUND: adjust timestamp based on gapUs
    {
        work->input.ordinal.customOrdinal = timestamp; // save input timestamp
        if (mFirstInputFrame) {
            // grab timestamps on first frame
            mPrevInputTimestamp = timestamp;
            mPrevCodecTimestamp = timestamp;
            mFirstInputFrame = false;
        } else if (mAdjustTimestampGapUs > 0) {
            work->input.ordinal.timestamp =
                mPrevCodecTimestamp
                        + c2_min((timestamp - mPrevInputTimestamp).peek(), mAdjustTimestampGapUs);
        } else if (mAdjustTimestampGapUs < 0) {
            work->input.ordinal.timestamp = mPrevCodecTimestamp - mAdjustTimestampGapUs;
        }
        mPrevInputTimestamp = work->input.ordinal.customOrdinal;
        mPrevCodecTimestamp = work->input.ordinal.timestamp;
        ALOGV("adjusting %lld to %lld (gap=%lld)",
              work->input.ordinal.customOrdinal.peekll(),
              work->input.ordinal.timestamp.peekll(),
              (long long)mAdjustTimestampGapUs);
    }

    work->input.ordinal.frameIndex = mFrameIndex++;
    work->input.buffers.clear();
    if (block) {
        std::shared_ptr<C2Buffer> c2Buffer(
                // TODO: fence
                new Buffer2D(block->share(
                        C2Rect(block->width(), block->height()), ::C2Fence())),
                [buffer, source = getSource()](C2Buffer *ptr) {
                    delete ptr;
                    // TODO: fence
                    (void)source->onInputBufferEmptied(buffer, -1);
                });
        work->input.buffers.push_back(c2Buffer);
    }
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);
    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));

    c2_status_t err = comp->queue(&items);
    if (err != C2_OK) {
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2OMXNode::getExtensionIndex(
        const char *parameterName, OMX_INDEXTYPE *index) {
    (void)parameterName;
    *index = OMX_IndexMax;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::dispatchMessage(const omx_message& msg) {
    if (msg.type != omx_message::EVENT) {
        return ERROR_UNSUPPORTED;
    }
    if (msg.u.event_data.event != OMX_EventDataSpaceChanged) {
        return ERROR_UNSUPPORTED;
    }
    android_dataspace dataSpace = (android_dataspace)msg.u.event_data.data1;
    uint32_t pixelFormat = msg.u.event_data.data3;

    // TODO: set dataspace on component to see if it impacts color aspects
    ALOGD("dataspace changed to %#x pixel format: %#x", dataSpace, pixelFormat);
    return OK;
}

sp<IOMXBufferSource> C2OMXNode::getSource() {
    return mBufferSource;
}

void C2OMXNode::setFrameSize(uint32_t width, uint32_t height) {
    mWidth = width;
    mHeight = height;
}

}  // namespace android
