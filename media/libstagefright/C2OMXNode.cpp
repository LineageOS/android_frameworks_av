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

#include "include/C2OMXNode.h"

namespace android {

namespace {

class Buffer2D : public C2Buffer {
public:
    explicit Buffer2D(C2ConstGraphicBlock block) : C2Buffer({ block }) {}
};

}  // namespace

C2OMXNode::C2OMXNode(const std::shared_ptr<C2Component> &comp) : mComp(comp) {}

status_t C2OMXNode::freeNode() {
    mComp.reset();
    return OK;
}

status_t C2OMXNode::sendCommand(OMX_COMMANDTYPE cmd, OMX_S32 param) {
    (void)cmd;
    (void)param;
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::getParameter(OMX_INDEXTYPE index, void *params, size_t size) {
    status_t err = ERROR_UNSUPPORTED;
    switch ((uint32_t)index) {
        case OMX_IndexParamConsumerUsageBits: {
            // TODO: read from intf()
            OMX_U32 *usage = (OMX_U32 *)params;
            *usage = GRALLOC_USAGE_SW_READ_OFTEN;
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
            pDef->format.video.nFrameWidth = 1080;
            pDef->format.video.nFrameHeight = 1920;
            err = OK;
            break;
        }
        default:
            break;
    }
    return err;
}

status_t C2OMXNode::setParameter(OMX_INDEXTYPE index, const void *params, size_t size) {
    (void)index;
    (void)params;
    (void)size;
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
    std::shared_ptr<C2Component> comp = mComp.lock();
    if (!comp) {
        return NO_INIT;
    }

    uint32_t c2Flags = 0;
    std::shared_ptr<C2GraphicBlock> block;

    C2Handle *handle = nullptr;
    if (omxBuf.mBufferType == OMXBuffer::kBufferTypeANWBuffer) {
        std::shared_ptr<C2GraphicAllocation> alloc;
        handle = WrapNativeCodec2GrallocHandle(
                native_handle_clone(omxBuf.mGraphicBuffer->handle),
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
    } else if (flags & OMX_BUFFERFLAG_EOS) {
        c2Flags = C2FrameData::FLAG_END_OF_STREAM;
    } else {
        return BAD_VALUE;
    }

    std::unique_ptr<C2Work> work(new C2Work);
    work->input.flags = (C2FrameData::flags_t)c2Flags;
    work->input.ordinal.timestamp = timestamp;
    work->input.ordinal.frameIndex = mFrameIndex++;
    work->input.buffers.clear();
    if (block) {
        std::shared_ptr<C2Buffer> c2Buffer(
                // TODO: fence
                new Buffer2D(block->share(
                        C2Rect(block->width(), block->height()), ::android::C2Fence())),
                [handle, buffer, source = getSource()](C2Buffer *ptr) {
                    delete ptr;
                    native_handle_delete(handle);
                    // TODO: fence
                    (void)source->onInputBufferEmptied(buffer, -1);
                });
        work->input.buffers.push_back(c2Buffer);
    }
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);
    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));

    c2_status_t err = comp->queue_nb(&items);
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
    // TODO: fill intf() with info inside |msg|.
    return OK;
}

sp<IOMXBufferSource> C2OMXNode::getSource() {
    return mBufferSource;
}

}  // namespace android
