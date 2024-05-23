/*
 * Copyright 2024, The Android Open Source Project
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
#define LOG_TAG "C2OMXNODE"
#include <log/log.h>

#include <OMX_Component.h>
#include <OMX_Index.h>
#include <OMX_IndexExt.h>

#include <media/stagefright/MediaErrors.h>

#include "C2OMXNode.h"
#include "C2NodeImpl.h"

namespace android {

namespace {

constexpr OMX_U32 kPortIndexInput = 0;

} // anomymous namespace

using ::android::media::BUFFERFLAG_ENDOFFRAME;
using ::android::media::BUFFERFLAG_EOS;

using ::aidl::android::media::IAidlNode;

C2OMXNode::C2OMXNode(const std::shared_ptr<Codec2Client::Component> &comp)
    : mImpl(new C2NodeImpl(comp, false)) {}

status_t C2OMXNode::freeNode() {
    return mImpl->freeNode();
}

status_t C2OMXNode::sendCommand(OMX_COMMANDTYPE cmd, OMX_S32 param) {
    if (cmd == OMX_CommandStateSet && param == OMX_StateLoaded) {
        // Reset first input frame so if C2OMXNode is recycled, the timestamp does not become
        // negative. This is a workaround for HW codecs that do not handle timestamp rollover.
        mImpl->onFirstInputFrame();
    }
    return ERROR_UNSUPPORTED;
}

status_t C2OMXNode::getParameter(OMX_INDEXTYPE index, void *params, size_t size) {
    status_t err = ERROR_UNSUPPORTED;
    switch ((uint32_t)index) {
        case OMX_IndexParamConsumerUsageBits: {
            OMX_U32 *usage = (OMX_U32 *)params;
            uint64_t val;
            mImpl->getConsumerUsageBits(&val);
            *usage = static_cast<uint32_t>(val & 0xFFFFFFFF);
            ALOGW("retrieving usage bits in 32 bits %llu -> %u",
                  (unsigned long long)val, (unsigned int)*usage);
            err = OK;
            break;
        }
        case OMX_IndexParamConsumerUsageBits64: {
            OMX_U64 *usage = (OMX_U64 *)params;
            uint64_t val;
            mImpl->getConsumerUsageBits(&val);
            *usage = val;
            err = OK;
            break;
        }
        case OMX_IndexParamPortDefinition: {
            if (size < sizeof(OMX_PARAM_PORTDEFINITIONTYPE)) {
                return BAD_VALUE;
            }
            OMX_PARAM_PORTDEFINITIONTYPE *pDef = (OMX_PARAM_PORTDEFINITIONTYPE *)params;
            if (pDef->nPortIndex != kPortIndexInput) {
                break;
            }
            IAidlNode::InputBufferParams bufferParams;
            mImpl->getInputBufferParams(&bufferParams);
            pDef->nBufferCountActual = bufferParams.bufferCountActual;
            pDef->eDomain = OMX_PortDomainVideo;
            pDef->format.video.nFrameWidth = bufferParams.frameWidth;
            pDef->format.video.nFrameHeight = bufferParams.frameHeight;
            pDef->format.video.eColorFormat = OMX_COLOR_FormatAndroidOpaque;
            err = OK;
            break;
        }
        default:
            break;
    }
    return err;
}

status_t C2OMXNode::setParameter(OMX_INDEXTYPE index, const void *params, size_t size) {
    if (params == NULL) {
        return BAD_VALUE;
    }
    switch ((uint32_t)index) {
        case OMX_IndexParamMaxFrameDurationForBitrateControl: {
            // handle max/fixed frame duration control
            if (size != sizeof(OMX_PARAM_U32TYPE)) {
                return BAD_VALUE;
            }
            // The incoming number is an int32_t contained in OMX_U32.
            int32_t gapUs = (int32_t)((OMX_PARAM_U32TYPE*)params)->nU32;
            mImpl->setAdjustTimestampGapUs(gapUs);
            return OK;
        }
        case OMX_IndexParamConsumerUsageBits: {
            if (size != sizeof(OMX_U32)) {
                return BAD_VALUE;
            }
            uint32_t usage = *((OMX_U32 *)params);
            mImpl->setConsumerUsageBits(static_cast<uint64_t>(usage));
            return OK;
        }
        case OMX_IndexParamConsumerUsageBits64: {
            if (size != sizeof(OMX_U64)) {
                return BAD_VALUE;
            }
            uint64_t usagell = *((OMX_U64 *)params);
            mImpl->setConsumerUsageBits(usagell);
            return OK;
        }
        default:
            break;
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
    return mImpl->setInputSurface(bufferSource);
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

namespace {
    uint32_t toNodeFlags(OMX_U32 flags) {
        uint32_t retFlags = 0;
        if (flags & OMX_BUFFERFLAG_ENDOFFRAME) {
            retFlags |= BUFFERFLAG_ENDOFFRAME;
        }
        if (flags & OMX_BUFFERFLAG_EOS) {
            retFlags |= BUFFERFLAG_EOS;
        }
        return retFlags;
    }
    int64_t toNodeTimestamp(OMX_TICKS ticks) {
        int64_t timestamp = 0;
#ifndef OMX_SKIP64BIT
        timestamp = ticks;
#else
        timestamp = ((ticks.nHighPart << 32) | ticks.nLowPart);
#endif
        return timestamp;
    }
} // anonymous namespace

status_t C2OMXNode::emptyBuffer(
        buffer_id buffer, const OMXBuffer &omxBuf,
        OMX_U32 flags, OMX_TICKS timestamp, int fenceFd) {
    if (omxBuf.mBufferType == OMXBuffer::kBufferTypeANWBuffer
            && omxBuf.mGraphicBuffer != nullptr) {
        return mImpl->submitBuffer(buffer, omxBuf.mGraphicBuffer, toNodeFlags(flags),
                                  toNodeTimestamp(timestamp), fenceFd);
    }
    sp<GraphicBuffer> gBuf;
    return mImpl->submitBuffer(buffer, gBuf, toNodeFlags(flags),
                              toNodeTimestamp(timestamp), fenceFd);
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
    return mImpl->onDataspaceChanged(
            msg.u.event_data.data1,
            msg.u.event_data.data3);
}

sp<IOMXBufferSource> C2OMXNode::getSource() {
    return mImpl->getSource();
}

void C2OMXNode::setFrameSize(uint32_t width, uint32_t height) {
    return mImpl->setFrameSize(width, height);
}

void C2OMXNode::onInputBufferDone(c2_cntr64_t index) {
    return mImpl->onInputBufferDone(index);
}

void C2OMXNode::onInputBufferEmptied() {
    return mImpl->onInputBufferEmptied();
}

android_dataspace C2OMXNode::getDataspace() {
    return mImpl->getDataspace();
}

uint32_t C2OMXNode::getPixelFormat() {
    return mImpl->getPixelFormat();
}

void C2OMXNode::setPriority(int priority) {
    return mImpl->setPriority(priority);
}

}  // namespace android
