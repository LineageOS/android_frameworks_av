/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "C2SoftMpeg4Dec"
#include <utils/Log.h>

#include "C2SoftMpeg4Dec.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>

#include "mp4dec_api.h"

namespace android {

#ifdef MPEG4
constexpr char kComponentName[] = "c2.google.mpeg4.decoder";
#else
constexpr char kComponentName[] = "c2.google.h263.decoder";
#endif

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatVideo)
            .inputMediaType(
#ifdef MPEG4
                    MEDIA_MIMETYPE_VIDEO_MPEG4
#else
                    MEDIA_MIMETYPE_VIDEO_H263
#endif
            )
            .outputMediaType(MEDIA_MIMETYPE_VIDEO_RAW)
            .build();
}

C2SoftMpeg4Dec::C2SoftMpeg4Dec(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mDecHandle(nullptr) {
}

C2SoftMpeg4Dec::~C2SoftMpeg4Dec() {
    onRelease();
}

c2_status_t C2SoftMpeg4Dec::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_CORRUPTED;
}

c2_status_t C2SoftMpeg4Dec::onStop() {
    if (mInitialized) {
        PVCleanUpVideoDecoder(mDecHandle);
        mInitialized = false;
    }
    for (int32_t i = 0; i < kNumOutputBuffers; ++i) {
        if (mOutputBuffer[i]) {
            free(mOutputBuffer[i]);
            mOutputBuffer[i] = nullptr;
        }
    }
    mNumSamplesOutput = 0;
    mFramesConfigured = false;
    mSignalledOutputEos = false;
    mSignalledError = false;

    return C2_OK;
}

void C2SoftMpeg4Dec::onReset() {
    (void) onStop();
}

void C2SoftMpeg4Dec::onRelease() {
    if (mInitialized) {
        PVCleanUpVideoDecoder(mDecHandle);
    }
    if (mOutBlock) {
        mOutBlock.reset();
    }
    for (int32_t i = 0; i < kNumOutputBuffers; ++i) {
        if (mOutputBuffer[i]) {
            free(mOutputBuffer[i]);
            mOutputBuffer[i] = nullptr;
        }
    }

    delete mDecHandle;
    mDecHandle = nullptr;
}

c2_status_t C2SoftMpeg4Dec::onFlush_sm() {
    if (mInitialized) {
        if (PV_TRUE != PVResetVideoDecoder(mDecHandle)) return C2_CORRUPTED;
    }
    mSignalledOutputEos = false;
    mSignalledError = false;
    return C2_OK;
}

status_t C2SoftMpeg4Dec::initDecoder() {
#ifdef MPEG4
    mIsMpeg4 = true;
#else
    mIsMpeg4 = false;
#endif
    if (!mDecHandle) {
        mDecHandle = new tagvideoDecControls;
    }
    memset(mDecHandle, 0, sizeof(tagvideoDecControls));

    for (int32_t i = 0; i < kNumOutputBuffers; ++i) {
        mOutputBuffer[i] = nullptr;
    }

    /* TODO: bring these values to 352 and 288. It cannot be done as of now
     * because, h263 doesn't seem to allow port reconfiguration. In OMX, the
     * problem of larger width and height than default width and height is
     * overcome by adaptivePlayBack() api call. This call gets width and height
     * information from extractor. Such a thing is not possible here.
     * So we are configuring to larger values.*/
    mWidth = 1408;
    mHeight = 1152;
    mNumSamplesOutput = 0;
    mInitialized = false;
    mFramesConfigured = false;
    mSignalledOutputEos = false;
    mSignalledError = false;

    return OK;
}

void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
    uint32_t flags = 0;
    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
        flags |= C2FrameData::FLAG_END_OF_STREAM;
        ALOGV("signalling eos");
    }
    work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

void C2SoftMpeg4Dec::finishWork(uint64_t index, const std::unique_ptr<C2Work> &work) {
    std::shared_ptr<C2Buffer> buffer = createGraphicBuffer(std::move(mOutBlock),
                                                           C2Rect(mWidth, mHeight));
    mOutBlock = nullptr;
    auto fillWork = [buffer, index](const std::unique_ptr<C2Work> &work) {
        uint32_t flags = 0;
        if ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) &&
                (c2_cntr64_t(index) == work->input.ordinal.frameIndex)) {
            flags |= C2FrameData::FLAG_END_OF_STREAM;
            ALOGV("signalling eos");
        }
        work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.buffers.push_back(buffer);
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
    };
    if (work && c2_cntr64_t(index) == work->input.ordinal.frameIndex) {
        fillWork(work);
    } else {
        finish(index, fillWork);
    }
}

c2_status_t C2SoftMpeg4Dec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool) {
    if (!mDecHandle) {
        ALOGE("not supposed to be here, invalid decoder context");
        return C2_CORRUPTED;
    }

    uint32_t outSize = align(mWidth, 16) * align(mHeight, 16) * 3 / 2;
    for (int32_t i = 0; i < kNumOutputBuffers; ++i) {
        if (!mOutputBuffer[i]) {
            mOutputBuffer[i] = (uint8_t *)malloc(outSize * sizeof(uint8_t));
            if (!mOutputBuffer[i]) return C2_NO_MEMORY;
        }
    }
    if (mOutBlock &&
            (mOutBlock->width() != align(mWidth, 16) || mOutBlock->height() != mHeight)) {
        mOutBlock.reset();
    }
    if (!mOutBlock) {
        uint32_t format = HAL_PIXEL_FORMAT_YV12;
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        c2_status_t err = pool->fetchGraphicBlock(align(mWidth, 16), mHeight, format, usage, &mOutBlock);
        if (err != C2_OK) {
            ALOGE("fetchGraphicBlock for Output failed with status %d", err);
            return err;
        }
        ALOGV("provided (%dx%d) required (%dx%d)",
              mOutBlock->width(), mOutBlock->height(), mWidth, mHeight);
    }
    return C2_OK;
}

bool C2SoftMpeg4Dec::handleResChange(const std::unique_ptr<C2Work> &work) {
    uint32_t disp_width, disp_height;
    PVGetVideoDimensions(mDecHandle, (int32 *)&disp_width, (int32 *)&disp_height);

    uint32_t buf_width, buf_height;
    PVGetBufferDimensions(mDecHandle, (int32 *)&buf_width, (int32 *)&buf_height);

    CHECK_LE(disp_width, buf_width);
    CHECK_LE(disp_height, buf_height);

    ALOGV("display size (%dx%d), buffer size (%dx%d)",
           disp_width, disp_height, buf_width, buf_height);

    bool resChanged = false;
    if (disp_width != mWidth || disp_height != mHeight) {
        mWidth = disp_width;
        mHeight = disp_height;
        resChanged = true;
        for (int32_t i = 0; i < kNumOutputBuffers; ++i) {
            if (mOutputBuffer[i]) {
                free(mOutputBuffer[i]);
                mOutputBuffer[i] = nullptr;
            }
        }

        if (!mIsMpeg4) {
            PVCleanUpVideoDecoder(mDecHandle);

            uint8_t *vol_data[1]{};
            int32_t vol_size = 0;

            if (!PVInitVideoDecoder(
                    mDecHandle, vol_data, &vol_size, 1, mWidth, mHeight, H263_MODE)) {
                ALOGE("Error in PVInitVideoDecoder H263_MODE while resChanged was set to true");
                work->result = C2_CORRUPTED;
                mSignalledError = true;
                return true;
            }
        }
        mFramesConfigured = false;
    }
    return resChanged;
}

/* TODO: can remove temporary copy after library supports writing to display
 * buffer Y, U and V plane pointers using stride info. */
static void copyOutputBufferToYV12Frame(uint8_t *dst, uint8_t *src, size_t dstYStride,
                                        size_t srcYStride, uint32_t width, uint32_t height) {
    size_t dstUVStride = align(dstYStride / 2, 16);
    size_t srcUVStride = srcYStride / 2;
    uint8_t *srcStart = src;
    uint8_t *dstStart = dst;
    size_t vStride = align(height, 16);
    for (size_t i = 0; i < height; ++i) {
         memcpy(dst, src, width);
         src += srcYStride;
         dst += dstYStride;
    }
    /* U buffer */
    src = srcStart + vStride * srcYStride;
    dst = dstStart + (dstYStride * height) + (dstUVStride * height / 2);
    for (size_t i = 0; i < height / 2; ++i) {
         memcpy(dst, src, width / 2);
         src += srcUVStride;
         dst += dstUVStride;
    }
    /* V buffer */
    src = srcStart + vStride * srcYStride * 5 / 4;
    dst = dstStart + (dstYStride * height);
    for (size_t i = 0; i < height / 2; ++i) {
         memcpy(dst, src, width / 2);
         src += srcUVStride;
         dst += dstUVStride;
    }
}

void C2SoftMpeg4Dec::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    const C2ConstLinearBlock inBuffer = work->input.buffers[0]->data().linearBlocks().front();
    size_t inOffset = inBuffer.offset();
    size_t inSize = inBuffer.size();
    uint32_t workIndex = work->input.ordinal.frameIndex.peeku() & 0xFFFFFFFF;
    C2ReadView rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
    if (inSize && rView.error()) {
        ALOGE("read view map failed %d", rView.error());
        work->result = C2_CORRUPTED;
        return;
    }
    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d, flags %x",
          inSize, (int)work->input.ordinal.timestamp.peeku(),
          (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);

    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    if (inSize == 0) {
        fillEmptyWork(work);
        if (eos) {
            mSignalledOutputEos = true;
        }
        return;
    }

    uint8_t *bitstream = const_cast<uint8_t *>(rView.data() + inOffset);
    uint32_t *start_code = (uint32_t *)bitstream;
    bool volHeader = *start_code == 0xB0010000;
    if (volHeader) {
        PVCleanUpVideoDecoder(mDecHandle);
        mInitialized = false;
    }

    if (!mInitialized) {
        uint8_t *vol_data[1]{};
        int32_t vol_size = 0;

        bool codecConfig = (work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) != 0;
        if (codecConfig || volHeader) {
            vol_data[0] = bitstream;
            vol_size = inSize;
        }
        MP4DecodingMode mode = (mIsMpeg4) ? MPEG4_MODE : H263_MODE;

        if (!PVInitVideoDecoder(
                mDecHandle, vol_data, &vol_size, 1,
                mWidth, mHeight, mode)) {
            ALOGE("PVInitVideoDecoder failed. Unsupported content?");
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        }
        mInitialized = true;
        MP4DecodingMode actualMode = PVGetDecBitstreamMode(mDecHandle);
        if (mode != actualMode) {
            ALOGE("Decoded mode not same as actual mode of the decoder");
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        }

        PVSetPostProcType(mDecHandle, 0);
        (void) handleResChange(work);
        if (codecConfig) {
            fillEmptyWork(work);
            return;
        }
    }

    while (inOffset < inSize) {
        c2_status_t err = ensureDecoderState(pool);
        if (C2_OK != err) {
            mSignalledError = true;
            work->result = err;
            return;
        }
        C2GraphicView wView = mOutBlock->map().get();
        if (wView.error()) {
            ALOGE("graphic view map failed %d", wView.error());
            work->result = C2_CORRUPTED;
            return;
        }

        uint32_t outSize = align(mWidth, 16) * align(mHeight, 16) * 3 / 2;
        uint32_t yFrameSize = sizeof(uint8) * mDecHandle->size;
        if (outSize < yFrameSize * 3 / 2){
            ALOGE("Too small output buffer: %d bytes", outSize);
            work->result = C2_NO_MEMORY;
            mSignalledError = true;
            return;
        }

        if (!mFramesConfigured) {
            PVSetReferenceYUV(mDecHandle,mOutputBuffer[1]);
            mFramesConfigured = true;
        }

        // Need to check if header contains new info, e.g., width/height, etc.
        VopHeaderInfo header_info;
        uint32_t useExtTimestamp = (inOffset == 0);
        int32_t tmpInSize = (int32_t)inSize;
        uint8_t *bitstreamTmp = bitstream;
        uint32_t timestamp = workIndex;
        if (PVDecodeVopHeader(
                    mDecHandle, &bitstreamTmp, &timestamp, &tmpInSize,
                    &header_info, &useExtTimestamp,
                    mOutputBuffer[mNumSamplesOutput & 1]) != PV_TRUE) {
            ALOGE("failed to decode vop header.");
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        }

        // H263 doesn't have VOL header, the frame size information is in short header, i.e. the
        // decoder may detect size change after PVDecodeVopHeader.
        bool resChange = handleResChange(work);
        if (mIsMpeg4 && resChange) {
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        } else if (resChange) {
            continue;
        }

        if (PVDecodeVopBody(mDecHandle, &tmpInSize) != PV_TRUE) {
            ALOGE("failed to decode video frame.");
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        }
        if (handleResChange(work)) {
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        }

        uint8_t *outputBufferY = wView.data()[C2PlanarLayout::PLANE_Y];
        (void)copyOutputBufferToYV12Frame(outputBufferY, mOutputBuffer[mNumSamplesOutput & 1],
                                          wView.width(), align(mWidth, 16), mWidth, mHeight);

        inOffset += inSize - (size_t)tmpInSize;
        finishWork(workIndex, work);
        ++mNumSamplesOutput;
        if (inSize - inOffset) {
            ALOGD("decoded frame, ignoring further trailing bytes %zu",
                   inSize - (size_t)tmpInSize);
            break;
        }
    }
}

c2_status_t C2SoftMpeg4Dec::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    (void) pool;
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }
    return C2_OK;
}

class C2SoftMpeg4DecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftMpeg4Dec(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftMpeg4DecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftMpeg4DecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
