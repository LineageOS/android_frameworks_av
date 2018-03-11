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
#define LOG_TAG "C2SoftVpx"
#include <utils/Log.h>

#include "C2SoftVpx.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

#ifdef VP9
constexpr char kComponentName[] = "c2.google.vp9.decoder";
#else
constexpr char kComponentName[] = "c2.google.vp8.decoder";
#endif

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatVideo)
            .inputMediaType(
#ifdef VP9
                    MEDIA_MIMETYPE_VIDEO_VP9
#else
                    MEDIA_MIMETYPE_VIDEO_VP8
#endif
            )
            .outputMediaType(MEDIA_MIMETYPE_VIDEO_RAW)
            .build();
}

C2SoftVpx::C2SoftVpx(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mCodecCtx(nullptr) {
}

C2SoftVpx::~C2SoftVpx() {
    onRelease();
}

c2_status_t C2SoftVpx::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_CORRUPTED;
}

c2_status_t C2SoftVpx::onStop() {
    (void) onFlush_sm();
    destroyDecoder();

    mSignalledError = false;
    mSignalledOutputEos = false;

    return C2_OK;
}

void C2SoftVpx::onReset() {
    (void) onStop();
    (void) initDecoder();
}

void C2SoftVpx::onRelease() {
    destroyDecoder();
}

c2_status_t C2SoftVpx::onFlush_sm() {
    if (mFrameParallelMode) {
        // Flush decoder by passing nullptr data ptr and 0 size.
        // Ideally, this should never fail.
        if (vpx_codec_decode(mCodecCtx, nullptr, 0, nullptr, 0)) {
            ALOGE("Failed to flush on2 decoder.");
            return C2_CORRUPTED;
        }
    }

    // Drop all the decoded frames in decoder.
    vpx_codec_iter_t iter = nullptr;
    while (vpx_codec_get_frame(mCodecCtx, &iter)) {
    }

    mSignalledError = false;
    mSignalledOutputEos = false;
    return C2_OK;
}

static int GetCPUCoreCount() {
    int cpuCoreCount = 1;
#if defined(_SC_NPROCESSORS_ONLN)
    cpuCoreCount = sysconf(_SC_NPROCESSORS_ONLN);
#else
    // _SC_NPROC_ONLN must be defined...
    cpuCoreCount = sysconf(_SC_NPROC_ONLN);
#endif
    CHECK(cpuCoreCount >= 1);
    ALOGV("Number of CPU cores: %d", cpuCoreCount);
    return cpuCoreCount;
}

status_t C2SoftVpx::initDecoder() {
#ifdef VP9
    mMode = MODE_VP9;
#else
    mMode = MODE_VP8;
#endif

    mWidth = 320;
    mHeight = 240;
    mFrameParallelMode = false;
    mSignalledOutputEos = false;
    mSignalledError = false;

    mCodecCtx = new vpx_codec_ctx_t;

    vpx_codec_dec_cfg_t cfg;
    memset(&cfg, 0, sizeof(vpx_codec_dec_cfg_t));
    cfg.threads = GetCPUCoreCount();

    vpx_codec_flags_t flags;
    memset(&flags, 0, sizeof(vpx_codec_flags_t));
    if (mFrameParallelMode) flags |= VPX_CODEC_USE_FRAME_THREADING;

    vpx_codec_err_t vpx_err;
    if ((vpx_err = vpx_codec_dec_init(
                 mCodecCtx, mMode == MODE_VP8 ? &vpx_codec_vp8_dx_algo : &vpx_codec_vp9_dx_algo,
                 &cfg, flags))) {
        ALOGE("on2 decoder failed to initialize. (%d)", vpx_err);
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2SoftVpx::destroyDecoder() {
    if  (mCodecCtx) {
        vpx_codec_destroy(mCodecCtx);
        delete mCodecCtx;
        mCodecCtx = nullptr;
    }

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

void C2SoftVpx::finishWork(uint64_t index, const std::unique_ptr<C2Work> &work,
                           const std::shared_ptr<C2GraphicBlock> &block) {
    std::shared_ptr<C2Buffer> buffer = createGraphicBuffer(block,
                                                           C2Rect(mWidth, mHeight));
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

void C2SoftVpx::process(
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
    C2ReadView rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
    if (inSize && rView.error()) {
        ALOGE("read view map failed %d", rView.error());
        work->result = C2_CORRUPTED;
        return;
    }

    bool codecConfig = ((work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) !=0);
    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d, flags %x",
          inSize, (int)work->input.ordinal.timestamp.peeku(),
          (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);

    // Software VP9 Decoder does not need the Codec Specific Data (CSD)
    // (specified in http://www.webmproject.org/vp9/profiles/). Ignore it if
    // it was passed.
    if (codecConfig) {
        // Ignore CSD buffer for VP9.
        if (mMode == MODE_VP9) {
            fillEmptyWork(work);
            return;
        } else {
            // Tolerate the CSD buffer for VP8. This is a workaround
            // for b/28689536. continue
            ALOGW("WARNING: Got CSD buffer for VP8. Continue");
        }
    }

    uint8_t *bitstream = const_cast<uint8_t *>(rView.data() + inOffset);
    int64_t frameIndex = work->input.ordinal.frameIndex.peekll();

    if (inSize) {
        vpx_codec_err_t err = vpx_codec_decode(
                mCodecCtx, bitstream, inSize, &frameIndex, 0);
        if (err != VPX_CODEC_OK) {
            ALOGE("on2 decoder failed to decode frame. err: %d", err);
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        }
    }

    (void)outputBuffer(pool, work);

    if (eos) {
        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
        mSignalledOutputEos = true;
    } else if (!inSize) {
        fillEmptyWork(work);
    }
}

static void copyOutputBufferToYV12Frame(uint8_t *dst,
        const uint8_t *srcY, const uint8_t *srcU, const uint8_t *srcV,
        size_t srcYStride, size_t srcUStride, size_t srcVStride,
        uint32_t width, uint32_t height, int32_t bpp) {
    size_t dstYStride = align(width, 16) * bpp ;
    size_t dstUVStride = align(dstYStride / 2, 16);
    uint8_t *dstStart = dst;

    for (size_t i = 0; i < height; ++i) {
         memcpy(dst, srcY, width * bpp);
         srcY += srcYStride;
         dst += dstYStride;
    }

    dst = dstStart + dstYStride * height;
    for (size_t i = 0; i < height / 2; ++i) {
         memcpy(dst, srcV, width / 2 * bpp);
         srcV += srcVStride;
         dst += dstUVStride;
    }

    dst = dstStart + (dstYStride * height) + (dstUVStride * height / 2);
    for (size_t i = 0; i < height / 2; ++i) {
         memcpy(dst, srcU, width / 2 * bpp);
         srcU += srcUStride;
         dst += dstUVStride;
    }
}

bool C2SoftVpx::outputBuffer(
        const std::shared_ptr<C2BlockPool> &pool,
        const std::unique_ptr<C2Work> &work)
{
    if (!(work && pool)) return false;

    vpx_codec_iter_t iter = nullptr;
    vpx_image_t *img = vpx_codec_get_frame(mCodecCtx, &iter);

    if (!img) return false;

    mWidth = img->d_w;
    mHeight = img->d_h;

    CHECK(img->fmt == VPX_IMG_FMT_I420 || img->fmt == VPX_IMG_FMT_I42016);
    int32_t bpp = 1;
    if (img->fmt == VPX_IMG_FMT_I42016) {
        bpp = 2;
    }

    std::shared_ptr<C2GraphicBlock> block;
    uint32_t format = HAL_PIXEL_FORMAT_YV12;
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool->fetchGraphicBlock(align(mWidth, 16) * bpp, mHeight, format, usage, &block);
    if (err != C2_OK) {
        ALOGE("fetchGraphicBlock for Output failed with status %d", err);
        work->result = err;
        return false;
    }

    C2GraphicView wView = block->map().get();
    if (wView.error()) {
        ALOGE("graphic view map failed %d", wView.error());
        work->result = C2_CORRUPTED;
        return false;
    }

    ALOGV("provided (%dx%d) required (%dx%d), out frameindex %d",
           block->width(), block->height(), mWidth, mHeight, (int)*(int64_t *)img->user_priv);

    uint8_t *dst = const_cast<uint8_t *>(wView.data()[C2PlanarLayout::PLANE_Y]);
    size_t srcYStride = img->stride[VPX_PLANE_Y];
    size_t srcUStride = img->stride[VPX_PLANE_U];
    size_t srcVStride = img->stride[VPX_PLANE_V];
    const uint8_t *srcY = (const uint8_t *)img->planes[VPX_PLANE_Y];
    const uint8_t *srcU = (const uint8_t *)img->planes[VPX_PLANE_U];
    const uint8_t *srcV = (const uint8_t *)img->planes[VPX_PLANE_V];
    copyOutputBufferToYV12Frame(dst, srcY, srcU, srcV,
                                srcYStride, srcUStride, srcVStride, mWidth, mHeight, bpp);

    finishWork(*(int64_t *)img->user_priv, work, std::move(block));
    return true;
}

c2_status_t C2SoftVpx::drainInternal(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool,
        const std::unique_ptr<C2Work> &work) {
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }

    while ((outputBuffer(pool, work))) {
    }

    if (drainMode == DRAIN_COMPONENT_WITH_EOS &&
            work && work->workletsProcessed == 0u) {
        fillEmptyWork(work);
    }

    return C2_OK;
}
c2_status_t C2SoftVpx::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    return drainInternal(drainMode, pool, nullptr);
}

class C2SoftVpxFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftVpx(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftVpxFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftVpxFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
