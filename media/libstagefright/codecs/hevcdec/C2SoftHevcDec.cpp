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
#define LOG_TAG "C2SoftHevcDec"
#include <utils/Log.h>

#include "ihevc_typedefs.h"
#include "iv.h"
#include "ivd.h"
#include "ihevcd_cxa.h"
#include "C2SoftHevcDec.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

constexpr char kComponentName[] = "c2.google.hevc.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatVideo)
            .inputMediaType(MEDIA_MIMETYPE_VIDEO_HEVC)
            .outputMediaType(MEDIA_MIMETYPE_VIDEO_RAW)
            .build();
}

static size_t getCpuCoreCount() {
    long cpuCoreCount = 1;
#if defined(_SC_NPROCESSORS_ONLN)
    cpuCoreCount = sysconf(_SC_NPROCESSORS_ONLN);
#else
    // _SC_NPROC_ONLN must be defined...
    cpuCoreCount = sysconf(_SC_NPROC_ONLN);
#endif
    CHECK(cpuCoreCount >= 1);
    ALOGV("Number of CPU cores: %ld", cpuCoreCount);
    return (size_t)cpuCoreCount;
}

static void *ivd_aligned_malloc(void *ctxt, WORD32 alignment, WORD32 size) {
    (void) ctxt;
    return memalign(alignment, size);
}

static void ivd_aligned_free(void *ctxt, void *mem) {
    (void) ctxt;
    free(mem);
}

C2SoftHevcDec::C2SoftHevcDec(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
            mDecHandle(nullptr),
            mOutBufferFlush(nullptr),
            mIvColorformat(IV_YUV_420P),
            mWidth(320),
            mHeight(240) {
}

C2SoftHevcDec::~C2SoftHevcDec() {
    onRelease();
}

c2_status_t C2SoftHevcDec::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_CORRUPTED;
}

c2_status_t C2SoftHevcDec::onStop() {
    if (OK != resetDecoder()) return C2_CORRUPTED;
    resetPlugin();
    return C2_OK;
}

void C2SoftHevcDec::onReset() {
    (void) onStop();
}

void C2SoftHevcDec::onRelease() {
    (void) deleteDecoder();
    if (mOutBufferFlush) {
        ivd_aligned_free(nullptr, mOutBufferFlush);
        mOutBufferFlush = nullptr;
    }
    if (mOutBlock) {
        mOutBlock.reset();
    }
}

c2_status_t C2SoftHevcDec::onFlush_sm() {
    if (OK != setFlushMode()) return C2_CORRUPTED;

    uint32_t displayStride = mStride;
    uint32_t displayHeight = mHeight;
    uint32_t bufferSize = displayStride * displayHeight * 3 / 2;
    mOutBufferFlush = (uint8_t *)ivd_aligned_malloc(nullptr, 128, bufferSize);
    if (!mOutBufferFlush) {
        ALOGE("could not allocate tmp output buffer (for flush) of size %u ", bufferSize);
        return C2_NO_MEMORY;
    }

    while (true) {
        ivd_video_decode_ip_t s_decode_ip;
        ivd_video_decode_op_t s_decode_op;

        setDecodeArgs(&s_decode_ip, &s_decode_op, nullptr, nullptr, 0, 0, 0);
        (void) ivdec_api_function(mDecHandle, &s_decode_ip, &s_decode_op);
        if (0 == s_decode_op.u4_output_present) {
            resetPlugin();
            break;
        }
    }

    ivd_aligned_free(nullptr, mOutBufferFlush);
    mOutBufferFlush = nullptr;

    return C2_OK;
}

status_t C2SoftHevcDec::createDecoder() {
    ivdext_create_ip_t s_create_ip;
    ivdext_create_op_t s_create_op;

    s_create_ip.s_ivd_create_ip_t.u4_size = sizeof(ivdext_create_ip_t);
    s_create_ip.s_ivd_create_ip_t.e_cmd = IVD_CMD_CREATE;
    s_create_ip.s_ivd_create_ip_t.u4_share_disp_buf = 0;
    s_create_ip.s_ivd_create_ip_t.e_output_format = mIvColorformat;
    s_create_ip.s_ivd_create_ip_t.pf_aligned_alloc = ivd_aligned_malloc;
    s_create_ip.s_ivd_create_ip_t.pf_aligned_free = ivd_aligned_free;
    s_create_ip.s_ivd_create_ip_t.pv_mem_ctxt = nullptr;
    s_create_op.s_ivd_create_op_t.u4_size = sizeof(ivdext_create_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_create_ip,
                                                     &s_create_op);
    if (status != IV_SUCCESS) {
        ALOGE("error in %s: 0x%x", __func__,
              s_create_op.s_ivd_create_op_t.u4_error_code);
        return UNKNOWN_ERROR;
    }
    mDecHandle = (iv_obj_t*)s_create_op.s_ivd_create_op_t.pv_handle;
    mDecHandle->pv_fxns = (void *)ivdec_api_function;
    mDecHandle->u4_size = sizeof(iv_obj_t);

    return OK;
}

status_t C2SoftHevcDec::setNumCores() {
    ivdext_ctl_set_num_cores_ip_t s_set_num_cores_ip;
    ivdext_ctl_set_num_cores_op_t s_set_num_cores_op;

    s_set_num_cores_ip.u4_size = sizeof(ivdext_ctl_set_num_cores_ip_t);
    s_set_num_cores_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_set_num_cores_ip.e_sub_cmd = IVDEXT_CMD_CTL_SET_NUM_CORES;
    s_set_num_cores_ip.u4_num_cores = mNumCores;
    s_set_num_cores_op.u4_size = sizeof(ivdext_ctl_set_num_cores_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_set_num_cores_ip,
                                                     &s_set_num_cores_op);
    if (IV_SUCCESS != status) {
        ALOGD("error in %s: 0x%x", __func__, s_set_num_cores_op.u4_error_code);
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2SoftHevcDec::setParams(size_t stride) {
    ivd_ctl_set_config_ip_t s_set_dyn_params_ip;
    ivd_ctl_set_config_op_t s_set_dyn_params_op;

    s_set_dyn_params_ip.u4_size = sizeof(ivd_ctl_set_config_ip_t);
    s_set_dyn_params_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_set_dyn_params_ip.e_sub_cmd = IVD_CMD_CTL_SETPARAMS;
    s_set_dyn_params_ip.u4_disp_wd = (UWORD32) stride;
    s_set_dyn_params_ip.e_frm_skip_mode = IVD_SKIP_NONE;
    s_set_dyn_params_ip.e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
    s_set_dyn_params_ip.e_vid_dec_mode = IVD_DECODE_FRAME;
    s_set_dyn_params_op.u4_size = sizeof(ivd_ctl_set_config_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_set_dyn_params_ip,
                                                     &s_set_dyn_params_op);
    if (status != IV_SUCCESS) {
        ALOGE("error in %s: 0x%x", __func__, s_set_dyn_params_op.u4_error_code);
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2SoftHevcDec::getVersion() {
    ivd_ctl_getversioninfo_ip_t s_get_versioninfo_ip;
    ivd_ctl_getversioninfo_op_t s_get_versioninfo_op;
    UWORD8 au1_buf[512];

    s_get_versioninfo_ip.u4_size = sizeof(ivd_ctl_getversioninfo_ip_t);
    s_get_versioninfo_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_get_versioninfo_ip.e_sub_cmd = IVD_CMD_CTL_GETVERSION;
    s_get_versioninfo_ip.pv_version_buffer = au1_buf;
    s_get_versioninfo_ip.u4_version_buffer_size = sizeof(au1_buf);
    s_get_versioninfo_op.u4_size = sizeof(ivd_ctl_getversioninfo_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_get_versioninfo_ip,
                                                     &s_get_versioninfo_op);
    if (status != IV_SUCCESS) {
        ALOGD("error in %s: 0x%x", __func__,
              s_get_versioninfo_op.u4_error_code);
    } else {
        ALOGV("ittiam decoder version number: %s",
              (char *) s_get_versioninfo_ip.pv_version_buffer);
    }

    return OK;
}

status_t C2SoftHevcDec::initDecoder() {
    if (OK != createDecoder()) return UNKNOWN_ERROR;
    mNumCores = MIN(getCpuCoreCount(), MAX_NUM_CORES);
    mStride = ALIGN64(mWidth);
    mSignalledError = false;
    mPreference = kPreferBitstream;
    memset(&mDefaultColorAspects, 0, sizeof(ColorAspects));
    memset(&mBitstreamColorAspects, 0, sizeof(ColorAspects));
    memset(&mFinalColorAspects, 0, sizeof(ColorAspects));
    mUpdateColorAspects = false;
    resetPlugin();
    (void) setNumCores();
    if (OK != setParams(mStride)) return UNKNOWN_ERROR;
    (void) getVersion();

    return OK;
}

bool C2SoftHevcDec::setDecodeArgs(ivd_video_decode_ip_t *ps_decode_ip,
                                  ivd_video_decode_op_t *ps_decode_op,
                                  C2ReadView *inBuffer,
                                  C2GraphicView *outBuffer,
                                  size_t inOffset,
                                  size_t inSize,
                                  uint32_t tsMarker) {
    uint32_t displayStride = mStride;
    uint32_t displayHeight = mHeight;
    size_t lumaSize = displayStride * displayHeight;
    size_t chromaSize = lumaSize >> 2;

    ps_decode_ip->u4_size = sizeof(ivd_video_decode_ip_t);
    ps_decode_ip->e_cmd = IVD_CMD_VIDEO_DECODE;
    if (inBuffer) {
        ps_decode_ip->u4_ts = tsMarker;
        ps_decode_ip->pv_stream_buffer = const_cast<uint8_t *>(inBuffer->data() + inOffset);
        ps_decode_ip->u4_num_Bytes = inSize;
    } else {
        ps_decode_ip->u4_ts = 0;
        ps_decode_ip->pv_stream_buffer = nullptr;
        ps_decode_ip->u4_num_Bytes = 0;
    }
    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[0] = lumaSize;
    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[1] = chromaSize;
    ps_decode_ip->s_out_buffer.u4_min_out_buf_size[2] = chromaSize;
    if (outBuffer) {
        if (outBuffer->width() < displayStride || outBuffer->height() < displayHeight) {
            ALOGE("Output buffer too small: provided (%dx%d) required (%ux%u)",
                  outBuffer->width(), outBuffer->height(), displayStride, displayHeight);
            return false;
        }
        ps_decode_ip->s_out_buffer.pu1_bufs[0] = outBuffer->data()[C2PlanarLayout::PLANE_Y];
        ps_decode_ip->s_out_buffer.pu1_bufs[1] = outBuffer->data()[C2PlanarLayout::PLANE_U];
        ps_decode_ip->s_out_buffer.pu1_bufs[2] = outBuffer->data()[C2PlanarLayout::PLANE_V];
    } else {
        ps_decode_ip->s_out_buffer.pu1_bufs[0] = mOutBufferFlush;
        ps_decode_ip->s_out_buffer.pu1_bufs[1] = mOutBufferFlush + lumaSize;
        ps_decode_ip->s_out_buffer.pu1_bufs[2] = mOutBufferFlush + lumaSize + chromaSize;
    }
    ps_decode_ip->s_out_buffer.u4_num_bufs = 3;
    ps_decode_op->u4_size = sizeof(ivd_video_decode_op_t);
    ps_decode_op->u4_output_present = 0;

    return true;
}

bool C2SoftHevcDec::colorAspectsDiffer(
        const ColorAspects &a, const ColorAspects &b) {
    if (a.mRange != b.mRange
        || a.mPrimaries != b.mPrimaries
        || a.mTransfer != b.mTransfer
        || a.mMatrixCoeffs != b.mMatrixCoeffs) {
        return true;
    }
    return false;
}

void C2SoftHevcDec::updateFinalColorAspects(
        const ColorAspects &otherAspects, const ColorAspects &preferredAspects) {
    Mutex::Autolock autoLock(mColorAspectsLock);
    ColorAspects newAspects;
    newAspects.mRange = preferredAspects.mRange != ColorAspects::RangeUnspecified ?
        preferredAspects.mRange : otherAspects.mRange;
    newAspects.mPrimaries = preferredAspects.mPrimaries != ColorAspects::PrimariesUnspecified ?
        preferredAspects.mPrimaries : otherAspects.mPrimaries;
    newAspects.mTransfer = preferredAspects.mTransfer != ColorAspects::TransferUnspecified ?
        preferredAspects.mTransfer : otherAspects.mTransfer;
    newAspects.mMatrixCoeffs = preferredAspects.mMatrixCoeffs != ColorAspects::MatrixUnspecified ?
        preferredAspects.mMatrixCoeffs : otherAspects.mMatrixCoeffs;

    // Check to see if need update mFinalColorAspects.
    if (colorAspectsDiffer(mFinalColorAspects, newAspects)) {
        mFinalColorAspects = newAspects;
        mUpdateColorAspects = true;
    }
}

status_t C2SoftHevcDec::handleColorAspectsChange() {
    if (mPreference == kPreferBitstream) {
        updateFinalColorAspects(mDefaultColorAspects, mBitstreamColorAspects);
    } else if (mPreference == kPreferContainer) {
        updateFinalColorAspects(mBitstreamColorAspects, mDefaultColorAspects);
    } else {
        return C2_CORRUPTED;
    }
    return C2_OK;
}

bool C2SoftHevcDec::getVuiParams() {
    ivdext_ctl_get_vui_params_ip_t s_get_vui_params_ip;
    ivdext_ctl_get_vui_params_op_t s_get_vui_params_op;

    s_get_vui_params_ip.u4_size = sizeof(ivdext_ctl_get_vui_params_ip_t);
    s_get_vui_params_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_get_vui_params_ip.e_sub_cmd =
            (IVD_CONTROL_API_COMMAND_TYPE_T) IHEVCD_CXA_CMD_CTL_GET_VUI_PARAMS;
    s_get_vui_params_op.u4_size = sizeof(ivdext_ctl_get_vui_params_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_get_vui_params_ip,
                                                     &s_get_vui_params_op);
    if (status != IV_SUCCESS) {
        ALOGD("error in %s: 0x%x", __func__, s_get_vui_params_op.u4_error_code);
        return false;
    }

    int32_t primaries = s_get_vui_params_op.u1_colour_primaries;
    int32_t transfer = s_get_vui_params_op.u1_transfer_characteristics;
    int32_t coeffs = s_get_vui_params_op.u1_matrix_coefficients;
    bool full_range = s_get_vui_params_op.u1_video_full_range_flag;

    ColorAspects colorAspects;
    ColorUtils::convertIsoColorAspectsToCodecAspects(
            primaries, transfer, coeffs, full_range, colorAspects);
    // Update color aspects if necessary.
    if (colorAspectsDiffer(colorAspects, mBitstreamColorAspects)) {
        mBitstreamColorAspects = colorAspects;
        status_t err = handleColorAspectsChange();
        CHECK(err == OK);
    }

    return true;
}

status_t C2SoftHevcDec::setFlushMode() {
    ivd_ctl_flush_ip_t s_set_flush_ip;
    ivd_ctl_flush_op_t s_set_flush_op;

    s_set_flush_ip.u4_size = sizeof(ivd_ctl_flush_ip_t);
    s_set_flush_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_set_flush_ip.e_sub_cmd = IVD_CMD_CTL_FLUSH;
    s_set_flush_op.u4_size = sizeof(ivd_ctl_flush_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_set_flush_ip,
                                                     &s_set_flush_op);
    if (status != IV_SUCCESS) {
        ALOGE("error in %s: 0x%x", __func__, s_set_flush_op.u4_error_code);
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2SoftHevcDec::resetDecoder() {
    ivd_ctl_reset_ip_t s_reset_ip;
    ivd_ctl_reset_op_t s_reset_op;

    s_reset_ip.u4_size = sizeof(ivd_ctl_reset_ip_t);
    s_reset_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_reset_ip.e_sub_cmd = IVD_CMD_CTL_RESET;
    s_reset_op.u4_size = sizeof(ivd_ctl_reset_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_reset_ip,
                                                     &s_reset_op);
    if (IV_SUCCESS != status) {
        ALOGE("error in %s: 0x%x", __func__, s_reset_op.u4_error_code);
        return UNKNOWN_ERROR;
    }
    mStride = 0;
    (void) setNumCores();
    mSignalledError = false;

    return OK;
}

void C2SoftHevcDec::resetPlugin() {
    mSignalledOutputEos = false;
    gettimeofday(&mTimeStart, nullptr);
    gettimeofday(&mTimeEnd, nullptr);
}

status_t C2SoftHevcDec::deleteDecoder() {
    if (mDecHandle) {
        ivdext_delete_ip_t s_delete_ip;
        ivdext_delete_op_t s_delete_op;

        s_delete_ip.s_ivd_delete_ip_t.u4_size = sizeof(ivdext_delete_ip_t);
        s_delete_ip.s_ivd_delete_ip_t.e_cmd = IVD_CMD_DELETE;
        s_delete_op.s_ivd_delete_op_t.u4_size = sizeof(ivdext_delete_op_t);
        IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                         &s_delete_ip,
                                                         &s_delete_op);
        if (status != IV_SUCCESS) {
            ALOGE("error in %s: 0x%x", __func__,
                  s_delete_op.s_ivd_delete_op_t.u4_error_code);
            return UNKNOWN_ERROR;
        }
        mDecHandle = nullptr;
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

void C2SoftHevcDec::finishWork(uint64_t index, const std::unique_ptr<C2Work> &work) {
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

c2_status_t C2SoftHevcDec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool) {
    if (!mDecHandle) {
        ALOGE("not supposed to be here, invalid decoder context");
        return C2_CORRUPTED;
    }
    if (mStride != ALIGN64(mWidth)) {
        mStride = ALIGN64(mWidth);
        if (OK != setParams(mStride)) return C2_CORRUPTED;
    }
    if (mOutBlock &&
            (mOutBlock->width() != mStride || mOutBlock->height() != mHeight)) {
        mOutBlock.reset();
    }
    if (!mOutBlock) {
        uint32_t format = HAL_PIXEL_FORMAT_YV12;
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        c2_status_t err = pool->fetchGraphicBlock(mStride, mHeight, format, usage, &mOutBlock);
        if (err != C2_OK) {
            ALOGE("fetchGraphicBlock for Output failed with status %d", err);
            return err;
        }
        ALOGV("provided (%dx%d) required (%dx%d)",
              mOutBlock->width(), mOutBlock->height(), mStride, mHeight);
    }

    return C2_OK;
}

// TODO: can overall error checking be improved?
// TODO: allow configuration of color format and usage for graphic buffers instead
//       of hard coding them to HAL_PIXEL_FORMAT_YV12
// TODO: pass coloraspects information to surface
// TODO: test support for dynamic change in resolution
// TODO: verify if the decoder sent back all frames
void C2SoftHevcDec::process(
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
        work->result = rView.error();
        return;
    }
    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    bool hasPicture = false;

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d, flags %x",
          inSize, (int)work->input.ordinal.timestamp.peeku(),
          (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);
    size_t inPos = 0;
    while (inPos < inSize) {
        if (C2_OK != ensureDecoderState(pool)) {
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        C2GraphicView wView = mOutBlock->map().get();
        if (wView.error()) {
            ALOGE("graphic view map failed %d", wView.error());
            work->result = wView.error();
            return;
        }
        ivd_video_decode_ip_t s_decode_ip;
        ivd_video_decode_op_t s_decode_op;
        if (!setDecodeArgs(&s_decode_ip, &s_decode_op, &rView, &wView,
                           inOffset + inPos, inSize - inPos, workIndex)) {
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        WORD32 delay;
        GETTIME(&mTimeStart, NULL);
        TIME_DIFF(mTimeEnd, mTimeStart, delay);
        (void) ivdec_api_function(mDecHandle, &s_decode_ip, &s_decode_op);
        WORD32 decodeTime;
        GETTIME(&mTimeEnd, nullptr);
        TIME_DIFF(mTimeStart, mTimeEnd, decodeTime);
        ALOGV("decodeTime=%6d delay=%6d numBytes=%6d", decodeTime, delay,
              s_decode_op.u4_num_bytes_consumed);
        if (IVD_MEM_ALLOC_FAILED == (s_decode_op.u4_error_code & 0xFF)) {
            ALOGE("allocation failure in decoder");
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        } else if (IVD_STREAM_WIDTH_HEIGHT_NOT_SUPPORTED == (s_decode_op.u4_error_code & 0xFF)) {
            ALOGE("unsupported resolution : %dx%d", mWidth, mHeight);
            work->result = C2_CORRUPTED;
            mSignalledError = true;
            return;
        } else if (IVD_RES_CHANGED == (s_decode_op.u4_error_code & 0xFF)) {
            ALOGV("resolution changed");
            drainInternal(DRAIN_COMPONENT_NO_EOS, pool, work);
            resetDecoder();
            resetPlugin();
            continue;
        }
        if (0 < s_decode_op.u4_pic_wd && 0 < s_decode_op.u4_pic_ht) {
            if (s_decode_op.u4_pic_wd != mWidth ||  s_decode_op.u4_pic_ht != mHeight) {
                mWidth = s_decode_op.u4_pic_wd;
                mHeight = s_decode_op.u4_pic_ht;
                CHECK_EQ(0u, s_decode_op.u4_output_present);
            }
        }
        (void) getVuiParams();
        if (mUpdateColorAspects) {
            mUpdateColorAspects = false;
        }
        hasPicture |= (1 == s_decode_op.u4_frame_decoded_flag);
        if (s_decode_op.u4_output_present) {
            finishWork(s_decode_op.u4_ts, work);
        }
        inPos += s_decode_op.u4_num_bytes_consumed;
        if (hasPicture && (inSize - inPos)) {
            ALOGD("decoded frame in current access nal, ignoring further trailing bytes %d",
                  (int)inSize - (int)inPos);
            break;
        }
    }

    if (eos) {
        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
        mSignalledOutputEos = true;
    } else if (!hasPicture) {
        fillEmptyWork(work);
    }
}

c2_status_t C2SoftHevcDec::drainInternal(
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

    if (OK != setFlushMode()) return C2_CORRUPTED;
    while (true) {
        if (C2_OK != ensureDecoderState(pool)) {
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return C2_CORRUPTED;
        }
        C2GraphicView wView = mOutBlock->map().get();
        if (wView.error()) {
            ALOGE("graphic view map failed %d", wView.error());
            return C2_CORRUPTED;
        }
        ivd_video_decode_ip_t s_decode_ip;
        ivd_video_decode_op_t s_decode_op;
        if (!setDecodeArgs(&s_decode_ip, &s_decode_op, nullptr, &wView, 0, 0, 0)) {
            mSignalledError = true;
            return C2_CORRUPTED;
        }
        (void) ivdec_api_function(mDecHandle, &s_decode_ip, &s_decode_op);
        if (s_decode_op.u4_output_present) {
            finishWork(s_decode_op.u4_ts, work);
        } else {
            break;
        }
    }

    if (drainMode == DRAIN_COMPONENT_WITH_EOS &&
            work && work->workletsProcessed == 0u) {
        fillEmptyWork(work);
    }

    return C2_OK;
}

c2_status_t C2SoftHevcDec::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    return drainInternal(drainMode, pool, nullptr);
}

class C2SoftHevcDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftHevcDec(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftHevcDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftHevcDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
