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
#define LOG_TAG "C2SoftMpeg2Dec"
#include <utils/Log.h>

#include "iv_datatypedef.h"
#include "iv.h"
#include "ivd.h"
#include "impeg2d.h"
#include "C2SoftMpeg2Dec.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

constexpr char kComponentName[] = "c2.google.mpeg2.decoder";

static std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatVideo)
            .inputMediaType(MEDIA_MIMETYPE_VIDEO_MPEG2)
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

static void *ivd_aligned_malloc(WORD32 alignment, WORD32 size) {
    return memalign(alignment, size);
}

static void ivd_aligned_free(void *mem) {
    free(mem);
}

C2SoftMpeg2Dec::C2SoftMpeg2Dec(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
            mDecHandle(nullptr),
            mMemRecords(nullptr),
            mOutBufferDrain(nullptr),
            mIvColorformat(IV_YUV_420P),
            mWidth(320),
            mHeight(240) {
    // If input dump is enabled, then open create an empty file
    GENERATE_FILE_NAMES();
    CREATE_DUMP_FILE(mInFile);
}

C2SoftMpeg2Dec::~C2SoftMpeg2Dec() {
    onRelease();
}

c2_status_t C2SoftMpeg2Dec::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_CORRUPTED;
}

c2_status_t C2SoftMpeg2Dec::onStop() {
    if (OK != resetDecoder()) return C2_CORRUPTED;
    resetPlugin();
    return C2_OK;
}

void C2SoftMpeg2Dec::onReset() {
    (void) onStop();
}

void C2SoftMpeg2Dec::onRelease() {
    (void) deleteDecoder();
    if (mOutBufferDrain) {
        ivd_aligned_free(mOutBufferDrain);
        mOutBufferDrain = nullptr;
    }
    if (mOutBlock) {
        mOutBlock.reset();
    }
    if (mMemRecords) {
        ivd_aligned_free(mMemRecords);
        mMemRecords = nullptr;
    }
}

c2_status_t C2SoftMpeg2Dec::onFlush_sm() {
    if (OK != setFlushMode()) return C2_CORRUPTED;

    uint32_t displayStride = mStride;
    uint32_t displayHeight = mHeight;
    uint32_t bufferSize = displayStride * displayHeight * 3 / 2;
    mOutBufferDrain = (uint8_t *)ivd_aligned_malloc(128, bufferSize);
    if (!mOutBufferDrain) {
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

    ivd_aligned_free(mOutBufferDrain);
    mOutBufferDrain = nullptr;

    return C2_OK;
}

status_t C2SoftMpeg2Dec::getNumMemRecords() {
    iv_num_mem_rec_ip_t s_num_mem_rec_ip;
    iv_num_mem_rec_op_t s_num_mem_rec_op;

    s_num_mem_rec_ip.u4_size = sizeof(s_num_mem_rec_ip);
    s_num_mem_rec_ip.e_cmd = IV_CMD_GET_NUM_MEM_REC;
    s_num_mem_rec_op.u4_size = sizeof(s_num_mem_rec_op);

    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_num_mem_rec_ip,
                                                     &s_num_mem_rec_op);
    if (IV_SUCCESS != status) {
        ALOGE("Error in getting mem records: 0x%x", s_num_mem_rec_op.u4_error_code);
        return UNKNOWN_ERROR;
    }
    mNumMemRecords = s_num_mem_rec_op.u4_num_mem_rec;

    return OK;
}

status_t C2SoftMpeg2Dec::fillMemRecords() {
    iv_mem_rec_t *ps_mem_rec = (iv_mem_rec_t *) ivd_aligned_malloc(
            128, mNumMemRecords * sizeof(iv_mem_rec_t));
    if (!ps_mem_rec) {
        ALOGE("Allocation failure");
        return NO_MEMORY;
    }
    memset(ps_mem_rec, 0, mNumMemRecords * sizeof(iv_mem_rec_t));
    for (size_t i = 0; i < mNumMemRecords; i++)
        ps_mem_rec[i].u4_size = sizeof(iv_mem_rec_t);
    mMemRecords = ps_mem_rec;

    ivdext_fill_mem_rec_ip_t s_fill_mem_ip;
    ivdext_fill_mem_rec_op_t s_fill_mem_op;

    s_fill_mem_ip.s_ivd_fill_mem_rec_ip_t.u4_size = sizeof(ivdext_fill_mem_rec_ip_t);
    s_fill_mem_ip.u4_share_disp_buf = 0;
    s_fill_mem_ip.e_output_format = mIvColorformat;
    s_fill_mem_ip.u4_deinterlace = 1;
    s_fill_mem_ip.s_ivd_fill_mem_rec_ip_t.e_cmd = IV_CMD_FILL_NUM_MEM_REC;
    s_fill_mem_ip.s_ivd_fill_mem_rec_ip_t.pv_mem_rec_location = mMemRecords;
    s_fill_mem_ip.s_ivd_fill_mem_rec_ip_t.u4_max_frm_wd = mWidth;
    s_fill_mem_ip.s_ivd_fill_mem_rec_ip_t.u4_max_frm_ht = mHeight;
    s_fill_mem_op.s_ivd_fill_mem_rec_op_t.u4_size = sizeof(ivdext_fill_mem_rec_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_fill_mem_ip,
                                                     &s_fill_mem_op);
    if (IV_SUCCESS != status) {
        ALOGE("Error in filling mem records: 0x%x",
              s_fill_mem_op.s_ivd_fill_mem_rec_op_t.u4_error_code);
        return UNKNOWN_ERROR;
    }

    CHECK_EQ(mNumMemRecords, s_fill_mem_op.s_ivd_fill_mem_rec_op_t.u4_num_mem_rec_filled);
    for (size_t i = 0; i < mNumMemRecords; i++, ps_mem_rec++) {
        ps_mem_rec->pv_base = ivd_aligned_malloc(
                ps_mem_rec->u4_mem_alignment, ps_mem_rec->u4_mem_size);
        if (!ps_mem_rec->pv_base) {
            ALOGE("Allocation failure for memory record #%zu of size %u",
                  i, ps_mem_rec->u4_mem_size);
            return NO_MEMORY;
        }
    }

    return OK;
}

status_t C2SoftMpeg2Dec::createDecoder() {
    ivdext_init_ip_t s_init_ip;
    ivdext_init_op_t s_init_op;

    s_init_ip.s_ivd_init_ip_t.u4_size = sizeof(ivdext_init_ip_t);
    s_init_ip.s_ivd_init_ip_t.e_cmd = (IVD_API_COMMAND_TYPE_T)IV_CMD_INIT;
    s_init_ip.s_ivd_init_ip_t.pv_mem_rec_location = mMemRecords;
    s_init_ip.s_ivd_init_ip_t.u4_frm_max_wd = mWidth;
    s_init_ip.s_ivd_init_ip_t.u4_frm_max_ht = mHeight;
    s_init_ip.u4_share_disp_buf = 0;
    s_init_ip.u4_deinterlace = 1;
    s_init_ip.s_ivd_init_ip_t.u4_num_mem_rec = mNumMemRecords;
    s_init_ip.s_ivd_init_ip_t.e_output_format = mIvColorformat;
    s_init_op.s_ivd_init_op_t.u4_size = sizeof(ivdext_init_op_t);

    mDecHandle = (iv_obj_t *)mMemRecords[0].pv_base;
    mDecHandle->pv_fxns = (void *)ivdec_api_function;
    mDecHandle->u4_size = sizeof(iv_obj_t);

    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_init_ip,
                                                     &s_init_op);
    if (status != IV_SUCCESS) {
        ALOGE("error in %s: 0x%x", __func__,
              s_init_op.s_ivd_init_op_t.u4_error_code);
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2SoftMpeg2Dec::setNumCores() {
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
    if (status != IV_SUCCESS) {
        ALOGD("error in %s: 0x%x", __func__, s_set_num_cores_op.u4_error_code);
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2SoftMpeg2Dec::setParams(size_t stride) {
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

status_t C2SoftMpeg2Dec::getVersion() {
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

status_t C2SoftMpeg2Dec::initDecoder() {
    status_t ret = getNumMemRecords();
    if (OK != ret) return ret;

    ret = fillMemRecords();
    if (OK != ret) return ret;

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

bool C2SoftMpeg2Dec::setDecodeArgs(ivd_video_decode_ip_t *ps_decode_ip,
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
        ps_decode_ip->u4_num_Bytes = inSize - inOffset;
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
        ps_decode_ip->s_out_buffer.pu1_bufs[0] = mOutBufferDrain;
        ps_decode_ip->s_out_buffer.pu1_bufs[1] = mOutBufferDrain + lumaSize;
        ps_decode_ip->s_out_buffer.pu1_bufs[2] = mOutBufferDrain + lumaSize + chromaSize;
    }
    ps_decode_ip->s_out_buffer.u4_num_bufs = 3;
    ps_decode_op->u4_size = sizeof(ivd_video_decode_op_t);

    return true;
}

bool C2SoftMpeg2Dec::colorAspectsDiffer(
        const ColorAspects &a, const ColorAspects &b) {
    if (a.mRange != b.mRange
        || a.mPrimaries != b.mPrimaries
        || a.mTransfer != b.mTransfer
        || a.mMatrixCoeffs != b.mMatrixCoeffs) {
        return true;
    }
    return false;
}

void C2SoftMpeg2Dec::updateFinalColorAspects(
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

status_t C2SoftMpeg2Dec::handleColorAspectsChange() {
    if (mPreference == kPreferBitstream) {
        updateFinalColorAspects(mDefaultColorAspects, mBitstreamColorAspects);
    } else if (mPreference == kPreferContainer) {
        updateFinalColorAspects(mBitstreamColorAspects, mDefaultColorAspects);
    } else {
        return C2_CORRUPTED;
    }
    return C2_OK;
}

bool C2SoftMpeg2Dec::getSeqInfo() {
    ivdext_ctl_get_seq_info_ip_t s_ctl_get_seq_info_ip;
    ivdext_ctl_get_seq_info_op_t s_ctl_get_seq_info_op;

    s_ctl_get_seq_info_ip.u4_size = sizeof(ivdext_ctl_get_seq_info_ip_t);
    s_ctl_get_seq_info_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_get_seq_info_ip.e_sub_cmd =
        (IVD_CONTROL_API_COMMAND_TYPE_T)IMPEG2D_CMD_CTL_GET_SEQ_INFO;
    s_ctl_get_seq_info_op.u4_size = sizeof(ivdext_ctl_get_seq_info_op_t);
    IV_API_CALL_STATUS_T status = ivdec_api_function(mDecHandle,
                                                     &s_ctl_get_seq_info_ip,
                                                     &s_ctl_get_seq_info_op);
    if (status != IV_SUCCESS) {
        ALOGW("Error in getting Sequence info: 0x%x", s_ctl_get_seq_info_op.u4_error_code);
        return false;
    }

    int32_t primaries = s_ctl_get_seq_info_op.u1_colour_primaries;
    int32_t transfer = s_ctl_get_seq_info_op.u1_transfer_characteristics;
    int32_t coeffs = s_ctl_get_seq_info_op.u1_matrix_coefficients;
    bool full_range =  false;  // mpeg2 video has limited range.

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

status_t C2SoftMpeg2Dec::setFlushMode() {
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

status_t C2SoftMpeg2Dec::resetDecoder() {
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
    (void) setNumCores();
    mStride = 0;
    mSignalledError = false;

    return OK;
}

void C2SoftMpeg2Dec::resetPlugin() {
    mSignalledOutputEos = false;
    gettimeofday(&mTimeStart, nullptr);
    gettimeofday(&mTimeEnd, nullptr);
}

status_t C2SoftMpeg2Dec::deleteDecoder() {
    if (mMemRecords) {
        iv_mem_rec_t *ps_mem_rec = mMemRecords;

        for (size_t i = 0; i < mNumMemRecords; i++, ps_mem_rec++) {
            if (ps_mem_rec->pv_base) {
                ivd_aligned_free(ps_mem_rec->pv_base);
            }
        }
        ivd_aligned_free(mMemRecords);
        mMemRecords = nullptr;
    }
    mDecHandle = nullptr;

    return OK;
}

status_t C2SoftMpeg2Dec::reInitDecoder() {
    deleteDecoder();

    status_t ret = initDecoder();
    if (OK != ret) {
        ALOGE("Failed to initialize decoder");
        deleteDecoder();
        return ret;
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

void C2SoftMpeg2Dec::finishWork(uint64_t index, const std::unique_ptr<C2Work> &work) {
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

c2_status_t C2SoftMpeg2Dec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool) {
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
void C2SoftMpeg2Dec::process(
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
    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    bool hasPicture = false;

    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d, flags %x",
          inSize, (int)work->input.ordinal.timestamp.peeku(),
          (int)work->input.ordinal.frameIndex.peeku(), work->input.flags);
    while (inOffset < inSize) {
        if (C2_OK != ensureDecoderState(pool)) {
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        C2GraphicView wView = mOutBlock->map().get();
        if (wView.error()) {
            ALOGE("graphic view map failed %d", wView.error());
            work->result = C2_CORRUPTED;
            return;
        }

        ivd_video_decode_ip_t s_decode_ip;
        ivd_video_decode_op_t s_decode_op;
        if (!setDecodeArgs(&s_decode_ip, &s_decode_op, &rView, &wView,
                           inOffset, inSize, workIndex)) {
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }
        // If input dump is enabled, then write to file
        DUMP_TO_FILE(mInFile, s_decode_ip.pv_stream_buffer, s_decode_ip.u4_num_Bytes);
        WORD32 delay;
        GETTIME(&mTimeStart, NULL);
        TIME_DIFF(mTimeEnd, mTimeStart, delay);
        (void) ivdec_api_function(mDecHandle, &s_decode_ip, &s_decode_op);
        WORD32 decodeTime;
        GETTIME(&mTimeEnd, nullptr);
        TIME_DIFF(mTimeStart, mTimeEnd, decodeTime);
        ALOGV("decodeTime=%6d delay=%6d numBytes=%6d ", decodeTime, delay,
              s_decode_op.u4_num_bytes_consumed);
        if (IMPEG2D_UNSUPPORTED_DIMENSIONS == s_decode_op.u4_error_code) {
            ALOGV("unsupported resolution : %dx%d", s_decode_op.u4_pic_wd, s_decode_op.u4_pic_ht);
            drainInternal(DRAIN_COMPONENT_NO_EOS, pool, work);
            resetPlugin();
            mWidth = s_decode_op.u4_pic_wd;
            mHeight = s_decode_op.u4_pic_ht;
            if (OK != reInitDecoder()) {
                ALOGE("Failed to reinitialize decoder");
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
            continue;
        } else if (IVD_RES_CHANGED == (s_decode_op.u4_error_code & 0xFF)) {
            ALOGV("resolution changed");
            drainInternal(DRAIN_COMPONENT_NO_EOS, pool, work);
            resetDecoder();
            resetPlugin();
            mWidth = s_decode_op.u4_pic_wd;
            mHeight = s_decode_op.u4_pic_ht;
            continue;
        }

        (void) getSeqInfo();
        if (mUpdateColorAspects) {
            mUpdateColorAspects = false;
        }
        hasPicture |= (1 == s_decode_op.u4_frame_decoded_flag);
        if (s_decode_op.u4_output_present) {
            finishWork(s_decode_op.u4_ts, work);
        }
        inOffset += s_decode_op.u4_num_bytes_consumed;
        if (hasPicture && (inSize - inOffset)) {
            ALOGD("decoded frame in current access nal, ignoring further trailing bytes %d",
                  (int)inSize - (int)inOffset);
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

c2_status_t C2SoftMpeg2Dec::drainInternal(
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

c2_status_t C2SoftMpeg2Dec::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    return drainInternal(drainMode, pool, nullptr);
}

class C2SoftMpeg2DecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftMpeg2Dec(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftMpeg2DecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftMpeg2DecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
