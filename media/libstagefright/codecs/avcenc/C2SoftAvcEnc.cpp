/*
 * Copyright 2018 The Android Open Source Project
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
#define LOG_TAG "C2SoftAvcEnc"
#include <utils/Log.h>
#include <utils/misc.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include "ih264_typedefs.h"
#include "ih264e.h"
#include "ih264e_error.h"
#include "iv2.h"
#include "ive2.h"
#include "C2SoftAvcEnc.h"

namespace android {

#define ive_api_function  ih264e_api_function

constexpr char kComponentName[] = "c2.google.avc.encoder";

namespace {

// From external/libavc/encoder/ih264e_bitstream.h
constexpr uint32_t MIN_STREAM_SIZE = 0x800;

static size_t GetCPUCoreCount() {
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

std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatVideo)
            .outputFormat(C2FormatCompressed)
            .inputMediaType(MEDIA_MIMETYPE_VIDEO_RAW)
            .outputMediaType(MEDIA_MIMETYPE_VIDEO_AVC)
            .build();
}

void ConvertRGBToPlanarYUV(
        uint8_t *dstY, size_t dstStride, size_t dstVStride,
        const C2GraphicView &src) {
    CHECK((src.width() & 1) == 0);
    CHECK((src.height() & 1) == 0);

    uint8_t *dstU = dstY + dstStride * dstVStride;
    uint8_t *dstV = dstU + (dstStride >> 1) * (dstVStride >> 1);

    const C2PlanarLayout &layout = src.layout();
    const uint8_t *pRed   = src.data()[C2PlanarLayout::PLANE_R];
    const uint8_t *pGreen = src.data()[C2PlanarLayout::PLANE_G];
    const uint8_t *pBlue  = src.data()[C2PlanarLayout::PLANE_B];

    for (size_t y = 0; y < src.height(); ++y) {
        for (size_t x = 0; x < src.width(); ++x) {
            unsigned red   = *pRed;
            unsigned green = *pGreen;
            unsigned blue  = *pBlue;

            // using ITU-R BT.601 conversion matrix
            unsigned luma =
                ((red * 66 + green * 129 + blue * 25) >> 8) + 16;

            dstY[x] = luma;

            if ((x & 1) == 0 && (y & 1) == 0) {
                unsigned U =
                    ((-red * 38 - green * 74 + blue * 112) >> 8) + 128;

                unsigned V =
                    ((red * 112 - green * 94 - blue * 18) >> 8) + 128;

                dstU[x >> 1] = U;
                dstV[x >> 1] = V;
            }
            pRed   += layout.planes[C2PlanarLayout::PLANE_R].colInc;
            pGreen += layout.planes[C2PlanarLayout::PLANE_G].colInc;
            pBlue  += layout.planes[C2PlanarLayout::PLANE_B].colInc;
        }

        if ((y & 1) == 0) {
            dstU += dstStride >> 1;
            dstV += dstStride >> 1;
        }

        pRed   -= layout.planes[C2PlanarLayout::PLANE_R].colInc * src.width();
        pGreen -= layout.planes[C2PlanarLayout::PLANE_G].colInc * src.width();
        pBlue  -= layout.planes[C2PlanarLayout::PLANE_B].colInc * src.width();
        pRed   += layout.planes[C2PlanarLayout::PLANE_R].rowInc;
        pGreen += layout.planes[C2PlanarLayout::PLANE_G].rowInc;
        pBlue  += layout.planes[C2PlanarLayout::PLANE_B].rowInc;

        dstY += dstStride;
    }
}

}  // namespace

C2SoftAvcEnc::C2SoftAvcEnc(const char *name, c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mUpdateFlag(0),
      mIvVideoColorFormat(IV_YUV_420P),
      mAVCEncProfile(IV_PROFILE_BASE),
      mAVCEncLevel(41),
      mStarted(false),
      mSawInputEOS(false),
      mSawOutputEOS(false),
      mSignalledError(false),
      mCodecCtx(NULL),
      mWidth(1080),
      mHeight(1920),
      mFramerate(60),
      mBitrate(20000),
      // TODO: output buffer size
      mOutBufferSize(524288) {

    // If dump is enabled, then open create an empty file
    GENERATE_FILE_NAMES();
    CREATE_DUMP_FILE(mInFile);
    CREATE_DUMP_FILE(mOutFile);

    initEncParams();
}

C2SoftAvcEnc::~C2SoftAvcEnc() {
    releaseEncoder();
}

c2_status_t C2SoftAvcEnc::onInit() {
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::onStop() {
    return C2_OK;
}

void C2SoftAvcEnc::onReset() {
    // TODO: use IVE_CMD_CTL_RESET?
    releaseEncoder();
    initEncParams();
}

void C2SoftAvcEnc::onRelease() {
    releaseEncoder();
}

c2_status_t C2SoftAvcEnc::onFlush_sm() {
    // TODO: use IVE_CMD_CTL_FLUSH?
    return C2_OK;
}

void  C2SoftAvcEnc::initEncParams() {
    mCodecCtx = NULL;
    mMemRecords = NULL;
    mNumMemRecords = DEFAULT_MEM_REC_CNT;
    mHeaderGenerated = 0;
    mNumCores = GetCPUCoreCount();
    mArch = DEFAULT_ARCH;
    mSliceMode = DEFAULT_SLICE_MODE;
    mSliceParam = DEFAULT_SLICE_PARAM;
    mHalfPelEnable = DEFAULT_HPEL;
    mIInterval = DEFAULT_I_INTERVAL;
    mIDRInterval = DEFAULT_IDR_INTERVAL;
    mDisableDeblkLevel = DEFAULT_DISABLE_DEBLK_LEVEL;
    mEnableFastSad = DEFAULT_ENABLE_FAST_SAD;
    mEnableAltRef = DEFAULT_ENABLE_ALT_REF;
    mEncSpeed = DEFAULT_ENC_SPEED;
    mIntra4x4 = DEFAULT_INTRA4x4;
    mConstrainedIntraFlag = DEFAULT_CONSTRAINED_INTRA;
    mAIRMode = DEFAULT_AIR;
    mAIRRefreshPeriod = DEFAULT_AIR_REFRESH_PERIOD;
    mPSNREnable = DEFAULT_PSNR_ENABLE;
    mReconEnable = DEFAULT_RECON_ENABLE;
    mEntropyMode = DEFAULT_ENTROPY_MODE;
    mBframes = DEFAULT_B_FRAMES;

    gettimeofday(&mTimeStart, NULL);
    gettimeofday(&mTimeEnd, NULL);
}

c2_status_t C2SoftAvcEnc::setDimensions() {
    ive_ctl_set_dimensions_ip_t s_dimensions_ip;
    ive_ctl_set_dimensions_op_t s_dimensions_op;
    IV_STATUS_T status;

    s_dimensions_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_dimensions_ip.e_sub_cmd = IVE_CMD_CTL_SET_DIMENSIONS;
    s_dimensions_ip.u4_ht = mHeight;
    s_dimensions_ip.u4_wd = mWidth;

    s_dimensions_ip.u4_timestamp_high = -1;
    s_dimensions_ip.u4_timestamp_low = -1;

    s_dimensions_ip.u4_size = sizeof(ive_ctl_set_dimensions_ip_t);
    s_dimensions_op.u4_size = sizeof(ive_ctl_set_dimensions_op_t);

    status = ive_api_function(mCodecCtx, &s_dimensions_ip, &s_dimensions_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set frame dimensions = 0x%x\n",
                s_dimensions_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setNumCores() {
    IV_STATUS_T status;
    ive_ctl_set_num_cores_ip_t s_num_cores_ip;
    ive_ctl_set_num_cores_op_t s_num_cores_op;
    s_num_cores_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_num_cores_ip.e_sub_cmd = IVE_CMD_CTL_SET_NUM_CORES;
    s_num_cores_ip.u4_num_cores = MIN(mNumCores, CODEC_MAX_CORES);
    s_num_cores_ip.u4_timestamp_high = -1;
    s_num_cores_ip.u4_timestamp_low = -1;
    s_num_cores_ip.u4_size = sizeof(ive_ctl_set_num_cores_ip_t);

    s_num_cores_op.u4_size = sizeof(ive_ctl_set_num_cores_op_t);

    status = ive_api_function(
            mCodecCtx, (void *) &s_num_cores_ip, (void *) &s_num_cores_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set processor params = 0x%x\n",
                s_num_cores_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setFrameRate() {
    ive_ctl_set_frame_rate_ip_t s_frame_rate_ip;
    ive_ctl_set_frame_rate_op_t s_frame_rate_op;
    IV_STATUS_T status;

    s_frame_rate_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_frame_rate_ip.e_sub_cmd = IVE_CMD_CTL_SET_FRAMERATE;

    s_frame_rate_ip.u4_src_frame_rate = mFramerate;
    s_frame_rate_ip.u4_tgt_frame_rate = mFramerate;

    s_frame_rate_ip.u4_timestamp_high = -1;
    s_frame_rate_ip.u4_timestamp_low = -1;

    s_frame_rate_ip.u4_size = sizeof(ive_ctl_set_frame_rate_ip_t);
    s_frame_rate_op.u4_size = sizeof(ive_ctl_set_frame_rate_op_t);

    status = ive_api_function(mCodecCtx, &s_frame_rate_ip, &s_frame_rate_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set frame rate = 0x%x\n",
                s_frame_rate_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setIpeParams() {
    ive_ctl_set_ipe_params_ip_t s_ipe_params_ip;
    ive_ctl_set_ipe_params_op_t s_ipe_params_op;
    IV_STATUS_T status;

    s_ipe_params_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_ipe_params_ip.e_sub_cmd = IVE_CMD_CTL_SET_IPE_PARAMS;

    s_ipe_params_ip.u4_enable_intra_4x4 = mIntra4x4;
    s_ipe_params_ip.u4_enc_speed_preset = mEncSpeed;
    s_ipe_params_ip.u4_constrained_intra_pred = mConstrainedIntraFlag;

    s_ipe_params_ip.u4_timestamp_high = -1;
    s_ipe_params_ip.u4_timestamp_low = -1;

    s_ipe_params_ip.u4_size = sizeof(ive_ctl_set_ipe_params_ip_t);
    s_ipe_params_op.u4_size = sizeof(ive_ctl_set_ipe_params_op_t);

    status = ive_api_function(mCodecCtx, &s_ipe_params_ip, &s_ipe_params_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set ipe params = 0x%x\n",
                s_ipe_params_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setBitRate() {
    ive_ctl_set_bitrate_ip_t s_bitrate_ip;
    ive_ctl_set_bitrate_op_t s_bitrate_op;
    IV_STATUS_T status;

    s_bitrate_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_bitrate_ip.e_sub_cmd = IVE_CMD_CTL_SET_BITRATE;

    s_bitrate_ip.u4_target_bitrate = mBitrate;

    s_bitrate_ip.u4_timestamp_high = -1;
    s_bitrate_ip.u4_timestamp_low = -1;

    s_bitrate_ip.u4_size = sizeof(ive_ctl_set_bitrate_ip_t);
    s_bitrate_op.u4_size = sizeof(ive_ctl_set_bitrate_op_t);

    status = ive_api_function(mCodecCtx, &s_bitrate_ip, &s_bitrate_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set bit rate = 0x%x\n", s_bitrate_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setFrameType(IV_PICTURE_CODING_TYPE_T e_frame_type) {
    ive_ctl_set_frame_type_ip_t s_frame_type_ip;
    ive_ctl_set_frame_type_op_t s_frame_type_op;
    IV_STATUS_T status;
    s_frame_type_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_frame_type_ip.e_sub_cmd = IVE_CMD_CTL_SET_FRAMETYPE;

    s_frame_type_ip.e_frame_type = e_frame_type;

    s_frame_type_ip.u4_timestamp_high = -1;
    s_frame_type_ip.u4_timestamp_low = -1;

    s_frame_type_ip.u4_size = sizeof(ive_ctl_set_frame_type_ip_t);
    s_frame_type_op.u4_size = sizeof(ive_ctl_set_frame_type_op_t);

    status = ive_api_function(mCodecCtx, &s_frame_type_ip, &s_frame_type_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set frame type = 0x%x\n",
                s_frame_type_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setQp() {
    ive_ctl_set_qp_ip_t s_qp_ip;
    ive_ctl_set_qp_op_t s_qp_op;
    IV_STATUS_T status;

    s_qp_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_qp_ip.e_sub_cmd = IVE_CMD_CTL_SET_QP;

    s_qp_ip.u4_i_qp = DEFAULT_I_QP;
    s_qp_ip.u4_i_qp_max = DEFAULT_QP_MAX;
    s_qp_ip.u4_i_qp_min = DEFAULT_QP_MIN;

    s_qp_ip.u4_p_qp = DEFAULT_P_QP;
    s_qp_ip.u4_p_qp_max = DEFAULT_QP_MAX;
    s_qp_ip.u4_p_qp_min = DEFAULT_QP_MIN;

    s_qp_ip.u4_b_qp = DEFAULT_P_QP;
    s_qp_ip.u4_b_qp_max = DEFAULT_QP_MAX;
    s_qp_ip.u4_b_qp_min = DEFAULT_QP_MIN;

    s_qp_ip.u4_timestamp_high = -1;
    s_qp_ip.u4_timestamp_low = -1;

    s_qp_ip.u4_size = sizeof(ive_ctl_set_qp_ip_t);
    s_qp_op.u4_size = sizeof(ive_ctl_set_qp_op_t);

    status = ive_api_function(mCodecCtx, &s_qp_ip, &s_qp_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set qp 0x%x\n", s_qp_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setEncMode(IVE_ENC_MODE_T e_enc_mode) {
    IV_STATUS_T status;
    ive_ctl_set_enc_mode_ip_t s_enc_mode_ip;
    ive_ctl_set_enc_mode_op_t s_enc_mode_op;

    s_enc_mode_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_enc_mode_ip.e_sub_cmd = IVE_CMD_CTL_SET_ENC_MODE;

    s_enc_mode_ip.e_enc_mode = e_enc_mode;

    s_enc_mode_ip.u4_timestamp_high = -1;
    s_enc_mode_ip.u4_timestamp_low = -1;

    s_enc_mode_ip.u4_size = sizeof(ive_ctl_set_enc_mode_ip_t);
    s_enc_mode_op.u4_size = sizeof(ive_ctl_set_enc_mode_op_t);

    status = ive_api_function(mCodecCtx, &s_enc_mode_ip, &s_enc_mode_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set in header encode mode = 0x%x\n",
                s_enc_mode_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setVbvParams() {
    ive_ctl_set_vbv_params_ip_t s_vbv_ip;
    ive_ctl_set_vbv_params_op_t s_vbv_op;
    IV_STATUS_T status;

    s_vbv_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_vbv_ip.e_sub_cmd = IVE_CMD_CTL_SET_VBV_PARAMS;

    s_vbv_ip.u4_vbv_buf_size = 0;
    s_vbv_ip.u4_vbv_buffer_delay = 1000;

    s_vbv_ip.u4_timestamp_high = -1;
    s_vbv_ip.u4_timestamp_low = -1;

    s_vbv_ip.u4_size = sizeof(ive_ctl_set_vbv_params_ip_t);
    s_vbv_op.u4_size = sizeof(ive_ctl_set_vbv_params_op_t);

    status = ive_api_function(mCodecCtx, &s_vbv_ip, &s_vbv_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set VBV params = 0x%x\n", s_vbv_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setAirParams() {
    ive_ctl_set_air_params_ip_t s_air_ip;
    ive_ctl_set_air_params_op_t s_air_op;
    IV_STATUS_T status;

    s_air_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_air_ip.e_sub_cmd = IVE_CMD_CTL_SET_AIR_PARAMS;

    s_air_ip.e_air_mode = mAIRMode;
    s_air_ip.u4_air_refresh_period = mAIRRefreshPeriod;

    s_air_ip.u4_timestamp_high = -1;
    s_air_ip.u4_timestamp_low = -1;

    s_air_ip.u4_size = sizeof(ive_ctl_set_air_params_ip_t);
    s_air_op.u4_size = sizeof(ive_ctl_set_air_params_op_t);

    status = ive_api_function(mCodecCtx, &s_air_ip, &s_air_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set air params = 0x%x\n", s_air_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setMeParams() {
    IV_STATUS_T status;
    ive_ctl_set_me_params_ip_t s_me_params_ip;
    ive_ctl_set_me_params_op_t s_me_params_op;

    s_me_params_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_me_params_ip.e_sub_cmd = IVE_CMD_CTL_SET_ME_PARAMS;

    s_me_params_ip.u4_enable_fast_sad = mEnableFastSad;
    s_me_params_ip.u4_enable_alt_ref = mEnableAltRef;

    s_me_params_ip.u4_enable_hpel = mHalfPelEnable;
    s_me_params_ip.u4_enable_qpel = DEFAULT_QPEL;
    s_me_params_ip.u4_me_speed_preset = DEFAULT_ME_SPEED;
    s_me_params_ip.u4_srch_rng_x = DEFAULT_SRCH_RNG_X;
    s_me_params_ip.u4_srch_rng_y = DEFAULT_SRCH_RNG_Y;

    s_me_params_ip.u4_timestamp_high = -1;
    s_me_params_ip.u4_timestamp_low = -1;

    s_me_params_ip.u4_size = sizeof(ive_ctl_set_me_params_ip_t);
    s_me_params_op.u4_size = sizeof(ive_ctl_set_me_params_op_t);

    status = ive_api_function(mCodecCtx, &s_me_params_ip, &s_me_params_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set me params = 0x%x\n", s_me_params_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setGopParams() {
    IV_STATUS_T status;
    ive_ctl_set_gop_params_ip_t s_gop_params_ip;
    ive_ctl_set_gop_params_op_t s_gop_params_op;

    s_gop_params_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_gop_params_ip.e_sub_cmd = IVE_CMD_CTL_SET_GOP_PARAMS;

    s_gop_params_ip.u4_i_frm_interval = mIInterval;
    s_gop_params_ip.u4_idr_frm_interval = mIDRInterval;

    s_gop_params_ip.u4_timestamp_high = -1;
    s_gop_params_ip.u4_timestamp_low = -1;

    s_gop_params_ip.u4_size = sizeof(ive_ctl_set_gop_params_ip_t);
    s_gop_params_op.u4_size = sizeof(ive_ctl_set_gop_params_op_t);

    status = ive_api_function(mCodecCtx, &s_gop_params_ip, &s_gop_params_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set GOP params = 0x%x\n",
                s_gop_params_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setProfileParams() {
    IV_STATUS_T status;
    ive_ctl_set_profile_params_ip_t s_profile_params_ip;
    ive_ctl_set_profile_params_op_t s_profile_params_op;

    s_profile_params_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_profile_params_ip.e_sub_cmd = IVE_CMD_CTL_SET_PROFILE_PARAMS;

    s_profile_params_ip.e_profile = DEFAULT_EPROFILE;
    s_profile_params_ip.u4_entropy_coding_mode = mEntropyMode;
    s_profile_params_ip.u4_timestamp_high = -1;
    s_profile_params_ip.u4_timestamp_low = -1;

    s_profile_params_ip.u4_size = sizeof(ive_ctl_set_profile_params_ip_t);
    s_profile_params_op.u4_size = sizeof(ive_ctl_set_profile_params_op_t);

    status = ive_api_function(mCodecCtx, &s_profile_params_ip, &s_profile_params_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to set profile params = 0x%x\n",
                s_profile_params_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setDeblockParams() {
    IV_STATUS_T status;
    ive_ctl_set_deblock_params_ip_t s_deblock_params_ip;
    ive_ctl_set_deblock_params_op_t s_deblock_params_op;

    s_deblock_params_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_deblock_params_ip.e_sub_cmd = IVE_CMD_CTL_SET_DEBLOCK_PARAMS;

    s_deblock_params_ip.u4_disable_deblock_level = mDisableDeblkLevel;

    s_deblock_params_ip.u4_timestamp_high = -1;
    s_deblock_params_ip.u4_timestamp_low = -1;

    s_deblock_params_ip.u4_size = sizeof(ive_ctl_set_deblock_params_ip_t);
    s_deblock_params_op.u4_size = sizeof(ive_ctl_set_deblock_params_op_t);

    status = ive_api_function(mCodecCtx, &s_deblock_params_ip, &s_deblock_params_op);
    if (status != IV_SUCCESS) {
        ALOGE("Unable to enable/disable deblock params = 0x%x\n",
                s_deblock_params_op.u4_error_code);
        return C2_CORRUPTED;
    }
    return C2_OK;
}

void C2SoftAvcEnc::logVersion() {
    ive_ctl_getversioninfo_ip_t s_ctl_ip;
    ive_ctl_getversioninfo_op_t s_ctl_op;
    UWORD8 au1_buf[512];
    IV_STATUS_T status;

    s_ctl_ip.e_cmd = IVE_CMD_VIDEO_CTL;
    s_ctl_ip.e_sub_cmd = IVE_CMD_CTL_GETVERSION;
    s_ctl_ip.u4_size = sizeof(ive_ctl_getversioninfo_ip_t);
    s_ctl_op.u4_size = sizeof(ive_ctl_getversioninfo_op_t);
    s_ctl_ip.pu1_version = au1_buf;
    s_ctl_ip.u4_version_bufsize = sizeof(au1_buf);

    status = ive_api_function(mCodecCtx, (void *) &s_ctl_ip, (void *) &s_ctl_op);

    if (status != IV_SUCCESS) {
        ALOGE("Error in getting version: 0x%x", s_ctl_op.u4_error_code);
    } else {
        ALOGV("Ittiam encoder version: %s", (char *)s_ctl_ip.pu1_version);
    }
    return;
}

c2_status_t C2SoftAvcEnc::initEncoder() {
    IV_STATUS_T status;
    WORD32 level;
    uint32_t displaySizeY;

    CHECK(!mStarted);

    c2_status_t errType = C2_OK;

    displaySizeY = mWidth * mHeight;
    if (displaySizeY > (1920 * 1088)) {
        level = 50;
    } else if (displaySizeY > (1280 * 720)) {
        level = 40;
    } else if (displaySizeY > (720 * 576)) {
        level = 31;
    } else if (displaySizeY > (624 * 320)) {
        level = 30;
    } else if (displaySizeY > (352 * 288)) {
        level = 21;
    } else if (displaySizeY > (176 * 144)) {
        level = 20;
    } else {
        level = 10;
    }
    mAVCEncLevel = MAX(level, mAVCEncLevel);

    mStride = mWidth;

    // TODO
    mIvVideoColorFormat = IV_YUV_420P;

    ALOGD("Params width %d height %d level %d colorFormat %d", mWidth,
            mHeight, mAVCEncLevel, mIvVideoColorFormat);

    /* Getting Number of MemRecords */
    {
        iv_num_mem_rec_ip_t s_num_mem_rec_ip;
        iv_num_mem_rec_op_t s_num_mem_rec_op;

        s_num_mem_rec_ip.u4_size = sizeof(iv_num_mem_rec_ip_t);
        s_num_mem_rec_op.u4_size = sizeof(iv_num_mem_rec_op_t);

        s_num_mem_rec_ip.e_cmd = IV_CMD_GET_NUM_MEM_REC;

        status = ive_api_function(0, &s_num_mem_rec_ip, &s_num_mem_rec_op);

        if (status != IV_SUCCESS) {
            ALOGE("Get number of memory records failed = 0x%x\n",
                    s_num_mem_rec_op.u4_error_code);
            return C2_CORRUPTED;
        }

        mNumMemRecords = s_num_mem_rec_op.u4_num_mem_rec;
    }

    /* Allocate array to hold memory records */
    if (mNumMemRecords > SIZE_MAX / sizeof(iv_mem_rec_t)) {
        ALOGE("requested memory size is too big.");
        return C2_CORRUPTED;
    }
    mMemRecords = (iv_mem_rec_t *)malloc(mNumMemRecords * sizeof(iv_mem_rec_t));
    if (NULL == mMemRecords) {
        ALOGE("Unable to allocate memory for hold memory records: Size %zu",
                mNumMemRecords * sizeof(iv_mem_rec_t));
        mSignalledError = true;
        return C2_CORRUPTED;
    }

    {
        iv_mem_rec_t *ps_mem_rec;
        ps_mem_rec = mMemRecords;
        for (size_t i = 0; i < mNumMemRecords; i++) {
            ps_mem_rec->u4_size = sizeof(iv_mem_rec_t);
            ps_mem_rec->pv_base = NULL;
            ps_mem_rec->u4_mem_size = 0;
            ps_mem_rec->u4_mem_alignment = 0;
            ps_mem_rec->e_mem_type = IV_NA_MEM_TYPE;

            ps_mem_rec++;
        }
    }

    /* Getting MemRecords Attributes */
    {
        iv_fill_mem_rec_ip_t s_fill_mem_rec_ip;
        iv_fill_mem_rec_op_t s_fill_mem_rec_op;

        s_fill_mem_rec_ip.u4_size = sizeof(iv_fill_mem_rec_ip_t);
        s_fill_mem_rec_op.u4_size = sizeof(iv_fill_mem_rec_op_t);

        s_fill_mem_rec_ip.e_cmd = IV_CMD_FILL_NUM_MEM_REC;
        s_fill_mem_rec_ip.ps_mem_rec = mMemRecords;
        s_fill_mem_rec_ip.u4_num_mem_rec = mNumMemRecords;
        s_fill_mem_rec_ip.u4_max_wd = mWidth;
        s_fill_mem_rec_ip.u4_max_ht = mHeight;
        s_fill_mem_rec_ip.u4_max_level = mAVCEncLevel;
        s_fill_mem_rec_ip.e_color_format = DEFAULT_INP_COLOR_FORMAT;
        s_fill_mem_rec_ip.u4_max_ref_cnt = DEFAULT_MAX_REF_FRM;
        s_fill_mem_rec_ip.u4_max_reorder_cnt = DEFAULT_MAX_REORDER_FRM;
        s_fill_mem_rec_ip.u4_max_srch_rng_x = DEFAULT_MAX_SRCH_RANGE_X;
        s_fill_mem_rec_ip.u4_max_srch_rng_y = DEFAULT_MAX_SRCH_RANGE_Y;

        status = ive_api_function(0, &s_fill_mem_rec_ip, &s_fill_mem_rec_op);

        if (status != IV_SUCCESS) {
            ALOGE("Fill memory records failed = 0x%x\n",
                    s_fill_mem_rec_op.u4_error_code);
            return C2_CORRUPTED;
        }
    }

    /* Allocating Memory for Mem Records */
    {
        WORD32 total_size;
        iv_mem_rec_t *ps_mem_rec;
        total_size = 0;
        ps_mem_rec = mMemRecords;

        for (size_t i = 0; i < mNumMemRecords; i++) {
            ps_mem_rec->pv_base = ive_aligned_malloc(
                    ps_mem_rec->u4_mem_alignment, ps_mem_rec->u4_mem_size);
            if (ps_mem_rec->pv_base == NULL) {
                ALOGE("Allocation failure for mem record id %zu size %u\n", i,
                        ps_mem_rec->u4_mem_size);
                return C2_CORRUPTED;

            }
            total_size += ps_mem_rec->u4_mem_size;

            ps_mem_rec++;
        }
    }

    /* Codec Instance Creation */
    {
        ive_init_ip_t s_init_ip;
        ive_init_op_t s_init_op;

        mCodecCtx = (iv_obj_t *)mMemRecords[0].pv_base;
        mCodecCtx->u4_size = sizeof(iv_obj_t);
        mCodecCtx->pv_fxns = (void *)ive_api_function;

        s_init_ip.u4_size = sizeof(ive_init_ip_t);
        s_init_op.u4_size = sizeof(ive_init_op_t);

        s_init_ip.e_cmd = IV_CMD_INIT;
        s_init_ip.u4_num_mem_rec = mNumMemRecords;
        s_init_ip.ps_mem_rec = mMemRecords;
        s_init_ip.u4_max_wd = mWidth;
        s_init_ip.u4_max_ht = mHeight;
        s_init_ip.u4_max_ref_cnt = DEFAULT_MAX_REF_FRM;
        s_init_ip.u4_max_reorder_cnt = DEFAULT_MAX_REORDER_FRM;
        s_init_ip.u4_max_level = mAVCEncLevel;
        s_init_ip.e_inp_color_fmt = mIvVideoColorFormat;

        if (mReconEnable || mPSNREnable) {
            s_init_ip.u4_enable_recon = 1;
        } else {
            s_init_ip.u4_enable_recon = 0;
        }
        s_init_ip.e_recon_color_fmt = DEFAULT_RECON_COLOR_FORMAT;
        s_init_ip.e_rc_mode = DEFAULT_RC_MODE;
        s_init_ip.u4_max_framerate = DEFAULT_MAX_FRAMERATE;
        s_init_ip.u4_max_bitrate = DEFAULT_MAX_BITRATE;
        s_init_ip.u4_num_bframes = mBframes;
        s_init_ip.e_content_type = IV_PROGRESSIVE;
        s_init_ip.u4_max_srch_rng_x = DEFAULT_MAX_SRCH_RANGE_X;
        s_init_ip.u4_max_srch_rng_y = DEFAULT_MAX_SRCH_RANGE_Y;
        s_init_ip.e_slice_mode = mSliceMode;
        s_init_ip.u4_slice_param = mSliceParam;
        s_init_ip.e_arch = mArch;
        s_init_ip.e_soc = DEFAULT_SOC;

        status = ive_api_function(mCodecCtx, &s_init_ip, &s_init_op);

        if (status != IV_SUCCESS) {
            ALOGE("Init encoder failed = 0x%x\n", s_init_op.u4_error_code);
            return C2_CORRUPTED;
        }
    }

    /* Get Codec Version */
    logVersion();

    /* set processor details */
    setNumCores();

    /* Video control Set Frame dimensions */
    setDimensions();

    /* Video control Set Frame rates */
    setFrameRate();

    /* Video control Set IPE Params */
    setIpeParams();

    /* Video control Set Bitrate */
    setBitRate();

    /* Video control Set QP */
    setQp();

    /* Video control Set AIR params */
    setAirParams();

    /* Video control Set VBV params */
    setVbvParams();

    /* Video control Set Motion estimation params */
    setMeParams();

    /* Video control Set GOP params */
    setGopParams();

    /* Video control Set Deblock params */
    setDeblockParams();

    /* Video control Set Profile params */
    setProfileParams();

    /* Video control Set in Encode header mode */
    setEncMode(IVE_ENC_MODE_HEADER);

    ALOGV("init_codec successfull");

    mSpsPpsHeaderReceived = false;
    mStarted = true;

    return C2_OK;
}

c2_status_t C2SoftAvcEnc::releaseEncoder() {
    IV_STATUS_T status = IV_SUCCESS;
    iv_retrieve_mem_rec_ip_t s_retrieve_mem_ip;
    iv_retrieve_mem_rec_op_t s_retrieve_mem_op;
    iv_mem_rec_t *ps_mem_rec;

    if (!mStarted) {
        return C2_OK;
    }

    s_retrieve_mem_ip.u4_size = sizeof(iv_retrieve_mem_rec_ip_t);
    s_retrieve_mem_op.u4_size = sizeof(iv_retrieve_mem_rec_op_t);
    s_retrieve_mem_ip.e_cmd = IV_CMD_RETRIEVE_MEMREC;
    s_retrieve_mem_ip.ps_mem_rec = mMemRecords;

    status = ive_api_function(mCodecCtx, &s_retrieve_mem_ip, &s_retrieve_mem_op);

    if (status != IV_SUCCESS) {
        ALOGE("Unable to retrieve memory records = 0x%x\n",
                s_retrieve_mem_op.u4_error_code);
        return C2_CORRUPTED;
    }

    /* Free memory records */
    ps_mem_rec = mMemRecords;
    for (size_t i = 0; i < s_retrieve_mem_op.u4_num_mem_rec_filled; i++) {
        ive_aligned_free(ps_mem_rec->pv_base);
        ps_mem_rec++;
    }

    free(mMemRecords);

    // clear other pointers into the space being free()d
    mCodecCtx = NULL;

    mStarted = false;

    return C2_OK;
}

c2_status_t C2SoftAvcEnc::setEncodeArgs(
        ive_video_encode_ip_t *ps_encode_ip,
        ive_video_encode_op_t *ps_encode_op,
        const C2GraphicView *const input,
        uint8_t *base,
        uint32_t capacity,
        uint64_t timestamp) {
    iv_raw_buf_t *ps_inp_raw_buf;

    ps_inp_raw_buf = &ps_encode_ip->s_inp_buf;
    ps_encode_ip->s_out_buf.pv_buf = base;
    ps_encode_ip->s_out_buf.u4_bytes = 0;
    ps_encode_ip->s_out_buf.u4_bufsize = capacity;
    ps_encode_ip->u4_size = sizeof(ive_video_encode_ip_t);
    ps_encode_op->u4_size = sizeof(ive_video_encode_op_t);

    ps_encode_ip->e_cmd = IVE_CMD_VIDEO_ENCODE;
    ps_encode_ip->pv_bufs = NULL;
    ps_encode_ip->pv_mb_info = NULL;
    ps_encode_ip->pv_pic_info = NULL;
    ps_encode_ip->u4_mb_info_type = 0;
    ps_encode_ip->u4_pic_info_type = 0;
    ps_encode_ip->u4_is_last = 0;
    ps_encode_ip->u4_timestamp_high = timestamp >> 32;
    ps_encode_ip->u4_timestamp_low = timestamp & 0xFFFFFFFF;
    ps_encode_op->s_out_buf.pv_buf = NULL;

    /* Initialize color formats */
    memset(ps_inp_raw_buf, 0, sizeof(iv_raw_buf_t));
    ps_inp_raw_buf->u4_size = sizeof(iv_raw_buf_t);
    ps_inp_raw_buf->e_color_fmt = mIvVideoColorFormat;
    if (input == nullptr) {
        if (mSawInputEOS){
            ps_encode_ip->u4_is_last = 1;
        }
        return C2_OK;
    }

    ALOGV("width = %d, height = %d", input->width(), input->height());
    if (mWidth != input->width() || mHeight != input->height()) {
        return C2_BAD_VALUE;
    }
    const C2PlanarLayout &layout = input->layout();
    uint8_t *yPlane = const_cast<uint8_t *>(input->data()[C2PlanarLayout::PLANE_Y]);
    uint8_t *uPlane = const_cast<uint8_t *>(input->data()[C2PlanarLayout::PLANE_U]);
    uint8_t *vPlane = const_cast<uint8_t *>(input->data()[C2PlanarLayout::PLANE_V]);
    int32_t yStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
    int32_t uStride = layout.planes[C2PlanarLayout::PLANE_U].rowInc;
    int32_t vStride = layout.planes[C2PlanarLayout::PLANE_V].rowInc;

    switch (layout.type) {
        case C2PlanarLayout::TYPE_RGB:
            // fall-through
        case C2PlanarLayout::TYPE_RGBA: {
            size_t yPlaneSize = input->width() * input->height();
            std::unique_ptr<uint8_t[]> freeBuffer;
            if (mFreeConversionBuffers.empty()) {
                freeBuffer.reset(new uint8_t[yPlaneSize * 3 / 2]);
            } else {
                freeBuffer.swap(mFreeConversionBuffers.front());
                mFreeConversionBuffers.pop_front();
            }
            yPlane = freeBuffer.get();
            mConversionBuffersInUse.push_back(std::move(freeBuffer));
            uPlane = yPlane + yPlaneSize;
            vPlane = uPlane + yPlaneSize / 4;
            yStride = input->width();
            uStride = vStride = input->width() / 2;
            ConvertRGBToPlanarYUV(yPlane, yStride, input->height(), *input);
            break;
        }
        case C2PlanarLayout::TYPE_YUV:
            // fall-through
        case C2PlanarLayout::TYPE_YUVA:
            // Do nothing
            break;
        default:
            ALOGE("Unrecognized plane type: %d", layout.type);
            return C2_BAD_VALUE;
    }

    switch (mIvVideoColorFormat) {
        case IV_YUV_420P:
        {
            // input buffer is supposed to be const but Ittiam API wants bare pointer.
            ps_inp_raw_buf->apv_bufs[0] = yPlane;
            ps_inp_raw_buf->apv_bufs[1] = uPlane;
            ps_inp_raw_buf->apv_bufs[2] = vPlane;

            ps_inp_raw_buf->au4_wd[0] = input->width();
            ps_inp_raw_buf->au4_wd[1] = input->width() / 2;
            ps_inp_raw_buf->au4_wd[2] = input->width() / 2;

            ps_inp_raw_buf->au4_ht[0] = input->height();
            ps_inp_raw_buf->au4_ht[1] = input->height() / 2;
            ps_inp_raw_buf->au4_ht[2] = input->height() / 2;

            ps_inp_raw_buf->au4_strd[0] = yStride;
            ps_inp_raw_buf->au4_strd[1] = uStride;
            ps_inp_raw_buf->au4_strd[2] = vStride;
            break;
        }

        case IV_YUV_422ILE:
        {
            // TODO
            // ps_inp_raw_buf->apv_bufs[0] = pu1_buf;
            // ps_inp_raw_buf->au4_wd[0] = mWidth * 2;
            // ps_inp_raw_buf->au4_ht[0] = mHeight;
            // ps_inp_raw_buf->au4_strd[0] = mStride * 2;
            break;
        }

        case IV_YUV_420SP_UV:
        case IV_YUV_420SP_VU:
        default:
        {
            ps_inp_raw_buf->apv_bufs[0] = yPlane;
            ps_inp_raw_buf->apv_bufs[1] = uPlane;

            ps_inp_raw_buf->au4_wd[0] = input->width();
            ps_inp_raw_buf->au4_wd[1] = input->width();

            ps_inp_raw_buf->au4_ht[0] = input->height();
            ps_inp_raw_buf->au4_ht[1] = input->height() / 2;

            ps_inp_raw_buf->au4_strd[0] = yStride;
            ps_inp_raw_buf->au4_strd[1] = uStride;
            break;
        }
    }
    return C2_OK;
}

void C2SoftAvcEnc::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    work->result = C2_OK;
    work->workletsProcessed = 0u;

    IV_STATUS_T status;
    WORD32 timeDelay, timeTaken;
    uint64_t timestamp = work->input.ordinal.timestamp.peekull();

    // Initialize encoder if not already initialized
    if (mCodecCtx == NULL) {
        if (C2_OK != initEncoder()) {
            ALOGE("Failed to initialize encoder");
            work->workletsProcessed = 1u;
            work->result = C2_CORRUPTED;
            return;
        }
    }
    if (mSignalledError) {
        return;
    }

    // while (!mSawOutputEOS && !outQueue.empty()) {
    c2_status_t error;
    ive_video_encode_ip_t s_encode_ip;
    ive_video_encode_op_t s_encode_op;

    if (!mSpsPpsHeaderReceived) {
        constexpr uint32_t kHeaderLength = MIN_STREAM_SIZE;
        uint8_t header[kHeaderLength];
        error = setEncodeArgs(
                &s_encode_ip, &s_encode_op, NULL, header, kHeaderLength, timestamp);
        if (error != C2_OK) {
            mSignalledError = true;
            work->workletsProcessed = 1u;
            work->result = C2_CORRUPTED;
            return;
        }
        status = ive_api_function(mCodecCtx, &s_encode_ip, &s_encode_op);

        if (IV_SUCCESS != status) {
            ALOGE("Encode header failed = 0x%x\n",
                    s_encode_op.u4_error_code);
            return;
        } else {
            ALOGV("Bytes Generated in header %d\n",
                    s_encode_op.s_out_buf.u4_bytes);
        }

        mSpsPpsHeaderReceived = true;

        std::unique_ptr<C2StreamCsdInfo::output> csd =
            C2StreamCsdInfo::output::AllocUnique(s_encode_op.s_out_buf.u4_bytes, 0u);
        memcpy(csd->m.value, header, s_encode_op.s_out_buf.u4_bytes);
        work->worklets.front()->output.configUpdate.push_back(std::move(csd));

        DUMP_TO_FILE(
                mOutFile, csd->m.value, csd->flexCount());
    }

    if (mUpdateFlag) {
        if (mUpdateFlag & kUpdateBitrate) {
            setBitRate();
        }
        if (mUpdateFlag & kRequestKeyFrame) {
            setFrameType(IV_IDR_FRAME);
        }
        if (mUpdateFlag & kUpdateAIRMode) {
            setAirParams();
            // notify(OMX_EventPortSettingsChanged, kOutputPortIndex,
            //         OMX_IndexConfigAndroidIntraRefresh, NULL);
        }
        mUpdateFlag = 0;
    }

    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
        mSawInputEOS = true;
    }

    /* In normal mode, store inputBufferInfo and this will be returned
       when encoder consumes this input */
    // if (!mInputDataIsMeta && (inputBufferInfo != NULL)) {
    //     for (size_t i = 0; i < MAX_INPUT_BUFFER_HEADERS; i++) {
    //         if (NULL == mInputBufferInfo[i]) {
    //             mInputBufferInfo[i] = inputBufferInfo;
    //             break;
    //         }
    //     }
    // }
    const C2GraphicView view =
        work->input.buffers[0]->data().graphicBlocks().front().map().get();
    if (view.error() != C2_OK) {
        ALOGE("graphic view map err = %d", view.error());
        return;
    }

    std::shared_ptr<C2LinearBlock> block;

    do {
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        // TODO: error handling, proper usage, etc.
        c2_status_t err = pool->fetchLinearBlock(mOutBufferSize, usage, &block);
        if (err != C2_OK) {
            ALOGE("fetch linear block err = %d", err);
            work->workletsProcessed = 1u;
            work->result = err;
            return;
        }
        C2WriteView wView = block->map().get();
        if (wView.error() != C2_OK) {
            ALOGE("write view map err = %d", wView.error());
            work->workletsProcessed = 1u;
            work->result = wView.error();
            return;
        }

        error = setEncodeArgs(
                &s_encode_ip, &s_encode_op, &view, wView.base(), wView.capacity(), timestamp);
        if (error != C2_OK) {
            mSignalledError = true;
            ALOGE("setEncodeArgs failed : %d", error);
            work->workletsProcessed = 1u;
            work->result = error;
            return;
        }

        // DUMP_TO_FILE(
        //         mInFile, s_encode_ip.s_inp_buf.apv_bufs[0],
        //         (mHeight * mStride * 3 / 2));

        GETTIME(&mTimeStart, NULL);
        /* Compute time elapsed between end of previous decode()
         * to start of current decode() */
        TIME_DIFF(mTimeEnd, mTimeStart, timeDelay);
        status = ive_api_function(mCodecCtx, &s_encode_ip, &s_encode_op);

        if (IV_SUCCESS != status) {
            if ((s_encode_op.u4_error_code & 0xFF) == IH264E_BITSTREAM_BUFFER_OVERFLOW) {
                // TODO: use IVE_CMD_CTL_GETBUFINFO for proper max input size?
                mOutBufferSize *= 2;
                continue;
            }
            ALOGE("Encode Frame failed = 0x%x\n",
                    s_encode_op.u4_error_code);
            mSignalledError = true;
            work->workletsProcessed = 1u;
            work->result = C2_CORRUPTED;
            return;
        }
    } while (IV_SUCCESS != status);

    // Hold input buffer reference
    mBuffers[s_encode_ip.s_inp_buf.apv_bufs[0]] = work->input.buffers[0];

    GETTIME(&mTimeEnd, NULL);
    /* Compute time taken for decode() */
    TIME_DIFF(mTimeStart, mTimeEnd, timeTaken);

    ALOGV("timeTaken=%6d delay=%6d numBytes=%6d", timeTaken, timeDelay,
            s_encode_op.s_out_buf.u4_bytes);

    void *freed = s_encode_op.s_inp_buf.apv_bufs[0];
    /* If encoder frees up an input buffer, mark it as free */
    if (freed != NULL) {
        if (mBuffers.count(freed) == 0u) {
            work->workletsProcessed = 1u;
            work->result = C2_CORRUPTED;
            return;
        }
        // Release input buffer reference
        mBuffers.erase(freed);

        auto it = std::find_if(
                mConversionBuffersInUse.begin(), mConversionBuffersInUse.end(),
                [freed](const auto &elem) { return elem.get() == freed; });
        if (it != mConversionBuffersInUse.end()) {
            mFreeConversionBuffers.push_back(std::move(*it));
            mConversionBuffersInUse.erase(it);
        }
    }

    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->worklets.front()->output.ordinal.timestamp =
        ((uint64_t)s_encode_op.u4_timestamp_high << 32) | s_encode_op.u4_timestamp_low;
    work->worklets.front()->output.buffers.clear();
    std::shared_ptr<C2Buffer> buffer =
        createLinearBuffer(block, 0, s_encode_op.s_out_buf.u4_bytes);
    work->worklets.front()->output.buffers.push_back(buffer);
    work->workletsProcessed = 1u;

    if (IV_IDR_FRAME == s_encode_op.u4_encoded_frame_type) {
        buffer->setInfo(std::make_shared<C2StreamPictureTypeMaskInfo::output>(
                0u /* stream id */, C2PictureTypeKeyFrame));
    }

    if (s_encode_op.u4_is_last) {
        // outputBufferHeader->nFlags |= OMX_BUFFERFLAG_EOS;
        mSawOutputEOS = true;
    } else {
        // outputBufferHeader->nFlags &= ~OMX_BUFFERFLAG_EOS;
    }
}

c2_status_t C2SoftAvcEnc::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    // TODO: use IVE_CMD_CTL_FLUSH?
    (void)drainMode;
    (void)pool;
    return C2_OK;
}


class C2SoftAvcEncFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftAvcEnc(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftAvcEncFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAvcEncFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
