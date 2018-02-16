/*
 * Copyright 2017 The Android Open Source Project
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
#define LOG_TAG "C2SoftAvcDec"
#include <utils/Log.h>

#include <cmath>
#include <thread>
#include <cinttypes>

#include "ih264_typedefs.h"
#include "iv.h"
#include "ivd.h"
#include "ih264d.h"
#include "C2SoftAvcDec.h"

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/MediaDefs.h>
#include <utils/misc.h>

#include "ih264d_defs.h"

namespace android {

struct iv_obj_t : public ::iv_obj_t {};
struct ivd_video_decode_ip_t : public ::ivd_video_decode_ip_t {};
struct ivd_video_decode_op_t : public ::ivd_video_decode_op_t {};

#define PRINT_TIME  ALOGV

constexpr char kComponentName[] = "c2.google.avc.decoder";
// #define codingType                      OMX_VIDEO_CodingAVC
#define CODEC_MIME_TYPE                 MEDIA_MIMETYPE_VIDEO_AVC

/** Function and structure definitions to keep code similar for each codec */
#define ivdec_api_function              ih264d_api_function
#define ivdext_create_ip_t              ih264d_create_ip_t
#define ivdext_create_op_t              ih264d_create_op_t
#define ivdext_delete_ip_t              ih264d_delete_ip_t
#define ivdext_delete_op_t              ih264d_delete_op_t
#define ivdext_ctl_set_num_cores_ip_t   ih264d_ctl_set_num_cores_ip_t
#define ivdext_ctl_set_num_cores_op_t   ih264d_ctl_set_num_cores_op_t

#define IVDEXT_CMD_CTL_SET_NUM_CORES    \
        (IVD_CONTROL_API_COMMAND_TYPE_T)IH264D_CMD_CTL_SET_NUM_CORES
namespace {

std::shared_ptr<C2ComponentInterface> BuildIntf(
        const char *name, c2_node_id_t id,
        std::function<void(C2ComponentInterface*)> deleter =
            std::default_delete<C2ComponentInterface>()) {
    return SimpleC2Interface::Builder(name, id, deleter)
            .inputFormat(C2FormatCompressed)
            .outputFormat(C2FormatVideo)
            .inputMediaType(MEDIA_MIMETYPE_VIDEO_AVC)
            .outputMediaType(MEDIA_MIMETYPE_VIDEO_RAW)
            .build();
}

void CopyPlane(
        uint8_t *dst, const C2PlaneInfo &plane,
        const uint8_t *src, uint32_t width, uint32_t height) {
    for (uint32_t row = 0; row < height; ++row) {
        for (uint32_t col = 0; col < width; ++col) {
            *dst = *src;
            dst += plane.colInc;
            ++src;
        }
        dst -= plane.colInc * width;
        dst += plane.rowInc;
    }
}

void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
    uint32_t flags = 0;
    if ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM)) {
        flags |= C2FrameData::FLAG_END_OF_STREAM;
    }
    work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

}  // namespace

///////////////////////////////////////////////////////////////////////////////

C2SoftAvcDec::C2SoftAvcDec(
        const char *name,
        c2_node_id_t id)
    : SimpleC2Component(BuildIntf(name, id)),
      mCodecCtx(NULL),
      mOutBuffer(NULL),
      mIvColorFormat(IV_YUV_420P),
      mChangingResolution(false),
      mSignalledError(false),
      mWidth(320),
      mHeight(240),
      mInputOffset(0) {
    ALOGV("in %s", __func__);
    GETTIME(&mTimeStart, NULL);

    // If input dump is enabled, then open create an empty file
    GENERATE_FILE_NAMES();
    CREATE_DUMP_FILE(mInFile);
}

C2SoftAvcDec::~C2SoftAvcDec() {
    ALOGV("in %s", __func__);
    CHECK_EQ(deInitDecoder(), (status_t)OK);
}

c2_status_t C2SoftAvcDec::onInit() {
    // TODO: initialize using intf
    return C2_OK;
}

c2_status_t C2SoftAvcDec::onStop() {
    ALOGV("onStop");
    mSignalledError = false;
    resetDecoder();
    resetPlugin();

    return C2_OK;
}

void C2SoftAvcDec::onReset() {
    ALOGV("onReset");
    (void)onStop();
}

void C2SoftAvcDec::onRelease() {
    (void)deInitDecoder();
}

c2_status_t C2SoftAvcDec::onFlush_sm() {
    setFlushMode();

    while (true) {
        ivd_video_decode_ip_t s_dec_ip;
        ivd_video_decode_op_t s_dec_op;
        IV_API_CALL_STATUS_T status;
        // size_t sizeY, sizeUV;

        setDecodeArgs(&s_dec_ip, &s_dec_op, NULL, NULL, 0, 0u);

        status = ivdec_api_function(mCodecCtx, (void *)&s_dec_ip, (void *)&s_dec_op);
        if (0 == s_dec_op.u4_output_present) {
            resetPlugin();
            break;
        }
    }

    if (mOutBuffer) {
        free(mOutBuffer);
        mOutBuffer = NULL;
    }
    return C2_OK;
}

static void *ivd_aligned_malloc(void *ctxt, WORD32 alignment, WORD32 size) {
    (void) ctxt;
    return memalign(alignment, size);
}

static void ivd_aligned_free(void *ctxt, void *buf) {
    (void) ctxt;
    free(buf);
    return;
}

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

void C2SoftAvcDec::logVersion() {
    ivd_ctl_getversioninfo_ip_t s_ctl_ip;
    ivd_ctl_getversioninfo_op_t s_ctl_op;
    UWORD8 au1_buf[512];
    IV_API_CALL_STATUS_T status;

    s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_GETVERSION;
    s_ctl_ip.u4_size = sizeof(ivd_ctl_getversioninfo_ip_t);
    s_ctl_op.u4_size = sizeof(ivd_ctl_getversioninfo_op_t);
    s_ctl_ip.pv_version_buffer = au1_buf;
    s_ctl_ip.u4_version_buffer_size = sizeof(au1_buf);

    status =
        ivdec_api_function(mCodecCtx, (void *)&s_ctl_ip, (void *)&s_ctl_op);

    if (status != IV_SUCCESS) {
        ALOGE("Error in getting version number: 0x%x",
                s_ctl_op.u4_error_code);
    } else {
        ALOGV("Ittiam decoder version number: %s",
                (char *)s_ctl_ip.pv_version_buffer);
    }
    return;
}

status_t C2SoftAvcDec::setParams(size_t stride) {
    ivd_ctl_set_config_ip_t s_ctl_ip;
    ivd_ctl_set_config_op_t s_ctl_op;
    IV_API_CALL_STATUS_T status;
    s_ctl_ip.u4_disp_wd = (UWORD32)stride;
    s_ctl_ip.e_frm_skip_mode = IVD_SKIP_NONE;

    s_ctl_ip.e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
    s_ctl_ip.e_vid_dec_mode = IVD_DECODE_FRAME;
    s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_SETPARAMS;
    s_ctl_ip.u4_size = sizeof(ivd_ctl_set_config_ip_t);
    s_ctl_op.u4_size = sizeof(ivd_ctl_set_config_op_t);

    ALOGV("Set the run-time (dynamic) parameters stride = %zu", stride);
    status = ivdec_api_function(mCodecCtx, (void *)&s_ctl_ip, (void *)&s_ctl_op);

    if (status != IV_SUCCESS) {
        ALOGE("Error in setting the run-time parameters: 0x%x",
                s_ctl_op.u4_error_code);

        return UNKNOWN_ERROR;
    }

    if (mOutBuffer != NULL) {
        free(mOutBuffer);
    }
    uint32_t bufferSize = mWidth * mHeight * 3 / 2;
    mOutBuffer = (uint8_t *)memalign(128, bufferSize);
    if (NULL == mOutBuffer) {
        ALOGE("Could not allocate output buffer of size %u", bufferSize);
        return C2_NO_MEMORY;
    }
    return OK;
}

status_t C2SoftAvcDec::resetPlugin() {
    mInputOffset = 0;

    /* Initialize both start and end times */
    gettimeofday(&mTimeStart, NULL);
    gettimeofday(&mTimeEnd, NULL);

    return OK;
}

status_t C2SoftAvcDec::resetDecoder() {
    ivd_ctl_reset_ip_t s_ctl_ip;
    ivd_ctl_reset_op_t s_ctl_op;
    IV_API_CALL_STATUS_T status;

    s_ctl_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_ip.e_sub_cmd = IVD_CMD_CTL_RESET;
    s_ctl_ip.u4_size = sizeof(ivd_ctl_reset_ip_t);
    s_ctl_op.u4_size = sizeof(ivd_ctl_reset_op_t);

    status = ivdec_api_function(mCodecCtx, (void *)&s_ctl_ip, (void *)&s_ctl_op);
    if (IV_SUCCESS != status) {
        ALOGE("Error in reset: 0x%x", s_ctl_op.u4_error_code);
        return UNKNOWN_ERROR;
    }
    mSignalledError = false;

    /* Set number of cores/threads to be used by the codec */
    setNumCores();

    mStride = 0;
    return OK;
}

status_t C2SoftAvcDec::setNumCores() {
    ivdext_ctl_set_num_cores_ip_t s_set_cores_ip;
    ivdext_ctl_set_num_cores_op_t s_set_cores_op;
    IV_API_CALL_STATUS_T status;
    s_set_cores_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_set_cores_ip.e_sub_cmd = IVDEXT_CMD_CTL_SET_NUM_CORES;
    s_set_cores_ip.u4_num_cores = MIN(mNumCores, CODEC_MAX_NUM_CORES);
    s_set_cores_ip.u4_size = sizeof(ivdext_ctl_set_num_cores_ip_t);
    s_set_cores_op.u4_size = sizeof(ivdext_ctl_set_num_cores_op_t);
    status = ivdec_api_function(
            mCodecCtx, (void *)&s_set_cores_ip, (void *)&s_set_cores_op);
    if (IV_SUCCESS != status) {
        ALOGE("Error in setting number of cores: 0x%x",
                s_set_cores_op.u4_error_code);
        return UNKNOWN_ERROR;
    }
    return OK;
}

status_t C2SoftAvcDec::setFlushMode() {
    ALOGV("setFlushMode");
    IV_API_CALL_STATUS_T status;
    ivd_ctl_flush_ip_t s_video_flush_ip;
    ivd_ctl_flush_op_t s_video_flush_op;

    s_video_flush_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_video_flush_ip.e_sub_cmd = IVD_CMD_CTL_FLUSH;
    s_video_flush_ip.u4_size = sizeof(ivd_ctl_flush_ip_t);
    s_video_flush_op.u4_size = sizeof(ivd_ctl_flush_op_t);

    /* Set the decoder in Flush mode, subsequent decode() calls will flush */
    status = ivdec_api_function(
            mCodecCtx, (void *)&s_video_flush_ip, (void *)&s_video_flush_op);

    if (status != IV_SUCCESS) {
        ALOGE("Error in setting the decoder in flush mode: (%d) 0x%x", status,
                s_video_flush_op.u4_error_code);
        return UNKNOWN_ERROR;
    }

    return OK;
}

status_t C2SoftAvcDec::initDecoder() {
    IV_API_CALL_STATUS_T status;

    mNumCores = GetCPUCoreCount();
    mCodecCtx = NULL;

    mStride = mWidth;

    /* Initialize the decoder */
    {
        ivdext_create_ip_t s_create_ip;
        ivdext_create_op_t s_create_op;

        void *dec_fxns = (void *)ivdec_api_function;

        s_create_ip.s_ivd_create_ip_t.u4_size = sizeof(ivdext_create_ip_t);
        s_create_ip.s_ivd_create_ip_t.e_cmd = IVD_CMD_CREATE;
        s_create_ip.s_ivd_create_ip_t.u4_share_disp_buf = 0;
        s_create_op.s_ivd_create_op_t.u4_size = sizeof(ivdext_create_op_t);
        s_create_ip.s_ivd_create_ip_t.e_output_format = (IV_COLOR_FORMAT_T)mIvColorFormat;
        s_create_ip.s_ivd_create_ip_t.pf_aligned_alloc = ivd_aligned_malloc;
        s_create_ip.s_ivd_create_ip_t.pf_aligned_free = ivd_aligned_free;
        s_create_ip.s_ivd_create_ip_t.pv_mem_ctxt = NULL;

        status = ivdec_api_function(mCodecCtx, (void *)&s_create_ip, (void *)&s_create_op);

        mCodecCtx = (iv_obj_t*)s_create_op.s_ivd_create_op_t.pv_handle;
        mCodecCtx->pv_fxns = dec_fxns;
        mCodecCtx->u4_size = sizeof(iv_obj_t);

        if (status != IV_SUCCESS) {
            ALOGE("Error in create: 0x%x",
                    s_create_op.s_ivd_create_op_t.u4_error_code);
            deInitDecoder();
            return UNKNOWN_ERROR;
        }
    }

    /* Reset the plugin state */
    resetPlugin();

    /* Set the run time (dynamic) parameters */
    setParams(mStride);

    /* Set number of cores/threads to be used by the codec */
    setNumCores();

    /* Get codec version */
    logVersion();

    mFlushNeeded = false;
    return OK;
}

status_t C2SoftAvcDec::deInitDecoder() {
    IV_API_CALL_STATUS_T status;

    if (mCodecCtx) {
        ivdext_delete_ip_t s_delete_ip;
        ivdext_delete_op_t s_delete_op;

        s_delete_ip.s_ivd_delete_ip_t.u4_size = sizeof(ivdext_delete_ip_t);
        s_delete_ip.s_ivd_delete_ip_t.e_cmd = IVD_CMD_DELETE;

        s_delete_op.s_ivd_delete_op_t.u4_size = sizeof(ivdext_delete_op_t);

        status = ivdec_api_function(mCodecCtx, (void *)&s_delete_ip, (void *)&s_delete_op);
        if (status != IV_SUCCESS) {
            ALOGE("Error in delete: 0x%x",
                    s_delete_op.s_ivd_delete_op_t.u4_error_code);
            return UNKNOWN_ERROR;
        }
        mCodecCtx = NULL;
    }

    mChangingResolution = false;

    return OK;
}

bool C2SoftAvcDec::getVUIParams() {
    IV_API_CALL_STATUS_T status;
    ih264d_ctl_get_vui_params_ip_t s_ctl_get_vui_params_ip;
    ih264d_ctl_get_vui_params_op_t s_ctl_get_vui_params_op;

    s_ctl_get_vui_params_ip.e_cmd = IVD_CMD_VIDEO_CTL;
    s_ctl_get_vui_params_ip.e_sub_cmd =
        (IVD_CONTROL_API_COMMAND_TYPE_T)IH264D_CMD_CTL_GET_VUI_PARAMS;

    s_ctl_get_vui_params_ip.u4_size =
        sizeof(ih264d_ctl_get_vui_params_ip_t);

    s_ctl_get_vui_params_op.u4_size = sizeof(ih264d_ctl_get_vui_params_op_t);

    status = ivdec_api_function(
            (iv_obj_t *)mCodecCtx, (void *)&s_ctl_get_vui_params_ip,
            (void *)&s_ctl_get_vui_params_op);

    if (status != IV_SUCCESS) {
        ALOGW("Error in getting VUI params: 0x%x",
                s_ctl_get_vui_params_op.u4_error_code);
        return false;
    }

    int32_t primaries = s_ctl_get_vui_params_op.u1_colour_primaries;
    int32_t transfer = s_ctl_get_vui_params_op.u1_tfr_chars;
    int32_t coeffs = s_ctl_get_vui_params_op.u1_matrix_coeffs;
    bool fullRange = s_ctl_get_vui_params_op.u1_video_full_range_flag;

    ColorAspects colorAspects;
    ColorUtils::convertIsoColorAspectsToCodecAspects(
            primaries, transfer, coeffs, fullRange, colorAspects);

    // Update color aspects if necessary.
    if (colorAspectsDiffer(colorAspects, mBitstreamColorAspects)) {
        mBitstreamColorAspects = colorAspects;
        status_t err = handleColorAspectsChange();
        CHECK(err == OK);
    }
    return true;
}

bool C2SoftAvcDec::setDecodeArgs(
        ivd_video_decode_ip_t *ps_dec_ip,
        ivd_video_decode_op_t *ps_dec_op,
        C2ReadView *inBuffer,
        C2GraphicView *outBuffer,
        uint32_t workIndex,
        size_t inOffset) {
    size_t width = mWidth;
    size_t height = mHeight;
    size_t sizeY = width * height;
    size_t sizeUV;

    ps_dec_ip->u4_size = sizeof(ivd_video_decode_ip_t);
    ps_dec_op->u4_size = sizeof(ivd_video_decode_op_t);
    ps_dec_op->u4_output_present = 0;

    ps_dec_ip->e_cmd = IVD_CMD_VIDEO_DECODE;

    /* When in flush and after EOS with zero byte input,
     * inBuffer is set to zero. Hence check for non-null */
    if (inBuffer) {
        ps_dec_ip->u4_ts = workIndex;
        ps_dec_ip->pv_stream_buffer = const_cast<uint8_t *>(inBuffer->data()) + inOffset;
        ps_dec_ip->u4_num_Bytes = inBuffer->capacity() - inOffset;
    } else {
        ps_dec_ip->u4_ts = 0;
        ps_dec_ip->pv_stream_buffer = NULL;
        ps_dec_ip->u4_num_Bytes = 0;
    }

    sizeUV = sizeY / 4;
    ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = sizeY;
    ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = sizeUV;
    ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = sizeUV;

    if (outBuffer) {
        if (outBuffer->width() < width ||
                outBuffer->height() < height) {
            ALOGE("Output buffer too small: provided (%dx%d) required (%zux%zu)",
                  outBuffer->width(), outBuffer->height(), width, height);
            return false;
        }
        ALOGV("width = %u, stride[0] = %u, stride[1] = %u, stride[2] = %u",
                outBuffer->width(),
                outBuffer->layout().planes[0].rowInc,
                outBuffer->layout().planes[1].rowInc,
                outBuffer->layout().planes[2].rowInc);
        const C2PlanarLayout &layout = outBuffer->layout();
        ps_dec_ip->s_out_buffer.pu1_bufs[0] = outBuffer->data()[0];
        if (layout.planes[0].rowInc != (int32_t)mWidth || layout.planes[1].colInc != 1) {
            ps_dec_ip->s_out_buffer.pu1_bufs[0] = mOutBuffer;
        }
        ps_dec_ip->s_out_buffer.pu1_bufs[1] = outBuffer->data()[1];
        if (layout.planes[1].rowInc != (int32_t)mWidth / 2 || layout.planes[1].colInc != 1) {
            ps_dec_ip->s_out_buffer.pu1_bufs[1] = mOutBuffer + sizeY;
        }
        ps_dec_ip->s_out_buffer.pu1_bufs[2] = outBuffer->data()[2];
        if (layout.planes[2].rowInc != (int32_t)mWidth / 2 || layout.planes[2].colInc != 1) {
            ps_dec_ip->s_out_buffer.pu1_bufs[2] = mOutBuffer + sizeY + sizeUV;
        }
    } else {
        // mOutBuffer always has the right size.
        ps_dec_ip->s_out_buffer.pu1_bufs[0] = mOutBuffer;
        ps_dec_ip->s_out_buffer.pu1_bufs[1] = mOutBuffer + sizeY;
        ps_dec_ip->s_out_buffer.pu1_bufs[2] = mOutBuffer + sizeY + sizeUV;
    }

    ps_dec_ip->s_out_buffer.u4_num_bufs = 3;
    return true;
}

c2_status_t C2SoftAvcDec::ensureDecoderState(const std::shared_ptr<C2BlockPool> &pool) {
    if (NULL == mCodecCtx) {
        if (OK != initDecoder()) {
            ALOGE("Failed to initialize decoder");
            // TODO: notify(OMX_EventError, OMX_ErrorUnsupportedSetting, 0, NULL);
            mSignalledError = true;
            return C2_CORRUPTED;
        }
    }
    if (mWidth != mStride) {
        /* Set the run-time (dynamic) parameters */
        mStride = mWidth;
        setParams(mStride);
    }

    if (!mAllocatedBlock) {
        // TODO: error handling
        // TODO: format & usage
        uint32_t format = HAL_PIXEL_FORMAT_YV12;
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        ALOGV("using allocator %u", pool->getAllocatorId());

        (void)pool->fetchGraphicBlock(
                mWidth, mHeight, format, usage, &mAllocatedBlock);
        ALOGV("provided (%dx%d) required (%dx%d)",
                mAllocatedBlock->width(), mAllocatedBlock->height(), mWidth, mHeight);
    }
    return C2_OK;
}

void C2SoftAvcDec::finishWork(uint64_t index, const std::unique_ptr<C2Work> &work) {
    std::shared_ptr<C2Buffer> buffer = createGraphicBuffer(mAllocatedBlock);
    mAllocatedBlock.reset();
    auto fillWork = [buffer](const std::unique_ptr<C2Work> &work) {
        uint32_t flags = 0;
        if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
            flags |= C2FrameData::FLAG_END_OF_STREAM;
            ALOGV("EOS");
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

void C2SoftAvcDec::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    bool eos = false;

    work->result = C2_OK;
    work->workletsProcessed = 0u;

    const C2ConstLinearBlock &buffer =
        work->input.buffers[0]->data().linearBlocks().front();
    if (buffer.size() == 0) {
        ALOGV("empty input: %llu", work->input.ordinal.frameIndex.peekull());
        // TODO: result?
        fillEmptyWork(work);
        if ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM)) {
            eos = true;
        }
        return;
    } else if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
        ALOGV("input EOS: %llu", work->input.ordinal.frameIndex.peekull());
        eos = true;
    }

    C2ReadView input = work->input.buffers[0]->data().linearBlocks().front().map().get();
    if (input.error() != C2_OK) {
        work->result = input.error();
        fillEmptyWork(work);
        ALOGD("map error: %d", input.error());
        return;
    }
    ALOGV("buffer.size() = %u, input.capacity() = %u", buffer.size(), input.capacity());
    uint32_t workIndex = work->input.ordinal.frameIndex.peeku() & 0xFFFFFFFF;
    size_t inOffset = 0u;

    while (inOffset < input.capacity()) {
        if (mSignalledError) {
            break;
        }
        (void)ensureDecoderState(pool);
        ivd_video_decode_ip_t s_dec_ip;
        ivd_video_decode_op_t s_dec_op;
        WORD32 timeDelay, timeTaken;
        //size_t sizeY, sizeUV;

        {
            C2GraphicView output = mAllocatedBlock->map().get();
            if (output.error() != C2_OK) {
                ALOGE("mapped err = %d", output.error());
                work->result = output.error();
                fillEmptyWork(work);
                return;
            }
            if (!setDecodeArgs(&s_dec_ip, &s_dec_op, &input, &output, workIndex, inOffset)) {
                ALOGE("Decoder arg setup failed");
                // TODO: notify(OMX_EventError, OMX_ErrorUndefined, 0, NULL);
                mSignalledError = true;
                break;
            }
            ALOGV("Decoder arg setup succeeded");
            // If input dump is enabled, then write to file
            DUMP_TO_FILE(mInFile, s_dec_ip.pv_stream_buffer, s_dec_ip.u4_num_Bytes, mInputOffset);

            GETTIME(&mTimeStart, NULL);
            /* Compute time elapsed between end of previous decode()
             * to start of current decode() */
            TIME_DIFF(mTimeEnd, mTimeStart, timeDelay);

            IV_API_CALL_STATUS_T status;
            status = ivdec_api_function(mCodecCtx, (void *)&s_dec_ip, (void *)&s_dec_op);
            ALOGV("status = %d, error_code = %d", status, (s_dec_op.u4_error_code & 0xFF));
            if (s_dec_op.u4_output_present) {
                const C2PlanarLayout &layout = output.layout();
                if (layout.planes[0].rowInc != (int32_t)mWidth || layout.planes[1].colInc != 1) {
                    CopyPlane(output.data()[0], layout.planes[0], mOutBuffer, mWidth, mHeight);
                }
                if (layout.planes[1].rowInc != (int32_t)mWidth / 2 || layout.planes[1].colInc != 1) {
                    CopyPlane(
                            output.data()[1], layout.planes[1],
                            mOutBuffer + (mWidth * mHeight), mWidth / 2, mHeight / 2);
                }
                if (layout.planes[2].rowInc != (int32_t)mWidth / 2 || layout.planes[2].colInc != 1) {
                    CopyPlane(
                            output.data()[2], layout.planes[2],
                            mOutBuffer + (mWidth * mHeight * 5 / 4), mWidth / 2, mHeight / 2);
                }
            }
        }

        bool unsupportedResolution =
            (IVD_STREAM_WIDTH_HEIGHT_NOT_SUPPORTED == (s_dec_op.u4_error_code & 0xFF));

        /* Check for unsupported dimensions */
        if (unsupportedResolution) {
            ALOGE("Unsupported resolution : %dx%d", mWidth, mHeight);
            // TODO: notify(OMX_EventError, OMX_ErrorUnsupportedSetting, 0, NULL);
            mSignalledError = true;
            break;
        }

        bool allocationFailed = (IVD_MEM_ALLOC_FAILED == (s_dec_op.u4_error_code & 0xFF));
        if (allocationFailed) {
            ALOGE("Allocation failure in decoder");
            // TODO: notify(OMX_EventError, OMX_ErrorUnsupportedSetting, 0, NULL);
            mSignalledError = true;
            break;
        }

        bool resChanged = (IVD_RES_CHANGED == (s_dec_op.u4_error_code & 0xFF));

        getVUIParams();

        GETTIME(&mTimeEnd, NULL);
        /* Compute time taken for decode() */
        TIME_DIFF(mTimeStart, mTimeEnd, timeTaken);

        PRINT_TIME("timeTaken=%6d delay=%6d numBytes=%6d", timeTaken, timeDelay,
               s_dec_op.u4_num_bytes_consumed);
        ALOGV("bytes total=%u", input.capacity());
        if (s_dec_op.u4_frame_decoded_flag && !mFlushNeeded) {
            mFlushNeeded = true;
        }

        if (1 != s_dec_op.u4_frame_decoded_flag) {
            /* If the input did not contain picture data, return work without
             * buffer */
            ALOGV("no picture data: %u", workIndex);
            fillEmptyWork(work);
        }

        if (resChanged) {
            ALOGV("res changed");
            if (mFlushNeeded) {
                drainInternal(DRAIN_COMPONENT_NO_EOS, pool, work);
            }
            resetDecoder();
            resetPlugin();
            mStride = mWidth;
            setParams(mStride);
            continue;
        }

        if ((0 < s_dec_op.u4_pic_wd) && (0 < s_dec_op.u4_pic_ht)) {
            uint32_t width = s_dec_op.u4_pic_wd;
            uint32_t height = s_dec_op.u4_pic_ht;
            ALOGV("width = %u height = %u", width, height);
            if (width != mWidth || height != mHeight) {
                mAllocatedBlock.reset();
                mWidth = width;
                mHeight = height;
            }
            // TODO: continue?
        }

        if (mUpdateColorAspects) {
            //notify(OMX_EventPortSettingsChanged, kOutputPortIndex,
            //    kDescribeColorAspectsIndex, NULL);
            ALOGV("update color aspect");
            mUpdateColorAspects = false;
        }

        if (s_dec_op.u4_output_present) {
            ALOGV("output_present: %d", s_dec_op.u4_ts);
            finishWork(s_dec_op.u4_ts, work);
        }

        inOffset += s_dec_op.u4_num_bytes_consumed;
    }
    if (inOffset >= input.capacity()) {
        /* If input EOS is seen, drain the decoder.
         * There can be a case where EOS is sent along with last picture data
         * In that case, only after decoding that input data, decoder has to be
         * put in flush. This case is handled here  */
        if (eos) {
            drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
        }
    }
}

c2_status_t C2SoftAvcDec::drainInternal(
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
    setFlushMode();

    while (true) {
        (void)ensureDecoderState(pool);
        C2GraphicView output = mAllocatedBlock->map().get();
        if (output.error() != OK) {
            ALOGE("mapped err = %d", output.error());
        }

        ivd_video_decode_ip_t s_dec_ip;
        ivd_video_decode_op_t s_dec_op;

        setDecodeArgs(&s_dec_ip, &s_dec_op, NULL, &output, 0, 0u);

        (void)ivdec_api_function(mCodecCtx, (void *)&s_dec_ip, (void *)&s_dec_op);

        if (s_dec_op.u4_output_present) {
            ALOGV("output_present: %d", s_dec_op.u4_ts);
            finishWork(s_dec_op.u4_ts, work);
        } else {
            break;
        }
    }

    if (drainMode == DRAIN_COMPONENT_WITH_EOS
            && work && work->workletsProcessed == 0u) {
        fillEmptyWork(work);
    }

    return C2_OK;
}

bool C2SoftAvcDec::colorAspectsDiffer(
        const ColorAspects &a, const ColorAspects &b) {
    if (a.mRange != b.mRange
        || a.mPrimaries != b.mPrimaries
        || a.mTransfer != b.mTransfer
        || a.mMatrixCoeffs != b.mMatrixCoeffs) {
        return true;
    }
    return false;
}

c2_status_t C2SoftAvcDec::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    return drainInternal(drainMode, pool, nullptr);
}

void C2SoftAvcDec::updateFinalColorAspects(
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

status_t C2SoftAvcDec::handleColorAspectsChange() {
//    int perference = getColorAspectPreference();
//    ALOGD("Color Aspects preference: %d ", perference);
//
//     if (perference == kPreferBitstream) {
//         updateFinalColorAspects(mDefaultColorAspects, mBitstreamColorAspects);
//     } else if (perference == kPreferContainer) {
//         updateFinalColorAspects(mBitstreamColorAspects, mDefaultColorAspects);
//     } else {
//         return OMX_ErrorUnsupportedSetting;
//     }
    updateFinalColorAspects(mDefaultColorAspects, mBitstreamColorAspects);
    return C2_OK;
}

class C2SoftAvcDecFactory : public C2ComponentFactory {
public:
    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(new C2SoftAvcDec(kComponentName, id), deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = BuildIntf(kComponentName, id, deleter);
        return C2_OK;
    }

    virtual ~C2SoftAvcDecFactory() override = default;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAvcDecFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
