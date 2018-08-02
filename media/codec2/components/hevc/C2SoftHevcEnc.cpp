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

//#define LOG_NDEBUG 0
#define LOG_TAG "C2SoftHevcEnc"
#include <log/log.h>

#include <media/hardware/VideoAPI.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/foundation/AUtils.h>

#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <Codec2BufferUtils.h>
#include <SimpleC2Interface.h>
#include <util/C2InterfaceHelper.h>

#include "ihevc_typedefs.h"
#include "itt_video_api.h"
#include "ihevce_api.h"
#include "ihevce_plugin.h"
#include "C2SoftHevcEnc.h"

namespace android {

class C2SoftHevcEnc::IntfImpl : public C2InterfaceHelper {
   public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper>& helper)
        : C2InterfaceHelper(helper) {
        setDerivedInstance(this);

        addParameter(
            DefineParam(mInputFormat, C2_NAME_INPUT_STREAM_FORMAT_SETTING)
                .withConstValue(
                    new C2StreamFormatConfig::input(0u, C2FormatVideo))
                .build());

        addParameter(
            DefineParam(mOutputFormat, C2_NAME_OUTPUT_STREAM_FORMAT_SETTING)
                .withConstValue(
                    new C2StreamFormatConfig::output(0u, C2FormatCompressed))
                .build());

        addParameter(
            DefineParam(mInputMediaType, C2_NAME_INPUT_PORT_MIME_SETTING)
                .withConstValue(AllocSharedString<C2PortMimeConfig::input>(
                    MEDIA_MIMETYPE_VIDEO_RAW))
                .build());

        addParameter(
            DefineParam(mOutputMediaType, C2_NAME_OUTPUT_PORT_MIME_SETTING)
                .withConstValue(AllocSharedString<C2PortMimeConfig::output>(
                    MEDIA_MIMETYPE_VIDEO_HEVC))
                .build());

        addParameter(DefineParam(mUsage, C2_NAME_INPUT_STREAM_USAGE_SETTING)
                         .withConstValue(new C2StreamUsageTuning::input(
                             0u, (uint64_t)C2MemoryUsage::CPU_READ))
                         .build());

        addParameter(
            DefineParam(mSize, C2_NAME_STREAM_VIDEO_SIZE_SETTING)
                .withDefault(new C2VideoSizeStreamTuning::input(0u, 320, 240))
                .withFields({
                    C2F(mSize, width).inRange(320, 1920, 2),
                    C2F(mSize, height).inRange(128, 1088, 2),
                })
                .withSetter(SizeSetter)
                .build());

        addParameter(
            DefineParam(mFrameRate, C2_NAME_STREAM_FRAME_RATE_SETTING)
                .withDefault(new C2StreamFrameRateInfo::output(0u, 30.))
                .withFields({C2F(mFrameRate, value).greaterThan(0.)})
                .withSetter(
                    Setter<decltype(*mFrameRate)>::StrictValueWithNoDeps)
                .build());

        addParameter(
            DefineParam(mBitrate, C2_NAME_STREAM_BITRATE_SETTING)
                .withDefault(new C2BitrateTuning::output(0u, 64000))
                .withFields({C2F(mBitrate, value).inRange(4096, 12000000)})
                .withSetter(BitrateSetter)
                .build());

        addParameter(
            DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                .withDefault(new C2StreamProfileLevelInfo::output(
                    0u, PROFILE_HEVC_MAIN, LEVEL_HEVC_MAIN_1))
                .withFields({
                    C2F(mProfileLevel, profile)
                        .oneOf({C2Config::PROFILE_HEVC_MAIN,
                                C2Config::PROFILE_HEVC_MAIN_STILL}),
                    C2F(mProfileLevel, level)
                        .oneOf({LEVEL_HEVC_MAIN_1, LEVEL_HEVC_MAIN_2,
                                LEVEL_HEVC_MAIN_2_1, LEVEL_HEVC_MAIN_3,
                                LEVEL_HEVC_MAIN_3_1, LEVEL_HEVC_MAIN_4,
                                LEVEL_HEVC_MAIN_4_1, LEVEL_HEVC_MAIN_5,
                                LEVEL_HEVC_MAIN_5_1, LEVEL_HEVC_MAIN_5_2}),
                })
                .withSetter(ProfileLevelSetter, mSize, mFrameRate, mBitrate)
                .build());

        addParameter(
                DefineParam(mRequestSync, C2_PARAMKEY_REQUEST_SYNC_FRAME)
                .withDefault(new C2StreamRequestSyncFrameTuning::output(0u, C2_FALSE))
                .withFields({C2F(mRequestSync, value).oneOf({ C2_FALSE, C2_TRUE }) })
                .withSetter(Setter<decltype(*mRequestSync)>::NonStrictValueWithNoDeps)
                .build());

        addParameter(
            DefineParam(mSyncFramePeriod, C2_PARAMKEY_SYNC_FRAME_INTERVAL)
                .withDefault(
                    new C2StreamSyncFrameIntervalTuning::output(0u, 1000000))
                .withFields({C2F(mSyncFramePeriod, value).any()})
                .withSetter(
                    Setter<decltype(*mSyncFramePeriod)>::StrictValueWithNoDeps)
                .build());
    }

    static C2R BitrateSetter(bool mayBlock,
                             C2P<C2StreamBitrateInfo::output>& me) {
        (void)mayBlock;
        C2R res = C2R::Ok();
        if (me.v.value <= 4096) {
            me.set().value = 4096;
        }
        return res;
    }

    static C2R SizeSetter(bool mayBlock,
                          const C2P<C2StreamPictureSizeInfo::input>& oldMe,
                          C2P<C2StreamPictureSizeInfo::input>& me) {
        (void)mayBlock;
        C2R res = C2R::Ok();
        if (!me.F(me.v.width).supportsAtAll(me.v.width)) {
            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.width)));
            me.set().width = oldMe.v.width;
        }
        if (!me.F(me.v.height).supportsAtAll(me.v.height)) {
            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.height)));
            me.set().height = oldMe.v.height;
        }
        return res;
    }

    static C2R ProfileLevelSetter(
            bool mayBlock,
            C2P<C2StreamProfileLevelInfo::output> &me,
            const C2P<C2VideoSizeStreamTuning::input> &size,
            const C2P<C2StreamFrameRateInfo::output> &frameRate,
            const C2P<C2BitrateTuning::output> &bitrate) {
        (void)mayBlock;
        if (!me.F(me.v.profile).supportsAtAll(me.v.profile)) {
            me.set().profile = PROFILE_HEVC_MAIN;
        }

        struct LevelLimits {
            C2Config::level_t level;
            uint64_t samplesPerSec;
            uint64_t samples;
            uint32_t bitrate;
        };

        constexpr LevelLimits kLimits[] = {
            { LEVEL_HEVC_MAIN_1,       552960,    36864,    128000 },
            { LEVEL_HEVC_MAIN_2,      3686400,   122880,   1500000 },
            { LEVEL_HEVC_MAIN_2_1,    7372800,   245760,   3000000 },
            { LEVEL_HEVC_MAIN_3,     16588800,   552960,   6000000 },
            { LEVEL_HEVC_MAIN_3_1,   33177600,   983040,  10000000 },
            { LEVEL_HEVC_MAIN_4,     66846720,  2228224,  12000000 },
            { LEVEL_HEVC_MAIN_4_1,  133693440,  2228224,  20000000 },
            { LEVEL_HEVC_MAIN_5,    267386880,  8912896,  25000000 },
            { LEVEL_HEVC_MAIN_5_1,  534773760,  8912896,  40000000 },
            { LEVEL_HEVC_MAIN_5_2, 1069547520,  8912896,  60000000 },
            { LEVEL_HEVC_MAIN_6,   1069547520, 35651584,  60000000 },
            { LEVEL_HEVC_MAIN_6_1, 2139095040, 35651584, 120000000 },
            { LEVEL_HEVC_MAIN_6_2, 4278190080, 35651584, 240000000 },
        };

        uint64_t samples = size.v.width * size.v.height;
        uint64_t samplesPerSec = samples * frameRate.v.value;

        // Check if the supplied level meets the MB / bitrate requirements. If
        // not, update the level with the lowest level meeting the requirements.

        bool found = false;
        // By default needsUpdate = false in case the supplied level does meet
        // the requirements.
        bool needsUpdate = false;
        for (const LevelLimits &limit : kLimits) {
            if (samples <= limit.samples && samplesPerSec <= limit.samplesPerSec &&
                    bitrate.v.value <= limit.bitrate) {
                // This is the lowest level that meets the requirements, and if
                // we haven't seen the supplied level yet, that means we don't
                // need the update.
                if (needsUpdate) {
                    ALOGD("Given level %x does not cover current configuration: "
                          "adjusting to %x", me.v.level, limit.level);
                    me.set().level = limit.level;
                }
                found = true;
                break;
            }
            if (me.v.level == limit.level) {
                // We break out of the loop when the lowest feasible level is
                // found. The fact that we're here means that our level doesn't
                // meet the requirement and needs to be updated.
                needsUpdate = true;
            }
        }
        if (!found) {
            // We set to the highest supported level.
            me.set().level = LEVEL_HEVC_MAIN_5_2;
        }
        return C2R::Ok();
    }

    UWORD32 getProfile_l() const {
        switch (mProfileLevel->profile) {
        case PROFILE_HEVC_MAIN:  [[fallthrough]];
        case PROFILE_HEVC_MAIN_STILL: return 1;
        default:
            ALOGD("Unrecognized profile: %x", mProfileLevel->profile);
            return 1;
        }
    }

    UWORD32 getLevel_l() const {
        struct Level {
            C2Config::level_t c2Level;
            UWORD32 hevcLevel;
        };
        constexpr Level levels[] = {
            { LEVEL_HEVC_MAIN_1,    30 },
            { LEVEL_HEVC_MAIN_2,    60 },
            { LEVEL_HEVC_MAIN_2_1,  63 },
            { LEVEL_HEVC_MAIN_3,    90 },
            { LEVEL_HEVC_MAIN_3_1,  93 },
            { LEVEL_HEVC_MAIN_4,   120 },
            { LEVEL_HEVC_MAIN_4_1, 123 },
            { LEVEL_HEVC_MAIN_5,   150 },
            { LEVEL_HEVC_MAIN_5_1, 153 },
            { LEVEL_HEVC_MAIN_5_2, 156 },
            { LEVEL_HEVC_MAIN_6,   180 },
            { LEVEL_HEVC_MAIN_6_1, 183 },
            { LEVEL_HEVC_MAIN_6_2, 186 },
        };
        for (const Level &level : levels) {
            if (mProfileLevel->level == level.c2Level) {
                return level.hevcLevel;
            }
        }
        ALOGD("Unrecognized level: %x", mProfileLevel->level);
        return 156;
    }
    uint32_t getSyncFramePeriod_l() const {
        if (mSyncFramePeriod->value < 0 ||
            mSyncFramePeriod->value == INT64_MAX) {
            return 0;
        }
        double period = mSyncFramePeriod->value / 1e6 * mFrameRate->value;
        return (uint32_t)c2_max(c2_min(period + 0.5, double(UINT32_MAX)), 1.);
    }

   std::shared_ptr<C2StreamPictureSizeInfo::input> getSize_l() const {
        return mSize;
    }
    std::shared_ptr<C2StreamFrameRateInfo::output> getFrameRate_l() const {
        return mFrameRate;
    }
    std::shared_ptr<C2StreamBitrateInfo::output> getBitrate_l() const {
        return mBitrate;
    }
    std::shared_ptr<C2StreamRequestSyncFrameTuning::output> getRequestSync_l() const {
        return mRequestSync;
    }

   private:
    std::shared_ptr<C2StreamFormatConfig::input> mInputFormat;
    std::shared_ptr<C2StreamFormatConfig::output> mOutputFormat;
    std::shared_ptr<C2PortMimeConfig::input> mInputMediaType;
    std::shared_ptr<C2PortMimeConfig::output> mOutputMediaType;
    std::shared_ptr<C2StreamUsageTuning::input> mUsage;
    std::shared_ptr<C2VideoSizeStreamTuning::input> mSize;
    std::shared_ptr<C2StreamFrameRateInfo::output> mFrameRate;
    std::shared_ptr<C2StreamRequestSyncFrameTuning::output> mRequestSync;
    std::shared_ptr<C2BitrateTuning::output> mBitrate;
    std::shared_ptr<C2StreamProfileLevelInfo::output> mProfileLevel;
    std::shared_ptr<C2StreamSyncFrameIntervalTuning::output> mSyncFramePeriod;
};
constexpr char COMPONENT_NAME[] = "c2.android.hevc.encoder";

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

C2SoftHevcEnc::C2SoftHevcEnc(const char* name, c2_node_id_t id,
                             const std::shared_ptr<IntfImpl>& intfImpl)
    : SimpleC2Component(
          std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl),
      mIvVideoColorFormat(IV_YUV_420P),
      mHevcEncProfile(1),
      mHevcEncLevel(30),
      mStarted(false),
      mSpsPpsHeaderReceived(false),
      mSignalledEos(false),
      mSignalledError(false),
      mCodecCtx(nullptr) {
    // If dump is enabled, then create an empty file
    GENERATE_FILE_NAMES();
    CREATE_DUMP_FILE(mInFile);
    CREATE_DUMP_FILE(mOutFile);

    gettimeofday(&mTimeStart, nullptr);
    gettimeofday(&mTimeEnd, nullptr);
}

C2SoftHevcEnc::~C2SoftHevcEnc() {
    releaseEncoder();
}

c2_status_t C2SoftHevcEnc::onInit() {
    return initEncoder();
}

c2_status_t C2SoftHevcEnc::onStop() {
    if (!mStarted) {
        return C2_OK;
    }
    return releaseEncoder();
}

void C2SoftHevcEnc::onReset() {
    onStop();
    initEncoder();
}

void C2SoftHevcEnc::onRelease() {
    onStop();
}

c2_status_t C2SoftHevcEnc::onFlush_sm() {
    return C2_OK;
}

static void fillEmptyWork(const std::unique_ptr<C2Work>& work) {
    uint32_t flags = 0;
    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
        flags |= C2FrameData::FLAG_END_OF_STREAM;
        ALOGV("Signalling EOS");
    }
    work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

c2_status_t C2SoftHevcEnc::initEncParams() {
    mCodecCtx = nullptr;
    mNumCores = MIN(GetCPUCoreCount(), CODEC_MAX_CORES);
    memset(&mEncParams, 0, sizeof(ihevce_static_cfg_params_t));

    // default configuration
    IHEVCE_PLUGIN_STATUS_T err = ihevce_set_def_params(&mEncParams);
    if (IHEVCE_EOK != err) {
        ALOGE("HEVC default init failed : 0x%x", err);
        return C2_CORRUPTED;
    }

    // update configuration
    mEncParams.s_src_prms.i4_width = mSize->width;
    mEncParams.s_src_prms.i4_height = mSize->height;
    mEncParams.s_src_prms.i4_frm_rate_denom = 1000;
    mEncParams.s_src_prms.i4_frm_rate_num = mFrameRate->value * mEncParams.s_src_prms.i4_frm_rate_denom;
    mEncParams.s_tgt_lyr_prms.as_tgt_params[0].i4_quality_preset = IHEVCE_QUALITY_P5;
    mEncParams.s_tgt_lyr_prms.as_tgt_params[0].ai4_tgt_bitrate[0] =
        mBitrate->value;
    mEncParams.s_tgt_lyr_prms.as_tgt_params[0].ai4_peak_bitrate[0] =
        mBitrate->value << 1;
    mEncParams.s_tgt_lyr_prms.as_tgt_params[0].i4_codec_level = mHevcEncLevel;
    mEncParams.s_coding_tools_prms.i4_max_i_open_gop_period = mIDRInterval;
    mEncParams.s_coding_tools_prms.i4_max_cra_open_gop_period = mIDRInterval;
    mIvVideoColorFormat = IV_YUV_420P;
    mEncParams.s_multi_thrd_prms.i4_max_num_cores = mNumCores;
    mEncParams.s_out_strm_prms.i4_codec_profile = mHevcEncProfile;
    mEncParams.s_config_prms.i4_rate_control_mode = 2;
    mEncParams.s_lap_prms.i4_rc_look_ahead_pics = 0;

    return C2_OK;
}

c2_status_t C2SoftHevcEnc::releaseEncoder() {
    mSpsPpsHeaderReceived = false;
    mSignalledEos = false;
    mSignalledError = false;
    mStarted = false;

    if (mCodecCtx) {
        IHEVCE_PLUGIN_STATUS_T err = ihevce_close(mCodecCtx);
        if (IHEVCE_EOK != err) return C2_CORRUPTED;
        mCodecCtx = nullptr;
    }
    return C2_OK;
}

c2_status_t C2SoftHevcEnc::drain(uint32_t drainMode,
                                 const std::shared_ptr<C2BlockPool>& pool) {
    (void)drainMode;
    (void)pool;
    return C2_OK;
}
c2_status_t C2SoftHevcEnc::initEncoder() {
    CHECK(!mCodecCtx);
    {
        IntfImpl::Lock lock = mIntf->lock();
        mSize = mIntf->getSize_l();
        mBitrate = mIntf->getBitrate_l();
        mFrameRate = mIntf->getFrameRate_l();
        mHevcEncProfile = mIntf->getProfile_l();
        mHevcEncLevel = mIntf->getLevel_l();
        mIDRInterval = mIntf->getSyncFramePeriod_l();
    }

    c2_status_t status = initEncParams();

    if (C2_OK != status) {
        ALOGE("Failed to initialize encoder params : 0x%x", status);
        mSignalledError = true;
        return status;
    }

    IHEVCE_PLUGIN_STATUS_T err = IHEVCE_EOK;
    err = ihevce_init(&mEncParams, &mCodecCtx);
    if (IHEVCE_EOK != err) {
        ALOGE("HEVC encoder init failed : 0x%x", err);
        return C2_CORRUPTED;
    }

    mStarted = true;
    return C2_OK;
}

c2_status_t C2SoftHevcEnc::setEncodeArgs(ihevce_inp_buf_t* ps_encode_ip,
                                         const C2GraphicView* const input,
                                         uint64_t timestamp) {
    ihevce_static_cfg_params_t* params = &mEncParams;
    memset(ps_encode_ip, 0, sizeof(ihevce_inp_buf_t));

    if (!input) {
        return C2_OK;
    }

    if (input->width() < mSize->width ||
        input->height() < mSize->height) {
        /* Expect width height to be configured */
        ALOGW("unexpected Capacity Aspect %d(%d) x %d(%d)", input->width(),
              mSize->width, input->height(), mSize->height);
        return C2_BAD_VALUE;
    }

    const C2PlanarLayout& layout = input->layout();
    uint8_t* yPlane =
        const_cast<uint8_t *>(input->data()[C2PlanarLayout::PLANE_Y]);
    uint8_t* uPlane =
        const_cast<uint8_t *>(input->data()[C2PlanarLayout::PLANE_U]);
    uint8_t* vPlane =
        const_cast<uint8_t *>(input->data()[C2PlanarLayout::PLANE_V]);
    int32_t yStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
    int32_t uStride = layout.planes[C2PlanarLayout::PLANE_U].rowInc;
    int32_t vStride = layout.planes[C2PlanarLayout::PLANE_V].rowInc;

    uint32_t width = mSize->width;
    uint32_t height = mSize->height;

    // width and height are always even
    // width and height are always even (as block size is 16x16)
    CHECK_EQ((width & 1u), 0u);
    CHECK_EQ((height & 1u), 0u);

    size_t yPlaneSize = width * height;

    switch (layout.type) {
        case C2PlanarLayout::TYPE_RGB:
            [[fallthrough]];
        case C2PlanarLayout::TYPE_RGBA: {
            MemoryBlock conversionBuffer =
                mConversionBuffers.fetch(yPlaneSize * 3 / 2);
            mConversionBuffersInUse.emplace(conversionBuffer.data(),
                                            conversionBuffer);
            yPlane = conversionBuffer.data();
            uPlane = yPlane + yPlaneSize;
            vPlane = uPlane + yPlaneSize / 4;
            yStride = width;
            uStride = vStride = yStride / 2;
            ConvertRGBToPlanarYUV(yPlane, yStride, height,
                                  conversionBuffer.size(), *input);
            break;
        }
        case C2PlanarLayout::TYPE_YUV: {
            if (!IsYUV420(*input)) {
                ALOGE("input is not YUV420");
                return C2_BAD_VALUE;
            }

            if (layout.planes[layout.PLANE_Y].colInc == 1 &&
                layout.planes[layout.PLANE_U].colInc == 1 &&
                layout.planes[layout.PLANE_V].colInc == 1 &&
                uStride == vStride && yStride == 2 * vStride) {
                // I420 compatible - already set up above
                break;
            }

            // copy to I420
            yStride = width;
            uStride = vStride = yStride / 2;
            MemoryBlock conversionBuffer =
                mConversionBuffers.fetch(yPlaneSize * 3 / 2);
            mConversionBuffersInUse.emplace(conversionBuffer.data(),
                                            conversionBuffer);
            MediaImage2 img =
                CreateYUV420PlanarMediaImage2(width, height, yStride, height);
            status_t err = ImageCopy(conversionBuffer.data(), &img, *input);
            if (err != OK) {
                ALOGE("Buffer conversion failed: %d", err);
                return C2_BAD_VALUE;
            }
            yPlane = conversionBuffer.data();
            uPlane = yPlane + yPlaneSize;
            vPlane = uPlane + yPlaneSize / 4;
            break;
        }

        case C2PlanarLayout::TYPE_YUVA:
            ALOGE("YUVA plane type is not supported");
            return C2_BAD_VALUE;

        default:
            ALOGE("Unrecognized plane type: %d", layout.type);
            return C2_BAD_VALUE;
    }

    switch (mIvVideoColorFormat) {
        case IV_YUV_420P: {
            // input buffer is supposed to be const but Ittiam API wants bare
            // pointer.
            ps_encode_ip->apv_inp_planes[0] = yPlane;
            ps_encode_ip->apv_inp_planes[1] = uPlane;
            ps_encode_ip->apv_inp_planes[2] = vPlane;

            ps_encode_ip->ai4_inp_strd[0] = yStride;
            ps_encode_ip->ai4_inp_strd[1] = uStride;
            ps_encode_ip->ai4_inp_strd[2] = vStride;

            ps_encode_ip->ai4_inp_size[0] = yStride * height;
            ps_encode_ip->ai4_inp_size[1] = uStride * height >> 1;
            ps_encode_ip->ai4_inp_size[2] = vStride * height >> 1;
            break;
        }

        case IV_YUV_422ILE: {
            // TODO
            break;
        }

        case IV_YUV_420SP_UV:
        case IV_YUV_420SP_VU:
        default: {
            ps_encode_ip->apv_inp_planes[0] = yPlane;
            ps_encode_ip->apv_inp_planes[1] = uPlane;
            ps_encode_ip->apv_inp_planes[2] = nullptr;

            ps_encode_ip->ai4_inp_strd[0] = yStride;
            ps_encode_ip->ai4_inp_strd[1] = uStride;
            ps_encode_ip->ai4_inp_strd[2] = 0;

            ps_encode_ip->ai4_inp_size[0] = yStride * height;
            ps_encode_ip->ai4_inp_size[1] = uStride * height >> 1;
            ps_encode_ip->ai4_inp_size[2] = 0;
            break;
        }
    }

    ps_encode_ip->i4_curr_bitrate =
        params->s_tgt_lyr_prms.as_tgt_params[0].ai4_tgt_bitrate[0];
    ps_encode_ip->i4_curr_peak_bitrate =
        params->s_tgt_lyr_prms.as_tgt_params[0].ai4_peak_bitrate[0];
    ps_encode_ip->i4_curr_rate_factor = params->s_config_prms.i4_rate_factor;
    ps_encode_ip->u8_pts = timestamp;
    return C2_OK;
}

void C2SoftHevcEnc::process(const std::unique_ptr<C2Work>& work,
                            const std::shared_ptr<C2BlockPool>& pool) {
    // Initialize output work
    work->result = C2_OK;
    work->workletsProcessed = 1u;
    work->worklets.front()->output.flags = work->input.flags;

    if (mSignalledError || mSignalledEos) {
        work->result = C2_BAD_VALUE;
        ALOGD("Signalled Error / Signalled Eos");
        return;
    }
    c2_status_t status = C2_OK;

    // Initialize encoder if not already initialized
    if (!mStarted) {
        status = initEncoder();
        if (C2_OK != status) {
            ALOGE("Failed to initialize encoder : 0x%x", status);
            mSignalledError = true;
            work->result = status;
            return;
        }
    }

    std::shared_ptr<const C2GraphicView> view;
    std::shared_ptr<C2Buffer> inputBuffer = nullptr;
    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    if (!work->input.buffers.empty()) {
        inputBuffer = work->input.buffers[0];
        view = std::make_shared<const C2GraphicView>(
            inputBuffer->data().graphicBlocks().front().map().get());
        if (view->error() != C2_OK) {
            ALOGE("graphic view map err = %d", view->error());
            mSignalledError = true;
            return;
        }
    }

    IHEVCE_PLUGIN_STATUS_T err = IHEVCE_EOK;

    fillEmptyWork(work);
    if (!mSpsPpsHeaderReceived) {
        ihevce_out_buf_t s_header_op{};
        err = ihevce_encode_header(mCodecCtx, &s_header_op);
        if (err == IHEVCE_EOK && s_header_op.i4_bytes_generated) {
            std::unique_ptr<C2StreamCsdInfo::output> csd =
                C2StreamCsdInfo::output::AllocUnique(
                    s_header_op.i4_bytes_generated, 0u);
            if (!csd) {
                ALOGE("CSD allocation failed");
                mSignalledError = true;
                work->result = C2_NO_MEMORY;
                return;
            }
            memcpy(csd->m.value, s_header_op.pu1_output_buf,
                   s_header_op.i4_bytes_generated);
            DUMP_TO_FILE(mOutFile, csd->m.value, csd->flexCount());
            work->worklets.front()->output.configUpdate.push_back(
                std::move(csd));
            mSpsPpsHeaderReceived = true;
        }
        if (!inputBuffer) {
            return;
        }
    }
    ihevce_inp_buf_t s_encode_ip{};
    ihevce_out_buf_t s_encode_op{};
    uint64_t timestamp = work->input.ordinal.timestamp.peekull();

    status = setEncodeArgs(&s_encode_ip, view.get(), timestamp);
    if (C2_OK != status) {
        mSignalledError = true;
        ALOGE("setEncodeArgs failed : 0x%x", status);
        work->result = status;
        return;
    }

    uint64_t timeDelay = 0;
    uint64_t timeTaken = 0;
    GETTIME(&mTimeStart, nullptr);
    TIME_DIFF(mTimeEnd, mTimeStart, timeDelay);

    ihevce_inp_buf_t* ps_encode_ip = (inputBuffer) ? &s_encode_ip : nullptr;

    err = ihevce_encode(mCodecCtx, ps_encode_ip, &s_encode_op);
    if (IHEVCE_EOK != err) {
        ALOGE("Encode Frame failed : 0x%x", err);
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    }

    GETTIME(&mTimeEnd, nullptr);
    /* Compute time taken for decode() */
    TIME_DIFF(mTimeStart, mTimeEnd, timeTaken);

    ALOGV("timeTaken=%6d delay=%6d numBytes=%6d", (int)timeTaken,
          (int)timeDelay, s_encode_op.i4_bytes_generated);

    if (s_encode_op.i4_bytes_generated) {
        std::shared_ptr<C2LinearBlock> block;
        C2MemoryUsage usage = {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};
        status = pool->fetchLinearBlock(s_encode_op.i4_bytes_generated, usage, &block);
        if (C2_OK != status) {
            ALOGE("fetchLinearBlock for Output failed with status 0x%x", status);
            work->result = C2_NO_MEMORY;
            mSignalledError = true;
            return;
        }
        C2WriteView wView = block->map().get();
        if (C2_OK != wView.error()) {
            ALOGE("write view map failed with status 0x%x", wView.error());
            work->result = wView.error();
            mSignalledError = true;
            return;
        }
        memcpy(wView.data(), s_encode_op.pu1_output_buf,
               s_encode_op.i4_bytes_generated);

        std::shared_ptr<C2Buffer> buffer =
            createLinearBuffer(block, 0, s_encode_op.i4_bytes_generated);

        DUMP_TO_FILE(mOutFile, s_encode_op.pu1_output_buf,
                     s_encode_op.i4_bytes_generated);

        work->worklets.front()->output.ordinal.timestamp = s_encode_op.u8_pts;
        if (s_encode_op.i4_is_key_frame) {
            ALOGV("IDR frame produced");
            buffer->setInfo(
                std::make_shared<C2StreamPictureTypeMaskInfo::output>(
                    0u /* stream id */, C2PictureTypeKeyFrame));
        }
        work->worklets.front()->output.buffers.push_back(buffer);
    }
    if (eos) {
        mSignalledEos = true;
    }
}

class C2SoftHevcEncFactory : public C2ComponentFactory {
   public:
    C2SoftHevcEncFactory()
        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
              GetCodec2PlatformComponentStore()->getParamReflector())) {}

    virtual c2_status_t createComponent(
        c2_node_id_t id, std::shared_ptr<C2Component>* const component,
        std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
            new C2SoftHevcEnc(
                COMPONENT_NAME, id,
                std::make_shared<C2SoftHevcEnc::IntfImpl>(mHelper)),
            deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
        c2_node_id_t id, std::shared_ptr<C2ComponentInterface>* const interface,
        std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
            new SimpleInterface<C2SoftHevcEnc::IntfImpl>(
                COMPONENT_NAME, id,
                std::make_shared<C2SoftHevcEnc::IntfImpl>(mHelper)),
            deleter);
        return C2_OK;
    }

    virtual ~C2SoftHevcEncFactory() override = default;

   private:
    std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftHevcEncFactory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
