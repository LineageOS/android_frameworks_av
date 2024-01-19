/*
 * Copyright (C) 2022 The Android Open Source Project
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
#define LOG_TAG "C2SoftAomEnc"
#include <log/log.h>

#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>

#include <C2Debug.h>
#include <Codec2CommonUtils.h>
#include <Codec2Mapper.h>
#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include "C2SoftAomEnc.h"

namespace android {

constexpr char COMPONENT_NAME[] = "c2.android.av1.encoder";

#define DEFAULT_SPEED 10

C2SoftAomEnc::IntfImpl::IntfImpl(const std::shared_ptr<C2ReflectorHelper>& helper)
    : SimpleInterface<void>::BaseParams(helper, COMPONENT_NAME, C2Component::KIND_ENCODER,
                                        C2Component::DOMAIN_VIDEO, MEDIA_MIMETYPE_VIDEO_AV1) {
    noPrivateBuffers();  // TODO: account for our buffers here
    noInputReferences();
    noOutputReferences();
    noInputLatency();
    noTimeStretch();
    setDerivedInstance(this);

    addParameter(DefineParam(mUsage, C2_PARAMKEY_INPUT_STREAM_USAGE)
                         .withConstValue(new C2StreamUsageTuning::input(
                                 0u, (uint64_t)C2MemoryUsage::CPU_READ))
                         .build());

    addParameter(DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
                         .withDefault(new C2StreamPictureSizeInfo::input(0u, 320, 240))
                         .withFields({
                                 C2F(mSize, width).inRange(2, 2048, 2),
                                 C2F(mSize, height).inRange(2, 2048, 2),
                         })
                         .withSetter(SizeSetter)
                         .build());

    addParameter(DefineParam(mBitrateMode, C2_PARAMKEY_BITRATE_MODE)
                         .withDefault(new C2StreamBitrateModeTuning::output(
                                 0u, C2Config::BITRATE_VARIABLE))
                         .withFields({C2F(mBitrateMode, value)
                                              .oneOf({C2Config::BITRATE_CONST,
                                                      C2Config::BITRATE_VARIABLE,
                                                      C2Config::BITRATE_IGNORE})})
                         .withSetter(Setter<decltype(*mBitrateMode)>::StrictValueWithNoDeps)
                         .build());

    addParameter(DefineParam(mFrameRate, C2_PARAMKEY_FRAME_RATE)
                         .withDefault(new C2StreamFrameRateInfo::output(0u, 30.))
                         // TODO: More restriction?
                         .withFields({C2F(mFrameRate, value).greaterThan(0.)})
                         .withSetter(Setter<decltype(*mFrameRate)>::StrictValueWithNoDeps)
                         .build());

    addParameter(DefineParam(mSyncFramePeriod, C2_PARAMKEY_SYNC_FRAME_INTERVAL)
                         .withDefault(new C2StreamSyncFrameIntervalTuning::output(0u, 1000000))
                         .withFields({C2F(mSyncFramePeriod, value).any()})
                         .withSetter(Setter<decltype(*mSyncFramePeriod)>::StrictValueWithNoDeps)
                         .build());

    addParameter(DefineParam(mBitrate, C2_PARAMKEY_BITRATE)
                         .withDefault(new C2StreamBitrateInfo::output(0u, 64000))
                         .withFields({C2F(mBitrate, value).inRange(4096, 40000000)})
                         .withSetter(BitrateSetter)
                         .build());

    addParameter(DefineParam(mComplexity, C2_PARAMKEY_COMPLEXITY)
                         .withDefault(new C2StreamComplexityTuning::output(0u, 0))
                         .withFields({C2F(mComplexity, value).inRange(0, 5)})
                         .withSetter(Setter<decltype(*mComplexity)>::NonStrictValueWithNoDeps)
                         .build());

    addParameter(DefineParam(mQuality, C2_PARAMKEY_QUALITY)
                         .withDefault(new C2StreamQualityTuning::output(0u, 80))
                         .withFields({C2F(mQuality, value).inRange(0, 100)})
                         .withSetter(Setter<decltype(*mQuality)>::NonStrictValueWithNoDeps)
                         .build());

    addParameter(DefineParam(mIntraRefresh, C2_PARAMKEY_INTRA_REFRESH)
                         .withConstValue(new C2StreamIntraRefreshTuning::output(
                                 0u, C2Config::INTRA_REFRESH_DISABLED, 0.))
                         .build());

    addParameter(DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                         .withDefault(new C2StreamProfileLevelInfo::output(0u, PROFILE_AV1_0,
                                                                           LEVEL_AV1_2))
                         .withFields({
                                 C2F(mProfileLevel, profile).equalTo(PROFILE_AV1_0),
                                 C2F(mProfileLevel, level)
                                    .oneOf({LEVEL_AV1_2, LEVEL_AV1_2_1, LEVEL_AV1_2_2,
                                            LEVEL_AV1_2_3, LEVEL_AV1_3, LEVEL_AV1_3_1,
                                            LEVEL_AV1_3_2, LEVEL_AV1_3_3, LEVEL_AV1_4,
                                            LEVEL_AV1_4_1}),
                         })
                         .withSetter(ProfileLevelSetter, mSize, mFrameRate, mBitrate)
                         .build());

    std::vector<uint32_t> pixelFormats = {HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
                                          HAL_PIXEL_FORMAT_YCBCR_420_888};
    if (isHalPixelFormatSupported((AHardwareBuffer_Format)HAL_PIXEL_FORMAT_YCBCR_P010)) {
        pixelFormats.push_back(HAL_PIXEL_FORMAT_YCBCR_P010);
    }
    addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
                         .withDefault(new C2StreamPixelFormatInfo::input(
                              0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
                         .withFields({C2F(mPixelFormat, value).oneOf({pixelFormats})})
                         .withSetter((Setter<decltype(*mPixelFormat)>::StrictValueWithNoDeps))
                         .build());

    addParameter(DefineParam(mRequestSync, C2_PARAMKEY_REQUEST_SYNC_FRAME)
                         .withDefault(new C2StreamRequestSyncFrameTuning::output(0u, C2_FALSE))
                         .withFields({C2F(mRequestSync, value).oneOf({C2_FALSE, C2_TRUE})})
                         .withSetter(Setter<decltype(*mRequestSync)>::NonStrictValueWithNoDeps)
                         .build());
    addParameter(
            DefineParam(mColorAspects, C2_PARAMKEY_COLOR_ASPECTS)
                    .withDefault(new C2StreamColorAspectsInfo::input(
                            0u, C2Color::RANGE_UNSPECIFIED, C2Color::PRIMARIES_UNSPECIFIED,
                            C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                    .withFields(
                            {C2F(mColorAspects, range)
                                     .inRange(C2Color::RANGE_UNSPECIFIED, C2Color::RANGE_OTHER),
                             C2F(mColorAspects, primaries)
                                     .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                              C2Color::PRIMARIES_OTHER),
                             C2F(mColorAspects, transfer)
                                     .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                              C2Color::TRANSFER_OTHER),
                             C2F(mColorAspects, matrix)
                                     .inRange(C2Color::MATRIX_UNSPECIFIED, C2Color::MATRIX_OTHER)})
                    .withSetter(ColorAspectsSetter)
                    .build());

    addParameter(
            DefineParam(mCodedColorAspects, C2_PARAMKEY_VUI_COLOR_ASPECTS)
                    .withDefault(new C2StreamColorAspectsInfo::output(
                            0u, C2Color::RANGE_LIMITED, C2Color::PRIMARIES_UNSPECIFIED,
                            C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                    .withFields(
                            {C2F(mCodedColorAspects, range)
                                     .inRange(C2Color::RANGE_UNSPECIFIED, C2Color::RANGE_OTHER),
                             C2F(mCodedColorAspects, primaries)
                                     .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                              C2Color::PRIMARIES_OTHER),
                             C2F(mCodedColorAspects, transfer)
                                     .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                              C2Color::TRANSFER_OTHER),
                             C2F(mCodedColorAspects, matrix)
                                     .inRange(C2Color::MATRIX_UNSPECIFIED, C2Color::MATRIX_OTHER)})
                    .withSetter(CodedColorAspectsSetter, mColorAspects)
                    .build());
}

C2R C2SoftAomEnc::IntfImpl::BitrateSetter(bool mayBlock, C2P<C2StreamBitrateInfo::output>& me) {
    (void)mayBlock;
    C2R res = C2R::Ok();
    if (me.v.value < 4096) {
        me.set().value = 4096;
    }
    return res;
}

C2R C2SoftAomEnc::IntfImpl::SizeSetter(bool mayBlock,
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

C2R C2SoftAomEnc::IntfImpl::ProfileLevelSetter(bool mayBlock,
                                               C2P<C2StreamProfileLevelInfo::output>& me,
                                               const C2P<C2StreamPictureSizeInfo::input>& size,
                                               const C2P<C2StreamFrameRateInfo::output>& frameRate,
                                               const C2P<C2StreamBitrateInfo::output>& bitrate) {
    (void)mayBlock;
    if (!me.F(me.v.profile).supportsAtAll(me.v.profile)) {
        me.set().profile = PROFILE_AV1_0;
    }
    struct LevelLimits {
        C2Config::level_t level;
        float samplesPerSec;
        uint64_t samples;
        uint32_t bitrate;
        size_t maxHSize;
        size_t maxVSize;
    };
    constexpr LevelLimits kLimits[] = {
            {LEVEL_AV1_2, 4423680, 147456, 1500000, 2048, 1152},
            {LEVEL_AV1_2_1, 8363520, 278784, 3000000, 2816, 1584},
            {LEVEL_AV1_3, 19975680, 665856, 6000000, 4352, 2448},
            {LEVEL_AV1_3_1, 37950720, 1065024, 10000000, 5504, 3096},
            {LEVEL_AV1_4, 70778880, 2359296, 12000000, 6144, 3456},
            {LEVEL_AV1_4_1, 141557760, 2359296, 20000000, 6144, 3456},
    };

    uint64_t samples = size.v.width * size.v.height;
    float samplesPerSec = float(samples) * frameRate.v.value;

    // Check if the supplied level meets the samples / bitrate requirements.
    // If not, update the level with the lowest level meeting the requirements.
    bool found = false;

    // By default needsUpdate = false in case the supplied level does meet
    // the requirements.
    bool needsUpdate = false;
    if (!me.F(me.v.level).supportsAtAll(me.v.level)) {
        needsUpdate = true;
    }
    for (const LevelLimits& limit : kLimits) {
        if (samples <= limit.samples && samplesPerSec <= limit.samplesPerSec &&
            bitrate.v.value <= limit.bitrate && size.v.width <= limit.maxHSize &&
            size.v.height <= limit.maxVSize) {
            // This is the lowest level that meets the requirements, and if
            // we haven't seen the supplied level yet, that means we don't
            // need the update.
            if (needsUpdate) {
                ALOGD("Given level %x does not cover current configuration: "
                        "adjusting to %x",
                        me.v.level, limit.level);
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
        me.set().level = LEVEL_AV1_4_1;
    }
    return C2R::Ok();
}

uint32_t C2SoftAomEnc::IntfImpl::getSyncFramePeriod() const {
    if (mSyncFramePeriod->value < 0 || mSyncFramePeriod->value == INT64_MAX) {
        return 0;
    }
    double period = mSyncFramePeriod->value / 1e6 * mFrameRate->value;
    return (uint32_t)c2_max(c2_min(period + 0.5, double(UINT32_MAX)), 1.);
}

C2R C2SoftAomEnc::IntfImpl::ColorAspectsSetter(bool mayBlock,
                                               C2P<C2StreamColorAspectsInfo::input>& me) {
    (void)mayBlock;
    if (me.v.range > C2Color::RANGE_OTHER) {
        me.set().range = C2Color::RANGE_OTHER;
    }
    if (me.v.primaries > C2Color::PRIMARIES_OTHER) {
        me.set().primaries = C2Color::PRIMARIES_OTHER;
    }
    if (me.v.transfer > C2Color::TRANSFER_OTHER) {
        me.set().transfer = C2Color::TRANSFER_OTHER;
    }
    if (me.v.matrix > C2Color::MATRIX_OTHER) {
        me.set().matrix = C2Color::MATRIX_OTHER;
    }
    return C2R::Ok();
}
C2R C2SoftAomEnc::IntfImpl::CodedColorAspectsSetter(
        bool mayBlock, C2P<C2StreamColorAspectsInfo::output>& me,
        const C2P<C2StreamColorAspectsInfo::input>& coded) {
    (void)mayBlock;
    me.set().range = coded.v.range;
    me.set().primaries = coded.v.primaries;
    me.set().transfer = coded.v.transfer;
    me.set().matrix = coded.v.matrix;
    return C2R::Ok();
}

uint32_t C2SoftAomEnc::IntfImpl::getLevel_l() const {
        return mProfileLevel->level - LEVEL_AV1_2;
}

C2SoftAomEnc::C2SoftAomEnc(const char* name, c2_node_id_t id,
                           const std::shared_ptr<IntfImpl>& intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl),
      mCodecContext(nullptr),
      mCodecConfiguration(nullptr),
      mCodecInterface(nullptr),
      mStrideAlign(2),
      mBitrateControlMode(AOM_VBR),
      mMinQuantizer(0),
      mMaxQuantizer(0),
      mLastTimestamp(INT64_MAX),
      mSignalledOutputEos(false),
      mSignalledError(false),
      mHeadersReceived(false),
      mIs10Bit(false) {
    ALOGV("Constructor");
}

C2SoftAomEnc::~C2SoftAomEnc() {
    ALOGV("Destructor");
    onRelease();
}

c2_status_t C2SoftAomEnc::onInit() {
    return C2_OK;
}

c2_status_t C2SoftAomEnc::onStop() {
    IntfImpl::Lock lock = mIntf->lock();
    std::shared_ptr<C2StreamRequestSyncFrameTuning::output> requestSync = mIntf->getRequestSync_l();
    lock.unlock();
    if (requestSync != mRequestSync) {
        // we can handle IDR immediately
        if (requestSync->value) {
            // unset request
            C2StreamRequestSyncFrameTuning::output clearSync(0u, C2_FALSE);
            std::vector<std::unique_ptr<C2SettingResult>> failures;
            mIntf->config({ &clearSync }, C2_MAY_BLOCK, &failures);
        }
        mRequestSync = requestSync;
    }
    onRelease();
    return C2_OK;
}

void C2SoftAomEnc::onReset() {
    (void)onStop();
}

void C2SoftAomEnc::onRelease() {
    if (mCodecContext) {
        aom_codec_destroy(mCodecContext);
        delete mCodecContext;
        mCodecContext = nullptr;
    }

    if (mCodecConfiguration) {
        delete mCodecConfiguration;
        mCodecConfiguration = nullptr;
    }

    // this one is not allocated by us
    mCodecInterface = nullptr;
    mHeadersReceived = false;
}

c2_status_t C2SoftAomEnc::onFlush_sm() {
    return onStop();
}

// c2Quality is in range of 0-100 (the more - the better),
// for AOM quality we are using a range of 15-50 (the less - the better)
static int MapC2QualityToAOMQuality (int c2Quality) {
    return 15 + 35 * (100 - c2Quality) / 100;
}

static int MapC2ComplexityToAOMSpeed (int c2Complexity) {
    int mapping[6] = {10, 9, 8, 7, 6, 6};
    if (c2Complexity > 5 || c2Complexity < 0) {
        ALOGW("Wrong complexity setting. Falling back to speed 10");
        return 10;
    }
    return mapping[c2Complexity];
}

aom_codec_err_t C2SoftAomEnc::setupCodecParameters() {
    aom_codec_err_t codec_return = AOM_CODEC_OK;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_TARGET_SEQ_LEVEL_IDX, mAV1EncLevel);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AOME_SET_CPUUSED,
                                     MapC2ComplexityToAOMSpeed(mComplexity->value));
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ROW_MT, 1);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_CDEF, 1);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_TPL_MODEL, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_DELTAQ_MODE, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_ORDER_HINT, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_AQ_MODE, 3);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_COEFF_COST_UPD_FREQ, 3);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_MODE_COST_UPD_FREQ, 3);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_MV_COST_UPD_FREQ, 3);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_PALETTE, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_OBMC, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_NOISE_SENSITIVITY, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_WARPED_MOTION, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_GLOBAL_MOTION, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_REF_FRAME_MVS, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_CFL_INTRA, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_SMOOTH_INTRA, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_ANGLE_DELTA, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_FILTER_INTRA, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_INTRA_DEFAULT_TX_ONLY, 1);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_DISABLE_TRELLIS_QUANT, 1);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_DIST_WTD_COMP, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_DIFF_WTD_COMP, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_DUAL_FILTER, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_INTERINTRA_COMP, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_INTERINTRA_WEDGE, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_INTRA_EDGE_FILTER, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_INTRABC, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_MASKED_COMP, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_PAETH_INTRA, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_QM, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_RECT_PARTITIONS, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_RESTORATION, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_SMOOTH_INTERINTRA, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_ENABLE_TX64, 0);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_MAX_REFERENCE_FRAMES, 3);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

    if (mBitrateControlMode == AOM_Q) {
        const int aomCQLevel = MapC2QualityToAOMQuality(mQuality->value);
        ALOGV("Set Q from %d to CQL %d",
              mQuality->value, aomCQLevel);

        codec_return = aom_codec_control(mCodecContext, AOME_SET_CQ_LEVEL, aomCQLevel);
        if (codec_return != AOM_CODEC_OK) goto BailOut;
    }

    ColorAspects sfAspects;
    if (!C2Mapper::map(mColorAspects->primaries, &sfAspects.mPrimaries)) {
        sfAspects.mPrimaries = android::ColorAspects::PrimariesUnspecified;
    }
    if (!C2Mapper::map(mColorAspects->range, &sfAspects.mRange)) {
        sfAspects.mRange = android::ColorAspects::RangeUnspecified;
    }
    if (!C2Mapper::map(mColorAspects->matrix, &sfAspects.mMatrixCoeffs)) {
        sfAspects.mMatrixCoeffs = android::ColorAspects::MatrixUnspecified;
    }
    if (!C2Mapper::map(mColorAspects->transfer, &sfAspects.mTransfer)) {
        sfAspects.mTransfer = android::ColorAspects::TransferUnspecified;
    }
    int32_t primaries, transfer, matrixCoeffs;
    bool range;
    ColorUtils::convertCodecColorAspectsToIsoAspects(sfAspects,
            &primaries,
            &transfer,
            &matrixCoeffs,
            &range);

    codec_return = aom_codec_control(mCodecContext, AV1E_SET_COLOR_RANGE, range);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_COLOR_PRIMARIES, primaries);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_TRANSFER_CHARACTERISTICS, transfer);
    if (codec_return != AOM_CODEC_OK) goto BailOut;
    codec_return = aom_codec_control(mCodecContext, AV1E_SET_MATRIX_COEFFICIENTS, matrixCoeffs);
    if (codec_return != AOM_CODEC_OK) goto BailOut;

BailOut:
    return codec_return;
}

status_t C2SoftAomEnc::initEncoder() {
    aom_codec_err_t codec_return;
    status_t result = UNKNOWN_ERROR;
    {
        IntfImpl::Lock lock = mIntf->lock();
        // Fetch config
        mSize = mIntf->getSize_l();
        mBitrate = mIntf->getBitrate_l();
        mBitrateMode = mIntf->getBitrateMode_l();
        mFrameRate = mIntf->getFrameRate_l();
        mIntraRefresh = mIntf->getIntraRefresh_l();
        mRequestSync = mIntf->getRequestSync_l();
        mColorAspects = mIntf->getCodedColorAspects_l();
        mQuality = mIntf->getQuality_l();
        mComplexity = mIntf->getComplexity_l();
        mAV1EncLevel = mIntf->getLevel_l();
    }


    switch (mBitrateMode->value) {
        case C2Config::BITRATE_CONST:
            mBitrateControlMode = AOM_CBR;
            break;
        case C2Config::BITRATE_IGNORE:
            mBitrateControlMode = AOM_Q;
            break;
        case C2Config::BITRATE_VARIABLE:
            [[fallthrough]];
        default:
            mBitrateControlMode = AOM_VBR;
            break;
    }

    mCodecInterface = aom_codec_av1_cx();
    if (!mCodecInterface) goto CleanUp;

    ALOGD("AOM: initEncoder. BRMode: %u. KF: %u. QP: %u - %u, 10Bit: %d, comlexity %d",
          (uint32_t)mBitrateControlMode,
          mIntf->getSyncFramePeriod(), mMinQuantizer, mMaxQuantizer, mIs10Bit, mComplexity->value);

    mCodecConfiguration = new aom_codec_enc_cfg_t;
    if (!mCodecConfiguration) goto CleanUp;

    codec_return = aom_codec_enc_config_default(mCodecInterface, mCodecConfiguration,
                                                AOM_USAGE_REALTIME);  // RT mode
    if (codec_return != AOM_CODEC_OK) {
        ALOGE("Error populating default configuration for aom encoder.");
        goto CleanUp;
    }

    mCodecConfiguration->g_w = mSize->width;
    mCodecConfiguration->g_h = mSize->height;
    mCodecConfiguration->g_bit_depth = mIs10Bit ? AOM_BITS_10 : AOM_BITS_8;
    mCodecConfiguration->g_input_bit_depth = mIs10Bit ? 10 : 8;


    mCodecConfiguration->g_threads = 0;
    mCodecConfiguration->g_error_resilient = 0;

    // timebase unit is microsecond
    // g_timebase is in seconds (i.e. 1/1000000 seconds)
    mCodecConfiguration->g_timebase.num = 1;
    mCodecConfiguration->g_timebase.den = 1000000;
    // rc_target_bitrate is in kbps, mBitrate in bps
    mCodecConfiguration->rc_target_bitrate = (mBitrate->value + 500) / 1000;
    mCodecConfiguration->rc_end_usage = mBitrateControlMode == AOM_Q ? AOM_Q : AOM_CBR;
    // Disable frame drop - not allowed in MediaCodec now.
    mCodecConfiguration->rc_dropframe_thresh = 0;
    // Disable lagged encoding.
    mCodecConfiguration->g_lag_in_frames = 0;

    // Disable spatial resizing.
    mCodecConfiguration->rc_resize_mode = 0;
    // Single-pass mode.
    mCodecConfiguration->g_pass = AOM_RC_ONE_PASS;

    // Maximum key frame interval - for CBR boost to 3000
    mCodecConfiguration->kf_max_dist = 3000;
    // Encoder determines optimal key frame placement automatically.
    mCodecConfiguration->kf_mode = AOM_KF_AUTO;
    // The amount of data that may be buffered by the decoding
    // application in ms.
    mCodecConfiguration->rc_buf_sz = 1000;

    if (mBitrateControlMode == AOM_CBR) {
        // Initial value of the buffer level in ms.
        mCodecConfiguration->rc_buf_initial_sz = 500;
        // Amount of data that the encoder should try to maintain in ms.
        mCodecConfiguration->rc_buf_optimal_sz = 600;
        // Maximum amount of bits that can be subtracted from the target
        // bitrate - expressed as percentage of the target bitrate.
        mCodecConfiguration->rc_undershoot_pct = 100;
        // Maximum amount of bits that can be added to the target
        // bitrate - expressed as percentage of the target bitrate.
        mCodecConfiguration->rc_overshoot_pct = 10;
    } else {
        // Maximum amount of bits that can be subtracted from the target
        // bitrate - expressed as percentage of the target bitrate.
        mCodecConfiguration->rc_undershoot_pct = 100;
        // Maximum amount of bits that can be added to the target
        // bitrate - expressed as percentage of the target bitrate.
        mCodecConfiguration->rc_overshoot_pct = 100;
    }

    if (mIntf->getSyncFramePeriod() >= 0) {
        mCodecConfiguration->kf_max_dist = mIntf->getSyncFramePeriod();
        mCodecConfiguration->kf_min_dist = mIntf->getSyncFramePeriod();
        mCodecConfiguration->kf_mode = AOM_KF_AUTO;
    }
    if (mMinQuantizer > 0) {
        mCodecConfiguration->rc_min_quantizer = mMinQuantizer;
    }
    if (mMaxQuantizer > 0) {
        mCodecConfiguration->rc_max_quantizer = mMaxQuantizer;
    } else {
        if (mBitrateControlMode == AOM_VBR) {
            // For VBR we are limiting MaxQP to 52 (down 11 steps) to maintain quality
            // 52 comes from experiments done on libaom standalone app
            mCodecConfiguration->rc_max_quantizer = 52;
        }
    }

    mCodecContext = new aom_codec_ctx_t;
    if (!mCodecContext) goto CleanUp;
    codec_return = aom_codec_enc_init(mCodecContext, mCodecInterface, mCodecConfiguration,
                                      mIs10Bit ? AOM_CODEC_USE_HIGHBITDEPTH : 0);
    if (codec_return != AOM_CODEC_OK) {
        ALOGE("Error initializing aom encoder");
        goto CleanUp;
    }

    codec_return = setupCodecParameters();
    if (codec_return != AOM_CODEC_OK) {
        ALOGE("Error setting up codec parameters");
        goto CleanUp;
    }

    mHeadersReceived = false;

    {
        uint32_t width = mSize->width;
        uint32_t height = mSize->height;
        if (((uint64_t)width * height) > ((uint64_t)INT32_MAX / 3)) {
            ALOGE("b/25812794, Buffer size is too big, width=%u, height=%u.", width, height);
        } else {
            uint32_t stride = (width + mStrideAlign - 1) & ~(mStrideAlign - 1);
            uint32_t vstride = (height + mStrideAlign - 1) & ~(mStrideAlign - 1);
            mConversionBuffer = MemoryBlock::Allocate(stride * vstride * 3 / (mIs10Bit? 1 : 2));
            if (!mConversionBuffer.size()) {
                ALOGE("Allocating conversion buffer failed.");
            } else {
                mNumInputFrames = -1;
                return OK;
            }
        }
    }

CleanUp:
    onRelease();
    return result;
}

void C2SoftAomEnc::process(const std::unique_ptr<C2Work>& work,
                           const std::shared_ptr<C2BlockPool>& pool) {
    // Initialize output work
    work->result = C2_OK;
    work->workletsProcessed = 1u;
    work->worklets.front()->output.flags = work->input.flags;

    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    std::shared_ptr<C2GraphicView> rView;
    std::shared_ptr<C2Buffer> inputBuffer;
    if (!work->input.buffers.empty()) {
        inputBuffer = work->input.buffers[0];
        rView = std::make_shared<C2GraphicView>(
                inputBuffer->data().graphicBlocks().front().map().get());
        if (rView->error() != C2_OK) {
            ALOGE("graphic view map err = %d", rView->error());
            work->result = C2_CORRUPTED;
            return;
        }
    } else {
        ALOGV("Empty input Buffer");
        uint32_t flags = 0;
        if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
            flags |= C2FrameData::FLAG_END_OF_STREAM;
        }
        work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
        return;
    }

    bool end_of_stream = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    aom_image_t raw_frame;
    const C2PlanarLayout& layout = rView->layout();
    if (!mHeadersReceived) {
        mIs10Bit = (layout.planes[layout.PLANE_Y].bitDepth == 10);

        // Re-Initialize encoder
        if (mCodecContext){
            onRelease();
        }
    }
    if (!mCodecContext && OK != initEncoder()) {
        ALOGE("Failed to initialize encoder");
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    }

    //(b/279387842)
    //workaround for incorrect crop size in view when using surface mode
    rView->setCrop_be(C2Rect(mSize->width, mSize->height));

    if (!mHeadersReceived) {
        Av1Config av1_config;
        constexpr uint32_t header_length = 2048;
        uint8_t header[header_length];
        size_t header_bytes;
        aom_fixed_buf_t* obu_sequence_header = aom_codec_get_global_headers(mCodecContext);
        int ret = 1;
        if (obu_sequence_header) {
            if (get_av1config_from_obu(reinterpret_cast<const uint8_t*>(obu_sequence_header->buf),
                                       obu_sequence_header->sz, false, &av1_config) == 0) {
                ret = write_av1config(&av1_config, header_length, &header_bytes, header);

            } else {
                ALOGE("Can not get config");
            }
            free(obu_sequence_header->buf);
            free(obu_sequence_header);
        }

        if (ret) {
            ALOGE("Can not write config");
            mSignalledError = true;
            work->result = C2_NO_MEMORY;
            work->workletsProcessed = 1u;
            return;
        }

        mHeadersReceived = true;
        std::unique_ptr<C2StreamInitDataInfo::output> csd =
                C2StreamInitDataInfo::output::AllocUnique(header_bytes, 0u);
        if (!csd) {
            ALOGE("CSD allocation failed");
            mSignalledError = true;
            work->result = C2_NO_MEMORY;
            work->workletsProcessed = 1u;
            return;
        }
        memcpy(csd->m.value, header, header_bytes);
        work->worklets.front()->output.configUpdate.push_back(std::move(csd));
        ALOGV("CSD Produced of size %zu bytes", header_bytes);
    }

    const C2ConstGraphicBlock inBuffer = inputBuffer->data().graphicBlocks().front();
    if (inBuffer.width() < mSize->width || inBuffer.height() < mSize->height) {
        ALOGE("unexpected Input buffer attributes %d(%d) x %d(%d)", inBuffer.width(), mSize->width,
              inBuffer.height(), mSize->height);
        mSignalledError = true;
        work->result = C2_BAD_VALUE;
        return;
    }


    uint32_t width = mSize->width;
    uint32_t height = mSize->height;
    if (width > 0x8000 || height > 0x8000) {
        ALOGE("Image too big: %u x %u", width, height);
        work->result = C2_BAD_VALUE;
        return;
    }
    uint32_t stride = (width + mStrideAlign - 1) & ~(mStrideAlign - 1);
    uint32_t vstride = (height + mStrideAlign - 1) & ~(mStrideAlign - 1);
    switch (layout.type) {
        case C2PlanarLayout::TYPE_RGB:
        case C2PlanarLayout::TYPE_RGBA: {
            std::shared_ptr<C2StreamColorAspectsInfo::output> colorAspects;
            {
                IntfImpl::Lock lock = mIntf->lock();
                colorAspects = mIntf->getCodedColorAspects_l();
            }
            ConvertRGBToPlanarYUV(mConversionBuffer.data(), stride, vstride,
                                  mConversionBuffer.size(), *rView.get(), colorAspects->matrix,
                                  colorAspects->range);
            aom_img_wrap(&raw_frame, AOM_IMG_FMT_I420, width, height, mStrideAlign,
                         mConversionBuffer.data());
            break;
        }
        case C2PlanarLayout::TYPE_YUV: {
            const bool isYUV420_10bit = IsYUV420_10bit(*rView);
            if (!IsYUV420(*rView) && !isYUV420_10bit) {
                ALOGE("input is not YUV420");
                work->result = C2_BAD_VALUE;
                return;
            }
            if (!isYUV420_10bit) {
                if (IsI420(*rView)) {
                    // I420 compatible - though with custom offset and stride
                    aom_img_wrap(&raw_frame, AOM_IMG_FMT_I420, width, height, mStrideAlign,
                                 (uint8_t*)rView->data()[0]);
                    raw_frame.planes[1] = (uint8_t*)rView->data()[1];
                    raw_frame.planes[2] = (uint8_t*)rView->data()[2];
                    raw_frame.stride[0] = layout.planes[layout.PLANE_Y].rowInc;
                    raw_frame.stride[1] = layout.planes[layout.PLANE_U].rowInc;
                    raw_frame.stride[2] = layout.planes[layout.PLANE_V].rowInc;
                } else {
                    // TODO(kyslov): Add image wrap for NV12
                    // copy to I420
                    MediaImage2 img = CreateYUV420PlanarMediaImage2(width, height, stride, vstride);
                    if (mConversionBuffer.size() >= stride * vstride * 3 / 2) {
                        status_t err = ImageCopy(mConversionBuffer.data(), &img, *rView);
                        if (err != OK) {
                            ALOGE("Buffer conversion failed: %d", err);
                            work->result = C2_BAD_VALUE;
                            return;
                        }
                        aom_img_wrap(&raw_frame, AOM_IMG_FMT_I420, stride, vstride, mStrideAlign,
                                     mConversionBuffer.data());
                        aom_img_set_rect(&raw_frame, 0, 0, width, height, 0);
                    } else {
                        ALOGE("Conversion buffer is too small: %u x %u for %zu", stride, vstride,
                              mConversionBuffer.size());
                        work->result = C2_BAD_VALUE;
                        return;
                    }
                }
            } else {  // 10 bits
                if (IsP010(*rView)) {
                    if (mConversionBuffer.size() >= stride * vstride * 3) {
                        uint16_t *dstY, *dstU, *dstV;
                        dstY = (uint16_t*)mConversionBuffer.data();
                        dstU = dstY + stride * vstride;
                        dstV = dstU + (stride * vstride) / 4;
                        convertP010ToYUV420Planar16(dstY, dstU, dstV, (uint16_t*)(rView->data()[0]),
                                                    (uint16_t*)(rView->data()[1]),
                                                    layout.planes[layout.PLANE_Y].rowInc / 2,
                                                    layout.planes[layout.PLANE_U].rowInc / 2,
                                                    stride, stride / 2, stride / 2, stride,
                                                    vstride);
                        aom_img_wrap(&raw_frame, AOM_IMG_FMT_I42016, stride, vstride, mStrideAlign,
                                     mConversionBuffer.data());
                        aom_img_set_rect(&raw_frame, 0, 0, width, height, 0);
                    } else {
                        ALOGE("Conversion buffer is too small: %u x %u for %zu", stride, vstride,
                              mConversionBuffer.size());
                        work->result = C2_BAD_VALUE;
                        return;
                    }
                } else {
                    ALOGE("Image format conversion is not supported.");
                    work->result = C2_BAD_VALUE;
                    return;
                }
            }
            break;
        }
        case C2PlanarLayout::TYPE_YUVA: {
            if (mConversionBuffer.size() >= stride * vstride * 3) {
                uint16_t *dstY, *dstU, *dstV;
                dstY = (uint16_t*)mConversionBuffer.data();
                dstU = dstY + stride * vstride;
                dstV = dstU + (stride * vstride) / 4;
                convertRGBA1010102ToYUV420Planar16(dstY, dstU, dstV, (uint32_t*)(rView->data()[0]),
                                                   layout.planes[layout.PLANE_Y].rowInc / 4, stride,
                                                   vstride, mColorAspects->matrix,
                                                   mColorAspects->range);
                aom_img_wrap(&raw_frame, AOM_IMG_FMT_I42016, stride, vstride, mStrideAlign,
                                mConversionBuffer.data());
                aom_img_set_rect(&raw_frame, 0, 0, width, height, 0);
            } else {
                ALOGE("Conversion buffer is too small: %u x %u for %zu", stride, vstride,
                        mConversionBuffer.size());
                work->result = C2_BAD_VALUE;
                return;
            }
            break;
        }

        default:
            ALOGE("Unrecognized plane type: %d", layout.type);
            work->result = C2_BAD_VALUE;
            return;
    }

    aom_enc_frame_flags_t flags = 0;
    // handle dynamic config parameters
    {
        IntfImpl::Lock lock = mIntf->lock();
        std::shared_ptr<C2StreamIntraRefreshTuning::output> intraRefresh =
                mIntf->getIntraRefresh_l();
        std::shared_ptr<C2StreamBitrateInfo::output> bitrate = mIntf->getBitrate_l();
        std::shared_ptr<C2StreamRequestSyncFrameTuning::output> requestSync =
                mIntf->getRequestSync_l();
        lock.unlock();

        if (intraRefresh != mIntraRefresh) {
            mIntraRefresh = intraRefresh;
            ALOGV("Got mIntraRefresh request");
        }

        if (requestSync != mRequestSync) {
            // we can handle IDR immediately
            if (requestSync->value) {
                // unset request
                C2StreamRequestSyncFrameTuning::output clearSync(0u, C2_FALSE);
                std::vector<std::unique_ptr<C2SettingResult>> failures;
                mIntf->config({&clearSync}, C2_MAY_BLOCK, &failures);
                ALOGV("Got sync request");
                flags |= AOM_EFLAG_FORCE_KF;
            }
            mRequestSync = requestSync;
        }

        if (bitrate != mBitrate) {
            mBitrate = bitrate;
            mCodecConfiguration->rc_target_bitrate = (mBitrate->value + 500) / 1000;
            aom_codec_err_t res = aom_codec_enc_config_set(mCodecContext, mCodecConfiguration);
            if (res != AOM_CODEC_OK) {
                ALOGE("aom encoder failed to update bitrate: %s", aom_codec_err_to_string(res));
                mSignalledError = true;
                work->result = C2_CORRUPTED;
                return;
            }
        }
    }

    uint64_t input_timestamp = work->input.ordinal.timestamp.peekull();
    uint32_t frame_duration;
    if (input_timestamp > mLastTimestamp) {
        frame_duration = (uint32_t)(input_timestamp - mLastTimestamp);
    } else {
        // Use default of 30 fps in case of 0 frame rate.
        float frame_rate = mFrameRate->value;
        if (frame_rate < 0.001) {
            frame_rate = 30.0;
        }
        frame_duration = (uint32_t)(1000000 / frame_rate + 0.5);
    }
    mLastTimestamp = input_timestamp;

    aom_codec_err_t codec_return =
            aom_codec_encode(mCodecContext, &raw_frame, input_timestamp, frame_duration, flags);
    if (codec_return != AOM_CODEC_OK) {
        ALOGE("aom encoder failed to encode frame");
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        return;
    }

    bool populated = false;
    aom_codec_iter_t encoded_packet_iterator = nullptr;
    const aom_codec_cx_pkt_t* encoded_packet;
    while ((encoded_packet = aom_codec_get_cx_data(mCodecContext, &encoded_packet_iterator))) {
        if (encoded_packet->kind == AOM_CODEC_CX_FRAME_PKT) {
            std::shared_ptr<C2LinearBlock> block;
            C2MemoryUsage usage = {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};
            c2_status_t err = pool->fetchLinearBlock(encoded_packet->data.frame.sz, usage, &block);
            if (err != C2_OK) {
                ALOGE("fetchLinearBlock for Output failed with status %d", err);
                work->result = C2_NO_MEMORY;
                return;
            }
            C2WriteView wView = block->map().get();
            if (wView.error()) {
                ALOGE("write view map failed %d", wView.error());
                work->result = C2_CORRUPTED;
                return;
            }

            memcpy(wView.data(), encoded_packet->data.frame.buf, encoded_packet->data.frame.sz);
            ++mNumInputFrames;

            ALOGD("bytes generated %zu", encoded_packet->data.frame.sz);
            uint32_t flags = 0;
            if (end_of_stream) {
                flags |= C2FrameData::FLAG_END_OF_STREAM;
            }

            work->worklets.front()->output.flags = (C2FrameData::flags_t)flags;
            work->worklets.front()->output.buffers.clear();
            std::shared_ptr<C2Buffer> buffer =
                    createLinearBuffer(block, 0, encoded_packet->data.frame.sz);
            if (encoded_packet->data.frame.flags & AOM_FRAME_IS_KEY) {
                buffer->setInfo(std::make_shared<C2StreamPictureTypeMaskInfo::output>(
                        0u /* stream id */, C2Config::SYNC_FRAME));
            }
            work->worklets.front()->output.buffers.push_back(buffer);
            work->worklets.front()->output.ordinal = work->input.ordinal;
            work->worklets.front()->output.ordinal.timestamp = encoded_packet->data.frame.pts;
            work->workletsProcessed = 1u;
            populated = true;
            if (end_of_stream) {
                mSignalledOutputEos = true;
                ALOGV("signalled End Of Stream");
            }
        }
    }
    if (!populated) {
        work->workletsProcessed = 0u;
    }
}

c2_status_t C2SoftAomEnc::drain(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool) {
    (void)pool;
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

class C2SoftAomEncFactory : public C2ComponentFactory {
  public:
    C2SoftAomEncFactory()
        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
                  GetCodec2PlatformComponentStore()->getParamReflector())) {}

    virtual c2_status_t createComponent(c2_node_id_t id,
                                        std::shared_ptr<C2Component>* const component,
                                        std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
                new C2SoftAomEnc(COMPONENT_NAME, id,
                                 std::make_shared<C2SoftAomEnc::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id, std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
                new SimpleInterface<C2SoftAomEnc::IntfImpl>(
                        COMPONENT_NAME, id, std::make_shared<C2SoftAomEnc::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual ~C2SoftAomEncFactory() override = default;

  private:
    std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

__attribute__((cfi_canonical_jump_table)) extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftAomEncFactory();
}

__attribute__((cfi_canonical_jump_table)) extern "C" void DestroyCodec2Factory(
        ::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
