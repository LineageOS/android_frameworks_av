/*
 * Copyright (C) 2024 The Android Open Source Project
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
#define LOG_TAG "C2SoftApvEnc"
#include <log/log.h>

#include <android_media_swcodec_flags.h>

#include <media/hardware/VideoAPI.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/foundation/AUtils.h>

#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <Codec2BufferUtils.h>
#include <Codec2CommonUtils.h>
#include <Codec2Mapper.h>
#include <SimpleC2Interface.h>
#include <media/stagefright/foundation/ABitReader.h>
#include <util/C2InterfaceHelper.h>
#include <cmath>
#include "C2SoftApvEnc.h"
#include "isAtLeastRelease.h"

namespace android {

namespace {

constexpr char COMPONENT_NAME[] = "c2.android.apv.encoder";
constexpr uint32_t kMinOutBufferSize = 524288;
constexpr uint32_t kMaxBitstreamBufSize = 16 * 1024 * 1024;
constexpr int32_t kApvQpMin = 0;
constexpr int32_t kApvQpMax = 51;

#define PROFILE_APV_DEFAULT 0
#define LEVEL_APV_DEFAULT 0
#define MAX_NUM_FRMS (1)  // supports only 1-frame input

}  // namespace

class C2SoftApvEnc::IntfImpl : public SimpleInterface<void>::BaseParams {
  public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper>& helper)
        : SimpleInterface<void>::BaseParams(helper, COMPONENT_NAME, C2Component::KIND_ENCODER,
                                            C2Component::DOMAIN_VIDEO, MEDIA_MIMETYPE_VIDEO_APV) {
        noPrivateBuffers();
        noInputReferences();
        noOutputReferences();
        noTimeStretch();
        setDerivedInstance(this);

        addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                             .withConstValue(new C2ComponentAttributesSetting(
                                     C2Component::ATTRIB_IS_TEMPORAL))
                             .build());

        addParameter(DefineParam(mUsage, C2_PARAMKEY_INPUT_STREAM_USAGE)
                             .withConstValue(new C2StreamUsageTuning::input(
                                     0u, (uint64_t)C2MemoryUsage::CPU_READ))
                             .build());

        // matches size limits in codec library
        addParameter(DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
                             .withDefault(new C2StreamPictureSizeInfo::input(0u, 320, 240))
                             .withFields({
                                     C2F(mSize, width).inRange(2, 4096, 2),
                                     C2F(mSize, height).inRange(2, 4096, 2),
                             })
                             .withSetter(SizeSetter)
                             .build());

        addParameter(DefineParam(mBitrate, C2_PARAMKEY_BITRATE)
                             .withDefault(new C2StreamBitrateInfo::output(0u, 512000))
                             .withFields({C2F(mBitrate, value).inRange(512000, 240000000)})
                             .withSetter(BitrateSetter)
                             .build());
        if (android::media::swcodec::flags::apv_software_codec_cq()) {
            addParameter(DefineParam(mBitrateMode, C2_PARAMKEY_BITRATE_MODE)
                             .withDefault(new C2StreamBitrateModeTuning::output(
                                     0u, C2Config::BITRATE_VARIABLE))
                             .withFields({C2F(mBitrateMode, value).oneOf({
                                     C2Config::BITRATE_VARIABLE,
                                     C2Config::BITRATE_IGNORE})})
                             .withSetter(Setter<decltype(*mBitrateMode)>::StrictValueWithNoDeps)
                             .build());
        }

        addParameter(DefineParam(mFrameRate, C2_PARAMKEY_FRAME_RATE)
                             .withDefault(new C2StreamFrameRateInfo::output(0u, 15.))
                             .withFields({C2F(mFrameRate, value).greaterThan(0.)})
                             .withSetter(Setter<decltype(*mFrameRate)>::StrictValueWithNoDeps)
                             .build());

        addParameter(DefineParam(mQuality, C2_PARAMKEY_QUALITY)
                             .withDefault(new C2StreamQualityTuning::output(0u, 0))
                             .withFields({C2F(mQuality, value).inRange(0, 100)})
                             .withSetter(Setter<decltype(*mQuality)>::NonStrictValueWithNoDeps)
                             .build());

        addParameter(
                DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                        .withDefault(new C2StreamProfileLevelInfo::output(
                                0u, C2Config::PROFILE_APV_422_10, LEVEL_APV_1_BAND_0))
                        .withFields({
                                C2F(mProfileLevel, profile).oneOf({C2Config::PROFILE_APV_422_10}),
                                C2F(mProfileLevel, level)
                                        .oneOf({
                                                C2Config::LEVEL_APV_1_BAND_0,
                                                C2Config::LEVEL_APV_1_1_BAND_0,
                                                C2Config::LEVEL_APV_2_BAND_0,
                                                C2Config::LEVEL_APV_2_1_BAND_0,
                                                C2Config::LEVEL_APV_3_BAND_0,
                                                C2Config::LEVEL_APV_3_1_BAND_0,
                                                C2Config::LEVEL_APV_4_BAND_0,
                                                C2Config::LEVEL_APV_4_1_BAND_0,
                                                C2Config::LEVEL_APV_5_BAND_0,
                                                C2Config::LEVEL_APV_5_1_BAND_0,
                                                C2Config::LEVEL_APV_6_BAND_0,
                                                C2Config::LEVEL_APV_6_1_BAND_0,
                                                C2Config::LEVEL_APV_7_BAND_0,
                                                C2Config::LEVEL_APV_7_1_BAND_0,
                                                C2Config::LEVEL_APV_1_BAND_1,
                                                C2Config::LEVEL_APV_1_1_BAND_1,
                                                C2Config::LEVEL_APV_2_BAND_1,
                                                C2Config::LEVEL_APV_2_1_BAND_1,
                                                C2Config::LEVEL_APV_3_BAND_1,
                                                C2Config::LEVEL_APV_3_1_BAND_1,
                                                C2Config::LEVEL_APV_4_BAND_1,
                                                C2Config::LEVEL_APV_4_1_BAND_1,
                                                C2Config::LEVEL_APV_5_BAND_1,
                                                C2Config::LEVEL_APV_5_1_BAND_1,
                                                C2Config::LEVEL_APV_6_BAND_1,
                                                C2Config::LEVEL_APV_6_1_BAND_1,
                                                C2Config::LEVEL_APV_7_BAND_1,
                                                C2Config::LEVEL_APV_7_1_BAND_1,
                                                C2Config::LEVEL_APV_1_BAND_2,
                                                C2Config::LEVEL_APV_1_1_BAND_2,
                                                C2Config::LEVEL_APV_2_BAND_2,
                                                C2Config::LEVEL_APV_2_1_BAND_2,
                                                C2Config::LEVEL_APV_3_BAND_2,
                                                C2Config::LEVEL_APV_3_1_BAND_2,
                                                C2Config::LEVEL_APV_4_BAND_2,
                                                C2Config::LEVEL_APV_4_1_BAND_2,
                                                C2Config::LEVEL_APV_5_BAND_2,
                                                C2Config::LEVEL_APV_5_1_BAND_2,
                                                C2Config::LEVEL_APV_6_BAND_2,
                                                C2Config::LEVEL_APV_6_1_BAND_2,
                                                C2Config::LEVEL_APV_7_BAND_2,
                                                C2Config::LEVEL_APV_7_1_BAND_2,
                                                C2Config::LEVEL_APV_1_BAND_3,
                                                C2Config::LEVEL_APV_1_1_BAND_3,
                                                C2Config::LEVEL_APV_2_BAND_3,
                                                C2Config::LEVEL_APV_2_1_BAND_3,
                                                C2Config::LEVEL_APV_3_BAND_3,
                                                C2Config::LEVEL_APV_3_1_BAND_3,
                                                C2Config::LEVEL_APV_4_BAND_3,
                                                C2Config::LEVEL_APV_4_1_BAND_3,
                                                C2Config::LEVEL_APV_5_BAND_3,
                                                C2Config::LEVEL_APV_5_1_BAND_3,
                                                C2Config::LEVEL_APV_6_BAND_3,
                                                C2Config::LEVEL_APV_6_1_BAND_3,
                                                C2Config::LEVEL_APV_7_BAND_3,
                                                C2Config::LEVEL_APV_7_1_BAND_3,
                                        }),
                        })
                        .withSetter(ProfileLevelSetter, mSize, mFrameRate, mBitrate)
                        .build());

        addParameter(DefineParam(mColorAspects, C2_PARAMKEY_COLOR_ASPECTS)
                             .withDefault(new C2StreamColorAspectsInfo::input(
                                     0u, C2Color::RANGE_UNSPECIFIED, C2Color::PRIMARIES_UNSPECIFIED,
                                     C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                             .withFields({C2F(mColorAspects, range)
                                                  .inRange(C2Color::RANGE_UNSPECIFIED,
                                                           C2Color::RANGE_OTHER),
                                          C2F(mColorAspects, primaries)
                                                  .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                                           C2Color::PRIMARIES_OTHER),
                                          C2F(mColorAspects, transfer)
                                                  .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                                           C2Color::TRANSFER_OTHER),
                                          C2F(mColorAspects, matrix)
                                                  .inRange(C2Color::MATRIX_UNSPECIFIED,
                                                           C2Color::MATRIX_OTHER)})
                             .withSetter(ColorAspectsSetter)
                             .build());

        addParameter(DefineParam(mCodedColorAspects, C2_PARAMKEY_VUI_COLOR_ASPECTS)
                             .withDefault(new C2StreamColorAspectsInfo::output(
                                     0u, C2Color::RANGE_LIMITED, C2Color::PRIMARIES_UNSPECIFIED,
                                     C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                             .withFields({C2F(mCodedColorAspects, range)
                                                  .inRange(C2Color::RANGE_UNSPECIFIED,
                                                           C2Color::RANGE_OTHER),
                                          C2F(mCodedColorAspects, primaries)
                                                  .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                                           C2Color::PRIMARIES_OTHER),
                                          C2F(mCodedColorAspects, transfer)
                                                  .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                                           C2Color::TRANSFER_OTHER),
                                          C2F(mCodedColorAspects, matrix)
                                                  .inRange(C2Color::MATRIX_UNSPECIFIED,
                                                           C2Color::MATRIX_OTHER)})
                             .withSetter(CodedColorAspectsSetter, mColorAspects)
                             .build());
        std::vector<uint32_t> pixelFormats = {
            HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED,
            HAL_PIXEL_FORMAT_YCBCR_420_888,
        };
        if (isHalPixelFormatSupported((AHardwareBuffer_Format)HAL_PIXEL_FORMAT_YCBCR_P010)) {
            pixelFormats.push_back(HAL_PIXEL_FORMAT_YCBCR_P010);
        }
        if (isHalPixelFormatSupported((AHardwareBuffer_Format)AHARDWAREBUFFER_FORMAT_YCbCr_P210)) {
            pixelFormats.push_back(AHARDWAREBUFFER_FORMAT_YCbCr_P210);
        }
        if (isHalPixelFormatSupported((AHardwareBuffer_Format)HAL_PIXEL_FORMAT_RGBA_1010102)) {
            pixelFormats.push_back(HAL_PIXEL_FORMAT_RGBA_1010102);
        }
        addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
                             .withDefault(new C2StreamPixelFormatInfo::input(
                                     0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
                             .withFields({C2F(mPixelFormat, value).oneOf({pixelFormats})})
                             .withSetter((Setter<decltype(*mPixelFormat)>::StrictValueWithNoDeps))
                             .build());
    }

    static C2R BitrateSetter(bool mayBlock, C2P<C2StreamBitrateInfo::output>& me) {
        (void)mayBlock;
        C2R res = C2R::Ok();
        if (me.v.value < 512000) {
            me.set().value = 512000;
        }
        return res;
    }

    static C2R SizeSetter(bool mayBlock, const C2P<C2StreamPictureSizeInfo::input>& oldMe,
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

    static C2R ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::output>& me,
                                  const C2P<C2StreamPictureSizeInfo::input>& size,
                                  const C2P<C2StreamFrameRateInfo::output>& frameRate,
                                  const C2P<C2StreamBitrateInfo::output>& bitrate) {
        (void)mayBlock;
        if (!me.F(me.v.profile).supportsAtAll(me.v.profile)) {
            me.set().profile = C2Config::PROFILE_APV_422_10;
        }
        if (!me.F(me.v.level).supportsAtAll(me.v.level)) {
            me.set().level = LEVEL_APV_1_BAND_0;
        }

        int32_t bandIdc = me.v.level <= LEVEL_APV_7_1_BAND_0 ? 0 :
                          me.v.level <= LEVEL_APV_7_1_BAND_1 ? 1 :
                          me.v.level <= LEVEL_APV_7_1_BAND_2 ? 2 : 3;

        me.set().level = decisionApvLevel(size.v.width, size.v.height, frameRate.v.value,
                                            (uint64_t)bitrate.v.value, bandIdc);
        return C2R::Ok();
    }

    static C2R ColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::input>& me) {
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

    static C2R CodedColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::output>& me,
                                       const C2P<C2StreamColorAspectsInfo::input>& coded) {
        (void)mayBlock;
        me.set().range = coded.v.range;
        me.set().primaries = coded.v.primaries;
        me.set().transfer = coded.v.transfer;
        me.set().matrix = coded.v.matrix;
        return C2R::Ok();
    }

    static C2Config::level_t decisionApvLevel(int32_t width, int32_t height, int32_t fps,
                                                    uint64_t bitrate, int32_t band) {
        C2Config::level_t level = C2Config::LEVEL_APV_1_BAND_0;
        struct LevelLimits {
            C2Config::level_t level;
            uint64_t samplesPerSec;
            uint64_t kbpsOfBand;
        };

        constexpr LevelLimits kLimitsBand0[] = {
            {LEVEL_APV_1_BAND_0, 3'041'280, 8'000},
            {LEVEL_APV_1_1_BAND_0, 6'082'560, 16'000},
            {LEVEL_APV_2_BAND_0, 15'667'200, 39'000},
            {LEVEL_APV_2_1_BAND_0, 31'334'400, 78'000},
            {LEVEL_APV_3_BAND_0, 66'846'720, 114'000},
            {LEVEL_APV_3_1_BAND_0, 133'693'440, 227'000},
            {LEVEL_APV_4_BAND_0, 265'420'800, 455'000},
            {LEVEL_APV_4_1_BAND_0, 530'841'600, 910'000},
            {LEVEL_APV_5_BAND_0, 1'061'683'200, 1'820'000},
            {LEVEL_APV_5_1_BAND_0, 2'123'366'400, 3'639'000},
            {LEVEL_APV_6_BAND_0, 4'777'574'400, 7'278'000},
            {LEVEL_APV_6_1_BAND_0, 8'493'465'600, 14'556'000},
            {LEVEL_APV_7_BAND_0, 16'986'931'200, 29'111'000},
            {LEVEL_APV_7_1_BAND_0, 33'973'862'400, 58'222'000},
        };

        constexpr LevelLimits kLimitsBand1[] = {
            {LEVEL_APV_1_BAND_1, 3'041'280, 11'000},
            {LEVEL_APV_1_1_BAND_1, 6'082'560, 21'000},
            {LEVEL_APV_2_BAND_1, 15'667'200, 54'000},
            {LEVEL_APV_2_1_BAND_1, 31'334'400, 108'00},
            {LEVEL_APV_3_BAND_1, 66'846'720, 159'000},
            {LEVEL_APV_3_1_BAND_1, 133'693'440, 317'000},
            {LEVEL_APV_4_BAND_1, 265'420'800, 637'000},
            {LEVEL_APV_4_1_BAND_1, 530'841'600, 1'274'000},
            {LEVEL_APV_5_BAND_1, 1'061'683'200, 2'548'000},
            {LEVEL_APV_5_1_BAND_1, 2'123'366'400, 5'095'000},
            {LEVEL_APV_6_BAND_1, 4'777'574'400, 10'189'000},
            {LEVEL_APV_6_1_BAND_1, 8'493'465'600, 20'378'000},
            {LEVEL_APV_7_BAND_1, 16'986'931'200, 40'756'000},
            {LEVEL_APV_7_1_BAND_1, 33'973'862'400, 81'511'000},
        };

        constexpr LevelLimits kLimitsBand2[] = {
            {LEVEL_APV_1_BAND_2, 3'041'280, 15'000},
            {LEVEL_APV_1_1_BAND_2, 6'082'560, 30'000},
            {LEVEL_APV_2_BAND_2, 15'667'200, 76'000},
            {LEVEL_APV_2_1_BAND_2, 31'334'400, 152'000},
            {LEVEL_APV_3_BAND_2, 66'846'720, 222'000},
            {LEVEL_APV_3_1_BAND_2, 133'693'440, 444'000},
            {LEVEL_APV_4_BAND_2, 265'420'800, 892'000},
            {LEVEL_APV_4_1_BAND_2, 530'841'600, 1'784'000},
            {LEVEL_APV_5_BAND_2, 1'061'683'200, 3'567'000},
            {LEVEL_APV_5_1_BAND_2, 2'123'366'400, 7'133'000},
            {LEVEL_APV_6_BAND_2, 4'777'574'400, 14'265'000},
            {LEVEL_APV_6_1_BAND_2, 8'493'465'600, 28'529'000},
            {LEVEL_APV_7_BAND_2, 16'986'931'200, 57'058'000},
            {LEVEL_APV_7_1_BAND_2, 33'973'862'400, 114'115'000},
        };

        constexpr LevelLimits kLimitsBand3[] = {
            {LEVEL_APV_1_BAND_3, 3'041'280, 23'000},
            {LEVEL_APV_1_1_BAND_3, 6'082'560, 45'000},
            {LEVEL_APV_2_BAND_3, 15'667'200, 114'000},
            {LEVEL_APV_2_1_BAND_3, 31'334'400, 227'000},
            {LEVEL_APV_3_BAND_3, 66'846'720, 333'000},
            {LEVEL_APV_3_1_BAND_3, 133'693'440, 666'000},
            {LEVEL_APV_4_BAND_3, 265'420'800, 1'338'000},
            {LEVEL_APV_4_1_BAND_3, 530'841'600, 2'675'000},
            {LEVEL_APV_5_BAND_3, 1'061'683'200, 5'350'000},
            {LEVEL_APV_5_1_BAND_3, 2'123'366'400, 10'699'000},
            {LEVEL_APV_6_BAND_3, 4'777'574'400, 21'397'000},
            {LEVEL_APV_6_1_BAND_3, 8'493'465'600, 42'793'000},
            {LEVEL_APV_7_BAND_3, 16'986'931'200, 85'586'000},
            {LEVEL_APV_7_1_BAND_3, 33'973'862'400, 171'172'000},
        };

        uint64_t samplesPerSec = (uint64_t) width * height * fps;
        if (band == 0) {
            for (const LevelLimits& limit : kLimitsBand0) {
                if (samplesPerSec <= limit.samplesPerSec && bitrate <= limit.kbpsOfBand * 1000) {
                    level = limit.level;
                    break;
                }
            }
        } else if (band == 1) {
            for (const LevelLimits& limit : kLimitsBand1) {
                if (samplesPerSec <= limit.samplesPerSec && bitrate <= limit.kbpsOfBand * 1000) {
                    level = limit.level;
                    break;
                }
            }
        } else if (band == 2) {
            for (const LevelLimits& limit : kLimitsBand2) {
                if (samplesPerSec <= limit.samplesPerSec && bitrate <= limit.kbpsOfBand * 1000) {
                    level = limit.level;
                    break;
                }
            }
        } else if (band == 3) {
            for (const LevelLimits& limit : kLimitsBand3) {
                if (samplesPerSec <= limit.samplesPerSec && bitrate <= limit.kbpsOfBand * 1000) {
                    level = limit.level;
                    break;
                }
            }
        } else {
            ALOGE("Invalid band_idc on calculte level");
        }

        return level;
    }

    uint32_t getProfile_l() const {
        int32_t profile = PROFILE_UNUSED;

        switch (mProfileLevel->profile) {
            case C2Config::PROFILE_APV_422_10:
                profile = 33;
                break;
            case C2Config::PROFILE_APV_422_12:
                profile = 44;
                break;
            case C2Config::PROFILE_APV_444_10:
                profile = 55;
                break;
            case C2Config::PROFILE_APV_444_12:
                profile = 66;
                break;
            case C2Config::PROFILE_APV_4444_10:
                profile = 77;
                break;
            case C2Config::PROFILE_APV_4444_12:
                profile = 88;
                break;
            case C2Config::PROFILE_APV_400_10:
                profile = 99;
                break;
            default:
                ALOGW("Unrecognized profile: %x", mProfileLevel->profile);
        }
        return profile;
    }

    uint32_t getLevel_l() const {
        int32_t level = LEVEL_UNUSED;

        // TODO: Add Band settings
        switch (mProfileLevel->level) {
            case C2Config::LEVEL_APV_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_BAND_3:
                level = 10;
                break;
            case C2Config::LEVEL_APV_1_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_1_BAND_3:
                level = 11;
                break;
            case C2Config::LEVEL_APV_2_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_BAND_3:
                level = 20;
                break;
            case C2Config::LEVEL_APV_2_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_1_BAND_3:
                level = 21;
                break;
            case C2Config::LEVEL_APV_3_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_BAND_3:
                level = 30;
                break;
            case C2Config::LEVEL_APV_3_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_1_BAND_3:
                level = 31;
                break;
            case C2Config::LEVEL_APV_4_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_BAND_3:
                level = 40;
                break;
            case C2Config::LEVEL_APV_4_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_1_BAND_3:
                level = 41;
                break;
            case C2Config::LEVEL_APV_5_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_BAND_3:
                level = 50;
                break;
            case C2Config::LEVEL_APV_5_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_1_BAND_3:
                level = 51;
                break;
            case C2Config::LEVEL_APV_6_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_BAND_3:
                level = 60;
                break;
            case C2Config::LEVEL_APV_6_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_1_BAND_3:
                level = 61;
                break;
            case C2Config::LEVEL_APV_7_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_BAND_3:
                level = 70;
                break;
            case C2Config::LEVEL_APV_7_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_1_BAND_3:
                level = 71;
                break;
            default:
                ALOGW("Unrecognized level: %x", mProfileLevel->level);
        }
        // Convert to APV level_idc according to APV spec
        return level * 3;
    }

    uint32_t getBandIdc_l() const {
        uint32_t bandIdc = 0;

        switch (mProfileLevel->level) {
            case C2Config::LEVEL_APV_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_1_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_BAND_0:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_1_BAND_0:
                bandIdc = 0;
                break;
            case C2Config::LEVEL_APV_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_1_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_BAND_1:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_1_BAND_1:
                bandIdc = 1;
                break;
            case C2Config::LEVEL_APV_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_1_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_BAND_2:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_1_BAND_2:
                bandIdc = 2;
                break;
            case C2Config::LEVEL_APV_1_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_1_1_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_2_1_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_3_1_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_4_1_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_5_1_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_6_1_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_BAND_3:
                [[fallthrough]];
            case C2Config::LEVEL_APV_7_1_BAND_3:
                bandIdc = 3;
                break;
            default:
                ALOGW("Unrecognized bandIdc through level: %x", mProfileLevel->level);
        }
        return bandIdc;
    }

    std::shared_ptr<C2StreamPictureSizeInfo::input> getSize_l() const { return mSize; }
    std::shared_ptr<C2StreamFrameRateInfo::output> getFrameRate_l() const { return mFrameRate; }
    std::shared_ptr<C2StreamBitrateInfo::output> getBitrate_l() const { return mBitrate; }
    std::shared_ptr<C2StreamBitrateModeTuning::output> getBitrateMode_l() const {
        return mBitrateMode;
    }
    std::shared_ptr<C2StreamQualityTuning::output> getQuality_l() const { return mQuality; }
    std::shared_ptr<C2StreamColorAspectsInfo::input> getColorAspects_l() const {
        return mColorAspects;
    }
    std::shared_ptr<C2StreamColorAspectsInfo::output> getCodedColorAspects_l() const {
        return mCodedColorAspects;
    }
    std::shared_ptr<C2StreamPictureQuantizationTuning::output> getPictureQuantization_l() const {
        return mPictureQuantization;
    }
    std::shared_ptr<C2StreamProfileLevelInfo::output> getProfileLevel_l() const {
        return mProfileLevel;
    }
    std::shared_ptr<C2StreamPixelFormatInfo::input> getPixelFormat_l() const {
        return mPixelFormat;
    }

  private:
    std::shared_ptr<C2StreamProfileLevelInfo::output> mProfileLevel;
    std::shared_ptr<C2StreamUsageTuning::input> mUsage;
    std::shared_ptr<C2StreamPictureSizeInfo::input> mSize;
    std::shared_ptr<C2StreamFrameRateInfo::output> mFrameRate;
    std::shared_ptr<C2StreamBitrateInfo::output> mBitrate;
    std::shared_ptr<C2StreamBitrateModeTuning::output> mBitrateMode;
    std::shared_ptr<C2StreamQualityTuning::output> mQuality;
    std::shared_ptr<C2StreamColorAspectsInfo::input> mColorAspects;
    std::shared_ptr<C2StreamColorAspectsInfo::output> mCodedColorAspects;
    std::shared_ptr<C2StreamPictureQuantizationTuning::output> mPictureQuantization;
    std::shared_ptr<C2StreamColorInfo::input> mColorFormat;
    std::shared_ptr<C2StreamPixelFormatInfo::input> mPixelFormat;
};

C2SoftApvEnc::C2SoftApvEnc(const char* name, c2_node_id_t id,
                           const std::shared_ptr<IntfImpl>& intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl),
      mColorFormat(OAPV_CF_PLANAR2),
      mStarted(false),
      mSignalledEos(false),
      mSignalledError(false),
      mOutBlock(nullptr) {
    resetEncoder();
}

C2SoftApvEnc::C2SoftApvEnc(const char* name, c2_node_id_t id,
                           const std::shared_ptr<C2ReflectorHelper>& helper)
    : C2SoftApvEnc(name, id, std::make_shared<IntfImpl>(helper)) {
}

C2SoftApvEnc::~C2SoftApvEnc() {
    onRelease();
}

c2_status_t C2SoftApvEnc::onInit() {
    return C2_OK;
}

c2_status_t C2SoftApvEnc::onStop() {
    return C2_OK;
}

void C2SoftApvEnc::onReset() {
    releaseEncoder();
    resetEncoder();
}

void C2SoftApvEnc::onRelease() {
    releaseEncoder();
}

c2_status_t C2SoftApvEnc::onFlush_sm() {
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

c2_status_t C2SoftApvEnc::resetEncoder() {
    ALOGV("reset");
    mInitEncoder = false;
    mStarted = false;
    mSignalledEos = false;
    mSignalledError = false;
    mBitDepth = 10;
    mMaxFrames = MAX_NUM_FRMS;
    mReceivedFrames = 0;
    mReceivedFirstFrame = false;
    mColorFormat = OAPV_CF_PLANAR2;
    memset(&mInputFrames, 0, sizeof(mInputFrames));
    memset(&mReconFrames, 0, sizeof(mReconFrames));
    return C2_OK;
}

c2_status_t C2SoftApvEnc::releaseEncoder() {
    for (int32_t i = 0; i < MAX_NUM_FRMS; i++) {
        if (mInputFrames.frm[i].imgb != nullptr) {
            imgb_release(mInputFrames.frm[i].imgb);
            mInputFrames.frm[i].imgb = nullptr;
        }
    }

    if (mBitstreamBuf) {
        std::free(mBitstreamBuf);
        mBitstreamBuf = nullptr;
    }
    return C2_OK;
}

c2_status_t C2SoftApvEnc::drain(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool) {
    return drainInternal(drainMode, pool, nullptr);
}

void C2SoftApvEnc::showEncoderParams(oapve_cdesc_t* cdsc) {
    std::string title = "APV encoder params:";
    ALOGD("%s width = %d, height = %d", title.c_str(), cdsc->param[0].w, cdsc->param[0].h);
    ALOGD("%s FrameRate = %f", title.c_str(),
          (double)cdsc->param[0].fps_num / cdsc->param[0].fps_den);
    ALOGD("%s BitRate = %d Kbps", title.c_str(), cdsc->param[0].bitrate);
    if (mQuality > 0) {
        ALOGD("%s Quality = %s", title.c_str(),
            mQuality->value <= 70 ? "LQ" : mQuality->value <= 80 ? "SQ"
                : mQuality->value <= 90 ? "HQ" : "UQ");
    }
    ALOGD("%s QP = %d", title.c_str(), cdsc->param[0].qp);
    ALOGD("%s profile_idc = %d, level_idc = %d, band_idc = %d", title.c_str(),
          cdsc->param[0].profile_idc, cdsc->param[0].level_idc / 3, cdsc->param[0].band_idc);
    ALOGD("%s Bitrate Mode: %d", title.c_str(), cdsc->param[0].rc_type);
    ALOGD("%s mColorAspects primaries: %d, transfer: %d, matrix: %d, range: %d", title.c_str(),
          mColorAspects->primaries, mColorAspects->transfer, mColorAspects->matrix,
          mColorAspects->range);
    ALOGD("%s mCodedColorAspects primaries: %d, transfer: %d, matrix: %d, range: %d", title.c_str(),
          mCodedColorAspects->primaries, mCodedColorAspects->transfer, mCodedColorAspects->matrix,
          mCodedColorAspects->range);
    ALOGD("%s Input color format: %s", title.c_str(),
          mColorFormat == OAPV_CF_YCBCR422 ? "YUV422P10LE" : "P210");
    ALOGD("%s max_num_frms: %d", title.c_str(), cdsc->max_num_frms);
}

c2_status_t C2SoftApvEnc::initEncoder() {
    if (mInitEncoder) {
        return C2_OK;
    }
    ALOGV("initEncoder");

    mSize = mIntf->getSize_l();
    mFrameRate = mIntf->getFrameRate_l();
    mBitrate = mIntf->getBitrate_l();
    mBitrateMode = mIntf->getBitrateMode_l();
    mQuality = mIntf->getQuality_l();
    mColorAspects = mIntf->getColorAspects_l();
    mCodedColorAspects = mIntf->getCodedColorAspects_l();
    mProfileLevel = mIntf->getProfileLevel_l();
    mPixelFormat = mIntf->getPixelFormat_l();
    mCodecDesc = std::make_unique<oapve_cdesc_t>();
    if (mCodecDesc == nullptr) {
        ALOGE("Allocate ctx failed");
        return C2_NO_INIT;
    }
    mCodecDesc->max_bs_buf_size = kMaxBitstreamBufSize;
    mCodecDesc->max_num_frms = MAX_NUM_FRMS;
    // TODO: Bound parameters to CPU count
    mCodecDesc->threads = 4;

    int32_t ret = C2_OK;
    /* set params */
    for (int32_t i = 0; i < mMaxFrames; i++) {
        oapve_param_t* param = &mCodecDesc->param[i];
        ret = oapve_param_default(param);
        if (OAPV_FAILED(ret)) {
            ALOGE("cannot set default parameter");
            return C2_NO_INIT;
        }
        setParams(*param);
    }

    showEncoderParams(mCodecDesc.get());

    /* create encoder */
    mEncoderId = oapve_create(mCodecDesc.get(), NULL);
    if (mEncoderId == NULL) {
        ALOGE("cannot create APV encoder");
        return C2_CORRUPTED;
    }

    /* create metadata */
    mMetaId = oapvm_create(&ret);
    if (mMetaId == NULL) {
        ALOGE("cannot create APV metadata");
        return C2_NO_MEMORY;
    }

    /* create image buffers */
    for (int32_t i = 0; i < mMaxFrames; i++) {
        if (mBitDepth == 10) {
            mInputFrames.frm[i].imgb = imgb_create(mCodecDesc->param[0].w, mCodecDesc->param[0].h,
                                                  OAPV_CS_SET(mColorFormat, mBitDepth, 0));
            mReconFrames.frm[i].imgb = nullptr;
        } else {
            mInputFrames.frm[i].imgb = imgb_create(mCodecDesc->param[0].w, mCodecDesc->param[0].h,
                                                  OAPV_CS_SET(mColorFormat, 10, 0));
            mReconFrames.frm[i].imgb = nullptr;
        }
    }

    /* allocate bitstream buffer */
    mBitstreamBuf = new unsigned char[kMaxBitstreamBufSize];
    if (mBitstreamBuf == nullptr) {
        ALOGE("cannot allocate bitstream buffer, size= %d", kMaxBitstreamBufSize);
        return C2_NO_MEMORY;
    }

    mStarted = true;
    mInitEncoder = true;
    return C2_OK;
}

void C2SoftApvEnc::setParams(oapve_param_t& param) {
    param.w = mSize->width;
    param.h = mSize->height;
    param.fps_num = (int)(mFrameRate->value * 100);
    param.fps_den = 100;
    param.bitrate = (int)(mBitrate->value / 1000);
    param.rc_type = OAPV_RC_ABR;

    param.qp = OAPVE_PARAM_QP_AUTO;
    param.band_idc = mIntf->getBandIdc_l();
    param.profile_idc = mIntf->getProfile_l();
    param.level_idc = mIntf->getLevel_l();

    if (android::media::swcodec::flags::apv_software_codec_cq()) {
        if (mBitrateMode->value == C2Config::BITRATE_VARIABLE &&
            mQuality->value == 0 && mBitrate->value == 512000) {
            mQuality->value = 90;
        }

        if (mQuality->value > 0) {
            int32_t family = mQuality->value <= 70 ? OAPV_FAMILY_422_LQ :
                        mQuality->value <= 80 ? OAPV_FAMILY_422_SQ :
                        mQuality->value <= 90 ? OAPV_FAMILY_422_HQ :
                        OAPV_FAMILY_444_UQ;
            int32_t familyBitrate;
            oapve_family_bitrate(family, param.w, param.h,
                        param.fps_num, param.fps_den, &familyBitrate);
            param.bitrate = familyBitrate;
            param.band_idc = family - 1;
            param.level_idc = OAPVE_PARAM_LEVEL_IDC_AUTO;
        }
    }

    mColorAspects = mIntf->getColorAspects_l();
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

    int32_t isoPrimaries, isoTransfer, isoMatrix;
    bool isoFullRange;
    ColorUtils::convertCodecColorAspectsToIsoAspects(sfAspects,
        &isoPrimaries, &isoTransfer, &isoMatrix, &isoFullRange);
    param.color_primaries = isoPrimaries;
    param.transfer_characteristics = isoTransfer;
    param.matrix_coefficients = isoMatrix;
    param.full_range_flag = isoFullRange;

    if (mColorAspects->primaries != C2Color::PRIMARIES_UNSPECIFIED ||
            mColorAspects->transfer != C2Color::TRANSFER_UNSPECIFIED ||
            mColorAspects->matrix != C2Color::MATRIX_UNSPECIFIED ||
            mColorAspects->range != C2Color::RANGE_UNSPECIFIED) {
        param.color_description_present_flag = 1;
    }
}

c2_status_t C2SoftApvEnc::setEncodeArgs(oapv_frms_t* inputFrames, const C2GraphicView* const input,
                                        uint64_t workIndex) {
    if (input->width() < mSize->width || input->height() < mSize->height) {
        /* Expect width height to be configured */
        ALOGW("unexpected Capacity Aspect %d(%d) x %d(%d)", input->width(), mSize->width,
              input->height(), mSize->height);
        return C2_BAD_VALUE;
    }
    const C2PlanarLayout& layout = input->layout();
    uint8_t* yPlane = const_cast<uint8_t*>(input->data()[C2PlanarLayout::PLANE_Y]);
    uint8_t* uPlane = const_cast<uint8_t*>(input->data()[C2PlanarLayout::PLANE_U]);
    uint8_t* vPlane = const_cast<uint8_t*>(input->data()[C2PlanarLayout::PLANE_V]);

    uint32_t width = mSize->width;
    uint32_t height = mSize->height;

    /* width and height must be even */
    if (width & 1u || height & 1u) {
        ALOGW("height(%u) and width(%u) must both be even", height, width);
        return C2_BAD_VALUE;
    }

    /* Set num frames */
    inputFrames->num_frms = MAX_NUM_FRMS;
    inputFrames->frm[mReceivedFrames].group_id = 1;
    inputFrames->frm[mReceivedFrames].pbu_type = OAPV_PBU_TYPE_PRIMARY_FRAME;

    switch (layout.type) {
        case C2PlanarLayout::TYPE_RGB: {
            uint16_t *dstY  = (uint16_t*)inputFrames->frm[0].imgb->a[0];
            uint16_t *dstUV = (uint16_t*)inputFrames->frm[0].imgb->a[1];
            size_t dstYStride = inputFrames->frm[0].imgb->s[0] / 2;
            size_t dstUVStride = inputFrames->frm[0].imgb->s[1] / 2;
            convertRGBToP210(dstY, dstUV, (uint32_t*)(input->data()[0]),
                                        layout.planes[layout.PLANE_Y].rowInc / 4,
                                        dstYStride, dstUVStride, width, height,
                                        mColorAspects->matrix, mColorAspects->range);
            break;
        }
        case C2PlanarLayout::TYPE_RGBA: {
            [[fallthrough]];
        }
        case C2PlanarLayout::TYPE_YUVA: {
            ALOGV("Convert from ABGR2101010 to P210");
            if (mColorFormat == OAPV_CF_PLANAR2) {
                uint16_t *dstY, *dstUV;
                dstY = (uint16_t*)inputFrames->frm[0].imgb->a[0];
                dstUV = (uint16_t*)inputFrames->frm[0].imgb->a[1];
                size_t dstYStride = inputFrames->frm[0].imgb->s[0] / 2;
                size_t dstUVStride = inputFrames->frm[0].imgb->s[1] / 2;
                convertRGBA1010102ToP210(dstY, dstUV, (uint32_t*)(input->data()[0]),
                                                layout.planes[layout.PLANE_Y].rowInc / 4,
                                                dstYStride, dstUVStride, width, height,
                                                mColorAspects->matrix, mColorAspects->range);
                break;
            } else {
                ALOGE("Not supported color format. %d", mColorFormat);
                return C2_BAD_VALUE;
            }
        }
        case C2PlanarLayout::TYPE_YUV: {
            if (IsP010(*input)) {
                ALOGV("Convert from P010 to P210");
                if (mColorFormat == OAPV_CF_PLANAR2) {
                    uint16_t *srcY  = (uint16_t*)(input->data()[0]);
                    uint16_t *srcUV = (uint16_t*)(input->data()[1]);
                    uint16_t *dstY  = (uint16_t*)inputFrames->frm[0].imgb->a[0];
                    uint16_t *dstUV = (uint16_t*)inputFrames->frm[0].imgb->a[1];
                    size_t dstYStride = inputFrames->frm[0].imgb->s[0] / 2;
                    size_t dstUVStride = inputFrames->frm[0].imgb->s[1] / 2;
                    convertP010ToP210(dstY, dstUV, srcY, srcUV,
                                      layout.planes[layout.PLANE_Y].rowInc / 2,
                                      layout.planes[layout.PLANE_U].rowInc / 2,
                                      dstYStride, dstUVStride, width, height);
                } else {
                    ALOGE("Not supported color format. %d", mColorFormat);
                    return C2_BAD_VALUE;
                }
            } else if (IsP210(*input)) {
                ALOGV("Convert from P210 to P210");
                if (mColorFormat == OAPV_CF_PLANAR2) {
                    uint16_t *srcY  = (uint16_t*)(input->data()[0]);
                    uint16_t *srcUV = (uint16_t*)(input->data()[1]);
                    uint16_t *dstY  = (uint16_t*)inputFrames->frm[0].imgb->a[0];
                    uint16_t *dstUV = (uint16_t*)inputFrames->frm[0].imgb->a[1];
                    size_t srcYStride = layout.planes[layout.PLANE_Y].rowInc / 2;
                    size_t srcUVStride = layout.planes[layout.PLANE_U].rowInc / 2;
                    size_t dstYStride = inputFrames->frm[0].imgb->s[0] / 2;
                    size_t dstUVStride = inputFrames->frm[0].imgb->s[1] / 2;

                    for (size_t y = 0; y < height; ++y) {
                        std::memcpy(dstY, srcY, width * sizeof(uint16_t));
                        dstY += dstYStride;
                        srcY += srcYStride;
                    }

                    for (size_t y = 0; y < height; ++y) {
                        std::memcpy(dstUV, srcUV, width * sizeof(uint16_t));
                        srcUV += srcUVStride;
                        dstUV += dstUVStride;
                    }
                } else {
                    ALOGE("Not supported color format. %d", mColorFormat);
                    return C2_BAD_VALUE;
                }
            } else if (IsNV12(*input) || IsNV21(*input)) {
                ALOGV("Convert from NV12 to P210");
                uint8_t  *srcY  = (uint8_t*)input->data()[0];
                uint8_t  *srcUV = (uint8_t*)input->data()[1];
                uint16_t *dstY  = (uint16_t*)inputFrames->frm[0].imgb->a[0];
                uint16_t *dstUV = (uint16_t*)inputFrames->frm[0].imgb->a[1];
                size_t dstYStride = inputFrames->frm[0].imgb->s[0] / 2;
                size_t dstUVStride = inputFrames->frm[0].imgb->s[1] / 2;
                convertSemiPlanar8ToP210(dstY, dstUV, srcY, srcUV,
                                         layout.planes[layout.PLANE_Y].rowInc,
                                         layout.planes[layout.PLANE_U].rowInc,
                                         dstYStride, dstUVStride,
                                         width, height, CONV_FORMAT_I420, IsNV12(*input));
            } else if (IsI420(*input)) {
                ALOGV("Convert from I420 to P210");
                uint8_t  *srcY  = (uint8_t*)input->data()[0];
                uint8_t  *srcU  = (uint8_t*)input->data()[1];
                uint8_t  *srcV  = (uint8_t*)input->data()[2];
                uint16_t *dstY  = (uint16_t*)inputFrames->frm[0].imgb->a[0];
                uint16_t *dstUV = (uint16_t*)inputFrames->frm[0].imgb->a[1];
                size_t dstYStride = inputFrames->frm[0].imgb->s[0] / 2;
                size_t dstUVStride = inputFrames->frm[0].imgb->s[1] / 2;
                convertPlanar8ToP210(dstY, dstUV, srcY, srcU, srcV,
                                        layout.planes[C2PlanarLayout::PLANE_Y].rowInc,
                                        layout.planes[C2PlanarLayout::PLANE_U].rowInc,
                                        layout.planes[C2PlanarLayout::PLANE_V].rowInc,
                                        dstYStride, dstUVStride,
                                        width, height,
                                        CONV_FORMAT_I420);

            } else {
                ALOGE("Not supported color format. %d", mColorFormat);
                return C2_BAD_VALUE;
            }
            break;
        }

        default:
            ALOGE("Unrecognized plane type: %d", layout.type);
            return C2_BAD_VALUE;
    }

    return C2_OK;
}

void C2SoftApvEnc::finishWork(uint64_t workIndex, const std::unique_ptr<C2Work>& work,
                              const std::shared_ptr<C2BlockPool>& pool, oapv_bitb_t* bitb,
                              oapve_stat_t* stat) {
    std::shared_ptr<C2LinearBlock> block;
    C2MemoryUsage usage = {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};
    c2_status_t status = pool->fetchLinearBlock(stat->write, usage, &block);
    if (C2_OK != status) {
        ALOGE("fetchLinearBlock for Output failed with status 0x%x", status);
        mSignalledError = true;
        work->result = status;
        work->workletsProcessed = 1u;
        return;
    }

    C2WriteView wView = block->map().get();
    if (C2_OK != wView.error()) {
        ALOGE("write view map failed with status 0x%x", wView.error());
        mSignalledError = true;
        work->result = wView.error();
        work->workletsProcessed = 1u;
        return;
    }
    if ((!mReceivedFirstFrame)) {
        createCsdData(work, bitb, stat->write);
        mReceivedFirstFrame = true;
    }

    memcpy(wView.data(), bitb->addr, stat->write);
    std::shared_ptr<C2Buffer> buffer = createLinearBuffer(block, 0, stat->write);

    /* All frames are SYNC FRAME */
    buffer->setInfo(std::make_shared<C2StreamPictureTypeMaskInfo::output>(0u /* stream id */,
                                                                          C2Config::SYNC_FRAME));

    auto fillWork = [buffer](const std::unique_ptr<C2Work>& work) {
        work->worklets.front()->output.flags = (C2FrameData::flags_t)0;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.buffers.push_back(buffer);
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
    };
    if (work && c2_cntr64_t(workIndex) == work->input.ordinal.frameIndex) {
        fillWork(work);
        if (mSignalledEos) {
            work->worklets.front()->output.flags = C2FrameData::FLAG_END_OF_STREAM;
        }
    } else {
        finish(workIndex, fillWork);
    }
}

void C2SoftApvEnc::createCsdData(const std::unique_ptr<C2Work>& work,
                                 oapv_bitb_t* bitb,
                                 uint32_t encodedSize) {
    if (encodedSize < 35) {
        ALOGE("the first frame size is too small, so no csd data will be created.");
        return;
    }
    ABitReader reader((uint8_t*)bitb->addr, encodedSize);

    uint8_t number_of_configuration_entry = 0;
    uint8_t pbu_type = 0;
    uint8_t number_of_frame_info = 0;
    bool color_description_present_flag = false;
    bool capture_time_distance_ignored = false;
    uint8_t profile_idc = 0;
    uint8_t level_idc = 0;
    uint8_t band_idc = 0;
    uint32_t frame_width = 0;
    uint32_t frame_height = 0;
    uint8_t chroma_format_idc = 0;
    uint8_t bit_depth_minus8 = 0;
    uint8_t capture_time_distance = 0;
    uint8_t color_primaries = 0;
    uint8_t transfer_characteristics = 0;
    uint8_t full_range_flag = 0;
    uint8_t matrix_coefficients = 0;

    /* pbu_header() */
    reader.skipBits(32);           // pbu_size
    reader.skipBits(32);           // signature
    reader.skipBits(32);           // currReadSize
    pbu_type = reader.getBits(8);  // pbu_type
    reader.skipBits(16);           // group_id
    reader.skipBits(8);            // reserved_zero_8bits

    /* frame info() */
    profile_idc = reader.getBits(8);            // profile_idc
    level_idc = reader.getBits(8);              // level_idc
    band_idc = reader.getBits(3);               // band_idc
    reader.skipBits(5);                         // reserved_zero_5bits
    frame_width = reader.getBits(24);           // width
    frame_height = reader.getBits(24);          // height
    chroma_format_idc = reader.getBits(4);      // chroma_format_idc
    bit_depth_minus8 = reader.getBits(4);       // bit_depth
    capture_time_distance = reader.getBits(8);  // capture_time_distance
    reader.skipBits(8);                         // reserved_zero_8bits

    /* frame header() */
    reader.skipBits(8);  // reserved_zero_8bit
    color_description_present_flag = reader.getBits(1);  // color_description_present_flag
    if (color_description_present_flag) {
        color_primaries = reader.getBits(8);           // color_primaries
        transfer_characteristics = reader.getBits(8);  // transfer_characteristics
        matrix_coefficients = reader.getBits(8);       // matrix_coefficients
        full_range_flag = reader.getBits(1);           // full_range_flag
        reader.skipBits(7);                            // reserved_zero_7bits
    }

    number_of_configuration_entry = 1;  // The real-time encoding on the device is assumed to be 1.
    number_of_frame_info = 1;  // The real-time encoding on the device is assumed to be 1.

    std::vector<uint8_t> csdData;

    csdData.push_back((uint8_t)0x1);
    csdData.push_back(number_of_configuration_entry);

    for (uint8_t i = 0; i < number_of_configuration_entry; i++) {
        csdData.push_back(pbu_type);
        csdData.push_back(number_of_frame_info);
        for (uint8_t j = 0; j < number_of_frame_info; j++) {
            csdData.push_back((uint8_t)((color_description_present_flag << 1) |
                                      capture_time_distance_ignored));
            csdData.push_back(profile_idc);
            csdData.push_back(level_idc);
            csdData.push_back(band_idc);
            csdData.push_back((uint8_t)((frame_width >> 24) & 0xff));
            csdData.push_back((uint8_t)((frame_width >> 16) & 0xff));
            csdData.push_back((uint8_t)((frame_width >> 8) & 0xff));
            csdData.push_back((uint8_t)(frame_width & 0xff));
            csdData.push_back((uint8_t)((frame_height >> 24) & 0xff));
            csdData.push_back((uint8_t)((frame_height >> 16) & 0xff));
            csdData.push_back((uint8_t)((frame_height >> 8) & 0xff));
            csdData.push_back((uint8_t)(frame_height & 0xff));
            csdData.push_back((uint8_t)(((chroma_format_idc << 4) & 0xf0) |
                                      (bit_depth_minus8 & 0xf)));
            csdData.push_back((uint8_t)(capture_time_distance));
            if (color_description_present_flag) {
                csdData.push_back(color_primaries);
                csdData.push_back(transfer_characteristics);
                csdData.push_back(matrix_coefficients);
                csdData.push_back(full_range_flag << 7);
            }
        }
    }

    std::unique_ptr<C2StreamInitDataInfo::output> csd =
        C2StreamInitDataInfo::output::AllocUnique(csdData.size(), 0u);
    if (!csd) {
        ALOGE("CSD allocation failed");
        mSignalledError = true;
        work->result = C2_NO_MEMORY;
        work->workletsProcessed = 1u;
        return;
    }

    memcpy(csd->m.value, csdData.data(), csdData.size());
    work->worklets.front()->output.configUpdate.push_back(std::move(csd));
}

c2_status_t C2SoftApvEnc::drainInternal(uint32_t drainMode,
                                        const std::shared_ptr<C2BlockPool>& pool,
                                        const std::unique_ptr<C2Work>& work) {
    fillEmptyWork(work);
    return C2_OK;
}

void C2SoftApvEnc::process(const std::unique_ptr<C2Work>& work,
                           const std::shared_ptr<C2BlockPool>& pool) {
    c2_status_t error;
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    work->worklets.front()->output.flags = work->input.flags;

    nsecs_t timeDelay = 0;
    uint64_t workIndex = work->input.ordinal.frameIndex.peekull();

    mSignalledEos = false;
    mOutBlock = nullptr;

    if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
        ALOGV("Got FLAG_END_OF_STREAM");
        mSignalledEos = true;
    }

    /* Initialize encoder if not already initialized */
    if (initEncoder() != C2_OK) {
        ALOGE("Failed to initialize encoder");
        mSignalledError = true;
        work->result = C2_CORRUPTED;
        work->workletsProcessed = 1u;
        ALOGE("[%s] Failed to make Codec context", __func__);
        return;
    }
    if (mSignalledError) {
        ALOGE("[%s] Received signalled error", __func__);
        return;
    }

    if (mSignalledEos) {
        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
        return;
    }

    std::shared_ptr<C2GraphicView> view;
    std::shared_ptr<C2Buffer> inputBuffer = nullptr;
    if (!work->input.buffers.empty()) {
        inputBuffer = work->input.buffers[0];
        view = std::make_shared<C2GraphicView>(
                inputBuffer->data().graphicBlocks().front().map().get());
        if (view->error() != C2_OK) {
            ALOGE("graphic view map err = %d", view->error());
            work->workletsProcessed = 1u;
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

    if (!inputBuffer) {
        fillEmptyWork(work);
        return;
    }

    oapve_stat_t stat;
    auto outBufferSize =
            mCodecDesc->param[mReceivedFrames].w * mCodecDesc->param[mReceivedFrames].h * 4;
    if (!mOutBlock) {
        C2MemoryUsage usage = {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};
        c2_status_t err = pool->fetchLinearBlock(outBufferSize, usage, &mOutBlock);
        if (err != C2_OK) {
            work->result = err;
            work->workletsProcessed = 1u;
            ALOGE("fetchLinearBlock has failed. err = %d", err);
            return;
        }
    }

    C2WriteView wView = mOutBlock->map().get();
    if (wView.error() != C2_OK) {
        work->result = wView.error();
        work->workletsProcessed = 1u;
        return;
    }

    view->setCrop_be(C2Rect(mSize->width, mSize->height));

    error = setEncodeArgs(&mInputFrames, view.get(), workIndex);
    if (error != C2_OK) {
        ALOGE("setEncodeArgs has failed. err = %d", error);
        mSignalledError = true;
        work->result = error;
        work->workletsProcessed = 1u;
        return;
    }

    if (++mReceivedFrames < mMaxFrames) {
        return;
    }
    mReceivedFrames = 0;

    std::shared_ptr<oapv_bitb_t> bits = std::make_shared<oapv_bitb_t>();
    std::memset(mBitstreamBuf, 0, kMaxBitstreamBufSize);
    bits->addr = mBitstreamBuf;
    bits->bsize = kMaxBitstreamBufSize;
    bits->err = C2_OK;

    if (mInputFrames.frm[0].imgb) {
        int32_t status =
                oapve_encode(mEncoderId, &mInputFrames, mMetaId, bits.get(), &stat, &mReconFrames);
        if (status != C2_OK) {
            ALOGE("oapve_encode has failed. err = %d", status);
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            work->workletsProcessed = 1u;
            return;
        }
    } else if (!mSignalledEos) {
        fillEmptyWork(work);
    }
    finishWork(workIndex, work, pool, bits.get(), &stat);
}

class C2SoftApvEncFactory : public C2ComponentFactory {
  public:
    C2SoftApvEncFactory()
        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
                  GetCodec2PlatformComponentStore()->getParamReflector())) {}

    virtual c2_status_t createComponent(c2_node_id_t id,
                                        std::shared_ptr<C2Component>* const component,
                                        std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
                new C2SoftApvEnc(COMPONENT_NAME, id,
                                 std::make_shared<C2SoftApvEnc::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    c2_status_t createInterface(c2_node_id_t id,
                                std::shared_ptr<C2ComponentInterface>* const interface,
                                std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
                new SimpleInterface<C2SoftApvEnc::IntfImpl>(
                        COMPONENT_NAME, id, std::make_shared<C2SoftApvEnc::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    ~C2SoftApvEncFactory() override = default;

  private:
    std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

__attribute__((cfi_canonical_jump_table)) extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    if (!android::media::swcodec::flags::apv_software_codec()) {
        ALOGV("APV SW Codec is not enabled");
        return nullptr;
    }

    bool enabled = isAtLeastRelease(36, "Baklava");
    ALOGD("isAtLeastRelease(36, Baklava) says enable: %s", enabled ? "yes" : "no");
    if (!enabled) {
        return nullptr;
    }

    return new ::android::C2SoftApvEncFactory();
}

__attribute__((cfi_canonical_jump_table)) extern "C" void DestroyCodec2Factory(
        ::C2ComponentFactory* factory) {
    delete factory;
}
