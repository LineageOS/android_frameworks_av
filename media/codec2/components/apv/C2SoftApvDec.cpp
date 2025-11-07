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
#define LOG_TAG "C2SoftApvDec"
#include <log/log.h>

#include <android_media_swcodec_flags.h>

#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>

#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <Codec2BufferUtils.h>
#include <Codec2CommonUtils.h>
#include <Codec2Mapper.h>
#include <SimpleC2Interface.h>
#include "C2SoftApvDec.h"
#include "isAtLeastRelease.h"

#include <cutils/properties.h>

const char* MEDIA_MIMETYPE_VIDEO_APV = "video/apv";

#define MAX_NUM_FRMS (1)  // supports only 1-frame output
#define FRM_IDX (0)       // supports only 1-frame output
#define MAX_SUPPORTED_WIDTH (4096)
#define MAX_SUPPORTED_HEIGHT (4096)
// check generic frame or not
#define IS_NON_AUX_FRM(frm)                              \
    (((frm)->pbu_type == OAPV_PBU_TYPE_PRIMARY_FRAME) || \
     ((frm)->pbu_type == OAPV_PBU_TYPE_NON_PRIMARY_FRAME))
// check auxiliary frame or not
#define IS_AUX_FRM(frm) (!(IS_NON_AUX_FRM(frm)))
#define OUTPUT_CSP_NATIVE (0)
#define OUTPUT_CSP_P210 (1)
#define CLIP3(min, v, max) (((v) < (min)) ? (min) : (((max) > (v)) ? (v) : (max)))

namespace android {
namespace {
constexpr char COMPONENT_NAME[] = "c2.android.apv.decoder";
constexpr uint32_t kDefaultOutputDelay = 8;
constexpr uint32_t kMaxOutputDelay = 16;
constexpr size_t kMinInputBufferSize = 2 * 1024 * 1024;
constexpr int32_t kDefaultSoftApvDecNumThreads = 1;
}  // namespace

class C2SoftApvDec::IntfImpl : public SimpleInterface<void>::BaseParams {
  public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper>& helper)
        : SimpleInterface<void>::BaseParams(helper, COMPONENT_NAME, C2Component::KIND_DECODER,
                                            C2Component::DOMAIN_VIDEO, MEDIA_MIMETYPE_VIDEO_APV) {
        noPrivateBuffers();  // TODO: account for our buffers here.
        noInputReferences();
        noOutputReferences();
        noInputLatency();
        noTimeStretch();

        addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                             .withConstValue(new C2ComponentAttributesSetting(
                                     C2Component::ATTRIB_IS_TEMPORAL))
                             .build());

        addParameter(DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
                             .withDefault(new C2StreamPictureSizeInfo::output(0u, 320, 240))
                             .withFields({
                                     C2F(mSize, width).inRange(2, MAX_SUPPORTED_WIDTH),
                                     C2F(mSize, height).inRange(2, MAX_SUPPORTED_HEIGHT),
                             })
                             .withSetter(SizeSetter)
                             .build());

        addParameter(
                DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                        .withDefault(new C2StreamProfileLevelInfo::input(
                                0u, C2Config::PROFILE_APV_422_10))
                        .withFields(
                                {C2F(mProfileLevel, profile).oneOf({C2Config::PROFILE_APV_422_10}),
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
                                                 })})
                        .withSetter(ProfileLevelSetter, mSize)
                        .build());

        mHdr10PlusInfoInput = C2StreamHdr10PlusInfo::input::AllocShared(0);
        addParameter(DefineParam(mHdr10PlusInfoInput, C2_PARAMKEY_INPUT_HDR10_PLUS_INFO)
                             .withDefault(mHdr10PlusInfoInput)
                             .withFields({
                                     C2F(mHdr10PlusInfoInput, m.value).any(),
                             })
                             .withSetter(Hdr10PlusInfoInputSetter)
                             .build());

        mHdr10PlusInfoOutput = C2StreamHdr10PlusInfo::output::AllocShared(0);
        addParameter(DefineParam(mHdr10PlusInfoOutput, C2_PARAMKEY_OUTPUT_HDR10_PLUS_INFO)
                             .withDefault(mHdr10PlusInfoOutput)
                             .withFields({
                                     C2F(mHdr10PlusInfoOutput, m.value).any(),
                             })
                             .withSetter(Hdr10PlusInfoOutputSetter)
                             .build());

        // default static info
        C2HdrStaticMetadataStruct defaultStaticInfo{};
        helper->addStructDescriptors<C2MasteringDisplayColorVolumeStruct, C2ColorXyStruct>();
        addParameter(
                DefineParam(mHdrStaticInfo, C2_PARAMKEY_HDR_STATIC_INFO)
                        .withDefault(new C2StreamHdrStaticInfo::output(0u, defaultStaticInfo))
                        .withFields({C2F(mHdrStaticInfo, mastering.red.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.red.y).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.green.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.green.y).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.blue.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.blue.y).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.white.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.white.x).inRange(0, 1),
                                     C2F(mHdrStaticInfo, mastering.maxLuminance).inRange(0, 65535),
                                     C2F(mHdrStaticInfo, mastering.minLuminance).inRange(0, 6.5535),
                                     C2F(mHdrStaticInfo, maxCll).inRange(0, 0XFFFF),
                                     C2F(mHdrStaticInfo, maxFall).inRange(0, 0XFFFF)})
                        .withSetter(HdrStaticInfoSetter)
                        .build());

        addParameter(DefineParam(mMaxSize, C2_PARAMKEY_MAX_PICTURE_SIZE)
                             .withDefault(new C2StreamMaxPictureSizeTuning::output(0u, 320, 240))
                             .withFields({
                                     C2F(mSize, width).inRange(2, 4096, 2),
                                     C2F(mSize, height).inRange(2, 4096, 2),
                             })
                             .withSetter(MaxPictureSizeSetter, mSize)
                             .build());

        addParameter(
                DefineParam(mMaxInputSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                        .withDefault(new C2StreamMaxBufferSizeInfo::input(0u, kMinInputBufferSize))
                        .withFields({
                                C2F(mMaxInputSize, value).any(),
                        })
                        .calculatedAs(MaxInputSizeSetter, mMaxSize)
                        .build());

        C2ChromaOffsetStruct locations[1] = {C2ChromaOffsetStruct::ITU_YUV_420_0()};
        std::shared_ptr<C2StreamColorInfo::output> defaultColorInfo =
                C2StreamColorInfo::output::AllocShared(1u, 0u, 8u /* bitDepth */, C2Color::YUV_420);
        memcpy(defaultColorInfo->m.locations, locations, sizeof(locations));

        defaultColorInfo = C2StreamColorInfo::output::AllocShared(
                {C2ChromaOffsetStruct::ITU_YUV_420_0()}, 0u, 8u /* bitDepth */, C2Color::YUV_420);
        helper->addStructDescriptors<C2ChromaOffsetStruct>();
        addParameter(DefineParam(mColorInfo, C2_PARAMKEY_CODED_COLOR_INFO)
                             .withConstValue(defaultColorInfo)
                             .build());

        addParameter(DefineParam(mDefaultColorAspects, C2_PARAMKEY_DEFAULT_COLOR_ASPECTS)
                             .withDefault(new C2StreamColorAspectsTuning::output(
                                     0u, C2Color::RANGE_UNSPECIFIED, C2Color::PRIMARIES_UNSPECIFIED,
                                     C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
                             .withFields({C2F(mDefaultColorAspects, range)
                                                  .inRange(C2Color::RANGE_UNSPECIFIED,
                                                           C2Color::RANGE_OTHER),
                                          C2F(mDefaultColorAspects, primaries)
                                                  .inRange(C2Color::PRIMARIES_UNSPECIFIED,
                                                           C2Color::PRIMARIES_OTHER),
                                          C2F(mDefaultColorAspects, transfer)
                                                  .inRange(C2Color::TRANSFER_UNSPECIFIED,
                                                           C2Color::TRANSFER_OTHER),
                                          C2F(mDefaultColorAspects, matrix)
                                                  .inRange(C2Color::MATRIX_UNSPECIFIED,
                                                           C2Color::MATRIX_OTHER)})
                             .withSetter(DefaultColorAspectsSetter)
                             .build());

        addParameter(DefineParam(mCodedColorAspects, C2_PARAMKEY_VUI_COLOR_ASPECTS)
                             .withDefault(new C2StreamColorAspectsInfo::input(
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
                             .withSetter(CodedColorAspectsSetter)
                             .build());

        addParameter(
                DefineParam(mColorAspects, C2_PARAMKEY_COLOR_ASPECTS)
                        .withDefault(new C2StreamColorAspectsInfo::output(
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
                                         .inRange(C2Color::MATRIX_UNSPECIFIED,
                                                  C2Color::MATRIX_OTHER)})
                        .withSetter(ColorAspectsSetter, mDefaultColorAspects, mCodedColorAspects)
                        .build());

        // TODO: support more formats?
        std::vector<uint32_t> pixelFormats = {HAL_PIXEL_FORMAT_YCBCR_420_888};
        if (isHalPixelFormatSupported((AHardwareBuffer_Format)HAL_PIXEL_FORMAT_YCBCR_P010)) {
            pixelFormats.push_back(HAL_PIXEL_FORMAT_YCBCR_P010);
        }
        if (isHalPixelFormatSupported((AHardwareBuffer_Format)AHARDWAREBUFFER_FORMAT_YCbCr_P210)) {
            pixelFormats.push_back(AHARDWAREBUFFER_FORMAT_YCbCr_P210);
        }
        if (isHalPixelFormatSupported((AHardwareBuffer_Format)HAL_PIXEL_FORMAT_RGBA_1010102)) {
            pixelFormats.push_back(HAL_PIXEL_FORMAT_RGBA_1010102);
        }

        // If color format surface isn't added to supported formats, there is no way to know
        // when the color-format is configured to surface. This is necessary to be able to
        // choose 10-bit format while decoding 10-bit clips in surface mode.
        pixelFormats.push_back(HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);
        addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
                             .withDefault(new C2StreamPixelFormatInfo::output(
                                     0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
                             .withFields({C2F(mPixelFormat, value).oneOf(pixelFormats)})
                             .withSetter((Setter<decltype(*mPixelFormat)>::StrictValueWithNoDeps))
                             .build());
    }

    static C2R SizeSetter(bool mayBlock, const C2P<C2StreamPictureSizeInfo::output>& oldMe,
                          C2P<C2StreamPictureSizeInfo::output>& me) {
        (void)mayBlock;
        ALOGV("%s - %d x %d", __FUNCTION__, me.v.width, me.v.height);
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

    static C2R MaxPictureSizeSetter(bool mayBlock, C2P<C2StreamMaxPictureSizeTuning::output>& me,
                                    const C2P<C2StreamPictureSizeInfo::output>& size) {
        (void)mayBlock;
        ALOGV("%s - %d x %d", __FUNCTION__, me.v.width, me.v.height);
        // TODO: get max width/height from the size's field helpers vs.
        // hardcoding
        me.set().width = c2_min(c2_max(me.v.width, size.v.width), 4096u);
        me.set().height = c2_min(c2_max(me.v.height, size.v.height), 4096u);
        return C2R::Ok();
    }

    static C2R MaxInputSizeSetter(bool mayBlock, C2P<C2StreamMaxBufferSizeInfo::input>& me,
                                  const C2P<C2StreamMaxPictureSizeTuning::output>& maxSize) {
        (void)mayBlock;
        ALOGV("%s", __FUNCTION__);
        // assume 1.25x compression as a worst case. Enforce the floor.
        me.set().value =
                /* 20 / 8 / 1.25 = 2: 20 is a bpp for 422 10 bit, 1.25 assumed min compression.*/
                c2_max((ALIGN_VAL(maxSize.v.width, 16) * ALIGN_VAL(maxSize.v.height, 16) * 2),
                     kMinInputBufferSize);
        return C2R::Ok();
    }

    static C2R DefaultColorAspectsSetter(bool mayBlock,
                                         C2P<C2StreamColorAspectsTuning::output>& me) {
        (void)mayBlock;
        ALOGV("%s - range: %u, primary: %u, transfer: %u, matrix: %u", __FUNCTION__, me.v.range,
              me.v.primaries, me.v.transfer, me.v.matrix);
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

    static C2R CodedColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::input>& me) {
        (void)mayBlock;
        ALOGV("%s - range: %u, primaries: %u, transfer: %u, matrix: %u", __func__, me.v.range,
              me.v.primaries, me.v.transfer, me.v.matrix);
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

    static C2R ColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::output>& me,
                                  const C2P<C2StreamColorAspectsTuning::output>& def,
                                  const C2P<C2StreamColorAspectsInfo::input>& coded) {
        (void)mayBlock;
        ALOGV("%s", __FUNCTION__);
        // take default values for all unspecified fields, and coded values for specified ones
        ALOGV("%s - coded range: %u, primaries: %u, transfer: %u, matrix: %u",
             __func__, coded.v.range, coded.v.primaries, coded.v.transfer, coded.v.matrix);
        me.set().range = coded.v.range == RANGE_UNSPECIFIED ? def.v.range : coded.v.range;
        me.set().primaries =
                coded.v.primaries == PRIMARIES_UNSPECIFIED ? def.v.primaries : coded.v.primaries;
        me.set().transfer =
                coded.v.transfer == TRANSFER_UNSPECIFIED ? def.v.transfer : coded.v.transfer;
        me.set().matrix = coded.v.matrix == MATRIX_UNSPECIFIED ? def.v.matrix : coded.v.matrix;
        ALOGV("%s - me.v.range = %u, me.v.primaries = %u, me.v.transfer = %u, me.v.matrix = %u",
              __func__, me.v.range, me.v.primaries, me.v.transfer, me.v.matrix);
        return C2R::Ok();
    }

    static C2R ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::input>& me,
                                  const C2P<C2StreamPictureSizeInfo::output>& size) {
        (void)mayBlock;
        ALOGV("%s", __FUNCTION__);
        (void)size;
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

    std::shared_ptr<C2StreamColorAspectsTuning::output> getDefaultColorAspects_l() {
        ALOGV("%s - mDefaultColorAspects: %u", __FUNCTION__, mDefaultColorAspects->primaries);
        return mDefaultColorAspects;
    }

    std::shared_ptr<C2StreamColorAspectsInfo::output> getColorAspects_l() {
        ALOGV("%s - mColorAspects: %u", __FUNCTION__, mColorAspects->primaries);
        return mColorAspects;
    }

    static C2R Hdr10PlusInfoInputSetter(bool mayBlock, C2P<C2StreamHdr10PlusInfo::input>& me) {
        (void)mayBlock;
        ALOGV("%s", __FUNCTION__);
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

    static C2R Hdr10PlusInfoOutputSetter(bool mayBlock, C2P<C2StreamHdr10PlusInfo::output>& me) {
        (void)mayBlock;
        ALOGV("%s", __FUNCTION__);
        (void)me;  // TODO: validate
        return C2R::Ok();
    }

    // unsafe getters
    std::shared_ptr<C2StreamPixelFormatInfo::output> getPixelFormat_l() const {
        return mPixelFormat;
    }

    static C2R HdrStaticInfoSetter(bool mayBlock, C2P<C2StreamHdrStaticInfo::output>& me) {
        (void)mayBlock;
        ALOGV("%s", __FUNCTION__);
        if (me.v.mastering.red.x > 1) {
            me.set().mastering.red.x = 1;
        }
        if (me.v.mastering.red.y > 1) {
            me.set().mastering.red.y = 1;
        }
        if (me.v.mastering.green.x > 1) {
            me.set().mastering.green.x = 1;
        }
        if (me.v.mastering.green.y > 1) {
            me.set().mastering.green.y = 1;
        }
        if (me.v.mastering.blue.x > 1) {
            me.set().mastering.blue.x = 1;
        }
        if (me.v.mastering.blue.y > 1) {
            me.set().mastering.blue.y = 1;
        }
        if (me.v.mastering.white.x > 1) {
            me.set().mastering.white.x = 1;
        }
        if (me.v.mastering.white.y > 1) {
            me.set().mastering.white.y = 1;
        }
        if (me.v.mastering.maxLuminance > 65535.0) {
            me.set().mastering.maxLuminance = 65535.0;
        }
        if (me.v.mastering.minLuminance > 6.5535) {
            me.set().mastering.minLuminance = 6.5535;
        }
        if (me.v.maxCll > 65535.0) {
            me.set().maxCll = 65535.0;
        }
        if (me.v.maxFall > 65535.0) {
            me.set().maxFall = 65535.0;
        }
        return C2R::Ok();
    }

  private:
    std::shared_ptr<C2StreamProfileLevelInfo::input> mProfileLevel;
    std::shared_ptr<C2StreamPictureSizeInfo::output> mSize;
    std::shared_ptr<C2StreamMaxPictureSizeTuning::output> mMaxSize;
    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mMaxInputSize;
    std::shared_ptr<C2StreamColorInfo::output> mColorInfo;
    std::shared_ptr<C2StreamPixelFormatInfo::output> mPixelFormat;
    std::shared_ptr<C2StreamColorAspectsTuning::output> mDefaultColorAspects;
    std::shared_ptr<C2StreamColorAspectsInfo::input> mCodedColorAspects;
    std::shared_ptr<C2StreamColorAspectsInfo::output> mColorAspects;
    std::shared_ptr<C2StreamHdr10PlusInfo::input> mHdr10PlusInfoInput;
    std::shared_ptr<C2StreamHdr10PlusInfo::output> mHdr10PlusInfoOutput;
    std::shared_ptr<C2StreamHdrStaticInfo::output> mHdrStaticInfo;
};

static void ivd_aligned_free(void* ctxt, void* mem) {
    (void)ctxt;
    free(mem);
}

C2SoftApvDec::C2SoftApvDec(const char* name, c2_node_id_t id,
                           const std::shared_ptr<IntfImpl>& intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl),
      mOutBufferFlush(nullptr),
      mOutputDelay(kDefaultOutputDelay),
      mOutIndex(0u),
      mHalPixelFormat(HAL_PIXEL_FORMAT_YV12),
      mWidth(320),
      mHeight(240),
      mSignalledOutputEos(false),
      mSignalledError(false),
      mDecHandle(nullptr),
      mMetadataHandle(nullptr),
      mOutCsp(OUTPUT_CSP_P210) {
    memset(&mOutFrames, 0, sizeof(oapv_frms_t));
}

C2SoftApvDec::C2SoftApvDec(const char* name, c2_node_id_t id,
                           const std::shared_ptr<C2ReflectorHelper>& helper)
    : C2SoftApvDec(name, id, std::make_shared<IntfImpl>(helper)) {
}

C2SoftApvDec::~C2SoftApvDec() {
    onRelease();
}

c2_status_t C2SoftApvDec::onInit() {
    ALOGV("%s", __FUNCTION__);
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_CORRUPTED;
}

c2_status_t C2SoftApvDec::onStop() {
    ALOGV("%s", __FUNCTION__);
    if (OK != resetDecoder()) return C2_CORRUPTED;
    resetPlugin();
    return C2_OK;
}

void C2SoftApvDec::onReset() {
    ALOGV("%s", __FUNCTION__);
    (void)onStop();
}

status_t C2SoftApvDec::deleteDecoder() {
    ALOGV("%s", __FUNCTION__);
    if (mDecHandle) {
        oapvd_delete(mDecHandle);
        mDecHandle = nullptr;
    }
    if (mMetadataHandle) {
        oapvm_delete(mMetadataHandle);
        mMetadataHandle = nullptr;
    }
    for (int i = 0; i < mOutFrames.num_frms; i++) {
        if (mOutFrames.frm[i].imgb != NULL) {
            mOutFrames.frm[i].imgb->release(mOutFrames.frm[i].imgb);
            mOutFrames.frm[i].imgb = NULL;
        }
    }
    return OK;
}

void C2SoftApvDec::onRelease() {
    ALOGV("%s", __FUNCTION__);
    (void)deleteDecoder();
    if (mOutBufferFlush) {
        ivd_aligned_free(nullptr, mOutBufferFlush);
        mOutBufferFlush = nullptr;
    }
    if (mOutBlock) {
        mOutBlock.reset();
    }
}

c2_status_t C2SoftApvDec::onFlush_sm() {
    ALOGV("%s", __FUNCTION__);
    mSignalledError = false;
    mSignalledOutputEos = false;
    return C2_OK;
}

status_t C2SoftApvDec::createDecoder() {
    ALOGV("%s", __FUNCTION__);
    return OK;
}

status_t C2SoftApvDec::initDecoder() {
    int ret;
    mSignalledError = false;
    mSignalledOutputEos = false;

    mHalPixelFormat = HAL_PIXEL_FORMAT_YV12;
    {
        IntfImpl::Lock lock = mIntf->lock();
        mPixelFormatInfo = mIntf->getPixelFormat_l();
        ALOGW("Hal pixel format = %d", mPixelFormatInfo->value);
    }

    oapvd_cdesc_t cdesc;
    memset(&cdesc, 0, sizeof(oapvd_cdesc_t));
    cdesc.threads = kDefaultSoftApvDecNumThreads;
    mDecHandle = oapvd_create(&cdesc, &ret);
    if (mDecHandle == nullptr) {
        ALOGE("ERROR: cannot create APV decoder (err=%d)\n", ret);
        return C2_NO_INIT;
    }

    memset(&mOutFrames, 0, sizeof(oapv_frms_t));

    mMetadataHandle = oapvm_create(&ret);
    if (OAPV_FAILED(ret)) {
        ALOGE("oapvm create failed");
        oapvd_delete(mDecHandle);
        mDecHandle = nullptr;
        return C2_NO_INIT;
    }

    ALOGV("oapvd init done");
    return OK;
}

status_t C2SoftApvDec::setFlushMode() {
    ALOGV("%s", __FUNCTION__);
    return OK;
}

status_t C2SoftApvDec::resetDecoder() {
    ALOGV("%s", __FUNCTION__);
    return OK;
}

void C2SoftApvDec::resetPlugin() {
    ALOGV("%s", __FUNCTION__);
    mSignalledOutputEos = false;
    if (mOutBlock) {
        mOutBlock.reset();
    }
}

void fillEmptyWork(const std::unique_ptr<C2Work>& work) {
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

void C2SoftApvDec::finishWork(uint64_t index, const std::unique_ptr<C2Work>& work,
                              const std::shared_ptr<C2GraphicBlock>& block) {
    std::shared_ptr<C2Buffer> buffer = createGraphicBuffer(block, C2Rect(mWidth, mHeight));

    {
        IntfImpl::Lock lock = mIntf->lock();
        buffer->setInfo(mIntf->getColorAspects_l());
    }

    class FillWork {
      public:
        FillWork(uint32_t flags, C2WorkOrdinalStruct ordinal,
                 const std::shared_ptr<C2Buffer>& buffer)
            : mFlags(flags), mOrdinal(ordinal), mBuffer(buffer) {}
        ~FillWork() = default;

        void operator()(const std::unique_ptr<C2Work>& work) {
            work->worklets.front()->output.flags = (C2FrameData::flags_t)mFlags;
            work->worklets.front()->output.buffers.clear();
            work->worklets.front()->output.ordinal = mOrdinal;
            work->workletsProcessed = 1u;
            work->result = C2_OK;
            if (mBuffer) {
                work->worklets.front()->output.buffers.push_back(mBuffer);
            }
            ALOGV("timestamp = %lld, index = %lld, w/%s buffer", mOrdinal.timestamp.peekll(),
                  mOrdinal.frameIndex.peekll(), mBuffer ? "" : "o");
        }

      private:
        const uint32_t mFlags;
        const C2WorkOrdinalStruct mOrdinal;
        const std::shared_ptr<C2Buffer> mBuffer;
    };

    auto fillWork = [buffer](const std::unique_ptr<C2Work>& work) {
        work->worklets.front()->output.flags = (C2FrameData::flags_t)0;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.buffers.push_back(buffer);
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->workletsProcessed = 1u;
    };

    if (work && c2_cntr64_t(index) == work->input.ordinal.frameIndex) {
        bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
        // TODO: Check if cloneAndSend can be avoided by tracking number of frames remaining
        if (eos) {
            if (buffer) {
                mOutIndex = index;
                C2WorkOrdinalStruct outOrdinal = work->input.ordinal;
                cloneAndSend(mOutIndex, work,
                             FillWork(C2FrameData::FLAG_INCOMPLETE, outOrdinal, buffer));
                buffer.reset();
            }
        } else {
            fillWork(work);
        }
    } else {
        finish(index, fillWork);
    }
}

static void copyBufferFromYUV420ToYV12(uint8_t* dstY, uint8_t* dstU, uint8_t* dstV,
                                       const uint8_t* srcY, const uint8_t* srcU,
                                       const uint8_t* srcV, size_t srcYStride, size_t srcUStride,
                                       size_t srcVStride, size_t dstYStride, size_t dstUStride,
                                       size_t dstVStride, uint32_t width, uint32_t height) {
    for (size_t i = 0; i < height; ++i) {
        memcpy(dstY, srcY, width);
        srcY += srcYStride;
        dstY += dstYStride;
    }

    for (size_t i = 0; i < height / 2; ++i) {
        memcpy(dstU, srcU, width / 2);
        memcpy(dstV, srcV, width / 2);
        dstU += dstUStride;
        srcU += srcUStride;
        dstV += dstVStride;
        srcV += srcVStride;
    }
}

static void copyBufferP210(uint16_t *dstY, uint16_t *dstUV, const uint16_t *srcY,
            const uint16_t *srcUV, size_t srcYStride, size_t srcUVStride, size_t dstYStride,
            size_t dstUVStride, size_t width, size_t height) {
    for (size_t y = 0; y < height; ++y) {
        memcpy(dstY, srcY, width * sizeof(uint16_t));
        srcY += srcYStride;
        dstY += dstYStride;
    }

    for (size_t y = 0; y < height; ++y) {
        memcpy(dstUV, srcUV, width * sizeof(uint16_t));
        srcUV += srcUVStride;
        dstUV += dstUVStride;
    }
}

static void copyBufferFromYUV422ToYV12(uint8_t* dstY, uint8_t* dstU, uint8_t* dstV,
                                       const uint8_t* srcY, const uint8_t* srcU,
                                       const uint8_t* srcV, size_t srcYStride, size_t srcUStride,
                                       size_t srcVStride, size_t dstYStride, size_t dstUStride,
                                       size_t dstVStride, uint32_t width, uint32_t height) {
    for (size_t i = 0; i < height; ++i) {
        memcpy(dstY, srcY, width);
        srcY += srcYStride;
        dstY += dstYStride;
    }

    for (size_t i = 0; i < height / 2; ++i) {
        memcpy(dstU, srcU, width / 2);
        memcpy(dstV, srcV, width / 2);
        dstU += dstUStride;
        srcU += srcUStride * 2;
        dstV += dstVStride;
        srcV += srcVStride * 2;
    }
}

static void copyBufferFromYUV42010bitToP010(uint16_t* dstY, uint16_t* dstUV, const uint16_t* srcY,
                                            const uint16_t* srcU, const uint16_t* srcV,
                                            size_t srcYStride, size_t srcUStride, size_t srcVStride,
                                            size_t dstYStride, size_t dstUVStride, size_t width,
                                            size_t height) {
    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            dstY[x] = srcY[x] << 6;
        }
        srcY += srcYStride;
        dstY += dstYStride;
    }

    for (size_t y = 0; y < height / 2; ++y) {
        for (size_t x = 0; x < width / 2; ++x) {
            dstUV[2 * x] = srcU[x] << 6;
            dstUV[2 * x + 1] = srcV[x] << 6;
        }
        srcU += srcUStride;
        srcV += srcVStride;
        dstUV += dstUVStride;
    }
}

static void copyBufferFromYUV42210bitToP010(uint16_t* dstY, uint16_t* dstUV, const uint16_t* srcY,
                                            const uint16_t* srcU, const uint16_t* srcV,
                                            size_t srcYStride, size_t srcUStride, size_t srcVStride,
                                            size_t dstYStride, size_t dstUVStride, size_t width,
                                            size_t height) {
    for (size_t y = 0; y < height; ++y) {
        for (size_t x = 0; x < width; ++x) {
            dstY[x] = srcY[x] << 6;
        }
        srcY += srcYStride;
        dstY += dstYStride;
    }

    for (size_t y = 0; y < height / 2; ++y) {
        for (size_t x = 0; x < width / 2; ++x) {
            dstUV[2 * x] = srcU[x] << 6;
            dstUV[2 * x + 1] = srcV[x] << 6;
        }
        srcU += srcUStride * 2;
        srcV += srcVStride * 2;
        dstUV += dstUVStride;
    }
}

static void copyBufferFromP210ToP010(uint16_t* dstY, uint16_t* dstUV, const uint16_t* srcY,
                                     const uint16_t* srcUV, size_t srcYStride, size_t srcUVStride,
                                     size_t dstYStride, size_t dstUVStride, size_t width,
                                     size_t height) {
    for (size_t y = 0; y < height; ++y) {
        memcpy(dstY, srcY, width * sizeof(uint16_t));
        srcY += srcYStride;
        dstY += dstYStride;
    }

    for (size_t y = 0; y < height / 2; ++y) {
        memcpy(dstUV, srcUV, width * 2);
        srcUV += srcUVStride * 2;
        dstUV += dstUVStride;
    }
}

static void copyBufferFromYUV42010bitToYV12(uint8_t* dstY, uint8_t* dstU, uint8_t* dstV,
                                            const uint16_t* srcY, const uint16_t* srcU,
                                            const uint16_t* srcV, size_t srcYStride,
                                            size_t srcUStride, size_t srcVStride, size_t dstYStride,
                                            size_t dstUStride, size_t dstVStride, uint32_t width,
                                            uint32_t height) {
    for (size_t i = 0; i < height; ++i) {
        for (size_t j = 0; j < width; ++j) {
            dstY[i * dstYStride + j] = (srcY[i * srcYStride + j] >> 2) & 0xFF;
        }
    }

    for (size_t i = 0; i < height / 2; ++i) {
        for (size_t j = 0; j < width / 2; ++j) {
            dstU[i * dstUStride + j] = (srcU[i * srcUStride + j] >> 2) & 0xFF;
        }
    }

    for (size_t i = 0; i < height / 2; ++i) {
        for (size_t j = 0; j < width / 2; ++j) {
            dstV[i * dstVStride + j] = (srcV[i * srcVStride + j] >> 2) & 0xFF;
        }
    }
}

static void copyBufferFromYUV42210bitToYV12(uint8_t* dstY, uint8_t* dstU, uint8_t* dstV,
                                            const uint16_t* srcY, const uint16_t* srcU,
                                            const uint16_t* srcV, size_t srcYStride,
                                            size_t srcUStride, size_t srcVStride, size_t dstYStride,
                                            size_t dstUStride, size_t dstVStride, uint32_t width,
                                            uint32_t height) {
    for (size_t i = 0; i < height; ++i) {
        for (size_t j = 0; j < width; ++j) {
            dstY[i * dstYStride + j] = (srcY[i * srcYStride + j] >> 2) & 0xFF;
        }
    }

    for (size_t i = 0; i < height / 2; ++i) {
        for (size_t j = 0; j < width / 2; ++j) {
            dstU[i * dstUStride + j] = (srcU[i * srcUStride * 2 + j] >> 2) & 0xFF;
        }
    }

    for (size_t i = 0; i < height / 2; ++i) {
        for (size_t j = 0; j < width / 2; ++j) {
            dstV[i * dstVStride + j] = (srcV[i * srcVStride * 2 + j] >> 2) & 0xFF;
        }
    }
}

static void copyBufferFromP210ToYV12(uint8_t* dstY, uint8_t* dstU, uint8_t* dstV,
                                     const uint16_t* srcY, const uint16_t* srcUV, size_t srcYStride,
                                     size_t srcUVStride, size_t dstYStride, size_t dstUStride,
                                     size_t dstVStride, size_t width, size_t height) {
    for (size_t i = 0; i < height; ++i) {
        for (size_t j = 0; j < width; ++j) {
            dstY[i * dstYStride + j] = (uint8_t)CLIP3(0, 255,
                            ((((int)srcY[i * srcYStride + j] >> 6) * 255.0) / 1023.0 + 0.5));
        }
    }

    for (size_t i = 0; i < height / 2; ++i) {
        for (size_t j = 0; j < width / 2; ++j) {
            dstU[i * dstVStride + j] = (uint8_t)CLIP3(0, 255,
                ((((int)srcUV[i * srcUVStride * 2 + j * 2] >> 6) * 255.0) / 1023.0 + 0.5));
            dstV[i * dstUStride + j] = (uint8_t)CLIP3(0, 255,
                ((((int)srcUV[i * srcUVStride * 2 + j * 2 + 1] >> 6) * 255.0) / 1023.0 + 0.5));
        }
    }
}

void C2SoftApvDec::process(const std::unique_ptr<C2Work>& work,
                           const std::shared_ptr<C2BlockPool>& pool) {
    // Initialize output work
    work->result = C2_OK;
    work->workletsProcessed = 0u;
    work->worklets.front()->output.configUpdate.clear();
    work->worklets.front()->output.flags = work->input.flags;
    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    int ret = 0;
    size_t inOffset = 0u;
    size_t inSize = 0u;
    C2ReadView rView = mDummyReadView;
    if (!work->input.buffers.empty()) {
        rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
        inSize = rView.capacity();
        if (inSize && rView.error()) {
            ALOGE("read view map failed %d", rView.error());
            work->result = C2_CORRUPTED;
            return;
        }
    }

    bool codecConfig = ((work->input.flags & C2FrameData::FLAG_CODEC_CONFIG) != 0);
    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);

    ALOGV("in buffer attr. size %zu timestamp %llu frameindex %d, flags %x", inSize,
          work->input.ordinal.timestamp.peekull(), (int)work->input.ordinal.frameIndex.peeku(),
          work->input.flags);

    if (codecConfig) {
        fillEmptyWork(work);
        return;
    }

    if (inSize > 0) {
        uint8_t* bitstream = const_cast<uint8_t*>(rView.data() + inOffset);
        oapv_au_info_t aui;
        oapv_bitb_t bitb;
        bitb.addr = bitstream + 4;  // skip au
        bitb.ssize = inSize - 4;

        if (OAPV_FAILED(oapvd_info(bitb.addr, bitb.ssize, &aui))) {
            ALOGE("cannot get information from bitstream");
            work->result = C2_CORRUPTED;
            return;
        }

        /* create decoding frame buffers */
        mOutFrames.num_frms = aui.num_frms;
        if (mOutFrames.num_frms <= 0) {
            ALOGE("Parse error - no output frame(%d)", mOutFrames.num_frms);
            fillEmptyWork(work);
            return;
        }
        bool reportResolutionChange = false;
        for (int i = 0; i < mOutFrames.num_frms; i++) {
            oapv_frm_info_t* finfo = &aui.frm_info[i];
            oapv_frm_t* frm = &mOutFrames.frm[i];

            if (mWidth != finfo->w || mHeight != finfo->h) {
                mWidth = finfo->w;
                mHeight = finfo->h;
                reportResolutionChange = true;
            }

            if (mWidth > MAX_SUPPORTED_WIDTH || mHeight > MAX_SUPPORTED_HEIGHT) {
                ALOGE("Stream resolution of %dx%d is not supported.", mWidth, mHeight);
                work->result = C2_CORRUPTED;
                return;
            }

            if (frm->imgb != NULL && (frm->imgb->w[0] != finfo->w || frm->imgb->h[0] != finfo->h)) {
                frm->imgb->release(frm->imgb);
                frm->imgb = NULL;
            }

            if (frm->imgb == NULL) {
                if (mOutCsp == OUTPUT_CSP_P210) {
                    frm->imgb = imgb_create(finfo->w, finfo->h, OAPV_CS_P210);
                } else {
                    frm->imgb = imgb_create(finfo->w, finfo->h, finfo->cs);
                }
                if (frm->imgb == NULL) {
                    ALOGE("cannot allocate image buffer (w:%d, h:%d, cs:%d)", finfo->w, finfo->h,
                          finfo->cs);
                    fillEmptyWork(work);
                    return;
                }
            }
        }

        if (reportResolutionChange) {
            C2StreamPictureSizeInfo::output size(0u, mWidth, mHeight);
            std::vector<std::unique_ptr<C2SettingResult>> failures;
            c2_status_t err = mIntf->config({&size}, C2_MAY_BLOCK, &failures);
            if (err == C2_OK) {
                work->worklets.front()->output.configUpdate.push_back(
                    C2Param::Copy(size));
            } else {
                ALOGE("Config update size failed");
                mSignalledError = true;
                work->workletsProcessed = 1u;
                work->result = C2_CORRUPTED;
                return;
            }
        }

        oapvd_stat_t stat;
        ret = oapvd_decode(mDecHandle, &bitb, &mOutFrames, mMetadataHandle, &stat);
        if (bitb.ssize != stat.read) {
            ALOGW("decode done, input size: %d, processed size: %d", bitb.ssize, stat.read);
        }

        if (OAPV_FAILED(ret)) {
            ALOGE("failed to decode bitstream\n");
            fillEmptyWork(work);
            return;
        }

        for(int i = 0; i < stat.aui.num_frms; i++) {
            oapv_frm_info_t* finfo = &stat.aui.frm_info[i];
            if(finfo->pbu_type == OAPV_PBU_TYPE_PRIMARY_FRAME) {
                if(finfo->color_description_present_flag > 0) {
                    vuiColorAspects.primaries = finfo->color_primaries;
                    vuiColorAspects.transfer = finfo->transfer_characteristics;
                    vuiColorAspects.coeffs = finfo->matrix_coefficients;
                    vuiColorAspects.fullRange = finfo->full_range_flag;
                }
            }
        }

        status_t err = outputBuffer(pool, work);
        if (err == NOT_ENOUGH_DATA) {
            if (inSize > 0) {
                ALOGV("Maybe non-display frame at %lld.", work->input.ordinal.frameIndex.peekll());
                // send the work back with empty buffer.
                inSize = 0;
            }
        } else if (err != OK) {
            ALOGD("Error while getting the output frame out");
            // work->result would be already filled; do fillEmptyWork() below to
            // send the work back.
            inSize = 0;
        }
    }

    if (eos) {
        drainInternal(DRAIN_COMPONENT_WITH_EOS, pool, work);
        mSignalledOutputEos = true;
    } else if (!inSize) {
        fillEmptyWork(work);
    }
}

void C2SoftApvDec::getVuiParams(const std::unique_ptr<C2Work> &work) {
    // convert vui aspects to C2 values if changed
    if (!(vuiColorAspects == mBitstreamColorAspects)) {
        mBitstreamColorAspects = vuiColorAspects;
        ColorAspects sfAspects;
        C2StreamColorAspectsInfo::input codedAspects = { 0u };
        ColorUtils::convertIsoColorAspectsToCodecAspects(
                vuiColorAspects.primaries, vuiColorAspects.transfer, vuiColorAspects.coeffs,
                vuiColorAspects.fullRange, sfAspects);
        if (!C2Mapper::map(sfAspects.mPrimaries, &codedAspects.primaries)) {
            codedAspects.primaries = C2Color::PRIMARIES_UNSPECIFIED;
        }
        if (!C2Mapper::map(sfAspects.mRange, &codedAspects.range)) {
            codedAspects.range = C2Color::RANGE_UNSPECIFIED;
        }
        if (!C2Mapper::map(sfAspects.mMatrixCoeffs, &codedAspects.matrix)) {
            codedAspects.matrix = C2Color::MATRIX_UNSPECIFIED;
        }
        if (!C2Mapper::map(sfAspects.mTransfer, &codedAspects.transfer)) {
            codedAspects.transfer = C2Color::TRANSFER_UNSPECIFIED;
        }
        ALOGV("colorAspects: primaries:%d, transfer:%d, coeffs:%d, fullRange:%d",
                codedAspects.primaries, codedAspects.transfer, codedAspects.matrix,
                codedAspects.range);
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        c2_status_t err = mIntf->config({&codedAspects}, C2_MAY_BLOCK, &failures);
        if (err == C2_OK) {
            work->worklets.front()->output.configUpdate.push_back(
              C2Param::Copy(codedAspects));
        } else {
            ALOGE("Config update colorAspect failed");
            mSignalledError = true;
            work->workletsProcessed = 1u;
            work->result = C2_CORRUPTED;
            return;
        }
    }
}

void C2SoftApvDec::getHDRStaticParams(const struct ApvHdrInfo *buffer,
                                       const std::unique_ptr<C2Work> &work) {
    C2StreamHdrStaticMetadataInfo::output hdrStaticMetadataInfo{};
    bool infoPresent = false;

    if(buffer->has_hdr_mdcv) {
        ALOGV("has hdr mdcv");
        // hdr_mdcv.primary_chromaticity_* values are in 0.16 fixed-point format.
        hdrStaticMetadataInfo.mastering.red.x =
            buffer->hdr_mdcv.primary_chromaticity_x[0] / 50000.0;
        hdrStaticMetadataInfo.mastering.red.y =
            buffer->hdr_mdcv.primary_chromaticity_y[0] / 50000.0;
        hdrStaticMetadataInfo.mastering.green.x =
            buffer->hdr_mdcv.primary_chromaticity_x[1] / 50000.0;
        hdrStaticMetadataInfo.mastering.green.y =
            buffer->hdr_mdcv.primary_chromaticity_y[1] / 50000.0;
        hdrStaticMetadataInfo.mastering.blue.x =
            buffer->hdr_mdcv.primary_chromaticity_x[2] / 50000.0;
        hdrStaticMetadataInfo.mastering.blue.y =
            buffer->hdr_mdcv.primary_chromaticity_y[2] / 50000.0;

        // hdr_mdcv.white_point_chromaticity_* values are in 0.16 fixed-point format.
        hdrStaticMetadataInfo.mastering.white.x =
            buffer->hdr_mdcv.white_point_chromaticity_x / 50000.0;
        hdrStaticMetadataInfo.mastering.white.y =
            buffer->hdr_mdcv.white_point_chromaticity_y / 50000.0;

        // hdr_mdcv.luminance_max is in 24.8 fixed-point format.
        hdrStaticMetadataInfo.mastering.maxLuminance =
            buffer->hdr_mdcv.max_mastering_luminance / 10000.0;
        // hdr_mdcv.luminance_min is in 18.14 format.
        hdrStaticMetadataInfo.mastering.minLuminance =
            buffer->hdr_mdcv.min_mastering_luminance / 10000.0;
        infoPresent = true;
    }

    if(buffer->has_hdr_cll) {
        ALOGV("has hdr cll");
        hdrStaticMetadataInfo.maxCll = buffer->hdr_cll.max_cll;
        hdrStaticMetadataInfo.maxFall = buffer->hdr_cll.max_fall;
        infoPresent = true;
    }

    // config if static info has changed
    if (infoPresent && !(hdrStaticMetadataInfo == mHdrStaticMetadataInfo)) {
        mHdrStaticMetadataInfo = hdrStaticMetadataInfo;
        work->worklets.front()->output.configUpdate.push_back(
                    C2Param::Copy(mHdrStaticMetadataInfo));
    }
}

void C2SoftApvDec::getHDR10PlusInfoData(const struct ApvHdrInfo *buffer,
                                         const std::unique_ptr<C2Work> &work) {
    if(!buffer->has_itut_t35) {
        ALOGV("no itu_t_t35 data");
        return;
    }

    std::vector<uint8_t> payload;
    size_t payloadSize = buffer->itut_t35.payload_size;
    if (payloadSize > 0) {
        payload.push_back(buffer->itut_t35.country_code);
        if ((unsigned char)buffer->itut_t35.country_code == 0xFF) {
            payload.push_back(buffer->itut_t35.country_code_extension_byte);
        }
        payload.insert(payload.end(), buffer->itut_t35.payload_bytes,
                    buffer->itut_t35.payload_bytes + buffer->itut_t35.payload_size);
    }

    std::unique_ptr<C2StreamHdr10PlusInfo::output> hdr10PlusInfo =
            C2StreamHdr10PlusInfo::output::AllocUnique(payload.size());
    if (!hdr10PlusInfo) {
        ALOGE("Hdr10PlusInfo allocation failed");
        mSignalledError = true;
        work->result = C2_NO_MEMORY;
        return;
    }
    memcpy(hdr10PlusInfo->m.value, payload.data(), payload.size());

    // config if hdr10Plus info has changed
    if (nullptr == mHdr10PlusInfo || !(*hdr10PlusInfo == *mHdr10PlusInfo)) {
        mHdr10PlusInfo = std::move(hdr10PlusInfo);
        work->worklets.front()->output.configUpdate.push_back(std::move(mHdr10PlusInfo));
    }
}

void C2SoftApvDec::getHdrInfo(struct ApvHdrInfo *hdrInfo, int groupId) {
    void *pld;
    int size;

    int ret = oapvm_get(mMetadataHandle, groupId, OAPV_METADATA_MDCV, &pld, &size, nullptr);
    if(ret == OAPV_OK) {
        if(size < sizeof(struct ApvHdrInfo::HdrMdcv)) {
            ALOGW("metadata_mdcv size is smaller than expected");
            return;
        }
        unsigned char *data = (unsigned char *)pld;
        hdrInfo->has_hdr_mdcv = true;
        for(int i = 0; i < 3; i++) {
            hdrInfo->hdr_mdcv.primary_chromaticity_x[i] = (*data++) << 8;
            hdrInfo->hdr_mdcv.primary_chromaticity_x[i] |= (*data++);
            hdrInfo->hdr_mdcv.primary_chromaticity_y[i] = (*data++) << 8;
            hdrInfo->hdr_mdcv.primary_chromaticity_y[i] |= (*data++);
        }
        hdrInfo->hdr_mdcv.white_point_chromaticity_x = (*data++) << 8;
        hdrInfo->hdr_mdcv.white_point_chromaticity_x |= (*data++);
        hdrInfo->hdr_mdcv.white_point_chromaticity_y = (*data++) << 8;
        hdrInfo->hdr_mdcv.white_point_chromaticity_y |= (*data++);
        hdrInfo->hdr_mdcv.max_mastering_luminance =  (*data++) << 24;
        hdrInfo->hdr_mdcv.max_mastering_luminance |= (*data++) << 16;
        hdrInfo->hdr_mdcv.max_mastering_luminance |= (*data++) << 8;
        hdrInfo->hdr_mdcv.max_mastering_luminance |= (*data++);
        hdrInfo->hdr_mdcv.min_mastering_luminance =  (*data++) << 24;
        hdrInfo->hdr_mdcv.min_mastering_luminance |= (*data++) << 16;
        hdrInfo->hdr_mdcv.min_mastering_luminance |= (*data++) << 8;
        hdrInfo->hdr_mdcv.min_mastering_luminance |= (*data);
    }

    ret = oapvm_get(mMetadataHandle, groupId, OAPV_METADATA_CLL, &pld, &size, nullptr);
    if(ret == OAPV_OK) {
        if(size < sizeof(struct ApvHdrInfo::HdrCll)) {
            ALOGW("metadata_cll size is smaller than expected");
            return;
        }
        unsigned char *data = (unsigned char *)pld;
        hdrInfo->has_hdr_cll = true;
        hdrInfo->hdr_cll.max_cll =  (*data++) << 8;
        hdrInfo->hdr_cll.max_cll |= (*data++);
        hdrInfo->hdr_cll.max_fall =  (*data++) << 8;
        hdrInfo->hdr_cll.max_fall |= (*data);
    }

    ret = oapvm_get(mMetadataHandle, groupId, OAPV_METADATA_ITU_T_T35, &pld, &size, nullptr);
    if(ret == OAPV_OK) {
        char *data = (char *)pld;
        hdrInfo->has_itut_t35 = true;
        int readSize = size;
        hdrInfo->itut_t35.country_code = *data++;
        readSize--;
        if((unsigned char)hdrInfo->itut_t35.country_code == 0xFF) {
            hdrInfo->itut_t35.country_code_extension_byte = *data++;
            readSize--;
        }
        hdrInfo->itut_t35.payload_bytes = data;
        hdrInfo->itut_t35.payload_size = readSize;
    }
}

status_t C2SoftApvDec::outputBuffer(const std::shared_ptr<C2BlockPool>& pool,
                                    const std::unique_ptr<C2Work>& work) {
    if (!(work && pool)) return BAD_VALUE;

    oapv_imgb_t* imgbOutput = nullptr;
    int groupId = -1;
    std::shared_ptr<C2GraphicBlock> block;

    if (mOutFrames.num_frms > 0) {
        for(int i = 0; i < mOutFrames.num_frms; i++) {
            oapv_frm_t* frm = &mOutFrames.frm[i];
            if(frm->pbu_type == OAPV_PBU_TYPE_PRIMARY_FRAME) {
                imgbOutput = frm->imgb;
                groupId = frm->group_id;
                break;
            }
        }
        if(imgbOutput == nullptr) {
            ALOGW("No OAPV primary frame");
            return false;
        }
    } else {
        ALOGW("No output frames");
        return false;
    }
    bool isMonochrome = OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CS_YCBCR400;

    getVuiParams(work);
    struct ApvHdrInfo hdrInfo = {};
    getHdrInfo(&hdrInfo, groupId);
    getHDRStaticParams(&hdrInfo, work);
    getHDR10PlusInfoData(&hdrInfo, work);

    if (mSignalledError) {
        // 'work' should already have signalled error at this point
        return C2_CORRUPTED;
    }

    uint32_t format = HAL_PIXEL_FORMAT_YV12;
    std::shared_ptr<C2StreamColorAspectsInfo::output> codedColorAspects;
    if (mPixelFormatInfo->value != HAL_PIXEL_FORMAT_YCBCR_420_888) {
        if ((mPixelFormatInfo->value != HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) &&
            isHalPixelFormatSupported((AHardwareBuffer_Format)mPixelFormatInfo->value)) {
            format = mPixelFormatInfo->value;
        } else if (isHalPixelFormatSupported(
                        (AHardwareBuffer_Format)AHARDWAREBUFFER_FORMAT_YCbCr_P210)) {
            format = AHARDWAREBUFFER_FORMAT_YCbCr_P210;
        } else if (isHalPixelFormatSupported(
                        (AHardwareBuffer_Format)HAL_PIXEL_FORMAT_YCBCR_P010)) {
            format = HAL_PIXEL_FORMAT_YCBCR_P010;
        } else if (isHalPixelFormatSupported(
                        (AHardwareBuffer_Format)HAL_PIXEL_FORMAT_RGBA_1010102)) {
            IntfImpl::Lock lock = mIntf->lock();
            codedColorAspects = mIntf->getColorAspects_l();
            format = HAL_PIXEL_FORMAT_RGBA_1010102;
        } else {
            format = HAL_PIXEL_FORMAT_YV12;
        }
    }

    if (mHalPixelFormat != format) {
        C2StreamPixelFormatInfo::output pixelFormat(0u, format);
        std::vector<std::unique_ptr<C2SettingResult>> failures;
        c2_status_t err = mIntf->config({&pixelFormat}, C2_MAY_BLOCK, &failures);
        if (err == C2_OK) {
            work->worklets.front()->output.configUpdate.push_back(C2Param::Copy(pixelFormat));
        } else {
            ALOGE("Config update pixelFormat failed");
            mSignalledError = true;
            work->workletsProcessed = 1u;
            work->result = C2_CORRUPTED;
            return UNKNOWN_ERROR;
        }
        mHalPixelFormat = format;
    }
    ALOGV("mHalPixelFormat: %u, format: %d", mHalPixelFormat, format);

    C2MemoryUsage usage = {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};

    // check. align height to 2 times does not work.
    c2_status_t err =
            pool->fetchGraphicBlock(align(mWidth, 16), align(mHeight, 16), format, usage, &block);

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

    ALOGV("provided (%dx%d) required (%dx%d)", block->width(), block->height(), mWidth, mHeight);

    uint8_t* dstY = const_cast<uint8_t*>(wView.data()[C2PlanarLayout::PLANE_Y]);
    uint8_t* dstU = const_cast<uint8_t*>(wView.data()[C2PlanarLayout::PLANE_U]);
    uint8_t* dstV = const_cast<uint8_t*>(wView.data()[C2PlanarLayout::PLANE_V]);

    C2PlanarLayout layout = wView.layout();
    size_t dstYStride = layout.planes[C2PlanarLayout::PLANE_Y].rowInc;
    size_t dstUStride = layout.planes[C2PlanarLayout::PLANE_U].rowInc;
    size_t dstVStride = layout.planes[C2PlanarLayout::PLANE_V].rowInc;

    if(format == HAL_PIXEL_FORMAT_RGBA_1010102) {
        if (OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs) == 10) {
            const uint16_t* srcY = (const uint16_t*)imgbOutput->a[0];
            const uint16_t* srcU = (const uint16_t*)imgbOutput->a[1];
            const uint16_t* srcV = (const uint16_t*)imgbOutput->a[2];
            size_t srcYStride = imgbOutput->s[0] / 2;
            size_t srcUStride = imgbOutput->s[1] / 2;
            size_t srcVStride = imgbOutput->s[2] / 2;
            dstYStride /= 4;
            if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_PLANAR2) {
                ALOGV("OAPV_CS_P210 to RGBA1010102");
                convertP210ToRGBA1010102((uint32_t *)dstY, srcY, srcU, srcYStride, srcUStride,
                                           dstYStride, mWidth, mHeight, codedColorAspects);
            } else {
                ALOGE("Not supported convert format : %d", OAPV_CS_GET_FORMAT(imgbOutput->cs));
            }
        } else {
            ALOGE("Not supported convert from bitdepth:%d, format: %d, to format: %d",
                  OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs), OAPV_CS_GET_FORMAT(imgbOutput->cs),
                  format);
        }
    } else if(format == AHARDWAREBUFFER_FORMAT_YCbCr_P210) {
        if(OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs) == 10) {
            const uint16_t *srcY = (const uint16_t *)imgbOutput->a[0];
            const uint16_t *srcU = (const uint16_t *)imgbOutput->a[1];
            const uint16_t *srcV = (const uint16_t *)imgbOutput->a[2];
            size_t srcYStride = imgbOutput->s[0] / 2;
            size_t srcUStride = imgbOutput->s[1] / 2;
            size_t srcVStride = imgbOutput->s[2] / 2;
            dstYStride /= 2;
            dstUStride /= 2;
            dstVStride /= 2;
            ALOGV("OAPV_CS_P210 buffer");
            copyBufferP210((uint16_t *)dstY, (uint16_t *)dstU, srcY, srcU,
                            srcYStride, srcUStride, dstYStride, dstUStride, mWidth, mHeight);
        } else {
            ALOGE("Not supported convder from bd:%d, format: %d(%s), to format: %d(%s)",
                OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs),
                OAPV_CS_GET_FORMAT(imgbOutput->cs),
                OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR420 ?
                    "YUV420" : (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR422 ?
                                 "YUV422" : "UNKNOWN"),
                format,
                format == HAL_PIXEL_FORMAT_YCBCR_P010 ?
                    "P010" : (format == HAL_PIXEL_FORMAT_YCBCR_420_888 ?
                         "YUV420" : (format == HAL_PIXEL_FORMAT_YV12 ? "YV12" : "UNKNOWN"))
                );
        }
    } else if(format == HAL_PIXEL_FORMAT_YCBCR_P010) {
        if (OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs) == 10) {
            const uint16_t* srcY = (const uint16_t*)imgbOutput->a[0];
            const uint16_t* srcU = (const uint16_t*)imgbOutput->a[1];
            const uint16_t* srcV = (const uint16_t*)imgbOutput->a[2];
            size_t srcYStride = imgbOutput->s[0] / 2;
            size_t srcUStride = imgbOutput->s[1] / 2;
            size_t srcVStride = imgbOutput->s[2] / 2;
            dstYStride /= 2;
            dstUStride /= 2;
            dstVStride /= 2;
            if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR420) {
                ALOGV("OAPV_CS_YUV420 10bit to P010");
                copyBufferFromYUV42010bitToP010((uint16_t*)dstY, (uint16_t*)dstU, srcY, srcU, srcV,
                                                srcYStride, srcUStride, srcVStride, dstYStride,
                                                dstUStride, mWidth, mHeight);
            } else if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR422) {
                ALOGV("OAPV_CS_YUV422 10bit to P010");
                copyBufferFromYUV42210bitToP010((uint16_t*)dstY, (uint16_t*)dstU, srcY, srcU, srcV,
                                                srcYStride, srcUStride, srcVStride, dstYStride,
                                                dstUStride, mWidth, mHeight);
            } else if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_PLANAR2) {
                ALOGV("OAPV_CS_P210 to P010");
                copyBufferFromP210ToP010((uint16_t*)dstY, (uint16_t*)dstU, srcY, srcU, srcYStride,
                                         srcUStride, dstYStride, dstUStride, mWidth, mHeight);
            } else {
                ALOGE("Not supported convert format : %d", OAPV_CS_GET_FORMAT(imgbOutput->cs));
            }
        } else {
            ALOGE("Not supported convder from bd:%d, format: %d(%s), to format: %d(%s)",
                  OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs), OAPV_CS_GET_FORMAT(imgbOutput->cs),
                  OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR420
                          ? "YUV420"
                          : (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR422 ? "YUV422"
                                                                                    : "UNKNOWN"),
                  format,
                  format == HAL_PIXEL_FORMAT_YCBCR_P010
                          ? "P010"
                          : (format == HAL_PIXEL_FORMAT_YCBCR_420_888
                                     ? "YUV420"
                                     : (format == HAL_PIXEL_FORMAT_YV12 ? "YV12" : "UNKNOWN")));
        }
    } else {  // HAL_PIXEL_FORMAT_YV12
        if (!IsI420(wView)) {
            ALOGE("Only P210 to I420 conversion is supported.");
        } else {
            if (OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs) == 10) {
                const uint16_t* srcY = (const uint16_t*)imgbOutput->a[0];
                const uint16_t* srcV = (const uint16_t*)imgbOutput->a[1];
                const uint16_t* srcU = (const uint16_t*)imgbOutput->a[2];
                size_t srcYStride = imgbOutput->s[0] / 2;
                size_t srcVStride = imgbOutput->s[1] / 2;
                size_t srcUStride = imgbOutput->s[2] / 2;
                if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR420) {
                    ALOGV("OAPV_CS_YUV420 10bit to YV12");
                    copyBufferFromYUV42010bitToYV12(
                        dstY, dstU, dstV, srcY, srcU, srcV, srcYStride, srcUStride,
                        srcVStride, dstYStride, dstUStride, dstVStride, mWidth,
                        mHeight);
                } else if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR422) {
                    ALOGV("OAPV_CS_YUV422 10bit to YV12");
                    copyBufferFromYUV42210bitToYV12(
                        dstY, dstU, dstV, srcY, srcU, srcV, srcYStride, srcUStride,
                        srcVStride, dstYStride, dstUStride, dstVStride, mWidth,
                        mHeight);
                } else if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_PLANAR2) {
                    ALOGV("OAPV_CS_P210 to YV12");
                    copyBufferFromP210ToYV12(dstY, dstU, dstV, srcY, srcV, srcYStride,
                                       srcVStride, dstYStride, dstUStride,
                                       dstVStride, mWidth, mHeight);
                } else {
                    ALOGE("Not supported convert format : %d",
                            OAPV_CS_GET_FORMAT(imgbOutput->cs));
                }
            } else if (OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs) == 8) {
                const uint8_t* srcY = (const uint8_t*)imgbOutput->a[0];
                const uint8_t* srcV = (const uint8_t*)imgbOutput->a[1];
                const uint8_t* srcU = (const uint8_t*)imgbOutput->a[2];
                size_t srcYStride = imgbOutput->s[0];
                size_t srcVStride = imgbOutput->s[1];
                size_t srcUStride = imgbOutput->s[2];
                if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR420) {
                    ALOGV("OAPV_CS_YUV420 to YV12");
                    copyBufferFromYUV420ToYV12(dstY, dstU, dstV, srcY, srcU, srcV,
                                         srcYStride, srcUStride, srcVStride,
                                         dstYStride, dstUStride, dstVStride,
                                         mWidth, mHeight);
                } else if (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR422) {
                    ALOGV("OAPV_CS_YUV422 to YV12");
                    copyBufferFromYUV422ToYV12(dstY, dstU, dstV, srcY, srcU, srcV,
                                         srcYStride, srcUStride, srcVStride,
                                         dstYStride, dstUStride, dstVStride,
                                         mWidth, mHeight);
                } else {
                    ALOGE("Not supported convert format : %d",
                        OAPV_CS_GET_FORMAT(imgbOutput->cs));
                }
            } else {
                ALOGE(
                "Not supported convert from bd:%d, format: %d(%s), to format: "
                    "%d(%s)",
                    OAPV_CS_GET_BIT_DEPTH(imgbOutput->cs),
                    OAPV_CS_GET_FORMAT(imgbOutput->cs),
                    OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR420
                        ? "YUV420"
                        : (OAPV_CS_GET_FORMAT(imgbOutput->cs) == OAPV_CF_YCBCR422
                           ? "YUV422"
                           : "UNKNOWN"),
                    format,
                    format == HAL_PIXEL_FORMAT_YCBCR_P010
                        ? "P010"
                        : (format == HAL_PIXEL_FORMAT_YCBCR_420_888
                           ? "YUV420"
                           : (format == HAL_PIXEL_FORMAT_YV12 ? "YV12"
                                                              : "UNKNOWN")));
            }
        }
    }

    finishWork(work->input.ordinal.frameIndex.peekll(), work, std::move(block));
    return OK;
}

c2_status_t C2SoftApvDec::drainInternal(uint32_t drainMode,
                                        const std::shared_ptr<C2BlockPool>& pool,
                                        const std::unique_ptr<C2Work>& work) {
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }

    if (drainMode == DRAIN_COMPONENT_WITH_EOS && work && work->workletsProcessed == 0u) {
        fillEmptyWork(work);
    }
    return C2_OK;
}

c2_status_t C2SoftApvDec::drain(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool) {
    return drainInternal(drainMode, pool, nullptr);
}

class C2SoftApvDecFactory : public C2ComponentFactory {
  public:
    C2SoftApvDecFactory()
        : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
                  GetCodec2PlatformComponentStore()->getParamReflector())) {}

    virtual c2_status_t createComponent(c2_node_id_t id,
                                        std::shared_ptr<C2Component>* const component,
                                        std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
                new C2SoftApvDec(COMPONENT_NAME, id,
                                 std::make_shared<C2SoftApvDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id, std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
                new SimpleInterface<C2SoftApvDec::IntfImpl>(
                        COMPONENT_NAME, id, std::make_shared<C2SoftApvDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual ~C2SoftApvDecFactory() override = default;

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

    return new ::android::C2SoftApvDecFactory();
}

__attribute__((cfi_canonical_jump_table)) extern "C" void DestroyCodec2Factory(
        ::C2ComponentFactory* factory) {
    delete factory;
}
