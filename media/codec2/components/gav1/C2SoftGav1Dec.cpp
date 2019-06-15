/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "C2SoftGav1Dec"
#include "C2SoftGav1Dec.h"

#include <C2Debug.h>
#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>
#include <log/log.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

// TODO(vigneshv): This will be changed to c2.android.av1.decoder once this
// component is fully functional.
constexpr char COMPONENT_NAME[] = "c2.android.gav1.decoder";

class C2SoftGav1Dec::IntfImpl : public SimpleInterface<void>::BaseParams {
 public:
  explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
      : SimpleInterface<void>::BaseParams(
            helper, COMPONENT_NAME, C2Component::KIND_DECODER,
            C2Component::DOMAIN_VIDEO, MEDIA_MIMETYPE_VIDEO_AV1) {
    noPrivateBuffers();  // TODO: account for our buffers here.
    noInputReferences();
    noOutputReferences();
    noInputLatency();
    noTimeStretch();

    addParameter(DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                     .withConstValue(new C2ComponentAttributesSetting(
                         C2Component::ATTRIB_IS_TEMPORAL))
                     .build());

    addParameter(
        DefineParam(mSize, C2_PARAMKEY_PICTURE_SIZE)
            .withDefault(new C2StreamPictureSizeInfo::output(0u, 320, 240))
            .withFields({
                C2F(mSize, width).inRange(2, 2048, 2),
                C2F(mSize, height).inRange(2, 2048, 2),
            })
            .withSetter(SizeSetter)
            .build());

    addParameter(DefineParam(mProfileLevel, C2_PARAMKEY_PROFILE_LEVEL)
                     .withDefault(new C2StreamProfileLevelInfo::input(
                         0u, C2Config::PROFILE_AV1_0, C2Config::LEVEL_AV1_2_1))
                     .withFields({C2F(mProfileLevel, profile)
                                      .oneOf({C2Config::PROFILE_AV1_0,
                                              C2Config::PROFILE_AV1_1}),
                                  C2F(mProfileLevel, level)
                                      .oneOf({
                                          C2Config::LEVEL_AV1_2,
                                          C2Config::LEVEL_AV1_2_1,
                                          C2Config::LEVEL_AV1_2_2,
                                          C2Config::LEVEL_AV1_3,
                                          C2Config::LEVEL_AV1_3_1,
                                          C2Config::LEVEL_AV1_3_2,
                                      })})
                     .withSetter(ProfileLevelSetter, mSize)
                     .build());

    mHdr10PlusInfoInput = C2StreamHdr10PlusInfo::input::AllocShared(0);
    addParameter(
        DefineParam(mHdr10PlusInfoInput, C2_PARAMKEY_INPUT_HDR10_PLUS_INFO)
            .withDefault(mHdr10PlusInfoInput)
            .withFields({
                C2F(mHdr10PlusInfoInput, m.value).any(),
            })
            .withSetter(Hdr10PlusInfoInputSetter)
            .build());

    mHdr10PlusInfoOutput = C2StreamHdr10PlusInfo::output::AllocShared(0);
    addParameter(
        DefineParam(mHdr10PlusInfoOutput, C2_PARAMKEY_OUTPUT_HDR10_PLUS_INFO)
            .withDefault(mHdr10PlusInfoOutput)
            .withFields({
                C2F(mHdr10PlusInfoOutput, m.value).any(),
            })
            .withSetter(Hdr10PlusInfoOutputSetter)
            .build());

    addParameter(
        DefineParam(mMaxSize, C2_PARAMKEY_MAX_PICTURE_SIZE)
            .withDefault(new C2StreamMaxPictureSizeTuning::output(0u, 320, 240))
            .withFields({
                C2F(mSize, width).inRange(2, 2048, 2),
                C2F(mSize, height).inRange(2, 2048, 2),
            })
            .withSetter(MaxPictureSizeSetter, mSize)
            .build());

    addParameter(DefineParam(mMaxInputSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                     .withDefault(new C2StreamMaxBufferSizeInfo::input(
                         0u, 320 * 240 * 3 / 4))
                     .withFields({
                         C2F(mMaxInputSize, value).any(),
                     })
                     .calculatedAs(MaxInputSizeSetter, mMaxSize)
                     .build());

    C2ChromaOffsetStruct locations[1] = {C2ChromaOffsetStruct::ITU_YUV_420_0()};
    std::shared_ptr<C2StreamColorInfo::output> defaultColorInfo =
        C2StreamColorInfo::output::AllocShared(1u, 0u, 8u /* bitDepth */,
                                               C2Color::YUV_420);
    memcpy(defaultColorInfo->m.locations, locations, sizeof(locations));

    defaultColorInfo = C2StreamColorInfo::output::AllocShared(
        {C2ChromaOffsetStruct::ITU_YUV_420_0()}, 0u, 8u /* bitDepth */,
        C2Color::YUV_420);
    helper->addStructDescriptors<C2ChromaOffsetStruct>();

    addParameter(DefineParam(mColorInfo, C2_PARAMKEY_CODED_COLOR_INFO)
                     .withConstValue(defaultColorInfo)
                     .build());

    addParameter(
        DefineParam(mDefaultColorAspects, C2_PARAMKEY_DEFAULT_COLOR_ASPECTS)
            .withDefault(new C2StreamColorAspectsTuning::output(
                0u, C2Color::RANGE_UNSPECIFIED, C2Color::PRIMARIES_UNSPECIFIED,
                C2Color::TRANSFER_UNSPECIFIED, C2Color::MATRIX_UNSPECIFIED))
            .withFields(
                {C2F(mDefaultColorAspects, range)
                     .inRange(C2Color::RANGE_UNSPECIFIED, C2Color::RANGE_OTHER),
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

    // TODO: support more formats?
    addParameter(DefineParam(mPixelFormat, C2_PARAMKEY_PIXEL_FORMAT)
                     .withConstValue(new C2StreamPixelFormatInfo::output(
                         0u, HAL_PIXEL_FORMAT_YCBCR_420_888))
                     .build());
  }

  static C2R SizeSetter(bool mayBlock,
                        const C2P<C2StreamPictureSizeInfo::output> &oldMe,
                        C2P<C2StreamPictureSizeInfo::output> &me) {
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

  static C2R MaxPictureSizeSetter(
      bool mayBlock, C2P<C2StreamMaxPictureSizeTuning::output> &me,
      const C2P<C2StreamPictureSizeInfo::output> &size) {
    (void)mayBlock;
    // TODO: get max width/height from the size's field helpers vs.
    // hardcoding
    me.set().width = c2_min(c2_max(me.v.width, size.v.width), 4096u);
    me.set().height = c2_min(c2_max(me.v.height, size.v.height), 4096u);
    return C2R::Ok();
  }

  static C2R MaxInputSizeSetter(
      bool mayBlock, C2P<C2StreamMaxBufferSizeInfo::input> &me,
      const C2P<C2StreamMaxPictureSizeTuning::output> &maxSize) {
    (void)mayBlock;
    // assume compression ratio of 2
    me.set().value =
        (((maxSize.v.width + 63) / 64) * ((maxSize.v.height + 63) / 64) * 3072);
    return C2R::Ok();
  }

  static C2R DefaultColorAspectsSetter(
      bool mayBlock, C2P<C2StreamColorAspectsTuning::output> &me) {
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

  static C2R ProfileLevelSetter(
      bool mayBlock, C2P<C2StreamProfileLevelInfo::input> &me,
      const C2P<C2StreamPictureSizeInfo::output> &size) {
    (void)mayBlock;
    (void)size;
    (void)me;  // TODO: validate
    return C2R::Ok();
  }

  std::shared_ptr<C2StreamColorAspectsTuning::output>
  getDefaultColorAspects_l() {
    return mDefaultColorAspects;
  }

  static C2R Hdr10PlusInfoInputSetter(bool mayBlock,
                                      C2P<C2StreamHdr10PlusInfo::input> &me) {
    (void)mayBlock;
    (void)me;  // TODO: validate
    return C2R::Ok();
  }

  static C2R Hdr10PlusInfoOutputSetter(bool mayBlock,
                                       C2P<C2StreamHdr10PlusInfo::output> &me) {
    (void)mayBlock;
    (void)me;  // TODO: validate
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
  std::shared_ptr<C2StreamHdr10PlusInfo::input> mHdr10PlusInfoInput;
  std::shared_ptr<C2StreamHdr10PlusInfo::output> mHdr10PlusInfoOutput;
};

C2SoftGav1Dec::C2SoftGav1Dec(const char *name, c2_node_id_t id,
                             const std::shared_ptr<IntfImpl> &intfImpl)
    : SimpleC2Component(
          std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl) {}

c2_status_t C2SoftGav1Dec::onInit() { return C2_OK; }
c2_status_t C2SoftGav1Dec::onStop() { return C2_OK; }
void C2SoftGav1Dec::onReset() {}
void C2SoftGav1Dec::onRelease(){};
c2_status_t C2SoftGav1Dec::onFlush_sm() { return C2_OK; }
void C2SoftGav1Dec::process(const std::unique_ptr<C2Work> & /*work*/,
                            const std::shared_ptr<C2BlockPool> & /*pool*/) {}
c2_status_t C2SoftGav1Dec::drain(
    uint32_t /*drainMode*/, const std::shared_ptr<C2BlockPool> & /*pool*/) {
  return C2_OK;
}

class C2SoftGav1Factory : public C2ComponentFactory {
 public:
  C2SoftGav1Factory()
      : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
            GetCodec2PlatformComponentStore()->getParamReflector())) {}

  virtual c2_status_t createComponent(
      c2_node_id_t id, std::shared_ptr<C2Component> *const component,
      std::function<void(C2Component *)> deleter) override {
    *component = std::shared_ptr<C2Component>(
        new C2SoftGav1Dec(COMPONENT_NAME, id,
                          std::make_shared<C2SoftGav1Dec::IntfImpl>(mHelper)),
        deleter);
    return C2_OK;
  }

  virtual c2_status_t createInterface(
      c2_node_id_t id, std::shared_ptr<C2ComponentInterface> *const interface,
      std::function<void(C2ComponentInterface *)> deleter) override {
    *interface = std::shared_ptr<C2ComponentInterface>(
        new SimpleInterface<C2SoftGav1Dec::IntfImpl>(
            COMPONENT_NAME, id,
            std::make_shared<C2SoftGav1Dec::IntfImpl>(mHelper)),
        deleter);
    return C2_OK;
  }

  virtual ~C2SoftGav1Factory() override = default;

 private:
  std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

extern "C" ::C2ComponentFactory *CreateCodec2Factory() {
  ALOGV("in %s", __func__);
  return new ::android::C2SoftGav1Factory();
}

extern "C" void DestroyCodec2Factory(::C2ComponentFactory *factory) {
  ALOGV("in %s", __func__);
  delete factory;
}
