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

#ifndef ANDROID_C2_SOFT_AV1_ENC_H_
#define ANDROID_C2_SOFT_AV1_ENC_H_

#include <inttypes.h>

#include <C2PlatformSupport.h>
#include <Codec2BufferUtils.h>
#include <SimpleC2Component.h>
#include <SimpleC2Interface.h>
#include <util/C2InterfaceHelper.h>

#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "common/av1_config.h"

namespace android {
struct C2SoftAomEnc : public SimpleC2Component {
    class IntfImpl;

    C2SoftAomEnc(const char* name, c2_node_id_t id, const std::shared_ptr<IntfImpl>& intfImpl);

    // From SimpleC2Component
    c2_status_t onInit() override final;
    c2_status_t onStop() override final;
    void onReset() override final;
    void onRelease() override final;
    c2_status_t onFlush_sm() override final;

    void process(const std::unique_ptr<C2Work>& work,
                 const std::shared_ptr<C2BlockPool>& pool) override final;
    c2_status_t drain(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool) override final;

  protected:
    virtual ~C2SoftAomEnc();

  private:
    std::shared_ptr<IntfImpl> mIntf;

    // Initializes aom encoder with available settings.
    status_t initEncoder();

    // aom specific opaque data structure that
    // stores encoder state
    aom_codec_ctx_t* mCodecContext;

    // aom specific data structure that
    // stores encoder configuration
    aom_codec_enc_cfg_t* mCodecConfiguration;

    // aom specific read-only data structure
    // that specifies algorithm interface
    aom_codec_iface_t* mCodecInterface;

    // align stride to the power of 2
    int32_t mStrideAlign;

    aom_rc_mode mBitrateControlMode;

    // Minimum (best quality) quantizer
    uint32_t mMinQuantizer;

    // Maximum (worst quality) quantizer
    uint32_t mMaxQuantizer;

    // Last input buffer timestamp
    uint64_t mLastTimestamp;

    // Number of input frames
    int64_t mNumInputFrames;

    // Conversion buffer is needed to input to
    // yuv420 planar format.
    MemoryBlock mConversionBuffer;

    // Signalled End Of Stream
    bool mSignalledOutputEos;

    // Signalled Error
    bool mSignalledError;

    bool mHeadersReceived;

    bool mIs10Bit;

    uint32_t mAV1EncLevel;

    std::shared_ptr<C2StreamPictureSizeInfo::input> mSize;
    std::shared_ptr<C2StreamIntraRefreshTuning::output> mIntraRefresh;
    std::shared_ptr<C2StreamFrameRateInfo::output> mFrameRate;
    std::shared_ptr<C2StreamBitrateInfo::output> mBitrate;
    std::shared_ptr<C2StreamQualityTuning::output> mQuality;
    std::shared_ptr<C2StreamComplexityTuning::output> mComplexity;
    std::shared_ptr<C2StreamBitrateModeTuning::output> mBitrateMode;
    std::shared_ptr<C2StreamRequestSyncFrameTuning::output> mRequestSync;
    std::shared_ptr<C2StreamColorAspectsInfo::output> mColorAspects;
    std::shared_ptr<C2StreamPictureQuantizationTuning::output> mQpBounds;

    aom_codec_err_t setupCodecParameters();
};

class C2SoftAomEnc::IntfImpl : public SimpleInterface<void>::BaseParams {
  public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper>& helper);

    static C2R BitrateSetter(bool mayBlock, C2P<C2StreamBitrateInfo::output>& me);

    static C2R SizeSetter(bool mayBlock, const C2P<C2StreamPictureSizeInfo::input>& oldMe,
                          C2P<C2StreamPictureSizeInfo::input>& me);

    static C2R ProfileLevelSetter(bool mayBlock, C2P<C2StreamProfileLevelInfo::output>& me,
                                  const C2P<C2StreamPictureSizeInfo::input>& size,
                                  const C2P<C2StreamFrameRateInfo::output>& frameRate,
                                  const C2P<C2StreamBitrateInfo::output>& bitrate);
    static C2R PictureQuantizationSetter(bool mayBlock,
                                         C2P<C2StreamPictureQuantizationTuning::output> &me);

    // unsafe getters
    std::shared_ptr<C2StreamPictureSizeInfo::input> getSize_l() const { return mSize; }
    std::shared_ptr<C2StreamIntraRefreshTuning::output> getIntraRefresh_l() const {
        return mIntraRefresh;
    }
    std::shared_ptr<C2StreamFrameRateInfo::output> getFrameRate_l() const { return mFrameRate; }
    std::shared_ptr<C2StreamBitrateInfo::output> getBitrate_l() const { return mBitrate; }
    std::shared_ptr<C2StreamQualityTuning::output> getQuality_l() const { return mQuality; }
    std::shared_ptr<C2StreamComplexityTuning::output> getComplexity_l() const {
      return mComplexity;
    }
    std::shared_ptr<C2StreamBitrateModeTuning::output> getBitrateMode_l() const {
        return mBitrateMode;
    }
    std::shared_ptr<C2StreamRequestSyncFrameTuning::output> getRequestSync_l() const {
        return mRequestSync;
    }
    std::shared_ptr<C2StreamColorAspectsInfo::output> getCodedColorAspects_l() const {
        return mCodedColorAspects;
    }
    std::shared_ptr<C2StreamPixelFormatInfo::input> getPixelFormat_l() const {
        return mPixelFormat;
    }
    std::shared_ptr<C2StreamPictureQuantizationTuning::output> getPictureQuantization_l() const {
        return mPictureQuantization;
    }
    uint32_t getSyncFramePeriod() const;
    static C2R ColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::input>& me);
    static C2R CodedColorAspectsSetter(bool mayBlock, C2P<C2StreamColorAspectsInfo::output>& me,
                                       const C2P<C2StreamColorAspectsInfo::input>& coded);
    uint32_t getLevel_l() const;

  private:
    std::shared_ptr<C2StreamUsageTuning::input> mUsage;
    std::shared_ptr<C2StreamPictureSizeInfo::input> mSize;
    std::shared_ptr<C2StreamFrameRateInfo::output> mFrameRate;
    std::shared_ptr<C2StreamIntraRefreshTuning::output> mIntraRefresh;
    std::shared_ptr<C2StreamRequestSyncFrameTuning::output> mRequestSync;
    std::shared_ptr<C2StreamSyncFrameIntervalTuning::output> mSyncFramePeriod;
    std::shared_ptr<C2StreamBitrateInfo::output> mBitrate;
    std::shared_ptr<C2StreamQualityTuning::output> mQuality;
    std::shared_ptr<C2StreamComplexityTuning::output> mComplexity;
    std::shared_ptr<C2StreamBitrateModeTuning::output> mBitrateMode;
    std::shared_ptr<C2StreamProfileLevelInfo::output> mProfileLevel;
    std::shared_ptr<C2StreamColorAspectsInfo::input> mColorAspects;
    std::shared_ptr<C2StreamColorAspectsInfo::output> mCodedColorAspects;
    std::shared_ptr<C2StreamPixelFormatInfo::input> mPixelFormat;
    std::shared_ptr<C2StreamPictureQuantizationTuning::output> mPictureQuantization;

};

}  // namespace android
#endif  // ANDROID_C2_SOFT_AV1_ENC_H_
