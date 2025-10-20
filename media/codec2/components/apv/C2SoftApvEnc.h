/*
 * Copyright 2024 The Android Open Source Project
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

#ifndef ANDROID_C2_SOFT_APV_ENC_H_
#define ANDROID_C2_SOFT_APV_ENC_H_

#include <SimpleC2Component.h>
#include <util/C2InterfaceHelper.h>
#include <utils/Vector.h>
#include <map>
#include "oapv.h"

#include <C2SoftApvCommon.h>

namespace android {

#define CODEC_MAX_CORES 4

#define APV_QP_MIN 1
#define APV_QP_MAX 51

struct C2SoftApvEnc final : public SimpleC2Component {
    class IntfImpl;

    C2SoftApvEnc(const char* name, c2_node_id_t id, const std::shared_ptr<IntfImpl>& intfImpl);
    C2SoftApvEnc(const char* name, c2_node_id_t id,
                 const std::shared_ptr<C2ReflectorHelper>& helper);
    virtual ~C2SoftApvEnc();

    // From SimpleC2Component
    c2_status_t onInit() override;
    c2_status_t onStop() override;
    void onReset() override;
    void onRelease() override;
    c2_status_t onFlush_sm() override;
    void process(const std::unique_ptr<C2Work>& work,
                 const std::shared_ptr<C2BlockPool>& pool) override;
    c2_status_t drain(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool) override;

  private:
    c2_status_t resetEncoder();
    c2_status_t initEncoder();
    c2_status_t releaseEncoder();
    c2_status_t setEncodeArgs(oapv_frms_t* imgb_inp, const C2GraphicView* const input,
                              uint64_t workIndex);
    void finishWork(uint64_t workIndex, const std::unique_ptr<C2Work>& work,
                    const std::shared_ptr<C2BlockPool>& pool, oapv_bitb_t* bitb,
                    oapve_stat_t* stat);
    c2_status_t drainInternal(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool,
                              const std::unique_ptr<C2Work>& work);
    void setParams(oapve_param_t& param);

    void showEncoderParams(oapve_cdesc_t* cdsc);

    void ColorConvertP010ToYUV422P10le(const C2GraphicView* const input, oapv_imgb_t* imgb);

    void createCsdData(const std::unique_ptr<C2Work>& work, oapv_bitb_t* bitb,
                       uint32_t encodedSize);

    std::shared_ptr<IntfImpl> mIntf;
    int32_t mBitDepth;
    int32_t mColorFormat;

    bool mStarted;
    bool mSignalledEos;
    bool mSignalledError;

    std::shared_ptr<C2StreamBitrateInfo::output> mBitrate;
    std::shared_ptr<C2StreamBitrateModeTuning::output> mBitrateMode;
    std::shared_ptr<C2StreamPictureSizeInfo::input> mSize;
    std::shared_ptr<C2StreamFrameRateInfo::output> mFrameRate;
    std::shared_ptr<C2StreamProfileLevelInfo::output> mProfileLevel;
    std::shared_ptr<C2StreamColorAspectsInfo::input> mColorAspects;
    std::shared_ptr<C2StreamColorAspectsInfo::output> mCodedColorAspects;
    std::shared_ptr<C2StreamPictureQuantizationTuning::output> mPictureQuantization;
    std::shared_ptr<C2StreamQualityTuning::output> mQuality;
    std::shared_ptr<C2LinearBlock> mOutBlock;
    std::shared_ptr<C2StreamComplexityTuning::output> mComplexity;
    std::shared_ptr<C2StreamPixelFormatInfo::input> mPixelFormat;

    std::map<const void*, std::shared_ptr<C2Buffer>> mBuffers;
    MemoryBlockPool mConversionBuffers;
    std::map<const void*, MemoryBlock> mConversionBuffersInUse;

    bool mInitEncoder;
    int32_t mMaxFrames;
    int32_t mReceivedFrames;
    std::unique_ptr<oapve_cdesc_t> mCodecDesc;
    oapv_frms_t mInputFrames;
    oapv_frms_t mReconFrames;
    oapve_t mEncoderId;
    oapvm_t mMetaId;
    uint8_t* mBitstreamBuf = nullptr;
    bool mReceivedFirstFrame = false;
    C2_DO_NOT_COPY(C2SoftApvEnc);
};
}  // namespace android

#endif  // ANDROID_C2_SOFT_APV_ENC_H_
