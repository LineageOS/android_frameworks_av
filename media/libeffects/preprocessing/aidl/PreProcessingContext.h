/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <android-base/logging.h>
#include <android-base/thread_annotations.h>
#include <audio_processing.h>
#include <unordered_map>

#include "PreProcessingTypes.h"
#include "effect-impl/EffectContext.h"

namespace aidl::android::hardware::audio::effect {

enum PreProcEffectState {
    PRE_PROC_STATE_UNINITIALIZED,
    PRE_PROC_STATE_INITIALIZED,
    PRE_PROC_STATE_ACTIVE,
};

class PreProcessingContext final : public EffectContext {
  public:
    PreProcessingContext(int statusDepth, const Parameter::Common& common,
                         const PreProcessingEffectType& type)
        : EffectContext(statusDepth, common), mType(type) {
        LOG(DEBUG) << __func__ << type;
        mState = PRE_PROC_STATE_UNINITIALIZED;
    }
    ~PreProcessingContext() override { LOG(DEBUG) << __func__; }

    RetCode init(const Parameter::Common& common);
    RetCode deInit();

    PreProcessingEffectType getPreProcessingType() const { return mType; }

    RetCode enable();
    RetCode disable();

    RetCode setCommon(const Parameter::Common& common) override;
    void updateConfigs(const Parameter::Common& common);

    RetCode setAcousticEchoCancelerEchoDelay(int echoDelayUs);
    int getAcousticEchoCancelerEchoDelay() const;
    RetCode setAcousticEchoCancelerMobileMode(bool mobileMode);
    bool getAcousticEchoCancelerMobileMode() const;

    RetCode setAutomaticGainControlV1TargetPeakLevel(int targetPeakLevel);
    int getAutomaticGainControlV1TargetPeakLevel() const;
    RetCode setAutomaticGainControlV1MaxCompressionGain(int maxCompressionGain);
    int getAutomaticGainControlV1MaxCompressionGain() const;
    RetCode setAutomaticGainControlV1EnableLimiter(bool enableLimiter);
    bool getAutomaticGainControlV1EnableLimiter() const;

    RetCode setAutomaticGainControlV2DigitalGain(int gain);
    int getAutomaticGainControlV2DigitalGain() const;
    RetCode setAutomaticGainControlV2LevelEstimator(
            AutomaticGainControlV2::LevelEstimator levelEstimator);
    AutomaticGainControlV2::LevelEstimator getAutomaticGainControlV2LevelEstimator() const;
    RetCode setAutomaticGainControlV2SaturationMargin(int saturationMargin);
    int getAutomaticGainControlV2SaturationMargin() const;

    RetCode setNoiseSuppressionLevel(NoiseSuppression::Level level);
    NoiseSuppression::Level getNoiseSuppressionLevel() const;

    IEffect::Status process(float* in, float* out, int samples);

  private:
    static constexpr inline int kAgcDefaultTargetLevel = 3;
    static constexpr inline int kAgcDefaultCompGain = 9;
    static constexpr inline bool kAgcDefaultLimiter = true;
    static constexpr inline webrtc::AudioProcessing::Config::NoiseSuppression::Level
            kNsDefaultLevel = webrtc::AudioProcessing::Config::NoiseSuppression::kModerate;

    std::mutex mMutex;
    const PreProcessingEffectType mType;
    PreProcEffectState mState;  // current state

    // handle on webRTC audio processing module (APM)
    rtc::scoped_refptr<webrtc::AudioProcessing> mAudioProcessingModule GUARDED_BY(mMutex);

    int mEnabledMsk GUARDED_BY(mMutex);       // bit field containing IDs of enabled pre processors
    int mProcessedMsk GUARDED_BY(mMutex);     // bit field containing IDs of pre processors already
                                              // processed in current round
    int mRevEnabledMsk GUARDED_BY(mMutex);    // bit field containing IDs of enabled pre processors
                                              // with reverse channel
    int mRevProcessedMsk GUARDED_BY(mMutex);  // bit field containing IDs of pre processors with
                                              // reverse channel already processed in current round

    webrtc::StreamConfig mInputConfig;   // input stream configuration
    webrtc::StreamConfig mOutputConfig;  // output stream configuration

    // Acoustic Echo Canceler
    int mEchoDelayUs = 0;
    bool mMobileMode = false;

    // Automatic Gain Control V1
    int mTargetPeakLevel = 0;
    int mMaxCompressionGain = 0;
    bool mEnableLimiter = false;

    // Automatic Gain Control V2
    int mDigitalGain = 0;
    AutomaticGainControlV2::LevelEstimator mLevelEstimator =
            AutomaticGainControlV2::LevelEstimator::RMS;
    int mSaturationMargin = 2;

    // NoiseSuppression
    NoiseSuppression::Level mLevel = NoiseSuppression::Level::LOW;
};

}  // namespace aidl::android::hardware::audio::effect
