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

#include <cstddef>
#define LOG_TAG "PreProcessingContext"
#include <audio_utils/primitives.h>
#include <Utils.h>

#include "PreProcessingContext.h"

namespace aidl::android::hardware::audio::effect {

using aidl::android::media::audio::common::AudioDeviceDescription;
using aidl::android::media::audio::common::AudioDeviceType;

RetCode PreProcessingContext::init(const Parameter::Common& common) {
    std::lock_guard lg(mMutex);
    webrtc::AudioProcessingBuilder apBuilder;
    mAudioProcessingModule = apBuilder.Create();
    if (mAudioProcessingModule == nullptr) {
        LOG(ERROR) << "init could not get apm engine";
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }

    updateConfigs(common);

    mEnabledMsk = 0;
    mProcessedMsk = 0;
    mRevEnabledMsk = 0;
    mRevProcessedMsk = 0;

    auto config = mAudioProcessingModule->GetConfig();
    switch (mType) {
        case PreProcessingEffectType::ACOUSTIC_ECHO_CANCELLATION:
            config.echo_canceller.mobile_mode = true;
            break;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V1:
            config.gain_controller1.target_level_dbfs = kAgcDefaultTargetLevel;
            config.gain_controller1.compression_gain_db = kAgcDefaultCompGain;
            config.gain_controller1.enable_limiter = kAgcDefaultLimiter;
            break;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V2:
            config.gain_controller2.fixed_digital.gain_db = 0.f;
            break;
        case PreProcessingEffectType::NOISE_SUPPRESSION:
            config.noise_suppression.level = kNsDefaultLevel;
            break;
    }
    mAudioProcessingModule->ApplyConfig(config);
    mState = PRE_PROC_STATE_INITIALIZED;
    return RetCode::SUCCESS;
}

RetCode PreProcessingContext::deInit() {
    std::lock_guard lg(mMutex);
    mAudioProcessingModule = nullptr;
    mState = PRE_PROC_STATE_UNINITIALIZED;
    return RetCode::SUCCESS;
}

RetCode PreProcessingContext::enable() {
    if (mState != PRE_PROC_STATE_INITIALIZED) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    int typeMsk = (1 << int(mType));
    std::lock_guard lg(mMutex);
    // Check if effect is already enabled.
    if ((mEnabledMsk & typeMsk) == typeMsk) {
        return RetCode::ERROR_ILLEGAL_PARAMETER;
    }
    mEnabledMsk |= typeMsk;
    auto config = mAudioProcessingModule->GetConfig();
    switch (mType) {
        case PreProcessingEffectType::ACOUSTIC_ECHO_CANCELLATION:
            config.echo_canceller.enabled = true;
            // AEC has reverse stream
            mRevEnabledMsk |= typeMsk;
            mRevProcessedMsk = 0;
            break;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V1:
            config.gain_controller1.enabled = true;
            break;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V2:
            config.gain_controller2.enabled = true;
            break;
        case PreProcessingEffectType::NOISE_SUPPRESSION:
            config.noise_suppression.enabled = true;
            break;
    }
    mProcessedMsk = 0;
    mAudioProcessingModule->ApplyConfig(config);
    mState = PRE_PROC_STATE_ACTIVE;
    return RetCode::SUCCESS;
}

RetCode PreProcessingContext::disable() {
    if (mState != PRE_PROC_STATE_ACTIVE) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    int typeMsk = (1 << int(mType));
    std::lock_guard lg(mMutex);
    // Check if effect is already disabled.
    if ((mEnabledMsk & typeMsk) != typeMsk) {
        return RetCode::ERROR_ILLEGAL_PARAMETER;
    }
    mEnabledMsk &= ~typeMsk;
    auto config = mAudioProcessingModule->GetConfig();
    switch (mType) {
        case PreProcessingEffectType::ACOUSTIC_ECHO_CANCELLATION:
            config.echo_canceller.enabled = false;
            // AEC has reverse stream
            mRevEnabledMsk &= ~typeMsk;
            mRevProcessedMsk = 0;
            break;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V1:
            config.gain_controller1.enabled = false;
            break;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V2:
            config.gain_controller2.enabled = false;
            break;
        case PreProcessingEffectType::NOISE_SUPPRESSION:
            config.noise_suppression.enabled = false;
            break;
    }
    mProcessedMsk = 0;
    mAudioProcessingModule->ApplyConfig(config);
    mState = PRE_PROC_STATE_INITIALIZED;
    return RetCode::SUCCESS;
}

RetCode PreProcessingContext::setCommon(const Parameter::Common& common) {
    if (auto ret = updateIOFrameSize(common); ret != RetCode::SUCCESS) {
        return ret;
    }
    mCommon = common;
    updateConfigs(common);
    return RetCode::SUCCESS;
}

void PreProcessingContext::updateConfigs(const Parameter::Common& common) {
    mInputConfig.set_sample_rate_hz(common.input.base.sampleRate);
    mInputConfig.set_num_channels(::aidl::android::hardware::audio::common::getChannelCount(
            common.input.base.channelMask));
    mOutputConfig.set_sample_rate_hz(common.input.base.sampleRate);
    mOutputConfig.set_num_channels(::aidl::android::hardware::audio::common::getChannelCount(
            common.output.base.channelMask));
}

RetCode PreProcessingContext::setAcousticEchoCancelerEchoDelay(int echoDelayUs) {
    mEchoDelayUs = echoDelayUs;
    std::lock_guard lg(mMutex);
    mAudioProcessingModule->set_stream_delay_ms(mEchoDelayUs / 1000);
    return RetCode::SUCCESS;
}

int PreProcessingContext::getAcousticEchoCancelerEchoDelay() const {
    return mEchoDelayUs;
}

RetCode PreProcessingContext::setAcousticEchoCancelerMobileMode(bool mobileMode) {
    mMobileMode = mobileMode;
    std::lock_guard lg(mMutex);
    auto config = mAudioProcessingModule->GetConfig();
    config.echo_canceller.mobile_mode = mobileMode;
    mAudioProcessingModule->ApplyConfig(config);
    return RetCode::SUCCESS;
}

bool PreProcessingContext::getAcousticEchoCancelerMobileMode() const {
    return mMobileMode;
}

RetCode PreProcessingContext::setAutomaticGainControlV1TargetPeakLevel(int targetPeakLevel) {
    mTargetPeakLevel = targetPeakLevel;
    std::lock_guard lg(mMutex);
    auto config = mAudioProcessingModule->GetConfig();
    config.gain_controller1.target_level_dbfs = -(mTargetPeakLevel / 100);
    mAudioProcessingModule->ApplyConfig(config);
    return RetCode::SUCCESS;
}

int PreProcessingContext::getAutomaticGainControlV1TargetPeakLevel() const {
    return mTargetPeakLevel;
}

RetCode PreProcessingContext::setAutomaticGainControlV1MaxCompressionGain(int maxCompressionGain) {
    mMaxCompressionGain = maxCompressionGain;
    std::lock_guard lg(mMutex);
    auto config = mAudioProcessingModule->GetConfig();
    config.gain_controller1.compression_gain_db = mMaxCompressionGain / 100;
    mAudioProcessingModule->ApplyConfig(config);
    return RetCode::SUCCESS;
}

int PreProcessingContext::getAutomaticGainControlV1MaxCompressionGain() const {
    return mMaxCompressionGain;
}

RetCode PreProcessingContext::setAutomaticGainControlV1EnableLimiter(bool enableLimiter) {
    mEnableLimiter = enableLimiter;
    std::lock_guard lg(mMutex);
    auto config = mAudioProcessingModule->GetConfig();
    config.gain_controller1.enable_limiter = mEnableLimiter;
    mAudioProcessingModule->ApplyConfig(config);
    return RetCode::SUCCESS;
}

bool PreProcessingContext::getAutomaticGainControlV1EnableLimiter() const {
    return mEnableLimiter;
}

RetCode PreProcessingContext::setAutomaticGainControlV2DigitalGain(int gain) {
    mDigitalGain = gain;
    std::lock_guard lg(mMutex);
    auto config = mAudioProcessingModule->GetConfig();
    config.gain_controller2.fixed_digital.gain_db = mDigitalGain;
    mAudioProcessingModule->ApplyConfig(config);
    return RetCode::SUCCESS;
}

int PreProcessingContext::getAutomaticGainControlV2DigitalGain() const {
    return mDigitalGain;
}

RetCode PreProcessingContext::setAutomaticGainControlV2LevelEstimator(
        AutomaticGainControlV2::LevelEstimator levelEstimator) {
    mLevelEstimator = levelEstimator;
    return RetCode::SUCCESS;
}

AutomaticGainControlV2::LevelEstimator
PreProcessingContext::getAutomaticGainControlV2LevelEstimator() const {
    return mLevelEstimator;
}

RetCode PreProcessingContext::setAutomaticGainControlV2SaturationMargin(int saturationMargin) {
    mSaturationMargin = saturationMargin;
    return RetCode::SUCCESS;
}

int PreProcessingContext::getAutomaticGainControlV2SaturationMargin() const {
    return mSaturationMargin;
}

RetCode PreProcessingContext::setNoiseSuppressionLevel(NoiseSuppression::Level level) {
    mLevel = level;
    std::lock_guard lg(mMutex);
    auto config = mAudioProcessingModule->GetConfig();
    config.noise_suppression.level =
            (webrtc::AudioProcessing::Config::NoiseSuppression::Level)level;
    mAudioProcessingModule->ApplyConfig(config);
    return RetCode::SUCCESS;
}

NoiseSuppression::Level PreProcessingContext::getNoiseSuppressionLevel() const {
    return mLevel;
}

IEffect::Status PreProcessingContext::process(float* in, float* out, int samples) {
    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!in, status, "nullInput");
    RETURN_VALUE_IF(!out, status, "nullOutput");
    status = {EX_ILLEGAL_STATE, 0, 0};
    int64_t inputFrameCount = getCommon().input.frameCount;
    int64_t outputFrameCount = getCommon().output.frameCount;
    RETURN_VALUE_IF(inputFrameCount != outputFrameCount, status, "FrameCountMismatch");
    RETURN_VALUE_IF(0 == getInputFrameSize(), status, "zeroFrameSize");

    LOG(DEBUG) << __func__ << " start processing";
    std::lock_guard lg(mMutex);

    // webrtc implementation clear out was_stream_delay_set every time after ProcessStream() call
    mAudioProcessingModule->set_stream_delay_ms(mEchoDelayUs / 1000);

    std::vector<int16_t> in16(samples);
    std::vector<int16_t> out16(samples);
    memcpy_to_i16_from_float(in16.data(), in, samples);

    mProcessedMsk |= (1 << int(mType));

    if ((mProcessedMsk & mEnabledMsk) == mEnabledMsk) {
        mProcessedMsk = 0;
        int processStatus = mAudioProcessingModule->ProcessStream(in16.data(), mInputConfig,
                                                                  mOutputConfig, out16.data());
        if (processStatus != 0) {
            LOG(ERROR) << "Process stream failed with error " << processStatus;
            return status;
        }
    }

    if (mType == PreProcessingEffectType::ACOUSTIC_ECHO_CANCELLATION) {
        mRevProcessedMsk |= (1 << int(mType));
        if ((mRevProcessedMsk & mRevEnabledMsk) == mRevEnabledMsk) {
            mRevProcessedMsk = 0;
            int revProcessStatus = mAudioProcessingModule->ProcessReverseStream(
                    in16.data(), mInputConfig, mInputConfig, out16.data());
            if (revProcessStatus != 0) {
                LOG(ERROR) << "Process reverse stream failed with error " << revProcessStatus;
                return status;
            }
        }
    }

    memcpy_to_float_from_i16(out, out16.data(), samples);

    return {STATUS_OK, samples, samples};
}

}  // namespace aidl::android::hardware::audio::effect
