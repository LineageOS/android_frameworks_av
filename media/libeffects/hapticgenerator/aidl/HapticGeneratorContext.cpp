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

#include <cstddef>
#define LOG_TAG "AHAL_HapticGeneratorContext"

#include <Utils.h>
#include <android-base/logging.h>
#include <android-base/parsedouble.h>
#include <android-base/properties.h>

#include "HapticGeneratorContext.h"

namespace aidl::android::hardware::audio::effect {

HapticGeneratorContext::HapticGeneratorContext(int statusDepth, const Parameter::Common& common)
    : EffectContext(statusDepth, common) {
    LOG(DEBUG) << __func__;
    mState = HAPTIC_GENERATOR_STATE_UNINITIALIZED;
    mSampleRate = common.input.base.sampleRate;
    mFrameCount = common.input.frameCount;
    init_params(common.input.base.channelMask, common.output.base.channelMask);
}

HapticGeneratorContext::~HapticGeneratorContext() {
    LOG(DEBUG) << __func__;
    mState = HAPTIC_GENERATOR_STATE_UNINITIALIZED;
}

RetCode HapticGeneratorContext::enable() {
    if (mState != HAPTIC_GENERATOR_STATE_INITIALIZED) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    mState = HAPTIC_GENERATOR_STATE_ACTIVE;
    return RetCode::SUCCESS;
}

RetCode HapticGeneratorContext::disable() {
    if (mState != HAPTIC_GENERATOR_STATE_ACTIVE) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    mState = HAPTIC_GENERATOR_STATE_INITIALIZED;
    return RetCode::SUCCESS;
}

void HapticGeneratorContext::reset() {
    for (auto& filter : mProcessorsRecord.filters) {
        filter->clear();
    }
    for (auto& slowEnv : mProcessorsRecord.slowEnvs) {
        slowEnv->clear();
    }
    for (auto& distortion : mProcessorsRecord.distortions) {
        distortion->clear();
    }
}

RetCode HapticGeneratorContext::setHgHapticScales(
        const std::vector<HapticGenerator::HapticScale>& hapticScales) {
    std::lock_guard lg(mMutex);
    for (auto hapticScale : hapticScales) {
        mParams.mHapticScales.insert_or_assign(hapticScale.id, hapticScale.scale);
    }
    mParams.mMaxVibratorScale = HapticGenerator::VibratorScale::MUTE;
    for (const auto& [id, vibratorScale] : mParams.mHapticScales) {
        mParams.mMaxVibratorScale = std::max(mParams.mMaxVibratorScale, vibratorScale);
    }
    return RetCode::SUCCESS;
}

HapticGenerator::VibratorInformation HapticGeneratorContext::getHgVibratorInformation() {
    std::lock_guard lg(mMutex);
    return mParams.mVibratorInfo;
}

std::vector<HapticGenerator::HapticScale> HapticGeneratorContext::getHgHapticScales() {
    std::vector<HapticGenerator::HapticScale> result;
    std::lock_guard lg(mMutex);
    for (const auto& [id, vibratorScale] : mParams.mHapticScales) {
        result.push_back({id, vibratorScale});
    }
    return result;
}

RetCode HapticGeneratorContext::setHgVibratorInformation(
        const HapticGenerator::VibratorInformation& vibratorInfo) {
    {
        std::lock_guard lg(mMutex);
        mParams.mVibratorInfo = vibratorInfo;

        if (mProcessorsRecord.bpf != nullptr) {
            mProcessorsRecord.bpf->setCoefficients(
                    ::android::audio_effect::haptic_generator::bpfCoefs(
                            mParams.mVibratorInfo.resonantFrequencyHz, DEFAULT_BPF_Q, mSampleRate));
        }
        if (mProcessorsRecord.bsf != nullptr) {
            mProcessorsRecord.bsf->setCoefficients(
                    ::android::audio_effect::haptic_generator::bsfCoefs(
                            mParams.mVibratorInfo.resonantFrequencyHz,
                            mParams.mVibratorInfo.qFactor, mParams.mVibratorInfo.qFactor / 2.0f,
                            mSampleRate));
        }
    }
    configure();
    return RetCode::SUCCESS;
}

IEffect::Status HapticGeneratorContext::process(float* in, float* out, int samples) {
    LOG(DEBUG) << __func__ << " in " << in << " out " << out << " sample " << samples;

    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!in, status, "nullInput");
    RETURN_VALUE_IF(!out, status, "nullOutput");
    status = {EX_ILLEGAL_STATE, 0, 0};
    RETURN_VALUE_IF(getInputFrameSize() != getOutputFrameSize(), status, "FrameSizeMismatch");
    auto frameSize = getInputFrameSize();
    RETURN_VALUE_IF(0 == frameSize, status, "zeroFrameSize");

    LOG(DEBUG) << __func__ << " start processing";
    // The audio data must not be modified but just written to
    // output buffer according the access mode.
    bool accumulate = false;
    if (in != out) {
        for (int i = 0; i < samples; i++) {
            if (accumulate) {
                out[i] += in[i];
            } else {
                out[i] = in[i];
            }
        }
    }

    if (mState != HAPTIC_GENERATOR_STATE_ACTIVE) {
        return status;
    }

    std::lock_guard lg(mMutex);
    if (mParams.mMaxVibratorScale == HapticGenerator::VibratorScale::MUTE) {
        // Haptic channels are muted, not need to generate haptic data.
        return {STATUS_OK, samples, samples};
    }

    // Resize buffer if the haptic sample count is greater than buffer size.
    size_t hapticSampleCount = mFrameCount * mParams.mHapticChannelCount;
    if (hapticSampleCount > mInputBuffer.size()) {
        // The inputBuffer and outputBuffer must have the same size, which must be at least
        // the haptic sample count.
        mInputBuffer.resize(hapticSampleCount);
        mOutputBuffer.resize(hapticSampleCount);
    }

    // Construct input buffer according to haptic channel source
    for (int64_t i = 0; i < mFrameCount; ++i) {
        for (int j = 0; j < mParams.mHapticChannelCount; ++j) {
            mInputBuffer[i * mParams.mHapticChannelCount + j] =
                    in[i * mParams.mAudioChannelCount + mParams.mHapticChannelSource[j]];
        }
    }

    float* hapticOutBuffer =
            runProcessingChain(mInputBuffer.data(), mOutputBuffer.data(), mFrameCount);
    ::android::os::scaleHapticData(
            hapticOutBuffer, hapticSampleCount,
            static_cast<::android::os::HapticScale>(mParams.mMaxVibratorScale),
            mParams.mVibratorInfo.qFactor);

    // For haptic data, the haptic playback thread will copy the data from effect input
    // buffer, which contains haptic data at the end of the buffer, directly to sink buffer.
    // In that case, copy haptic data to input buffer instead of output buffer.
    // Note: this may not work with rpc/binder calls
    for (size_t i = 0; i < hapticSampleCount; ++i) {
        in[samples + i] = hapticOutBuffer[i];
    }
    return {STATUS_OK, samples, static_cast<int32_t>(samples + hapticSampleCount)};
}

void HapticGeneratorContext::init_params(media::audio::common::AudioChannelLayout inputChMask,
                                         media::audio::common::AudioChannelLayout outputChMask) {
    std::lock_guard lg(mMutex);
    mParams.mMaxVibratorScale = HapticGenerator::VibratorScale::MUTE;
    mParams.mVibratorInfo.resonantFrequencyHz = DEFAULT_RESONANT_FREQUENCY;
    mParams.mVibratorInfo.qFactor = DEFAULT_BSF_ZERO_Q;

    mParams.mAudioChannelCount = ::aidl::android::hardware::audio::common::getChannelCount(
            inputChMask, ~media::audio::common::AudioChannelLayout::LAYOUT_HAPTIC_AB);
    mParams.mHapticChannelCount = ::aidl::android::hardware::audio::common::getChannelCount(
            outputChMask, media::audio::common::AudioChannelLayout::LAYOUT_HAPTIC_AB);
    LOG_ALWAYS_FATAL_IF(mParams.mHapticChannelCount > 2, "haptic channel count is too large");
    for (int i = 0; i < mParams.mHapticChannelCount; ++i) {
        // By default, use the first audio channel to generate haptic channels.
        mParams.mHapticChannelSource[i] = 0;
    }

    mState = HAPTIC_GENERATOR_STATE_INITIALIZED;
}

float HapticGeneratorContext::getDistortionOutputGain() {
    float distortionOutputGain = getFloatProperty(
            "vendor.audio.hapticgenerator.distortion.output.gain", DEFAULT_DISTORTION_OUTPUT_GAIN);
    LOG(DEBUG) << "Using distortion output gain as " << distortionOutputGain;
    return distortionOutputGain;
}

float HapticGeneratorContext::getFloatProperty(const std::string& key, float defaultValue) {
    float result;
    std::string value = ::android::base::GetProperty(key, "");
    if (!value.empty() && ::android::base::ParseFloat(value, &result)) {
        return result;
    }
    return defaultValue;
}

void HapticGeneratorContext::addBiquadFilter(std::shared_ptr<HapticBiquadFilter> filter) {
    // The process chain captures the shared pointer of the filter in lambda.
    // The process record will keep a shared pointer to the filter so that it is possible to
    // access the filter outside of the process chain.
    mProcessorsRecord.filters.push_back(filter);
    mProcessingChain.push_back([filter](float* out, const float* in, size_t frameCount) {
        filter->process(out, in, frameCount);
    });
}

/**
 * Build haptic generator processing chain.
 */
void HapticGeneratorContext::buildProcessingChain() {
    std::lock_guard lg(mMutex);
    const size_t channelCount = mParams.mHapticChannelCount;
    float highPassCornerFrequency = 50.0f;
    auto hpf = ::android::audio_effect::haptic_generator::createHPF2(highPassCornerFrequency,
                                                                     mSampleRate, channelCount);
    addBiquadFilter(hpf);
    float lowPassCornerFrequency = 9000.0f;
    auto lpf = ::android::audio_effect::haptic_generator::createLPF2(lowPassCornerFrequency,
                                                                     mSampleRate, channelCount);
    addBiquadFilter(lpf);

    auto ramp = std::make_shared<::android::audio_effect::haptic_generator::Ramp>(
            channelCount);  // ramp = half-wave rectifier.
    // The process chain captures the shared pointer of the ramp in lambda. It will be the only
    // reference to the ramp.
    // The process record will keep a weak pointer to the ramp so that it is possible to access
    // the ramp outside of the process chain.
    mProcessorsRecord.ramps.push_back(ramp);
    mProcessingChain.push_back([ramp](float* out, const float* in, size_t frameCount) {
        ramp->process(out, in, frameCount);
    });

    highPassCornerFrequency = 60.0f;
    hpf = ::android::audio_effect::haptic_generator::createHPF2(highPassCornerFrequency,
                                                                mSampleRate, channelCount);
    addBiquadFilter(hpf);
    lowPassCornerFrequency = 700.0f;
    lpf = ::android::audio_effect::haptic_generator::createLPF2(lowPassCornerFrequency, mSampleRate,
                                                                channelCount);
    addBiquadFilter(lpf);

    lowPassCornerFrequency = 400.0f;
    lpf = ::android::audio_effect::haptic_generator::createLPF2(lowPassCornerFrequency, mSampleRate,
                                                                channelCount);
    addBiquadFilter(lpf);
    lowPassCornerFrequency = 500.0f;
    lpf = ::android::audio_effect::haptic_generator::createLPF2(lowPassCornerFrequency, mSampleRate,
                                                                channelCount);
    addBiquadFilter(lpf);

    auto bpf = ::android::audio_effect::haptic_generator::createBPF(
            mParams.mVibratorInfo.resonantFrequencyHz, DEFAULT_BPF_Q, mSampleRate, channelCount);
    mProcessorsRecord.bpf = bpf;
    addBiquadFilter(bpf);

    float normalizationPower = DEFAULT_SLOW_ENV_NORMALIZATION_POWER;
    // The process chain captures the shared pointer of the slow envelope in lambda. It will
    // be the only reference to the slow envelope.
    // The process record will keep a weak pointer to the slow envelope so that it is possible
    // to access the slow envelope outside of the process chain.
    // SlowEnvelope = partial normalizer, or AGC.
    auto slowEnv = std::make_shared<::android::audio_effect::haptic_generator::SlowEnvelope>(
            5.0f /*envCornerFrequency*/, mSampleRate, normalizationPower, 0.01f /*envOffset*/,
            channelCount);
    mProcessorsRecord.slowEnvs.push_back(slowEnv);
    mProcessingChain.push_back([slowEnv](float* out, const float* in, size_t frameCount) {
        slowEnv->process(out, in, frameCount);
    });

    auto bsf = ::android::audio_effect::haptic_generator::createBSF(
            mParams.mVibratorInfo.resonantFrequencyHz, mParams.mVibratorInfo.qFactor,
            mParams.mVibratorInfo.qFactor / 2.0f, mSampleRate, channelCount);
    mProcessorsRecord.bsf = bsf;
    addBiquadFilter(bsf);

    // The process chain captures the shared pointer of the Distortion in lambda. It will
    // be the only reference to the Distortion.
    // The process record will keep a weak pointer to the Distortion so that it is possible
    // to access the Distortion outside of the process chain.
    auto distortion = std::make_shared<::android::audio_effect::haptic_generator::Distortion>(
            DEFAULT_DISTORTION_CORNER_FREQUENCY, mSampleRate, DEFAULT_DISTORTION_INPUT_GAIN,
            DEFAULT_DISTORTION_CUBE_THRESHOLD, getDistortionOutputGain(), channelCount);
    mProcessorsRecord.distortions.push_back(distortion);
    mProcessingChain.push_back([distortion](float* out, const float* in, size_t frameCount) {
        distortion->process(out, in, frameCount);
    });
}

void HapticGeneratorContext::configure() {
    mProcessingChain.clear();
    mProcessorsRecord.filters.clear();
    mProcessorsRecord.ramps.clear();
    mProcessorsRecord.slowEnvs.clear();
    mProcessorsRecord.distortions.clear();

    buildProcessingChain();
}

/**
 * Run the processing chain to generate haptic data from audio data
 *
 * @param buf1 a buffer contains raw audio data
 * @param buf2 a buffer that is large enough to keep all the data
 * @param frameCount frame count of the data
 *
 * @return a pointer to the output buffer
 */
float* HapticGeneratorContext::runProcessingChain(float* buf1, float* buf2, size_t frameCount) {
    float* in = buf1;
    float* out = buf2;
    for (const auto processingFunc : mProcessingChain) {
        processingFunc(out, in, frameCount);
        std::swap(in, out);
    }
    return in;
}

}  // namespace aidl::android::hardware::audio::effect
