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

#pragma once

#include "effect-impl/EffectContext.h"
#include "Processors.h"

#include <vibrator/ExternalVibrationUtils.h>

#include <cstddef>
#include <map>

namespace aidl::android::hardware::audio::effect {

enum HapticGeneratorState {
    HAPTIC_GENERATOR_STATE_UNINITIALIZED,
    HAPTIC_GENERATOR_STATE_INITIALIZED,
    HAPTIC_GENERATOR_STATE_ACTIVE,
};

struct HapticGeneratorParam {
    // The audio channels used to generate haptic channels. The first channel will be used to
    // generate HAPTIC_A, The second channel will be used to generate HAPTIC_B.
    // The value will be offset of audio channel
    int mHapticChannelSource[2];

    int mHapticChannelCount;
    int mAudioChannelCount;

    std::map<int, HapticGenerator::VibratorScale> mHapticScales;
    // max intensity will be used to scale haptic data.
    HapticGenerator::VibratorScale mMaxVibratorScale;

    HapticGenerator::VibratorInformation mVibratorInfo;
};

// A structure to keep all shared pointers for all processors in HapticGenerator.
struct HapticGeneratorProcessorsRecord {
    std::vector<std::shared_ptr<HapticBiquadFilter>> filters;
    std::vector<std::shared_ptr<::android::audio_effect::haptic_generator::Ramp>> ramps;
    std::vector<std::shared_ptr<::android::audio_effect::haptic_generator::SlowEnvelope>> slowEnvs;
    std::vector<std::shared_ptr<::android::audio_effect::haptic_generator::Distortion>> distortions;

    // Cache band-pass filter and band-stop filter for updating parameters
    // according to vibrator info
    std::shared_ptr<HapticBiquadFilter> bpf;
    std::shared_ptr<HapticBiquadFilter> bsf;
};

class HapticGeneratorContext final : public EffectContext {
  public:
    HapticGeneratorContext(int statusDepth, const Parameter::Common& common);
    ~HapticGeneratorContext();
    RetCode enable();
    RetCode disable();
    void reset();

    RetCode setHgHapticScales(const std::vector<HapticGenerator::HapticScale>& hapticScales);
    std::vector<HapticGenerator::HapticScale> getHgHapticScales() const;

    RetCode setHgVibratorInformation(const HapticGenerator::VibratorInformation& vibratorInfo);
    HapticGenerator::VibratorInformation getHgVibratorInformation() const;

    IEffect::Status process(float* in, float* out, int samples);

    RetCode setCommon(const Parameter::Common& common) override;

  private:
    static constexpr float DEFAULT_RESONANT_FREQUENCY = 150.0f;
    static constexpr float DEFAULT_BSF_ZERO_Q = 8.0f;
    static constexpr float DEFAULT_BSF_POLE_Q = 4.0f;
    static constexpr float DEFAULT_DISTORTION_OUTPUT_GAIN = 1.5f;
    static constexpr float DEFAULT_BPF_Q = 1.0f;
    static constexpr float DEFAULT_SLOW_ENV_NORMALIZATION_POWER = -0.8f;
    static constexpr float DEFAULT_DISTORTION_CORNER_FREQUENCY = 300.0f;
    static constexpr float DEFAULT_DISTORTION_INPUT_GAIN = 0.3f;
    static constexpr float DEFAULT_DISTORTION_CUBE_THRESHOLD = 0.1f;

    HapticGeneratorState mState;
    HapticGeneratorParam mParams;
    int mSampleRate;
    int64_t mFrameCount = 0;

    // A cache for all shared pointers of the HapticGenerator
    struct HapticGeneratorProcessorsRecord mProcessorsRecord;

    // Using a vector of functions to record the processing chain for haptic-generating algorithm.
    // The three parameters of the processing functions are pointer to output buffer, pointer to
    // input buffer and frame count.
    std::vector<std::function<void(float*, const float*, size_t)>> mProcessingChain;

    // inputBuffer is where to keep input buffer for the generating algorithm. It will be
    // constructed according to hapticChannelSource.
    std::vector<float> mInputBuffer;

    // outputBuffer is a buffer having the same length as inputBuffer. It can be used as
    // intermediate buffer in the generating algorithm.
    std::vector<float> mOutputBuffer;

    void init_params(const Parameter::Common& common);
    void configure();

    float getDistortionOutputGain() const;
    float getFloatProperty(const std::string& key, float defaultValue) const;
    void addBiquadFilter(std::shared_ptr<HapticBiquadFilter> filter);
    void buildProcessingChain();
    float* runProcessingChain(float* buf1, float* buf2, size_t frameCount);

    std::string paramToString(const struct HapticGeneratorParam& param) const;
    std::string contextToString() const;
};

}  // namespace aidl::android::hardware::audio::effect
