/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef _EFFECT_HAPTIC_GENERATOR_PROCESSORS_H_
#define _EFFECT_HAPTIC_GENERATOR_PROCESSORS_H_

#include <sys/types.h>

#include <memory>
#include <vector>

#include <audio_utils/BiquadFilter.h>

using HapticBiquadFilter = android::audio_utils::BiquadFilter<float>;
using BiquadFilterCoefficients = std::array<float, android::audio_utils::kBiquadNumCoefs>;

namespace android::audio_effect::haptic_generator {

// A class providing a process function that makes input data non-negative.
class Ramp {
public:
    explicit Ramp(size_t channelCount);

    void process(float *out, const float *in, size_t frameCount);

private:
    const size_t mChannelCount;
};


class SlowEnvelope {
public:
    SlowEnvelope(float cornerFrequency, float sampleRate,
                 float normalizationPower, float envOffset,
                 size_t channelCount);

    void process(float *out, const float *in, size_t frameCount);

    void setNormalizationPower(float normalizationPower);

    void clear();

private:
    const std::shared_ptr<HapticBiquadFilter> mLpf;
    std::vector<float> mLpfInBuffer;
    std::vector<float> mLpfOutBuffer;
    float mNormalizationPower;
    const float mEnvOffset;
    const float mChannelCount;
};


// A class providing a process function that compressively distorts a waveforms
class Distortion {
public:
    Distortion(float cornerFrequency, float sampleRate,
               float inputGain, float cubeThreshold,
               float outputGain, size_t channelCount);

    void process(float *out, const float *in, size_t frameCount);

    void setCornerFrequency(float cornerFrequency);
    void setInputGain(float inputGain);
    void setCubeThrehold(float cubeThreshold);
    void setOutputGain(float outputGain);

    void clear();

private:
    const std::shared_ptr<HapticBiquadFilter> mLpf;
    std::vector<float> mLpfInBuffer;
    float mSampleRate;
    float mCornerFrequency;
    float mInputGain;
    float mCubeThreshold;
    float mOutputGain;
    const size_t mChannelCount;
};

// Helper functions

BiquadFilterCoefficients cascadeFirstOrderFilters(const BiquadFilterCoefficients &coefs1,
                                                  const BiquadFilterCoefficients &coefs2);

BiquadFilterCoefficients lpfCoefs(const float cornerFrequency, const float sampleRate);

BiquadFilterCoefficients bpfCoefs(const float ringingFrequency,
                                  const float q,
                                  const float sampleRate);

BiquadFilterCoefficients bsfCoefs(const float ringingFrequency,
                                  const float zq,
                                  const float pq,
                                  const float sampleRate);

std::shared_ptr<HapticBiquadFilter> createLPF(const float cornerFrequency,
                                        const float sampleRate,
                                        const size_t channelCount);

// Create two cascaded LPF with same corner frequency.
std::shared_ptr<HapticBiquadFilter> createLPF2(const float cornerFrequency,
                                         const float sampleRate,
                                         const size_t channelCount);

// Create two cascaded HPF with same corner frequency.
std::shared_ptr<HapticBiquadFilter> createHPF2(const float cornerFrequency,
                                         const float sampleRate,
                                         const size_t channelCount);

std::shared_ptr<HapticBiquadFilter> createBPF(const float ringingFrequency,
                                        const float q,
                                        const float sampleRate,
                                        const size_t channelCount);

std::shared_ptr<HapticBiquadFilter> createBSF(const float ringingFrequency,
                                        const float zq,
                                        const float pq,
                                        const float sampleRate,
                                        const size_t channelCount);

} // namespace android::audio_effect::haptic_generator

#endif // _EFFECT_HAPTIC_GENERATOR_PROCESSORS_H_
