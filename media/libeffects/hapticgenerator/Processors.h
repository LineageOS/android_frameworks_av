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

using android::audio_utils::BiquadFilter;
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
                 float normalizationPower, size_t channelCount);

    void process(float *out, const float *in, size_t frameCount);

    void clear();

private:
    const std::shared_ptr<BiquadFilter> mLpf;
    std::vector<float> mLpfInBuffer;
    std::vector<float> mLpfOutBuffer;
    const float mNormalizationPower;
    const float mChannelCount;
    const float mEnv;
};

// Helper functions

BiquadFilterCoefficients cascadeFirstOrderFilters(const BiquadFilterCoefficients &coefs1,
                                                  const BiquadFilterCoefficients &coefs2);

std::shared_ptr<BiquadFilter> createLPF(const float cornerFrequency,
                                        const float sampleRate,
                                        const size_t channelCount);

// Create two cascaded LPF with same corner frequency.
std::shared_ptr<BiquadFilter> createLPF2(const float cornerFrequency,
                                         const float sampleRate,
                                         const size_t channelCount);

// Create two cascaded HPF with same corner frequency.
std::shared_ptr<BiquadFilter> createHPF2(const float cornerFrequency,
                                         const float sampleRate,
                                         const size_t channelCount);

std::shared_ptr<BiquadFilter> createAPF(const float cornerFrequency,
                                        const float sampleRate,
                                        const size_t channelCount);

// Create two cascaded APF with two different corner frequency.
std::shared_ptr<BiquadFilter> createAPF2(const float cornerFrequency1,
                                         const float cornerFrequency2,
                                         const float sampleRate,
                                         const size_t channelCount);

std::shared_ptr<BiquadFilter> createBPF(const float ringingFrequency,
                                        const float q,
                                        const float sampleRate,
                                        const size_t channelCount);

std::shared_ptr<BiquadFilter> createBSF(const float ringingFrequency,
                                        const float zq,
                                        const float pq,
                                        const float sampleRate,
                                        const size_t channelCount);

} // namespace android::audio_effect::haptic_generator

#endif // _EFFECT_HAPTIC_GENERATOR_PROCESSORS_H_
