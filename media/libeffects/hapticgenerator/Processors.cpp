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

#define LOG_TAG "EffectHG_Processors"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <assert.h>

#include <cmath>

#include "Processors.h"

#if defined(__aarch64__) || defined(__ARM_NEON__)
#ifndef USE_NEON
#define USE_NEON (true)
#endif
#else
#define USE_NEON (false)
#endif
#if USE_NEON
#include <arm_neon.h>
#endif

namespace android::audio_effect::haptic_generator {

float getRealPoleZ(float cornerFrequency, float sampleRate) {
    // This will be a pole of a first order filter.
    float realPoleS = -2 * M_PI * cornerFrequency;
    return exp(realPoleS / sampleRate); // zero-pole matching
}

std::pair<float, float> getComplexPoleZ(float ringingFrequency, float q, float sampleRate) {
    // This is the pole for 1/(s^2 + s/q + 1) in normalized frequency. The other pole is
    // the complex conjugate of this.
    float poleImagS = 2 * M_PI * ringingFrequency;
    float poleRealS = -poleImagS / (2 * q);
    float poleRadius = exp(poleRealS / sampleRate);
    float poleImagZ = poleRadius * sin(poleImagS / sampleRate);
    float poleRealZ = poleRadius * cos(poleImagS / sampleRate);
    return {poleRealZ, poleImagZ};
}

// Implementation of Ramp

Ramp::Ramp(size_t channelCount) : mChannelCount(channelCount) {}

void Ramp::process(float *out, const float *in, size_t frameCount) {
    size_t i = 0;
#if USE_NEON
    size_t sampleCount = frameCount * mChannelCount;
    float32x2_t allZero = vdup_n_f32(0.0f);
    while (i + 1 < sampleCount) {
        vst1_f32(out, vmax_f32(vld1_f32(in), allZero));
        in += 2;
        out += 2;
        i += 2;
    }
#endif // USE_NEON
    for (; i < frameCount * mChannelCount; ++i) {
        *out = *in >= 0.0f ? *in : 0.0f;
        out++;
        in++;
    }
}

// Implementation of SlowEnvelope

SlowEnvelope::SlowEnvelope(
        float cornerFrequency,
        float sampleRate,
        float normalizationPower,
        float envOffset,
        size_t channelCount)
        : mLpf(createLPF(cornerFrequency, sampleRate, channelCount)),
          mNormalizationPower(normalizationPower),
          mEnvOffset(envOffset),
          mChannelCount(channelCount) {}

void SlowEnvelope::process(float* out, const float* in, size_t frameCount) {
    size_t sampleCount = frameCount * mChannelCount;
    if (sampleCount > mLpfOutBuffer.size()) {
        mLpfOutBuffer.resize(sampleCount);
        mLpfInBuffer.resize(sampleCount);
    }
    for (size_t i = 0; i < sampleCount; ++i) {
        mLpfInBuffer[i] = fabs(in[i]);
    }
    mLpf->process(mLpfOutBuffer.data(), mLpfInBuffer.data(), frameCount);
    for (size_t i = 0; i < sampleCount; ++i) {
        out[i] = in[i] * pow(mLpfOutBuffer[i] + mEnvOffset, mNormalizationPower);
    }
}

void SlowEnvelope::setNormalizationPower(float normalizationPower) {
    mNormalizationPower = normalizationPower;
}

void SlowEnvelope::clear() {
    mLpf->clear();
}

// Implementation of distortion

Distortion::Distortion(
        float cornerFrequency,
        float sampleRate,
        float inputGain,
        float cubeThreshold,
        float outputGain,
        size_t channelCount)
        : mLpf(createLPF2(cornerFrequency, sampleRate, channelCount)),
          mSampleRate(sampleRate),
          mCornerFrequency(cornerFrequency),
          mInputGain(inputGain),
          mCubeThreshold(cubeThreshold),
          mOutputGain(outputGain),
          mChannelCount(channelCount) {}

void Distortion::process(float *out, const float *in, size_t frameCount) {
    size_t sampleCount = frameCount * mChannelCount;
    if (sampleCount > mLpfInBuffer.size()) {
        mLpfInBuffer.resize(sampleCount);
    }
    for (size_t i = 0; i < sampleCount; ++i) {
        const float x = mInputGain * in[i];
        mLpfInBuffer[i] = x * x * x / (mCubeThreshold + x * x);  // "Coring" nonlinearity.
    }
    mLpf->process(out, mLpfInBuffer.data(), frameCount);  // Reduce 3*F components.
    for (size_t i = 0; i < sampleCount; ++i) {
        const float x = out[i];
        out[i] = mOutputGain * x / (1.0f + fabs(x));  // Soft limiter.
    }
}

void Distortion::setCornerFrequency(float cornerFrequency) {
    mCornerFrequency = cornerFrequency;
    BiquadFilterCoefficients coefficient = lpfCoefs(cornerFrequency, mSampleRate);
    mLpf->setCoefficients(coefficient);
}

void Distortion::setInputGain(float inputGain) {
    mInputGain = inputGain;
}

void Distortion::setCubeThrehold(float cubeThreshold) {
    mCubeThreshold = cubeThreshold;
}

void Distortion::setOutputGain(float outputGain) {
    mOutputGain = outputGain;
}

void Distortion::clear() {
    mLpf->clear();
}


// Implementation of helper functions

BiquadFilterCoefficients cascadeFirstOrderFilters(const BiquadFilterCoefficients &coefs1,
                                                   const BiquadFilterCoefficients &coefs2) {
    assert(coefs1[2] == 0.0f);
    assert(coefs2[2] == 0.0f);
    assert(coefs1[4] == 0.0f);
    assert(coefs2[4] == 0.0f);
    return {coefs1[0] * coefs2[0],
            coefs1[0] * coefs2[1] + coefs1[1] * coefs2[0],
            coefs1[1] * coefs2[1],
            coefs1[3] + coefs2[3],
            coefs1[3] * coefs2[3]};
}

BiquadFilterCoefficients lpfCoefs(const float cornerFrequency, const float sampleRate) {
    BiquadFilterCoefficients coefficient;
    float realPoleZ = getRealPoleZ(cornerFrequency, sampleRate);
    // This is a zero at nyquist
    coefficient[0] = 0.5f * (1 - realPoleZ);
    coefficient[1] = coefficient[0];
    coefficient[2] = 0.0f;
    coefficient[3] = -realPoleZ; // This is traditional 1/(s+1) filter
    coefficient[4] = 0.0f;
    return coefficient;
}

BiquadFilterCoefficients bpfCoefs(const float ringingFrequency,
                                  const float q,
                                  const float sampleRate) {
    BiquadFilterCoefficients coefficient;
    const auto [real, img] = getComplexPoleZ(ringingFrequency, q, sampleRate);
    // Note: this is not a standard cookbook BPF, but a low pass filter with zero at DC
    coefficient[0] = 1.0f;
    coefficient[1] = -1.0f;
    coefficient[2] = 0.0f;
    coefficient[3] = -2 * real;
    coefficient[4] = real * real + img * img;
    return coefficient;
}

BiquadFilterCoefficients bsfCoefs(const float ringingFrequency,
                                  const float zq,
                                  const float pq,
                                  const float sampleRate) {
    BiquadFilterCoefficients coefficient;
    const auto [zeroReal, zeroImg] = getComplexPoleZ(ringingFrequency, zq, sampleRate);
    float zeroCoeff1 = -2 * zeroReal;
    float zeroCoeff2 = zeroReal* zeroReal + zeroImg * zeroImg;
    const auto [poleReal, poleImg] = getComplexPoleZ(ringingFrequency, pq, sampleRate);
    float poleCoeff1 = -2 * poleReal;
    float poleCoeff2 = poleReal * poleReal + poleImg * poleImg;
    const float norm = (1.0f + poleCoeff1 + poleCoeff2) / (1.0f + zeroCoeff1 + zeroCoeff2);
    coefficient[0] = 1.0f * norm;
    coefficient[1] = zeroCoeff1 * norm;
    coefficient[2] = zeroCoeff2 * norm;
    coefficient[3] = poleCoeff1;
    coefficient[4] = poleCoeff2;
    return coefficient;
}

std::shared_ptr<HapticBiquadFilter> createLPF(const float cornerFrequency,
                                        const float sampleRate,
                                        const size_t channelCount) {
    BiquadFilterCoefficients coefficient = lpfCoefs(cornerFrequency, sampleRate);
    return std::make_shared<HapticBiquadFilter>(channelCount, coefficient);
}

std::shared_ptr<HapticBiquadFilter> createLPF2(const float cornerFrequency,
                                         const float sampleRate,
                                         const size_t channelCount) {
    BiquadFilterCoefficients coefficient = lpfCoefs(cornerFrequency, sampleRate);
    return std::make_shared<HapticBiquadFilter>(
            channelCount, cascadeFirstOrderFilters(coefficient, coefficient));
}

std::shared_ptr<HapticBiquadFilter> createHPF2(const float cornerFrequency,
                                         const float sampleRate,
                                         const size_t channelCount) {
    BiquadFilterCoefficients coefficient;
    // Note: this is valid only when corner frequency is less than nyquist / 2.
    float realPoleZ = getRealPoleZ(cornerFrequency, sampleRate);

    // Note: this is a zero at DC
    coefficient[0] = 0.5f * (1 + realPoleZ);
    coefficient[1] = -coefficient[0];
    coefficient[2] = 0.0f;
    coefficient[3] = -realPoleZ;
    coefficient[4] = 0.0f;
    return std::make_shared<HapticBiquadFilter>(
            channelCount, cascadeFirstOrderFilters(coefficient, coefficient));
}

std::shared_ptr<HapticBiquadFilter> createBPF(const float ringingFrequency,
                                        const float q,
                                        const float sampleRate,
                                        const size_t channelCount) {
    BiquadFilterCoefficients coefficient = bpfCoefs(ringingFrequency, q, sampleRate);
    return std::make_shared<HapticBiquadFilter>(channelCount, coefficient);
}

std::shared_ptr<HapticBiquadFilter> createBSF(const float ringingFrequency,
                                        const float zq,
                                        const float pq,
                                        const float sampleRate,
                                        const size_t channelCount) {
    BiquadFilterCoefficients coefficient = bsfCoefs(ringingFrequency, zq, pq, sampleRate);
    return std::make_shared<HapticBiquadFilter>(channelCount, coefficient);
}

} // namespace android::audio_effect::haptic_generator
