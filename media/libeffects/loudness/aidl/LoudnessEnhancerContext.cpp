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

#include "LoudnessEnhancerContext.h"

namespace aidl::android::hardware::audio::effect {

LoudnessEnhancerContext::LoudnessEnhancerContext(int statusDepth, const Parameter::Common& common)
    : EffectContext(statusDepth, common) {
    LOG(DEBUG) << __func__;
    mState = LOUDNESS_ENHANCER_STATE_UNINITIALIZED;
    mSampleRate = common.input.base.sampleRate;
    init_params();
}

LoudnessEnhancerContext::~LoudnessEnhancerContext() {
    LOG(DEBUG) << __func__;
    mState = LOUDNESS_ENHANCER_STATE_UNINITIALIZED;
}

RetCode LoudnessEnhancerContext::enable() {
    if (mState != LOUDNESS_ENHANCER_STATE_INITIALIZED) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    mState = LOUDNESS_ENHANCER_STATE_ACTIVE;
    return RetCode::SUCCESS;
}

RetCode LoudnessEnhancerContext::disable() {
    if (mState != LOUDNESS_ENHANCER_STATE_ACTIVE) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    mState = LOUDNESS_ENHANCER_STATE_INITIALIZED;
    return RetCode::SUCCESS;
}

void LoudnessEnhancerContext::reset() {
    float targetAmp = pow(10, mGain / 2000.0f);  // mB to linear amplification
    {
        std::lock_guard lg(mMutex);
        if (mCompressor != nullptr) {
            // Get samplingRate from input
            mCompressor->Initialize(targetAmp, mSampleRate);
        }
    }
}

RetCode LoudnessEnhancerContext::setLeGain(int gainMb) {
    mGain = gainMb;
    reset();  // apply parameter update
    return RetCode::SUCCESS;
}

IEffect::Status LoudnessEnhancerContext::lvmProcess(float* in, float* out, int samples) {
    LOG(DEBUG) << __func__ << " in " << in << " out " << out << " sample " << samples;

    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!in, status, "nullInput");
    RETURN_VALUE_IF(!out, status, "nullOutput");
    status = {EX_ILLEGAL_STATE, 0, 0};
    RETURN_VALUE_IF(getInputFrameSize() != getOutputFrameSize(), status, "FrameSizeMismatch");
    auto frameSize = getInputFrameSize();
    RETURN_VALUE_IF(0 == frameSize, status, "zeroFrameSize");

    LOG(DEBUG) << __func__ << " start processing";
    {
        std::lock_guard lg(mMutex);
        // PcmType is always expected to be Float 32 bit.
        constexpr float scale = 1 << 15;  // power of 2 is lossless conversion to int16_t range
        constexpr float inverseScale = 1.f / scale;
        const float inputAmp = pow(10, mGain / 2000.0f) * scale;
        float leftSample, rightSample;
        if (mCompressor != nullptr) {
            for (int inIdx = 0; inIdx < samples; inIdx += 2) {
                // makeup gain is applied on the input of the compressor
                leftSample = inputAmp * in[inIdx];
                rightSample = inputAmp * in[inIdx + 1];
                mCompressor->Compress(&leftSample, &rightSample);
                in[inIdx] = leftSample * inverseScale;
                in[inIdx + 1] = rightSample * inverseScale;
            }
        } else {
            for (int inIdx = 0; inIdx < samples; inIdx += 2) {
                leftSample = inputAmp * in[inIdx];
                rightSample = inputAmp * in[inIdx + 1];
                in[inIdx] = leftSample * inverseScale;
                in[inIdx + 1] = rightSample * inverseScale;
            }
        }
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
    }
    return {STATUS_OK, samples, samples};
}

void LoudnessEnhancerContext::init_params() {
    mGain = LOUDNESS_ENHANCER_DEFAULT_TARGET_GAIN_MB;
    float targetAmp = pow(10, mGain / 2000.0f);  // mB to linear amplification
    LOG(DEBUG) << __func__ << "Target gain = " << mGain << "mB <=> factor = " << targetAmp;

    {
        std::lock_guard lg(mMutex);
        mCompressor = std::make_unique<le_fx::AdaptiveDynamicRangeCompression>();
        mCompressor->Initialize(targetAmp, mSampleRate);
    }
    mState = LOUDNESS_ENHANCER_STATE_INITIALIZED;
}

}  // namespace aidl::android::hardware::audio::effect
