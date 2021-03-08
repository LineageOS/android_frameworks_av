/*
 * Copyright 2021 The Android Open Source Project
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

#include <array>
#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <climits>
#include <cstdlib>
#include <gtest/gtest.h>
#include <hardware/audio_effect.h>
#include <log/log.h>
#include <random>
#include <stdint.h>
#include <system/audio.h>
#include <vector>

namespace android {
template <typename T>
static float computeSnr(const T* ref, const T* tst, size_t count) {
    double signal{};
    double noise{};

    for (size_t i = 0; i < count; ++i) {
        const double value(ref[i]);
        const double diff(tst[i] - value);
        signal += value * value;
        noise += diff * diff;
    }
    // Initialized to large value to handle
    // cases where ref and tst match exactly
    float snr = FLT_MAX;
    if (signal > 0.0f && noise > 0.0f) {
        snr = 10.f * log(signal / noise);
    }
    return snr;
}

class EffectTestHelper {
  public:
    EffectTestHelper(const effect_uuid_t* uuid, size_t inChMask, size_t outChMask,
                     size_t sampleRate, size_t frameCount, size_t loopCount)
        : mUuid(uuid),
          mInChMask(inChMask),
          mInChannelCount(audio_channel_count_from_out_mask(mInChMask)),
          mOutChMask(outChMask),
          mOutChannelCount(audio_channel_count_from_out_mask(mOutChMask)),
          mSampleRate(sampleRate),
          mFrameCount(frameCount),
          mLoopCount(loopCount) {}
    void createEffect();
    void releaseEffect();
    void setConfig();
    void setParam(uint32_t type, uint32_t val);
    void process(float* input, float* output);

    // Corresponds to SNR for 1 bit difference between two int16_t signals
    static constexpr float kSNRThreshold = 90.308998;

    static constexpr audio_channel_mask_t kChMasks[] = {
            AUDIO_CHANNEL_OUT_MONO,          AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_CHANNEL_OUT_2POINT1,       AUDIO_CHANNEL_OUT_2POINT0POINT2,
            AUDIO_CHANNEL_OUT_QUAD,          AUDIO_CHANNEL_OUT_QUAD_BACK,
            AUDIO_CHANNEL_OUT_QUAD_SIDE,     AUDIO_CHANNEL_OUT_SURROUND,
            AUDIO_CHANNEL_INDEX_MASK_4,      AUDIO_CHANNEL_OUT_2POINT1POINT2,
            AUDIO_CHANNEL_OUT_3POINT0POINT2, AUDIO_CHANNEL_OUT_PENTA,
            AUDIO_CHANNEL_INDEX_MASK_5,      AUDIO_CHANNEL_OUT_3POINT1POINT2,
            AUDIO_CHANNEL_OUT_5POINT1,       AUDIO_CHANNEL_OUT_5POINT1_BACK,
            AUDIO_CHANNEL_OUT_5POINT1_SIDE,  AUDIO_CHANNEL_INDEX_MASK_6,
            AUDIO_CHANNEL_OUT_6POINT1,       AUDIO_CHANNEL_INDEX_MASK_7,
            AUDIO_CHANNEL_OUT_5POINT1POINT2, AUDIO_CHANNEL_OUT_7POINT1,
            AUDIO_CHANNEL_INDEX_MASK_8,      AUDIO_CHANNEL_INDEX_MASK_9,
            AUDIO_CHANNEL_INDEX_MASK_10,     AUDIO_CHANNEL_INDEX_MASK_11,
            AUDIO_CHANNEL_INDEX_MASK_12,     AUDIO_CHANNEL_INDEX_MASK_13,
            AUDIO_CHANNEL_INDEX_MASK_14,     AUDIO_CHANNEL_INDEX_MASK_15,
            AUDIO_CHANNEL_INDEX_MASK_16,     AUDIO_CHANNEL_INDEX_MASK_17,
            AUDIO_CHANNEL_INDEX_MASK_18,     AUDIO_CHANNEL_INDEX_MASK_19,
            AUDIO_CHANNEL_INDEX_MASK_20,     AUDIO_CHANNEL_INDEX_MASK_21,
            AUDIO_CHANNEL_INDEX_MASK_22,     AUDIO_CHANNEL_INDEX_MASK_23,
            AUDIO_CHANNEL_INDEX_MASK_24,
    };

    static constexpr size_t kNumChMasks = std::size(kChMasks);

    static constexpr size_t kSampleRates[] = {8000,  11025, 12000, 16000, 22050,  24000, 32000,
                                              44100, 48000, 88200, 96000, 176400, 192000};

    static constexpr size_t kNumSampleRates = std::size(kSampleRates);

    static constexpr size_t kFrameCounts[] = {4, 2048};

    static constexpr size_t kNumFrameCounts = std::size(kFrameCounts);

    static constexpr size_t kLoopCounts[] = {1, 4};

    static constexpr size_t kNumLoopCounts = std::size(kLoopCounts);

  private:
    const effect_uuid_t* mUuid;
    const size_t mInChMask;
    const size_t mInChannelCount;
    const size_t mOutChMask;
    const size_t mOutChannelCount;
    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    effect_handle_t mEffectHandle{};
};
}  // namespace android
