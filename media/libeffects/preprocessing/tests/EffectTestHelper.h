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
#include <audio_effects/effect_aec.h>
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
    EffectTestHelper(const effect_uuid_t* uuid, size_t chMask, size_t sampleRate, size_t loopCount)
        : mUuid(uuid),
          mChMask(chMask),
          mChannelCount(audio_channel_count_from_in_mask(mChMask)),
          mSampleRate(sampleRate),
          mFrameCount(mSampleRate * kTenMilliSecVal),
          mLoopCount(loopCount) {}
    void createEffect();
    void releaseEffect();
    void setConfig(bool configReverse);
    void setParam(uint32_t type, uint32_t val);
    void process(int16_t* input, int16_t* output, bool setAecEchoDelay);
    void process_reverse(int16_t* farInput, int16_t* output);

    // Corresponds to SNR for 1 bit difference between two int16_t signals
    static constexpr float kSNRThreshold = 90.308998;

    static constexpr audio_channel_mask_t kChMasks[] = {
            AUDIO_CHANNEL_IN_MONO,
            AUDIO_CHANNEL_IN_STEREO,
            AUDIO_CHANNEL_IN_FRONT_BACK,
            AUDIO_CHANNEL_IN_6,
            AUDIO_CHANNEL_IN_2POINT0POINT2,
            AUDIO_CHANNEL_IN_2POINT1POINT2,
            AUDIO_CHANNEL_IN_3POINT0POINT2,
            AUDIO_CHANNEL_IN_3POINT1POINT2,
            AUDIO_CHANNEL_IN_5POINT1,
            AUDIO_CHANNEL_IN_VOICE_UPLINK_MONO,
            AUDIO_CHANNEL_IN_VOICE_DNLINK_MONO,
            AUDIO_CHANNEL_IN_VOICE_CALL_MONO,
    };

    static constexpr float kTenMilliSecVal = 0.01;

    static constexpr size_t kNumChMasks = std::size(kChMasks);

    static constexpr size_t kSampleRates[] = {8000,  11025, 12000, 16000, 22050,
                                              24000, 32000, 44100, 48000};

    static constexpr size_t kNumSampleRates = std::size(kSampleRates);

    static constexpr size_t kLoopCounts[] = {1, 4};

    static constexpr size_t kNumLoopCounts = std::size(kLoopCounts);

    static constexpr size_t kAECDelay = 0;

  private:
    const effect_uuid_t* mUuid;
    const size_t mChMask;
    const size_t mChannelCount;
    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    effect_handle_t mEffectHandle{};
};
