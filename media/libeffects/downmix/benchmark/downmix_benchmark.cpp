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

#include <random>
#include <vector>

#include <audio_effects/effect_downmix.h>
#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <audio_utils/Statistics.h>
#include <benchmark/benchmark.h>
#include <log/log.h>
#include <system/audio.h>

#include "EffectDownmix.h"

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

static constexpr audio_channel_mask_t kChannelPositionMasks[] = {
    AUDIO_CHANNEL_OUT_FRONT_LEFT,
    AUDIO_CHANNEL_OUT_FRONT_CENTER,
    AUDIO_CHANNEL_OUT_STEREO,
    AUDIO_CHANNEL_OUT_2POINT1,
    AUDIO_CHANNEL_OUT_2POINT0POINT2,
    AUDIO_CHANNEL_OUT_QUAD, // AUDIO_CHANNEL_OUT_QUAD_BACK
    AUDIO_CHANNEL_OUT_QUAD_SIDE,
    AUDIO_CHANNEL_OUT_SURROUND,
    AUDIO_CHANNEL_OUT_2POINT1POINT2,
    AUDIO_CHANNEL_OUT_3POINT0POINT2,
    AUDIO_CHANNEL_OUT_PENTA,
    AUDIO_CHANNEL_OUT_3POINT1POINT2,
    AUDIO_CHANNEL_OUT_5POINT1, // AUDIO_CHANNEL_OUT_5POINT1_BACK
    AUDIO_CHANNEL_OUT_5POINT1_SIDE,
    AUDIO_CHANNEL_OUT_6POINT1,
    AUDIO_CHANNEL_OUT_5POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1,
    AUDIO_CHANNEL_OUT_5POINT1POINT4,
    AUDIO_CHANNEL_OUT_7POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1POINT4,
    AUDIO_CHANNEL_OUT_13POINT_360RA,
    AUDIO_CHANNEL_OUT_22POINT2,
};

static constexpr effect_uuid_t downmix_uuid = {
    0x93f04452, 0xe4fe, 0x41cc, 0x91f9, {0xe4, 0x75, 0xb6, 0xd1, 0xd6, 0x9f}};

static constexpr size_t kFrameCount = 1000;

/*
Pixel 4XL
--------------------------------------------------------
Benchmark              Time             CPU   Iterations
--------------------------------------------------------
BM_Downmix/0        2845 ns         2839 ns       246585 AUDIO_CHANNEL_OUT_MONO
BM_Downmix/1        2844 ns         2838 ns       246599
BM_Downmix/2        3727 ns         3719 ns       188227 AUDIO_CHANNEL_OUT_STEREO
BM_Downmix/3        4609 ns         4600 ns       152148 AUDIO_CHANNEL_OUT_2POINT1
BM_Downmix/4        3727 ns         3719 ns       188228 AUDIO_CHANNEL_OUT_2POINT0POINT2
BM_Downmix/5        1787 ns         1784 ns       392384 AUDIO_CHANNEL_OUT_QUAD
BM_Downmix/6        1787 ns         1783 ns       392527 AUDIO_CHANNEL_OUT_QUAD_SIDE
BM_Downmix/7        5493 ns         5481 ns       127740 AUDIO_CHANNEL_OUT_SURROUND
BM_Downmix/8        4610 ns         4600 ns       152168 AUDIO_CHANNEL_OUT_2POINT1POINT2
BM_Downmix/9        4610 ns         4600 ns       152162 AUDIO_CHANNEL_OUT_3POINT0POINT2
BM_Downmix/10       6377 ns         6362 ns       110042 AUDIO_CHANNEL_OUT_PENTA
BM_Downmix/11       5493 ns         5481 ns       127683 AUDIO_CHANNEL_OUT_3POINT1POINT2
BM_Downmix/12       2758 ns         2752 ns       251488 AUDIO_CHANNEL_OUT_5POINT1
BM_Downmix/13       2683 ns         2677 ns       261421 AUDIO_CHANNEL_OUT_5POINT1_SIDE
BM_Downmix/14       8141 ns         8124 ns        86157 AUDIO_CHANNEL_OUT_6POINT1
BM_Downmix/15       7265 ns         7249 ns        96554 AUDIO_CHANNEL_OUT_5POINT1POINT2
BM_Downmix/16       3158 ns         3151 ns       222188 AUDIO_CHANNEL_OUT_7POINT1
BM_Downmix/17       7291 ns         7276 ns        96226 AUDIO_CHANNEL_OUT_5POINT1POINT4
BM_Downmix/18       9050 ns         9031 ns        77512 AUDIO_CHANNEL_OUT_7POINT1POINT2
BM_Downmix/19       9056 ns         9036 ns        77467 AUDIO_CHANNEL_OUT_7POINT1POINT4
BM_Downmix/20       6426 ns         6412 ns       109164 AUDIO_CHANNEL_OUT_13POINT_360RA
BM_Downmix/21      11743 ns        11716 ns        59762 AUDIO_CHANNEL_OUT_22POINT2
*/

static void BM_Downmix(benchmark::State& state) {
    const audio_channel_mask_t channelMask = kChannelPositionMasks[state.range(0)];
    const size_t channelCount = audio_channel_count_from_out_mask(channelMask);
    const int sampleRate = 48000;

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(channelMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(kFrameCount * channelCount);
    std::vector<float> output(kFrameCount * FCC_2);
    for (auto& in : input) {
        in = dis(gen);
    }
    effect_handle_t effectHandle = nullptr;
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(
            &downmix_uuid, 1, 1, &effectHandle);
        status != 0) {
        ALOGE("create_effect returned an error = %d\n", status);
        return;
    }

    effect_config_t config{};
    config.inputCfg.accessMode = EFFECT_BUFFER_ACCESS_READ;
    config.inputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
    config.inputCfg.bufferProvider.getBuffer = nullptr;
    config.inputCfg.bufferProvider.releaseBuffer = nullptr;
    config.inputCfg.bufferProvider.cookie = nullptr;
    config.inputCfg.mask = EFFECT_CONFIG_ALL;

    config.outputCfg.accessMode = EFFECT_BUFFER_ACCESS_WRITE;
    config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
    config.outputCfg.bufferProvider.getBuffer = nullptr;
    config.outputCfg.bufferProvider.releaseBuffer = nullptr;
    config.outputCfg.bufferProvider.cookie = nullptr;
    config.outputCfg.mask = EFFECT_CONFIG_ALL;

    config.inputCfg.samplingRate = sampleRate;
    config.inputCfg.channels = channelMask;

    config.outputCfg.samplingRate = sampleRate;
    config.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO; // output always stereo

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (int status = (*effectHandle)
            ->command(effectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                    &config, &replySize, &reply);
        status != 0) {
        ALOGE("command returned an error = %d\n", status);
        return;
    }

    if (int status = (*effectHandle)
            ->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
        status != 0) {
        ALOGE("Command enable call returned error %d\n", reply);
        return;
    }

    // Run the test
    for (auto _ : state) {
        benchmark::DoNotOptimize(input.data());
        benchmark::DoNotOptimize(output.data());

        audio_buffer_t inBuffer = {.frameCount = kFrameCount, .f32 = input.data()};
        audio_buffer_t outBuffer = {.frameCount = kFrameCount, .f32 = output.data()};
        (*effectHandle)->process(effectHandle, &inBuffer, &outBuffer);

        benchmark::ClobberMemory();
    }

    state.SetComplexityN(channelCount);
    state.SetLabel(audio_channel_out_mask_to_string(channelMask));

    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle); status != 0) {
        ALOGE("release_effect returned an error = %d\n", status);
        return;
    }
}

static void DownmixArgs(benchmark::internal::Benchmark* b) {
    for (int i = 0; i < (int)std::size(kChannelPositionMasks); i++) {
        b->Args({i});
    }
}

BENCHMARK(BM_Downmix)->Apply(DownmixArgs);

BENCHMARK_MAIN();
