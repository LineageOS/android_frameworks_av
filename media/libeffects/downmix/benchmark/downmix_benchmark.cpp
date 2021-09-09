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
BM_Downmix/0        3553 ns         3545 ns       197503 AUDIO_CHANNEL_OUT_MONO
BM_Downmix/1        2846 ns         2840 ns       202849
BM_Downmix/2        4436 ns         4426 ns       158176 AUDIO_CHANNEL_OUT_STEREO
BM_Downmix/3        5320 ns         5307 ns       131870 AUDIO_CHANNEL_OUT_2POINT1
BM_Downmix/4        4437 ns         4426 ns       159523 AUDIO_CHANNEL_OUT_2POINT0POINT2
BM_Downmix/5        2493 ns         2487 ns       281496 AUDIO_CHANNEL_OUT_QUAD
BM_Downmix/6        2493 ns         2487 ns       281456 AUDIO_CHANNEL_OUT_QUAD_SIDE
BM_Downmix/7        6204 ns         6188 ns       115044 AUDIO_CHANNEL_OUT_SURROUND
BM_Downmix/8        5320 ns         5307 ns       100000 AUDIO_CHANNEL_OUT_2POINT1POINT2
BM_Downmix/9        5320 ns         5307 ns       100000 AUDIO_CHANNEL_OUT_3POINT0POINT2
BM_Downmix/10       7088 ns         7071 ns       108264 AUDIO_CHANNEL_OUT_PENTA
BM_Downmix/11       6203 ns         6188 ns       117021 AUDIO_CHANNEL_OUT_3POINT1POINT2
BM_Downmix/12       3105 ns         3097 ns       226182 AUDIO_CHANNEL_OUT_5POINT1
BM_Downmix/13       3112 ns         3105 ns       225488 AUDIO_CHANNEL_OUT_5POINT1_SIDE
BM_Downmix/14       8855 ns         8831 ns        79265 AUDIO_CHANNEL_OUT_6POINT1
BM_Downmix/15       7971 ns         7951 ns        90918 AUDIO_CHANNEL_OUT_5POINT1POINT2
BM_Downmix/16       3547 ns         3539 ns       197780 AUDIO_CHANNEL_OUT_7POINT1
BM_Downmix/17       7972 ns         7953 ns        90101 AUDIO_CHANNEL_OUT_5POINT1POINT4
BM_Downmix/18       9737 ns         9714 ns        72773 AUDIO_CHANNEL_OUT_7POINT1POINT2
BM_Downmix/19       9745 ns         9721 ns        72015 AUDIO_CHANNEL_OUT_7POINT1POINT4
BM_Downmix/20       7070 ns         7053 ns       109476 AUDIO_CHANNEL_OUT_13POINT_360RA
BM_Downmix/21      12413 ns        12381 ns        57455 AUDIO_CHANNEL_OUT_22POINT2
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
