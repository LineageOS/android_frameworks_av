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
//    AUDIO_CHANNEL_OUT_MONO,
//    AUDIO_CHANNEL_OUT_FRONT_CENTER,
    AUDIO_CHANNEL_OUT_STEREO,
    AUDIO_CHANNEL_OUT_2POINT1,
//    AUDIO_CHANNEL_OUT_2POINT0POINT2,
    AUDIO_CHANNEL_OUT_QUAD,
    AUDIO_CHANNEL_OUT_QUAD_BACK,
    AUDIO_CHANNEL_OUT_QUAD_SIDE,
    AUDIO_CHANNEL_OUT_SURROUND,
//    AUDIO_CHANNEL_OUT_2POINT1POINT2,
//    AUDIO_CHANNEL_OUT_3POINT0POINT2,
    AUDIO_CHANNEL_OUT_PENTA,
//    AUDIO_CHANNEL_OUT_3POINT1POINT2,
    AUDIO_CHANNEL_OUT_5POINT1,
    AUDIO_CHANNEL_OUT_5POINT1_BACK,
    AUDIO_CHANNEL_OUT_5POINT1_SIDE,
    AUDIO_CHANNEL_OUT_6POINT1,
//    AUDIO_CHANNEL_OUT_5POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1,
//    AUDIO_CHANNEL_OUT_5POINT1POINT4,
//    AUDIO_CHANNEL_OUT_7POINT1POINT2,
//    AUDIO_CHANNEL_OUT_7POINT1POINT4,
//    AUDIO_CHANNEL_OUT_13POINT_360RA,
//    AUDIO_CHANNEL_OUT_22POINT2,
};

static constexpr effect_uuid_t downmix_uuid = {
    0x93f04452, 0xe4fe, 0x41cc, 0x91f9, {0xe4, 0x75, 0xb6, 0xd1, 0xd6, 0x9f}};

static constexpr size_t kFrameCount = 1000;

/*
Pixel 3XL
downmix_benchmark:
  #BM_Downmix/0     5211 ns    5194 ns       135028
  #BM_Downmix/1     5611 ns    5593 ns       126034
  #BM_Downmix/2     2151 ns    2145 ns       325651
  #BM_Downmix/3     2263 ns    2256 ns       325645
  #BM_Downmix/4     2146 ns    2139 ns       310723
  #BM_Downmix/5     6236 ns    6215 ns       112742
  #BM_Downmix/6     6415 ns    6394 ns       109240
  #BM_Downmix/7     6806 ns    6783 ns       102283
  #BM_Downmix/8     6802 ns    6780 ns       103021
  #BM_Downmix/9     6841 ns    6818 ns       102421
  #BM_Downmix/10    7798 ns    7772 ns        90136
  #BM_Downmix/11    8591 ns    8562 ns        81242
--
downmix_benchmark: (generic fold for all channel masks)
  #BM_Downmix/0     5205 ns    5188 ns       134594
  #BM_Downmix/1     5604 ns    5586 ns       124443
  #BM_Downmix/2     5564 ns    5546 ns       126144
  #BM_Downmix/3     5736 ns    5718 ns       126185
  #BM_Downmix/4     5721 ns    5705 ns       121404
  #BM_Downmix/5     6264 ns    6243 ns       112684
  #BM_Downmix/6     6417 ns    6395 ns       109391
  #BM_Downmix/7     6739 ns    6718 ns       103811
  #BM_Downmix/8     6762 ns    6740 ns       103860
  #BM_Downmix/9     6769 ns    6747 ns       103680
  #BM_Downmix/10    7806 ns    7779 ns        90045
  #BM_Downmix/11    7939 ns    7911 ns        88370
*/

static void BM_Downmix(benchmark::State& state) {
    const audio_channel_mask_t channelMask = kChannelPositionMasks[state.range(0)];
    const size_t channelCount = audio_channel_count_from_out_mask(channelMask);
    const int sampleRate = 48000;

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(channelMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(kFrameCount * channelCount);
    std::vector<float> output(kFrameCount * 2);
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

    state.SetComplexityN(state.range(0));

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
