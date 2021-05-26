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
  #BM_Downmix/0     4719 ns    4704 ns       148890
  #BM_Downmix/1     5050 ns    5034 ns       139104
  #BM_Downmix/2     1506 ns    1501 ns       466795
  #BM_Downmix/3     1554 ns    1549 ns       444498
  #BM_Downmix/4     1514 ns    1510 ns       463697
  #BM_Downmix/5     4442 ns    4428 ns       158016
  #BM_Downmix/6     4404 ns    4378 ns       159858
  #BM_Downmix/7     4851 ns    4835 ns       144681
  #BM_Downmix/8     4848 ns    4832 ns       144560
  #BM_Downmix/9     4859 ns    4844 ns       144496
  #BM_Downmix/10    5806 ns    5788 ns       120751
  #BM_Downmix/11    5051 ns    5036 ns       138920
--
downmix_benchmark: (generic fold)
  #BM_Downmix/0     4723 ns    4708 ns       148605
  #BM_Downmix/1     5081 ns    5065 ns       137920
  #BM_Downmix/2     4472 ns    4458 ns       160047
  #BM_Downmix/3     4359 ns    4345 ns       158744
  #BM_Downmix/4     4722 ns    4706 ns       149648
  #BM_Downmix/5     4426 ns    4412 ns       158618
  #BM_Downmix/6     4377 ns    4363 ns       160217
  #BM_Downmix/7     5262 ns    5245 ns       133155
  #BM_Downmix/8     5265 ns    5248 ns       132817
  #BM_Downmix/9     5246 ns    5229 ns       133932
  #BM_Downmix/10    5819 ns    5801 ns       120295
  #BM_Downmix/11    6030 ns    6011 ns       116619
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
