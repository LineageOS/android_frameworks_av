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
    AUDIO_CHANNEL_OUT_QUAD,
    AUDIO_CHANNEL_OUT_QUAD_BACK,
    AUDIO_CHANNEL_OUT_QUAD_SIDE,
    AUDIO_CHANNEL_OUT_SURROUND,
    AUDIO_CHANNEL_OUT_2POINT1POINT2,
    AUDIO_CHANNEL_OUT_3POINT0POINT2,
    AUDIO_CHANNEL_OUT_PENTA,
    AUDIO_CHANNEL_OUT_3POINT1POINT2,
    AUDIO_CHANNEL_OUT_5POINT1,
    AUDIO_CHANNEL_OUT_5POINT1_BACK,
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
Pixel 3XL
downmix_benchmark:
  #BM_Downmix/0     4723 ns    4708 ns       148694
  #BM_Downmix/1     4717 ns    4702 ns       148873
  #BM_Downmix/2     4803 ns    4788 ns       145893
  #BM_Downmix/3     5056 ns    5041 ns       139110
  #BM_Downmix/4     4710 ns    4696 ns       149625
  #BM_Downmix/5     1514 ns    1509 ns       463694
  #BM_Downmix/6     1513 ns    1509 ns       463451
  #BM_Downmix/7     1516 ns    1511 ns       463899
  #BM_Downmix/8     4445 ns    4431 ns       157831
  #BM_Downmix/9     5081 ns    5065 ns       138412
  #BM_Downmix/10    4354 ns    4341 ns       161247
  #BM_Downmix/11    4411 ns    4397 ns       158893
  #BM_Downmix/12    4434 ns    4420 ns       157992
  #BM_Downmix/13    4845 ns    4830 ns       144873
  #BM_Downmix/14    4851 ns    4835 ns       144954
  #BM_Downmix/15    4884 ns    4870 ns       144233
  #BM_Downmix/16    5832 ns    5813 ns       120565
  #BM_Downmix/17    5241 ns    5224 ns       133927
  #BM_Downmix/18    5044 ns    5028 ns       139131
  #BM_Downmix/19    5244 ns    5227 ns       132315
  #BM_Downmix/20    5943 ns    5923 ns       117759
  #BM_Downmix/21    5990 ns    5971 ns       117263
  #BM_Downmix/22    4468 ns    4454 ns       156689
  #BM_Downmix/23    7306 ns    7286 ns        95911
--
downmix_benchmark: (generic fold)
  #BM_Downmix/0     4722 ns    4707 ns       149847
  #BM_Downmix/1     4714 ns    4698 ns       148748
  #BM_Downmix/2     4794 ns    4779 ns       145661
  #BM_Downmix/3     5053 ns    5035 ns       139172
  #BM_Downmix/4     4695 ns    4678 ns       149762
  #BM_Downmix/5     4381 ns    4368 ns       159675
  #BM_Downmix/6     4387 ns    4373 ns       160267
  #BM_Downmix/7     4732 ns    4717 ns       148514
  #BM_Downmix/8     4430 ns    4415 ns       158133
  #BM_Downmix/9     5101 ns    5084 ns       138353
  #BM_Downmix/10    4356 ns    4343 ns       160821
  #BM_Downmix/11    4397 ns    4383 ns       159995
  #BM_Downmix/12    4438 ns    4424 ns       158117
  #BM_Downmix/13    5243 ns    5226 ns       133863
  #BM_Downmix/14    5259 ns    5242 ns       131855
  #BM_Downmix/15    5245 ns    5228 ns       133686
  #BM_Downmix/16    5829 ns    5809 ns       120543
  #BM_Downmix/17    5245 ns    5228 ns       133533
  #BM_Downmix/18    5935 ns    5916 ns       118282
  #BM_Downmix/19    5263 ns    5245 ns       133657
  #BM_Downmix/20    5998 ns    5978 ns       114693
  #BM_Downmix/21    5989 ns    5969 ns       117450
  #BM_Downmix/22    4442 ns    4431 ns       157913
  #BM_Downmix/23    7309 ns    7290 ns        95797
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
