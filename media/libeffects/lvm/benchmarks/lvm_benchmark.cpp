/*
 * Copyright 2020 The Android Open Source Project
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

#include <array>
#include <climits>
#include <cstdlib>
#include <random>
#include <vector>
#include <log/log.h>
#include <benchmark/benchmark.h>
#include <hardware/audio_effect.h>
#include <system/audio.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
constexpr effect_uuid_t kEffectUuids[] = {
        // NXP SW BassBoost
        {0x8631f300, 0x72e2, 0x11df, 0xb57e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Virtualizer
        {0x1d4033c0, 0x8557, 0x11df, 0x9f2d, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Equalizer
        {0xce772f20, 0x847d, 0x11df, 0xbb17, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Volume
        {0x119341a0, 0x8469, 0x11df, 0x81f9, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

constexpr size_t kFrameCount = 2048;

constexpr audio_channel_mask_t kChMasks[] = {
        AUDIO_CHANNEL_OUT_MONO,    AUDIO_CHANNEL_OUT_STEREO,  AUDIO_CHANNEL_OUT_2POINT1,
        AUDIO_CHANNEL_OUT_QUAD,    AUDIO_CHANNEL_OUT_PENTA,   AUDIO_CHANNEL_OUT_5POINT1,
        AUDIO_CHANNEL_OUT_6POINT1, AUDIO_CHANNEL_OUT_7POINT1,
};

constexpr size_t kNumChMasks = std::size(kChMasks);
constexpr int kSampleRate = 44100;
// TODO(b/131240940) Remove once effects are updated to produce mono output
constexpr size_t kMinOutputChannelCount = 2;

/*******************************************************************
 * A test result running on Pixel 3 for comparison.
 * The first parameter indicates the number of channels.
 * The second parameter indicates the effect.
 * 0: Bass Boost, 1: Virtualizer, 2: Equalizer, 3: Volume
 * -----------------------------------------------------
 * Benchmark           Time             CPU   Iterations
 * -----------------------------------------------------
 * BM_LVM/2/0     131279 ns       130855 ns         5195
 * BM_LVM/2/1     184814 ns       184219 ns         3799
 * BM_LVM/2/2      91935 ns        91649 ns         7647
 * BM_LVM/2/3      26707 ns        26623 ns        26281
 * BM_LVM/3/0     172130 ns       171562 ns         4085
 * BM_LVM/3/1     192443 ns       191923 ns         3644
 * BM_LVM/3/2     127444 ns       127107 ns         5483
 * BM_LVM/3/3      26811 ns        26730 ns        26163
 * BM_LVM/4/0     223688 ns       223076 ns         3133
 * BM_LVM/4/1     204961 ns       204408 ns         3425
 * BM_LVM/4/2     169162 ns       168708 ns         4143
 * BM_LVM/4/3      37330 ns        37225 ns        18795
 * BM_LVM/5/0     272628 ns       271668 ns         2568
 * BM_LVM/5/1     218487 ns       217883 ns         3212
 * BM_LVM/5/2     211049 ns       210479 ns         3324
 * BM_LVM/5/3      46962 ns        46835 ns        15051
 * BM_LVM/6/0     318881 ns       317734 ns         2216
 * BM_LVM/6/1     231899 ns       231244 ns         3028
 * BM_LVM/6/2     252655 ns       251963 ns         2771
 * BM_LVM/6/3      54944 ns        54794 ns        12799
 * BM_LVM/7/0     366622 ns       365262 ns         1916
 * BM_LVM/7/1     245076 ns       244388 ns         2866
 * BM_LVM/7/2     295105 ns       294304 ns         2379
 * BM_LVM/7/3      63595 ns        63420 ns        11070
 * BM_LVM/8/0     410957 ns       409387 ns         1706
 * BM_LVM/8/1     257824 ns       257098 ns         2723
 * BM_LVM/8/2     342546 ns       341530 ns         2059
 * BM_LVM/8/3      72896 ns        72700 ns         9685
 *******************************************************************/

static void BM_LVM(benchmark::State& state) {
    const size_t chMask = kChMasks[state.range(0) - 1];
    const effect_uuid_t uuid = kEffectUuids[state.range(1)];
    const size_t channelCount = audio_channel_count_from_out_mask(chMask);

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(chMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(kFrameCount * channelCount);
    for (auto& in : input) {
        in = dis(gen);
    }

    effect_handle_t effectHandle = nullptr;
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&uuid, 1, 1, &effectHandle);
        status != 0) {
        ALOGE("create_effect returned an error = %d\n", status);
        return;
    }

    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = kSampleRate;
    config.inputCfg.channels = config.outputCfg.channels = chMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (int status = (*effectHandle)
                             ->command(effectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                                       &config, &replySize, &reply);
        status != 0) {
        ALOGE("command returned an error = %d\n", status);
        return;
    }

    if (int status =
                (*effectHandle)
                        ->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
        status != 0) {
        ALOGE("Command enable call returned error %d\n", reply);
        return;
    }

    // Run the test
    for (auto _ : state) {
        std::vector<float> output(kFrameCount * std::max(channelCount, kMinOutputChannelCount));

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

static void LVMArgs(benchmark::internal::Benchmark* b) {
    // TODO(b/131240940) Test single channel once effects are updated to process mono data
    for (int i = 2; i <= kNumChMasks; i++) {
        for (int j = 0; j < kNumEffectUuids; ++j) {
            b->Args({i, j});
        }
    }
}

BENCHMARK(BM_LVM)->Apply(LVMArgs);

BENCHMARK_MAIN();
