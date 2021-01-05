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
#include "EffectReverb.h"

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
constexpr effect_uuid_t kEffectUuids[] = {
        {0x172cdf00,
         0xa3bc,
         0x11df,
         0xa72f,
         {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // preset-insert mode
        {0xf29a1400,
         0xa3bb,
         0x11df,
         0x8ddc,
         {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // preset-aux mode
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

constexpr size_t kFrameCount = 2048;

constexpr int kPresets[] = {
        REVERB_PRESET_NONE,      REVERB_PRESET_SMALLROOM,  REVERB_PRESET_MEDIUMROOM,
        REVERB_PRESET_LARGEROOM, REVERB_PRESET_MEDIUMHALL, REVERB_PRESET_LARGEHALL,
        REVERB_PRESET_PLATE,
};

constexpr size_t kNumPresets = std::size(kPresets);

constexpr int kSampleRate = 44100;

int reverbSetConfigParam(uint32_t paramType, uint32_t paramValue, effect_handle_t effectHandle) {
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    uint32_t paramData[2] = {paramType, paramValue};
    auto effectParam = (effect_param_t*)malloc(sizeof(effect_param_t) + sizeof(paramData));
    memcpy(&effectParam->data[0], &paramData[0], sizeof(paramData));
    effectParam->psize = sizeof(paramData[0]);
    effectParam->vsize = sizeof(paramData[1]);
    int status = (*effectHandle)
                         ->command(effectHandle, EFFECT_CMD_SET_PARAM,
                                   sizeof(effect_param_t) + sizeof(paramData), effectParam,
                                   &replySize, &reply);
    free(effectParam);
    if (status != 0) {
        ALOGE("Reverb set config returned an error = %d\n", status);
        return status;
    }
    return reply;
}

/*******************************************************************
 * A test result running on Pixel 3 with for comparison.
 * The first parameter indicates the preset level id.
 * The second parameter indicates the effect.
 * 0: preset-insert mode, 1: preset-aux mode
 * --------------------------------------------------------
 * Benchmark              Time             CPU   Iterations
 * --------------------------------------------------------
 * BM_REVERB/0/0      19312 ns        19249 ns        36282
 * BM_REVERB/0/1       5613 ns         5596 ns       125032
 * BM_REVERB/1/0     605453 ns       603714 ns         1131
 * BM_REVERB/1/1     589421 ns       587758 ns         1161
 * BM_REVERB/2/0     605760 ns       604006 ns         1131
 * BM_REVERB/2/1     589434 ns       587777 ns         1161
 * BM_REVERB/3/0     605574 ns       603828 ns         1131
 * BM_REVERB/3/1     589566 ns       587862 ns         1162
 * BM_REVERB/4/0     605634 ns       603894 ns         1131
 * BM_REVERB/4/1     589506 ns       587856 ns         1161
 * BM_REVERB/5/0     605644 ns       603929 ns         1131
 * BM_REVERB/5/1     589592 ns       587863 ns         1161
 * BM_REVERB/6/0     610544 ns       608561 ns         1131
 * BM_REVERB/6/1     589686 ns       587871 ns         1161
 *******************************************************************/

static void BM_REVERB(benchmark::State& state) {
    const size_t chMask = AUDIO_CHANNEL_OUT_STEREO;
    const size_t preset = kPresets[state.range(0)];
    const effect_uuid_t uuid = kEffectUuids[state.range(1)];
    const size_t channelCount = audio_channel_count_from_out_mask(chMask);

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(chMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(kFrameCount * channelCount);
    std::vector<float> output(kFrameCount * channelCount);
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

    if (int status = reverbSetConfigParam(REVERB_PARAM_PRESET, preset, effectHandle); status != 0) {
        ALOGE("Invalid reverb preset. Error %d\n", status);
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

static void REVERBArgs(benchmark::internal::Benchmark* b) {
    for (int i = 0; i < kNumPresets; i++) {
        for (int j = 0; j < kNumEffectUuids; ++j) {
            b->Args({i, j});
        }
    }
}

BENCHMARK(BM_REVERB)->Apply(REVERBArgs);

BENCHMARK_MAIN();
