/*
 * Copyright 2022 The Android Open Source Project
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
#include <dlfcn.h>
#include <random>
#include <vector>

#include <benchmark/benchmark.h>
#include <hardware/audio_effect.h>
#include <log/log.h>

audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM = [] {
    audio_effect_library_t symbol{};
    void* effectLib = dlopen("libspatialaudio.so", RTLD_NOW);
    if (effectLib) {
        audio_effect_library_t* effectInterface =
                (audio_effect_library_t*)dlsym(effectLib, AUDIO_EFFECT_LIBRARY_INFO_SYM_AS_STR);
        if (effectInterface == nullptr) {
            ALOGE("dlsym failed: %s", dlerror());
            dlclose(effectLib);
            exit(-1);
        }
        symbol = (audio_effect_library_t)(*effectInterface);
    } else {
        ALOGE("dlopen failed: %s", dlerror());
        exit(-1);
    }
    return symbol;
}();

// channel masks
constexpr int kInputChMask = AUDIO_CHANNEL_OUT_5POINT1;

// sampleRates
constexpr size_t kSampleRates[] = {
        44100,
        48000,
        96000,
};
constexpr size_t kNumSampleRates = std::size(kSampleRates);

// duration in ms
constexpr size_t kDurations[] = {2, 5, 10};
constexpr size_t kNumDurations = std::size(kDurations);

// effect uuids
constexpr effect_uuid_t kEffectUuid = {
        0xcc4677de, 0xff72, 0x11eb, 0x9a03, {0x02, 0x42, 0xac, 0x13, 0x00, 0x03}};

constexpr float kMinAmplitude = -1.0f;
constexpr float kMaxAmplitude = 1.0f;

/*******************************************************************
 * A test result running on Pixel 5 for comparison.
 * The first parameter indicates the sample rate.
 * 0: 44100, 1: 48000, 2: 96000
 * The second parameter indicates the duration in ms.
 * 0: 2, 1: 5, 2: 10
 * -------------------------------------------------------------
 * Benchmark                   Time             CPU   Iterations
 * -------------------------------------------------------------
 * BM_SPATIALIZER/0/0     739848 ns       738497 ns          934
 * BM_SPATIALIZER/0/1    1250503 ns      1248337 ns          480
 * BM_SPATIALIZER/0/2    2094092 ns      2090092 ns          310
 * BM_SPATIALIZER/1/0     783114 ns       781626 ns          683
 * BM_SPATIALIZER/1/1    1332951 ns      1330473 ns          452
 * BM_SPATIALIZER/1/2    2258313 ns      2254022 ns          289
 * BM_SPATIALIZER/2/0    1210332 ns      1207957 ns          477
 * BM_SPATIALIZER/2/1    2356259 ns      2351764 ns          269
 * BM_SPATIALIZER/2/2    4267814 ns      4259567 ns          155
 *******************************************************************/

static void BM_SPATIALIZER(benchmark::State& state) {
    const size_t sampleRate = kSampleRates[state.range(0)];
    const size_t durationMs = kDurations[state.range(1)];
    const size_t frameCount = durationMs * sampleRate / 1000;
    const size_t inputChannelCount = audio_channel_count_from_out_mask(kInputChMask);
    const size_t outputChannelCount = audio_channel_count_from_out_mask(AUDIO_CHANNEL_OUT_STEREO);

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(kInputChMask);
    std::uniform_real_distribution<> dis(kMinAmplitude, kMaxAmplitude);
    std::vector<float> input(frameCount * inputChannelCount);
    for (auto& in : input) {
        in = dis(gen);
    }

    effect_handle_t effectHandle = nullptr;
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&kEffectUuid, 1 /* sessionId */,
                                                                 1 /* ioId */, &effectHandle);
        status != 0) {
        ALOGE("create_effect returned an error = %d\n", status);
        return;
    }

    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = sampleRate;
    config.inputCfg.channels = kInputChMask;
    config.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
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

    if (int status = (*effectHandle)
                             ->command(effectHandle, EFFECT_CMD_ENABLE, sizeof(effect_config_t),
                                       &config, &replySize, &reply);
        status != 0) {
        ALOGE("command returned an error = %d\n", status);
        return;
    }

    // Run the test
    std::vector<float> output(frameCount * outputChannelCount);
    for (auto _ : state) {
        benchmark::DoNotOptimize(input.data());
        benchmark::DoNotOptimize(output.data());

        audio_buffer_t inBuffer = {.frameCount = frameCount, .f32 = input.data()};
        audio_buffer_t outBuffer = {.frameCount = frameCount, .f32 = output.data()};
        (*effectHandle)->process(effectHandle, &inBuffer, &outBuffer);

        benchmark::ClobberMemory();
    }

    state.SetComplexityN(frameCount);

    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle); status != 0) {
        ALOGE("release_effect returned an error = %d\n", status);
        return;
    }
}

static void SPATIALIZERArgs(benchmark::internal::Benchmark* b) {
    for (int i = 0; i < kNumSampleRates; i++) {
        for (int j = 0; j < kNumDurations; ++j) {
            b->Args({i, j});
        }
    }
}

BENCHMARK(BM_SPATIALIZER)->Apply(SPATIALIZERArgs);

BENCHMARK_MAIN();
