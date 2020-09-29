/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <inttypes.h>
#include <type_traits>
#include "../../../../system/media/audio_utils/include/audio_utils/primitives.h"
#define LOG_ALWAYS_FATAL(...)

#include <../AudioMixerOps.h>

#include <benchmark/benchmark.h>

using namespace android;

template <int MIXTYPE, int NCHAN>
static void BM_VolumeRampMulti(benchmark::State& state) {
    constexpr size_t FRAME_COUNT = 1000;
    constexpr size_t SAMPLE_COUNT = FRAME_COUNT * NCHAN;

    // data inialized to 0.
    float out[SAMPLE_COUNT]{};
    float in[SAMPLE_COUNT]{};
    float aux[FRAME_COUNT]{};

    // volume initialized to 0
    float vola = 0.f;
    float vol[2] = {0.f, 0.f};

    // some volume increment
    float volainc = 0.01f;
    float volinc[2] = {0.01f, 0.01f};

    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(out);
        benchmark::DoNotOptimize(in);
        volumeRampMulti<MIXTYPE, NCHAN>(out, FRAME_COUNT, in, aux, vol, volinc, &vola, volainc);
        benchmark::ClobberMemory();
    }
}

template <int MIXTYPE, int NCHAN>
static void BM_VolumeMulti(benchmark::State& state) {
    constexpr size_t FRAME_COUNT = 1000;
    constexpr size_t SAMPLE_COUNT = FRAME_COUNT * NCHAN;

    // data inialized to 0.
    float out[SAMPLE_COUNT]{};
    float in[SAMPLE_COUNT]{};
    float aux[FRAME_COUNT]{};

    // volume initialized to 0
    float vola = 0.f;
    float vol[2] = {0.f, 0.f};


    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(out);
        benchmark::DoNotOptimize(in);
        volumeMulti<MIXTYPE, NCHAN>(out, FRAME_COUNT, in, aux, vol, vola);
        benchmark::ClobberMemory();
    }
}

// MULTI mode and MULTI_SAVEONLY mode are not used by AudioMixer for channels > 2,
// which is ensured by a static_assert (won't compile for those configurations).
// So we benchmark MIXTYPE_MULTI_MONOVOL and MIXTYPE_MULTI_SAVEONLY_MONOVOL compared
// with MIXTYPE_MULTI_STEREOVOL and MIXTYPE_MULTI_SAVEONLY_STEREOVOL.
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_MONOVOL, 2);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_MONOVOL, 2);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_STEREOVOL, 2);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_STEREOVOL, 2);

BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_MONOVOL, 4);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_MONOVOL, 4);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_STEREOVOL, 4);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_STEREOVOL, 4);

BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_MONOVOL, 5);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_MONOVOL, 5);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_STEREOVOL, 5);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_STEREOVOL, 5);

BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_MONOVOL, 8);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_MONOVOL, 8);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_STEREOVOL, 8);
BENCHMARK_TEMPLATE(BM_VolumeRampMulti, MIXTYPE_MULTI_SAVEONLY_STEREOVOL, 8);

BENCHMARK_TEMPLATE(BM_VolumeMulti, MIXTYPE_MULTI_MONOVOL, 8);
BENCHMARK_TEMPLATE(BM_VolumeMulti, MIXTYPE_MULTI_SAVEONLY_MONOVOL, 8);
BENCHMARK_TEMPLATE(BM_VolumeMulti, MIXTYPE_MULTI_STEREOVOL, 8);
BENCHMARK_TEMPLATE(BM_VolumeMulti, MIXTYPE_MULTI_SAVEONLY_STEREOVOL, 8);

BENCHMARK_MAIN();
