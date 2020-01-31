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

#include <media/MediaMetricsItem.h>
#include <benchmark/benchmark.h>

class MyItem : public android::mediametrics::BaseItem {
public:
    static bool mySubmitBuffer() {
        // Deliberately lame so that we're measuring just the cost to deliver things to the service.
        return submitBuffer("", 0);
    }
};

static void BM_SubmitBuffer(benchmark::State& state)
{
    while (state.KeepRunning()) {
        MyItem myItem;
        bool ok = myItem.mySubmitBuffer();
        if (ok == false) {
            // submitBuffer() currently uses one-way binder IPC, which provides unreliable delivery
            // with at-most-one guarantee.
            // It is expected that the call may occasionally fail if the one-way queue is full.
            // The Iterations magic number below was tuned to reduce, but not eliminate, failures.
            state.SkipWithError("failed");
            return;
        }
        benchmark::ClobberMemory();
    }
}

BENCHMARK(BM_SubmitBuffer)->Iterations(4000);   // Adjust magic number until test runs

BENCHMARK_MAIN();
