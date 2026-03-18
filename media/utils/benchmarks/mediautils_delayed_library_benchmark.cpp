/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <benchmark/benchmark.h>
#include <mediautils/MediaUtilsDelayed.h>

/*
Pixel 10
arm64-v8a mediautils_delayed_library_benchmark
----------------------------------------------
arm64-v8a mediautils_delayed_library_benchmark (1 Test)
[1/1] mediautils_delayed_library_benchmark#BM_GetCallStackStringForTid: PASSED (10ms)
	cpu_time_ns: 2297010.0255474453
	family_index: 0
	per_family_instance_index: 0
	real_time_ns: 2302609.204378274
*/

static void BM_GetCallStackStringForTid(benchmark::State& state) {
    for (auto _ : state) {
        std::string s = android::mediautils::getCallStackStringForTid();
        benchmark::DoNotOptimize(s);
    }
}
BENCHMARK(BM_GetCallStackStringForTid);

BENCHMARK_MAIN();
