/*
 * Copyright (C) 2024 The Android Open Source Project
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

#pragma once

#include <audio_utils/threads.h>
#include <benchmark/benchmark.h>
#include <psh_utils/PowerStats.h>
#include <psh_utils/PowerStatsCollector.h>

#include <future>

namespace android::media::psh_utils {

enum CoreClass {
    CORE_LITTLE,
    CORE_MID,
    CORE_BIG,
};

inline std::string toString(CoreClass coreClass) {
    switch (coreClass) {
        case CORE_LITTLE: return "LITTLE";
        case CORE_MID: return "MID";
        case CORE_BIG: return "BIG";
        default: return "UNKNOWN";
    }
}

/**
 * A benchmark fixture is used to specify benchmarks that have a custom SetUp() and
 * TearDown().  This is **required** for performance testing, as a typical benchmark
 * method **may be called several times** during a run.
 *
 * A fixture ensures that SetUp() and TearDown() and the resulting statistics accumulation
 * is done only once.   Note: BENCHMARK(BM_func)->Setup(DoSetup)->Teardown(DoTeardown)
 * does something similar, but it requires some singleton to contain the state properly.
 */
class PerformanceFixture : public benchmark::Fixture {
public:
    // call this to start the profiling
    virtual void startProfiler(CoreClass coreClass) {
        mCores = android::audio_utils::get_number_cpus();
        if (mCores == 0) return;
        mCoreClass = coreClass;
        std::array<unsigned, 3> coreSelection{0U, mCores / 2 + 1, mCores - 1};
        mCore = coreSelection[std::min((size_t)coreClass, std::size(coreSelection) - 1)];

        auto& collector = android::media::psh_utils::PowerStatsCollector::getCollector();
        mStartStats = collector.getStats();

        // Possibly change priority to improve benchmarking
        // android::audio_utils::set_thread_priority(gettid(), 98);

        android::audio_utils::set_thread_affinity(0 /* pid */, 1 << mCore);
    }

    void TearDown(benchmark::State &state) override {
        const auto N = state.complexity_length_n();
        state.counters["N"] = benchmark::Counter(N,
                benchmark::Counter::kIsIterationInvariantRate, benchmark::Counter::OneK::kIs1024);
        if (mStartStats) {
            auto& collector = android::media::psh_utils::PowerStatsCollector::getCollector();
            const auto stopStats = collector.getStats();
            android::media::psh_utils::PowerStats diff = *stopStats - *mStartStats;
            auto cpuEnergy = diff.energyFrom("CPU");
            auto memEnergy = diff.energyFrom("MEM");

            constexpr float kMwToW = 1e-3;
            state.counters["WCPU"] = benchmark::Counter(std::get<2>(cpuEnergy) * kMwToW,
                                                          benchmark::Counter::kDefaults,
                                                          benchmark::Counter::OneK::kIs1000);
            state.counters["WMem"] = benchmark::Counter(std::get<2>(memEnergy) * kMwToW,
                                                          benchmark::Counter::kDefaults,
                                                          benchmark::Counter::OneK::kIs1000);
            state.counters["JCPU"] = benchmark::Counter(
                    std::get<1>(cpuEnergy) / N / state.iterations(), benchmark::Counter::kDefaults,
                    benchmark::Counter::OneK::kIs1000);
            state.counters["JMem"] = benchmark::Counter(
                    std::get<1>(memEnergy) / N / state.iterations(), benchmark::Counter::kDefaults,
                    benchmark::Counter::OneK::kIs1000);
        }
    }

protected:
    // these are only initialized upon startProfiler.
    unsigned mCores = 0;
    int mCore = 0;
    CoreClass mCoreClass = CORE_LITTLE;
    std::shared_ptr<const android::media::psh_utils::PowerStats> mStartStats;
};

} // namespace android::media::psh_utils
