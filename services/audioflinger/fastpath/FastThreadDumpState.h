/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <type_traits>

#include "Configuration.h"
#include "FastThreadState.h"

namespace android {

// The FastThreadDumpState keeps a cache of FastThread statistics that can be logged by dumpsys.
// Each individual native word-sized field is accessed atomically.  But the
// overall structure is non-atomic, that is there may be an inconsistency between fields.
// No barriers or locks are used for either writing or reading.
// Only POD types are permitted, and the contents shouldn't be trusted (i.e. do range checks).
// It has a different lifetime than the FastThread, and so it can't be a member of FastThread.
struct FastThreadDumpState {
    FastThreadDumpState();

    FastThreadState::Command mCommand = FastThreadState::INITIAL;  // current command
    uint32_t mUnderruns = 0;        // total number of underruns
    uint32_t mOverruns = 0;         // total number of overruns
    struct timespec mMeasuredWarmupTs{};  // measured warmup time
    uint32_t mWarmupCycles = 0;     // number of loop cycles required to warmup

#ifdef FAST_THREAD_STATISTICS
    // Recently collected samples of per-cycle monotonic time, thread CPU time, and CPU frequency.
    // kSamplingN is max size of sampling frame (statistics), and must be a power of 2 <= 0x8000.
    // The sample arrays are virtually allocated based on this compile-time constant,
    // but are only initialized and used based on the runtime parameter mSamplingN.
    static const uint32_t kSamplingN = 0x8000;
    // Compile-time constant for a "low RAM device", must be a power of 2 <= kSamplingN.
    // This value was chosen such that each array uses 1 small page (4 Kbytes).
    static const uint32_t kSamplingNforLowRamDevice = 0x400;
    // Corresponding runtime maximum size of sample arrays, must be a power of 2 <= kSamplingN.
    uint32_t mSamplingN = 0;
    // The bounds define the interval of valid samples, and are represented as follows:
    //      newest open (excluded) endpoint   = lower 16 bits of bounds, modulo N
    //      oldest closed (included) endpoint = upper 16 bits of bounds, modulo N
    // Number of valid samples is newest - oldest.
    uint32_t mBounds = 0;               // bounds for mMonotonicNs, mThreadCpuNs, and mCpukHz
    // The elements in the *Ns arrays are in units of nanoseconds <= 3999999999.
    uint32_t mMonotonicNs[kSamplingN];  // delta monotonic (wall clock) time
    uint32_t mLoadNs[kSamplingN];       // delta CPU load in time
#ifdef CPU_FREQUENCY_STATISTICS
    uint32_t mCpukHz[kSamplingN];       // absolute CPU clock frequency in kHz, bits 0-3 are CPU#
#endif

    // Increase sampling window after construction, must be a power of 2 <= kSamplingN
    void    increaseSamplingN(uint32_t samplingN);
#endif

};  // struct FastThreadDumpState

// No virtuals.
static_assert(!std::is_polymorphic_v<FastThreadDumpState>);

}  // namespace android
