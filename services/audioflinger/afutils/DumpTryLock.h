/*
 *
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <audio_utils/mutex.h>
#include <utils/Mutex.h>
#include <utils/Timers.h>

namespace android::afutils {

inline bool dumpTryLock(Mutex& mutex)
{
    static constexpr int kDumpLockTimeoutNs = 1'000'000'000;
    const status_t err = mutex.timedLock(kDumpLockTimeoutNs);
    return err == NO_ERROR;
}

// Note: the std::timed_mutex try_lock_for and try_lock_until methods are inefficient.
// It is better to use std::mutex and call this method.
//
inline bool dumpTryLock(audio_utils::mutex& mutex) TRY_ACQUIRE(true, mutex)
{
    static constexpr int64_t kDumpLockTimeoutNs = 1'000'000'000;

    const int64_t timeoutNs = kDumpLockTimeoutNs + systemTime(SYSTEM_TIME_REALTIME);
    const struct timespec ts = {
        .tv_sec = static_cast<time_t>(timeoutNs / 1000000000),
        .tv_nsec = static_cast<long>(timeoutNs % 1000000000),
    };
    return pthread_mutex_timedlock(mutex.native_handle(), &ts) == 0;
}

}  // android::afutils
