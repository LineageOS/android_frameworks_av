/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <vector>

#include <mediautils/TimerThread.h>

namespace android {

// A class monitoring execution time for a code block (scoped variable) and causing an assert
// if it exceeds a certain time

class TimeCheck {
  public:
    // The default timeout is chosen to be less than system server watchdog timeout
    static constexpr uint32_t kDefaultTimeOutMs = 5000;

    TimeCheck(const char* tag, uint32_t timeoutMs = kDefaultTimeOutMs);
    ~TimeCheck();
    static void setAudioHalPids(const std::vector<pid_t>& pids);
    static std::vector<pid_t> getAudioHalPids();

  private:
    static TimerThread* getTimeCheckThread();
    static void accessAudioHalPids(std::vector<pid_t>* pids, bool update);
    static void crash(const char* tag, std::chrono::system_clock::time_point startTime);

    const TimerThread::Handle mTimerHandle;
};

};  // namespace android
