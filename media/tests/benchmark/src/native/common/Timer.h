/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef __TIMER_H__
#define __TIMER_H__

#include <sys/time.h>
#include <algorithm>
#include <numeric>
#include <vector>
#include <utils/Timers.h>

using namespace std;

class Timer {
  public:
    Timer() {
        mInitTimeNs = 0;
        mDeInitTimeNs = 0;
    }

    ~Timer() {
        if (!mInputTimer.empty()) mInputTimer.clear();
        if (!mOutputTimer.empty()) mOutputTimer.clear();
    }

  private:
    nsecs_t mInitTimeNs;
    nsecs_t mDeInitTimeNs;
    nsecs_t mStartTimeNs;
    std::vector<nsecs_t> mInputTimer;
    std::vector<nsecs_t> mOutputTimer;

  public:
    nsecs_t getCurTime() { return systemTime(CLOCK_MONOTONIC); }

    void setInitTime(nsecs_t initTime) { mInitTimeNs = initTime; }

    void setDeInitTime(nsecs_t deInitTime) { mDeInitTimeNs = deInitTime; }

    void setStartTime() { mStartTimeNs = systemTime(CLOCK_MONOTONIC); }

    void addInputTime() { mInputTimer.push_back(systemTime(CLOCK_MONOTONIC)); }

    void addOutputTime() { mOutputTimer.push_back(systemTime(CLOCK_MONOTONIC)); }

    void resetTimers() {
        if (!mInputTimer.empty()) mInputTimer.clear();
        if (!mOutputTimer.empty()) mOutputTimer.clear();
    }

    std::vector<nsecs_t> getOutputTimer() { return mOutputTimer; }

    nsecs_t getInitTime() { return mInitTimeNs; }

    nsecs_t getDeInitTime() { return mDeInitTimeNs; }

    nsecs_t getTimeDiff(nsecs_t sTime, nsecs_t eTime) { return (eTime - sTime); }

    nsecs_t getTotalTime() {
        if (mOutputTimer.empty()) return -1;
        return (*(mOutputTimer.end() - 1) - mStartTimeNs);
    }

    void dumpStatistics(std::string operation, std::string inputReference, int64_t duarationUs);
};

#endif  // __TIMER_H__
