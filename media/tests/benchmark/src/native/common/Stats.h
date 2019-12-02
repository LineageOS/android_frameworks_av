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

#ifndef __STATS_H__
#define __STATS_H__

#include <android/log.h>
#include <inttypes.h>

#ifndef ALOG
#define ALOG(priority, tag, ...) ((void)__android_log_print(ANDROID_##priority, tag, __VA_ARGS__))

#define ALOGI(...) ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define ALOGD(...) ALOG(LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) ALOG(LOG_WARN, LOG_TAG, __VA_ARGS__)

#ifndef LOG_NDEBUG
#define LOG_NDEBUG 1
#endif

#if LOG_NDEBUG
#define ALOGV(cond, ...)   ((void)0)
#else
#define ALOGV(...) ALOG(LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#endif
#endif  // ALOG

#include <sys/time.h>
#include <algorithm>
#include <numeric>
#include <vector>

// Include local copy of Timers taken from system/core/libutils
#include "utils/Timers.h"

using namespace std;

class Stats {
  public:
    Stats() {
        mInitTimeNs = 0;
        mDeInitTimeNs = 0;
    }

    ~Stats() {
        reset();
    }

  private:
    nsecs_t mInitTimeNs;
    nsecs_t mDeInitTimeNs;
    nsecs_t mStartTimeNs;
    std::vector<int32_t> mFrameSizes;
    std::vector<nsecs_t> mInputTimer;
    std::vector<nsecs_t> mOutputTimer;

  public:
    nsecs_t getCurTime() { return systemTime(CLOCK_MONOTONIC); }

    void setInitTime(nsecs_t initTime) { mInitTimeNs = initTime; }

    void setDeInitTime(nsecs_t deInitTime) { mDeInitTimeNs = deInitTime; }

    void setStartTime() { mStartTimeNs = systemTime(CLOCK_MONOTONIC); }

    void addFrameSize(int32_t size) { mFrameSizes.push_back(size); }

    void addInputTime() { mInputTimer.push_back(systemTime(CLOCK_MONOTONIC)); }

    void addOutputTime() { mOutputTimer.push_back(systemTime(CLOCK_MONOTONIC)); }

    void reset() {
        if (!mFrameSizes.empty()) mFrameSizes.clear();
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

    void dumpStatistics(string operation, string inputReference, int64_t duarationUs,
                        string codecName = "", string mode = "", string statsFile = "");
};

#endif  // __STATS_H__
