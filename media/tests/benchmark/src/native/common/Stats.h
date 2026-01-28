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
#include <chrono>
#include <numeric>
#include <vector>

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
    int64_t mInitTimeNs;
    int64_t mDeInitTimeNs;
    int64_t mStartTimeNs;
    std::vector<int32_t> mFrameSizes;
    std::vector<int64_t> mInputTimer;
    std::vector<int64_t> mOutputTimer;

  public:
    int64_t getCurTime() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
    }

    void setInitTime(int64_t initTime) { mInitTimeNs = initTime; }

    void setDeInitTime(int64_t deInitTime) { mDeInitTimeNs = deInitTime; }

    void setStartTime() { mStartTimeNs = getCurTime(); }

    void addFrameSize(int32_t size) { mFrameSizes.push_back(size); }

    void addInputTime() { mInputTimer.push_back(getCurTime()); }

    void addOutputTime() { mOutputTimer.push_back(getCurTime()); }

    void reset() {
        if (!mFrameSizes.empty()) mFrameSizes.clear();
        if (!mInputTimer.empty()) mInputTimer.clear();
        if (!mOutputTimer.empty()) mOutputTimer.clear();
    }

    std::vector<int64_t> getOutputTimer() { return mOutputTimer; }

    int64_t getInitTime() { return mInitTimeNs; }

    int64_t getDeInitTime() { return mDeInitTimeNs; }

    int64_t getTimeDiff(int64_t sTime, int64_t eTime) { return (eTime - sTime); }

    int64_t getTotalTime() {
        if (mOutputTimer.empty()) return -1;
        return (*(mOutputTimer.end() - 1) - mStartTimeNs);
    }

    void dumpStatistics(const string& operation, const string& inputReference,
                        int64_t duarationUs, const string& componentName = "",
                        const string& mode = "", const string& statsFile = "");

    void uploadMetrics(const string& operation, const string& inputReference,
                      const int64_t& durationUs, const string& componentName = "",
                      const string& mode = "");
};
#endif  // __STATS_H__
