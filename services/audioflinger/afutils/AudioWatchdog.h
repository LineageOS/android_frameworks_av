/*
 * Copyright (C) 2012 The Android Open Source Project
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

// The watchdog thread runs periodically.  It has two functions:
//   (a) verify that adequate CPU time is available, and log
//       as soon as possible when there appears to be a CPU shortage
//   (b) monitor the other threads [not yet implemented]

#pragma once

#include <mutex>
#include <time.h>
#include <utils/Thread.h>

namespace android {

// Keeps a cache of AudioWatchdog statistics that can be logged by dumpsys.
// The usual caveats about atomicity of information apply.
struct AudioWatchdogDump {
    uint32_t mUnderruns = 0;    // total number of underruns
    uint32_t mLogs = 0;         // total number of log messages
    time_t   mMostRecent = 0;   // time of most recent log
    void     dump(int fd);  // should only be called on a stable copy, not the original
};

class AudioWatchdog : public Thread {

public:
    explicit AudioWatchdog(unsigned periodMs = 50) : Thread(false /*canCallJava*/),
            mPeriodNs(periodMs * 1000000), mMaxCycleNs(mPeriodNs * 2)
        {
            // force an immediate log on first underrun
            mLogTs.tv_sec = MIN_TIME_BETWEEN_LOGS_SEC;
            mLogTs.tv_nsec = 0;
        }

     // Do not call Thread::requestExitAndWait() without first calling requestExit().
    // Thread::requestExitAndWait() is not virtual, and the implementation doesn't do enough.
    void            requestExit() override;

    // FIXME merge API and implementation with AudioTrackThread
    void            pause();   // suspend thread from execution at next loop boundary
    void            resume();  // allow thread to execute, if not requested to exit

    // Where to store the dump, or NULL to not update
    void            setDump(AudioWatchdogDump* dump);

private:
    bool            threadLoop() override;

    static constexpr int32_t MIN_TIME_BETWEEN_LOGS_SEC = 60;
    const uint32_t  mPeriodNs;       // nominal period
    const uint32_t  mMaxCycleNs;     // maximum allowed time of one cycle before declaring underrun

    mutable std::mutex mLock;      // Thread::mLock is private
    std::condition_variable mCond; // Thread::mThreadExitedCondition is private
    bool            mPaused GUARDED_BY(mLock) = false; // whether thread is currently paused
    bool            mOldTsValid GUARDED_BY(mLock) = false;  // whether mOldTs is valid
    struct timespec mOldTs GUARDED_BY(mLock);          // monotonic time when threadLoop last ran
    struct timespec mLogTs GUARDED_BY(mLock);          // time since last log (ctor init).
    uint32_t        mUnderruns GUARDED_BY(mLock) = 0;  // total number of underruns
    uint32_t        mLogs GUARDED_BY(mLock) = 0;       // total number of logs

    // where to store the dump, always non-NULL
    AudioWatchdogDump*  mDump GUARDED_BY(mLock) = &mDummyDump;
    AudioWatchdogDump   mDummyDump; // default area for dump in case setDump() is not called
};

}   // namespace android

