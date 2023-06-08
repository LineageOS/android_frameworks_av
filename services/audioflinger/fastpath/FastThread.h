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

#include "Configuration.h"
#ifdef CPU_FREQUENCY_STATISTICS
#include <cpustats/ThreadCpuUsage.h>
#endif
#include <utils/Thread.h>
#include "FastThreadState.h"

namespace android {

// FastThread is the common abstract base class of FastMixer and FastCapture
class FastThread : public Thread {

public:
            FastThread(const char *cycleMs, const char *loadUs);

private:
    // implement Thread::threadLoop()
    bool threadLoop() override;

protected:
    // callouts to subclass in same lexical order as they were in original FastMixer.cpp
    // FIXME need comments
    virtual const FastThreadState *poll() = 0;
    virtual void setNBLogWriter(NBLog::Writer *logWriter __unused) { }
    virtual void onIdle() = 0;
    virtual void onExit() = 0;
    virtual bool isSubClassCommand(FastThreadState::Command command) = 0;
    virtual void onStateChange() = 0;
    virtual void onWork() = 0;

    // FIXME these former local variables need comments
    const FastThreadState*  mPrevious = nullptr;
    const FastThreadState*  mCurrent = nullptr;
    struct timespec mOldTs{};
    bool            mOldTsValid = false;
    int64_t         mSleepNs = -1;     // -1: busy wait, 0: sched_yield, > 0: nanosleep
    int64_t         mPeriodNs = 0;     // expected period; the time required to
                                       // render one mix buffer
    int64_t         mUnderrunNs = 0;   // underrun likely when write cycle
                                       // is greater than this value
    int64_t         mOverrunNs = 0;    // overrun likely when write cycle is less than this value
    int64_t         mForceNs = 0;      // if overrun detected,
                                       // force the write cycle to take this much time
    int64_t         mWarmupNsMin = 0;  // warmup complete when write cycle is greater
                                       //  than or equal to this value
    int64_t         mWarmupNsMax = INT64_MAX;  // and less than or equal to this value
    FastThreadDumpState* mDummyDumpState = nullptr;
    FastThreadDumpState* mDumpState = nullptr;
    bool            mIgnoreNextOverrun = true; // used to ignore initial overrun
                                               //  and first after an underrun
#ifdef FAST_THREAD_STATISTICS
    struct timespec mOldLoad;       // previous value of clock_gettime(CLOCK_THREAD_CPUTIME_ID)
    bool            mOldLoadValid = false;  // whether oldLoad is valid
    uint32_t        mBounds = 0;
    bool            mFull = false;        // whether we have collected at least mSamplingN samples
#ifdef CPU_FREQUENCY_STATISTICS
    ThreadCpuUsage  mTcu;           // for reading the current CPU clock frequency in kHz
#endif
#endif
    unsigned        mColdGen = 0;       // last observed mColdGen
    bool            mIsWarm = false;        // true means ready to mix,
                                    // false means wait for warmup before mixing
    struct timespec   mMeasuredWarmupTs{};  // how long did it take for warmup to complete
    uint32_t          mWarmupCycles = 0;  // counter of number of loop cycles during warmup phase
    uint32_t          mWarmupConsecutiveInRangeCycles = 0; // number of consecutive cycles in range
    const sp<NBLog::Writer> mDummyNBLogWriter{new NBLog::Writer()};
    status_t          mTimestampStatus = INVALID_OPERATION;

    FastThreadState::Command mCommand = FastThreadState::INITIAL;
    bool            mAttemptedWrite = false;

    // init in constructor
    char            mCycleMs[16];   // cycle_ms + suffix
    char            mLoadUs[16];    // load_us + suffix

};  // class FastThread

}  // namespace android
