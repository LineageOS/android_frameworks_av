/*
 * Copyright (C) 2022 The Android Open Source Project
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

/**
 * The CameraService watchdog is used to help detect bad states in the
 * Camera HAL. The threadloop uses cycle counters, assigned to each calling
 * thread, to monitor the elapsing time and kills the process when the
 * expected duration has exceeded.
 * Notes on multi-threaded behaviors:
 *    - The threadloop is blocked/paused when there are no calls being
 *   monitored (when the TID cycle to counter map is empty).
 *   - The start and stop functions handle simultaneous call monitoring
 *   and single call monitoring differently. See function documentation for
 *   more details.
 * To disable/enable:
 *   - adb shell cmd media.camera set-cameraservice-watchdog [0/1]
 */
#pragma once
#include <chrono>
#include <thread>
#include <time.h>
#include <utils/Thread.h>
#include <utils/Log.h>
#include <unordered_map>

// Used to wrap the call of interest in start and stop calls
#define WATCH(toMonitor) watchThread([&]() { return toMonitor;}, gettid())
#define WATCH_CUSTOM_TIMER(toMonitor, cycles, cycleLength) \
        watchThread([&]() { return toMonitor;}, gettid(), cycles, cycleLength);

// Default cycles and cycle length values used to calculate permitted elapsed time
const static size_t   kMaxCycles     = 100;
const static uint32_t kCycleLengthMs = 100;

namespace android {

class CameraServiceWatchdog : public Thread {

public:
    explicit CameraServiceWatchdog() : mPause(true), mMaxCycles(kMaxCycles),
            mCycleLengthMs(kCycleLengthMs), mEnabled(true) {};

    explicit CameraServiceWatchdog (size_t maxCycles, uint32_t cycleLengthMs, bool enabled) :
            mPause(true), mMaxCycles(maxCycles), mCycleLengthMs(cycleLengthMs), mEnabled(enabled)
                    {};

    virtual ~CameraServiceWatchdog() {};

    virtual void requestExit();

    /** Enables/disables the watchdog */
    void setEnabled(bool enable);

    /** Used to wrap monitored calls in start and stop functions using custom timer values */
    template<typename T>
    auto watchThread(T func, uint32_t tid, uint32_t cycles, uint32_t cycleLength) {
        decltype(func()) res;

        if (cycles != mMaxCycles || cycleLength != mCycleLengthMs) {
            // Create another instance of the watchdog to prevent disruption
            // of timer for current monitored calls

            // Lock for mEnabled
            mEnabledLock.lock();
            sp<CameraServiceWatchdog> tempWatchdog =
                    new CameraServiceWatchdog(cycles, cycleLength, mEnabled);
            mEnabledLock.unlock();

            status_t status = tempWatchdog->run("CameraServiceWatchdog");
            if (status != OK) {
                ALOGE("Unable to watch thread: %s (%d)", strerror(-status), status);
                res = watchThread(func, tid);
                return res;
            }

            res = tempWatchdog->watchThread(func, tid);
            tempWatchdog->requestExit();
            tempWatchdog.clear();
        } else {
            // If custom timer values are equivalent to set class timer values, use
            // current thread
            res = watchThread(func, tid);
        }

        return res;
    }

    /** Used to wrap monitored calls in start and stop functions using class timer values */
    template<typename T>
    auto watchThread(T func, uint32_t tid) {
        decltype(func()) res;
        AutoMutex _l(mEnabledLock);

        if (mEnabled) {
            start(tid);
            res = func();
            stop(tid);
        } else {
            res = func();
        }

        return res;
    }

private:

    /**
     * Start adds a cycle counter for the calling thread. When threadloop is blocked/paused,
     * start() unblocks and starts the watchdog
     */
    void start(uint32_t tid);

    /**
     * If there are no calls left to be monitored, stop blocks/pauses threadloop
     * otherwise stop() erases the cycle counter to end watchdog for the calling thread
     */
    void stop(uint32_t tid);

    virtual bool    threadLoop();

    Mutex           mWatchdogLock;      // Lock for condition variable
    Mutex           mEnabledLock;       // Lock for enabled status
    Condition       mWatchdogCondition; // Condition variable for stop/start
    bool            mPause;             // True if tid map is empty
    uint32_t        mMaxCycles;         // Max cycles
    uint32_t        mCycleLengthMs;     // Length of time elapsed per cycle
    bool            mEnabled;           // True if watchdog is enabled

    std::unordered_map<uint32_t, uint32_t> tidToCycleCounterMap; // Thread Id to cycle counter map
};

}   // namespace android
