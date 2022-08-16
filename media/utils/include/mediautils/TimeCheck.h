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

namespace android::mediautils {

// A class monitoring execution time for a code block (scoped variable) and causing an assert
// if it exceeds a certain time

class TimeCheck {
  public:
    using OnTimerFunc = std::function<void(bool /* timeout */, float /* elapsedMs */ )>;

    // The default timeout is chosen to be less than system server watchdog timeout
    static constexpr uint32_t kDefaultTimeOutMs = 5000;

    /**
     * TimeCheck is a RAII object which will notify a callback
     * on timer expiration or when the object is deallocated.
     *
     * TimeCheck is used as a watchdog and aborts by default on timer expiration.
     * When it aborts, it will also send a debugger signal to pids passed in through
     * setAudioHalPids().
     *
     * If the callback function returns for timeout it will not be called again for
     * the deallocation.
     *
     * \param tag       string associated with the TimeCheck object.
     * \param onTimer   callback function with 2 parameters
     *                      bool timeout  (which is true when the TimeCheck object
     *                                    times out, false when the TimeCheck object is
     *                                    destroyed or leaves scope before the timer expires.)
     *                      float elapsedMs (the elapsed time to this event).
     *                  The callback when timeout is true will be called on a different thread.
     *                  This will cancel the callback on the destructor but is not guaranteed
     *                  to block for callback completion if it is already in progress
     *                  (for maximum concurrency and reduced deadlock potential), so use proper
     *                  lifetime analysis (e.g. shared or weak pointers).
     * \param timeoutMs timeout in milliseconds.
     *                  A zero timeout means no timeout is set -
     *                  the callback is called only when
     *                  the TimeCheck object is destroyed or leaves scope.
     * \param crashOnTimeout true if the object issues an abort on timeout.
     */
    explicit TimeCheck(std::string tag, OnTimerFunc&& onTimer = {},
            uint32_t timeoutMs = kDefaultTimeOutMs, bool crashOnTimeout = true);

    TimeCheck() = default;
    // Remove copy constructors as there should only be one call to the destructor.
    // Move is kept implicitly disabled, but would be logically consistent if enabled.
    TimeCheck(const TimeCheck& other) = delete;
    TimeCheck& operator=(const TimeCheck&) = delete;

    ~TimeCheck();
    static std::string toString();
    static void setAudioHalPids(const std::vector<pid_t>& pids);
    static std::vector<pid_t> getAudioHalPids();

  private:
    // Helper class for handling events.
    // The usage here is const safe.
    class TimeCheckHandler {
    public:
        const std::string tag;
        const OnTimerFunc onTimer;
        const bool crashOnTimeout;
        const std::chrono::system_clock::time_point startTime;
        const pid_t tid;

        void onCancel(TimerThread::Handle handle) const;
        void onTimeout() const;
    };

    static TimerThread& getTimeCheckThread();
    static void accessAudioHalPids(std::vector<pid_t>* pids, bool update);

    // mTimeCheckHandler is immutable, prefer to be first initialized, last destroyed.
    // Technically speaking, we do not need a shared_ptr here because TimerThread::cancelTask()
    // is mutually exclusive of the callback, but the price paid for lifetime safety is minimal.
    const std::shared_ptr<const TimeCheckHandler> mTimeCheckHandler;
    const TimerThread::Handle mTimerHandle = TimerThread::INVALID_HANDLE;
};

// Returns a TimeCheck object that sends info to MethodStatistics
// obtained from getStatisticsForClass(className).
TimeCheck makeTimeCheckStatsForClassMethod(
        std::string_view className, std::string_view methodName);

}  // namespace android::mediautils
