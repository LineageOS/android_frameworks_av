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

#include <chrono>
#include <vector>

#include <mediautils/TimerThread.h>

namespace android::mediautils {

// A class monitoring execution time for a code block (scoped variable) and causing an assert
// if it exceeds a certain time

class TimeCheck {
  public:

    // Duration for TimeCheck is based on steady_clock, typically nanoseconds.
    using Duration = std::chrono::steady_clock::duration;

    // Duration for printing is in milliseconds, using float for additional precision.
    using FloatMs = std::chrono::duration<float, std::milli>;

    // OnTimerFunc is the callback function with 2 parameters.
    //  bool timeout  (which is true when the TimeCheck object
    //                 times out, false when the TimeCheck object is
    //                 destroyed or leaves scope before the timer expires.)
    //  float elapsedMs (the elapsed time to this event).
    using OnTimerFunc = std::function<void(bool /* timeout */, float /* elapsedMs */ )>;

    // The default timeout is chosen to be less than system server watchdog timeout
    // Note: kDefaultTimeOutMs should be no less than 2 seconds, otherwise spurious timeouts
    // may occur with system suspend.
    static constexpr TimeCheck::Duration kDefaultTimeoutDuration = std::chrono::milliseconds(3000);

    // Due to suspend abort not incrementing the monotonic clock,
    // we allow another second chance timeout after the first timeout expires.
    //
    // The total timeout is therefore kDefaultTimeoutDuration + kDefaultSecondChanceDuration,
    // and the result is more stable when the monotonic clock increments during suspend.
    //
    static constexpr TimeCheck::Duration kDefaultSecondChanceDuration =
            std::chrono::milliseconds(2000);

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
     * \param onTimer   callback function with 2 parameters (described above in OnTimerFunc).
     *                  The callback when timeout is true will be called on a different thread.
     *                  This will cancel the callback on the destructor but is not guaranteed
     *                  to block for callback completion if it is already in progress
     *                  (for maximum concurrency and reduced deadlock potential), so use proper
     *                  lifetime analysis (e.g. shared or weak pointers).
     * \param requestedTimeoutDuration timeout in milliseconds.
     *                  A zero timeout means no timeout is set -
     *                  the callback is called only when
     *                  the TimeCheck object is destroyed or leaves scope.
     * \param secondChanceDuration additional milliseconds to wait if the first timeout expires.
     *                  This is used to prevent false timeouts if the steady (monotonic)
     *                  clock advances on aborted suspend.
     * \param crashOnTimeout true if the object issues an abort on timeout.
     */
    explicit TimeCheck(std::string_view tag, OnTimerFunc&& onTimer,
            Duration requestedTimeoutDuration, Duration secondChanceDuration,
            bool crashOnTimeout);

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
        template <typename S, typename F>
        TimeCheckHandler(S&& _tag, F&& _onTimer, bool _crashOnTimeout,
            Duration _timeoutDuration, Duration _secondChanceDuration,
            std::chrono::system_clock::time_point _startSystemTime,
            pid_t _tid)
            : tag(std::forward<S>(_tag))
            , onTimer(std::forward<F>(_onTimer))
            , crashOnTimeout(_crashOnTimeout)
            , timeoutDuration(_timeoutDuration)
            , secondChanceDuration(_secondChanceDuration)
            , startSystemTime(_startSystemTime)
            , tid(_tid)
            {}
        const FixedString62 tag;
        const OnTimerFunc onTimer;
        const bool crashOnTimeout;
        const Duration timeoutDuration;
        const Duration secondChanceDuration;
        const std::chrono::system_clock::time_point startSystemTime;
        const pid_t tid;

        void onCancel(TimerThread::Handle handle) const;
        void onTimeout(TimerThread::Handle handle) const;
    };

    // Returns a string that represents the timeout vs elapsed time,
    // and diagnostics if there are any potential issues.
    static std::string analyzeTimeouts(
            float timeoutMs, float elapsedSteadyMs, float elapsedSystemMs);

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
