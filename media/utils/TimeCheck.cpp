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

#include <csignal>
#include "mediautils/TimerThread.h"
#define LOG_TAG "TimeCheck"

// go/keep-sorted start
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <audio_utils/Time.h>
#include <cutils/properties.h>
#include <mediautils/EventLog.h>
#include <mediautils/FixedString.h>
#include <mediautils/MethodStatistics.h>
#include <mediautils/TidWrapper.h>
#include <mediautils/TimeCheck.h>
#include <optional>
#include <utils/Log.h>
//go/keep-sorted end

#if defined(__ANDROID__)
#include "debuggerd/handler.h"
#endif


namespace android::mediautils {

// Note: The sum of kDefaultTimeOutDurationMs and kDefaultSecondChanceDurationMs
// should be no less than 2 seconds, otherwise spurious timeouts
// may occur with system suspend.
static constexpr int kDefaultTimeoutDurationMs = 3000;

// Due to suspend abort not incrementing the monotonic clock,
// we allow another second chance timeout after the first timeout expires.
//
// The total timeout is therefore kDefaultTimeoutDuration + kDefaultSecondChanceDuration,
// and the result is more stable when the monotonic clock increments during suspend.
//
static constexpr int kDefaultSecondChanceDurationMs = 2000;

/* static */
TimeCheck::Duration TimeCheck::getDefaultTimeoutDuration() {
    static constinit std::atomic<int> defaultTimeoutDurationMs{};
    auto defaultMs = defaultTimeoutDurationMs.load(std::memory_order_relaxed);
    if (defaultMs == 0) {
        defaultMs = property_get_int32(
                "audio.timecheck.timeout_duration_ms", kDefaultTimeoutDurationMs);
        if (defaultMs < 1) defaultMs = kDefaultTimeoutDurationMs;
        defaultTimeoutDurationMs.store(defaultMs, std::memory_order_relaxed);
    }
    return std::chrono::milliseconds(defaultMs);
}

/* static */
TimeCheck::Duration TimeCheck::getDefaultSecondChanceDuration() {
    static constinit std::atomic<int> defaultSecondChanceDurationMs{};
    auto defaultMs = defaultSecondChanceDurationMs.load(std::memory_order_relaxed);
    if (defaultMs == 0) {
        defaultMs = property_get_int32(
                "audio.timecheck.second_chance_duration_ms", kDefaultSecondChanceDurationMs);
        if (defaultMs < 1) defaultMs = kDefaultSecondChanceDurationMs;
        defaultSecondChanceDurationMs.store(defaultMs, std::memory_order_relaxed);
    }
    return std::chrono::milliseconds(defaultMs);
}

// This function appropriately signals a pid to dump a backtrace if we are
// running on device (and the HAL exists). If we are not running on an Android
// device, there is no HAL to signal (so we do nothing).
static inline void signalAudioHAL([[maybe_unused]] pid_t pid) {
#if defined(__ANDROID__)
    sigqueue(pid, DEBUGGER_SIGNAL, {.sival_int = 0});
#endif
}

// Audio HAL server pids vector used to generate audio HAL processes tombstone
// when audioserver watchdog triggers.
// We use a lockless storage to avoid potential deadlocks in the context of watchdog
// trigger.
// Protection again simultaneous writes is not needed given one update takes place
// during AudioFlinger construction and other comes necessarily later once the IAudioFlinger
// interface is available.
// The use of an atomic index just guaranties that current vector is fully initialized
// when read.
/* static */
void TimeCheck::accessAudioHalPids(std::vector<pid_t>* pids, bool update) {
    static constexpr int kNumAudioHalPidsVectors = 3;
    static std::vector<pid_t> audioHalPids[kNumAudioHalPidsVectors];
    static std::atomic<unsigned> curAudioHalPids = 0;

    if (update) {
        audioHalPids[(curAudioHalPids++ + 1) % kNumAudioHalPidsVectors] = *pids;
    } else {
        *pids = audioHalPids[curAudioHalPids % kNumAudioHalPidsVectors];
    }
}

/* static */
void TimeCheck::setAudioHalPids(const std::vector<pid_t>& pids) {
    accessAudioHalPids(&(const_cast<std::vector<pid_t>&>(pids)), true);
}

/* static */
std::vector<pid_t> TimeCheck::getAudioHalPids() {
    std::vector<pid_t> pids;
    accessAudioHalPids(&pids, false);
    return pids;
}

/* static */
std::string TimeCheck::signalAudioHals() {
    std::vector<pid_t> pids = getAudioHalPids();
    std::string halPids;
    if (pids.size() != 0) {
        for (const auto& pid : pids) {
            ALOGI("requesting tombstone for pid: %d", pid);
            halPids.append(std::to_string(pid)).append(" ");
            signalAudioHAL(pid);
        }
        // Allow time to complete, usually the caller is forcing restart afterwards.
        sleep(1);
    }
    return halPids;
}

/* static */
TimerThread& TimeCheck::getTimeCheckThread() {
    static TimerThread sTimeCheckThread{};
    return sTimeCheckThread;
}

/* static */
std::string TimeCheck::toString() {
    // note pending and retired are individually locked for maximum concurrency,
    // snapshot is not instantaneous at a single time.
    return getTimeCheckThread().getSnapshotAnalysis().toString();
}

TimeCheck::TimeCheck(std::string_view tag, OnTimerFunc&& onTimer, Duration requestedTimeoutDuration,
        Duration secondChanceDuration, bool crashOnTimeout)
    : mTimeCheckHandler{ std::make_shared<TimeCheckHandler>(
            tag, std::move(onTimer), crashOnTimeout, requestedTimeoutDuration,
            secondChanceDuration, std::chrono::system_clock::now(), getThreadIdWrapper()) }
    , mTimerHandle(requestedTimeoutDuration.count() == 0
              /* for TimeCheck we don't consider a non-zero secondChanceDuration here */
              ? getTimeCheckThread().trackTask(mTimeCheckHandler->tag)
              : getTimeCheckThread().scheduleTask(
                      mTimeCheckHandler->tag,
                      // Pass in all the arguments by value to this task for safety.
                      // The thread could call the callback before the constructor is finished.
                      // The destructor is not blocked on callback.
                      [ timeCheckHandler = mTimeCheckHandler ](TimerThread::Handle timerHandle) {
                          timeCheckHandler->onTimeout(timerHandle);
                      },
                      requestedTimeoutDuration,
                      secondChanceDuration)) {}

TimeCheck::~TimeCheck() {
    if (mTimeCheckHandler) {
        mTimeCheckHandler->onCancel(mTimerHandle);
    }
}

/* static */
std::string TimeCheck::analyzeTimeouts(
        float requestedTimeoutMs, float secondChanceMs,
        float elapsedSteadyMs, float elapsedSystemMs) {
    // Track any OS clock issues with suspend.
    // It is possible that the elapsedSystemMs is much greater than elapsedSteadyMs if
    // a suspend occurs; however, we always expect the timeout ms should always be slightly
    // less than the elapsed steady ms regardless of whether a suspend occurs or not.

    const float totalTimeoutMs = requestedTimeoutMs + secondChanceMs;
    std::string s = std::format(
            "Timeout ms {:.2f} ({:.2f} + {:.2f})"
            " elapsed steady ms {:.4f} elapsed system ms {:.4f}",
            totalTimeoutMs, requestedTimeoutMs, secondChanceMs, elapsedSteadyMs, elapsedSystemMs);

    // Is there something unusual?
    static constexpr float TOLERANCE_CONTEXT_SWITCH_MS = 200.f;

    if (totalTimeoutMs > elapsedSteadyMs || totalTimeoutMs > elapsedSystemMs) {
        s.append("\nError: early expiration - "
                "totalTimeoutMs should be less than elapsed time");
    }

    if (elapsedSteadyMs > elapsedSystemMs + TOLERANCE_CONTEXT_SWITCH_MS) {
        s.append("\nWarning: steady time should not advance faster than system time");
    }

    // This has been found in suspend stress testing.
    if (elapsedSteadyMs > totalTimeoutMs + TOLERANCE_CONTEXT_SWITCH_MS) {
        s.append("\nWarning: steady time significantly exceeds timeout "
                "- possible thread stall or aborted suspend");
    }

    // This has been found in suspend stress testing.
    if (elapsedSystemMs > totalTimeoutMs + TOLERANCE_CONTEXT_SWITCH_MS) {
        s.append("\nInformation: system time significantly exceeds timeout "
                "- possible suspend");
    }
    return s;
}

// To avoid any potential race conditions, the timer handle
// (expiration = clock steady start + timeout) is passed into the callback.
void TimeCheck::TimeCheckHandler::onCancel(TimerThread::Handle timerHandle) const
{
    if (TimeCheck::getTimeCheckThread().cancelTask(timerHandle) && onTimer) {
        const std::chrono::steady_clock::time_point endSteadyTime =
                std::chrono::steady_clock::now();
        const float elapsedSteadyMs = std::chrono::duration_cast<FloatMs>(
                endSteadyTime - timerHandle + timeoutDuration).count();
        // send the elapsed steady time for statistics.
        onTimer(false /* timeout */, elapsedSteadyMs);
    }
}

// To avoid any potential race conditions, the timer handle
// (expiration = clock steady start + timeout) is passed into the callback.
void TimeCheck::TimeCheckHandler::onTimeout(TimerThread::Handle timerHandle) const
{
    const std::chrono::steady_clock::time_point endSteadyTime = std::chrono::steady_clock::now();
    const std::chrono::system_clock::time_point endSystemTime = std::chrono::system_clock::now();
    // timerHandle incorporates the timeout
    const float elapsedSteadyMs = std::chrono::duration_cast<FloatMs>(
            endSteadyTime - (timerHandle - timeoutDuration)).count();
    const float elapsedSystemMs = std::chrono::duration_cast<FloatMs>(
            endSystemTime - startSystemTime).count();
    const float requestedTimeoutMs = std::chrono::duration_cast<FloatMs>(
            timeoutDuration).count();
    const float secondChanceMs = std::chrono::duration_cast<FloatMs>(
            secondChanceDuration).count();

    if (onTimer) {
        onTimer(true /* timeout */, elapsedSteadyMs);
    }

    if (!crashOnTimeout) return;

    // Generate the TimerThread summary string early before sending signals to the
    // HAL processes which can affect thread behavior.
    const auto snapshotAnalysis = getTimeCheckThread().getSnapshotAnalysis(4 /* retiredCount */);

    // Generate audio HAL processes tombstones.
    std::string halPids = signalAudioHals();
    if (!halPids.empty()) {
        halPids = "HAL pids [ " + halPids + "]";
    } else {
        halPids = "No HAL process pids available";
        ALOGI("%s", (halPids + ", skipping tombstones").c_str());
    }

    LOG_EVENT_STRING(LOGTAG_AUDIO_BINDER_TIMEOUT, tag.c_str());

    // Create abort message string - caution: this can be very large.
    const std::string abortMessage = std::string("TimeCheck timeout for ")
            .append(tag)
            .append(" scheduled ").append(audio_utils::formatTime(startSystemTime))
            .append(" on thread ").append(std::to_string(tid)).append("\n")
            .append(analyzeTimeouts(requestedTimeoutMs, secondChanceMs,
                    elapsedSteadyMs, elapsedSystemMs)).append("\n")
            .append(halPids).append("\n")
            .append(snapshotAnalysis.toString());

    // In many cases, the initial timeout stack differs from the abort backtrace because
    // (1) the time difference between initial timeout and the final abort signal
    // and (2) signalling the HAL audio service may cause
    // the thread to unblock and continue.

    // Note: LOG_ALWAYS_FATAL limits the size of the string - per log/log.h:
    // Log message text may be truncated to less than an
    // implementation-specific limit (1023 bytes).
    //
    // Here, we send the string through android-base/logging.h LOG()
    // to avoid the size limitation. LOG(FATAL) does an abort whereas
    // LOG(FATAL_WITHOUT_ABORT) does not abort.

    static constexpr pid_t invalidPid = TimerThread::SnapshotAnalysis::INVALID_PID;
    pid_t tidToAbort = invalidPid;
    if (snapshotAnalysis.suspectTid != invalidPid) {
        tidToAbort = snapshotAnalysis.suspectTid;
    } else if (snapshotAnalysis.timeoutTid != invalidPid) {
        tidToAbort = snapshotAnalysis.timeoutTid;
    }

    LOG(FATAL_WITHOUT_ABORT) << abortMessage;
    const auto ret = abortTid(tidToAbort);
    if (ret < 0) {
        LOG(FATAL) << "TimeCheck thread signal failed, aborting process. "
                       "errno: " << errno << base::ErrnoNumberAsString(errno);
    }
}

template <typename T>
concept is_ptr = requires(T t) { *t; t.operator->(); };

// Automatically create a TimeCheck class for a class and method.
// This is used for Audio HAL support.
template <typename T>
T makeTimeCheckStatsForClassMethodGeneric(
        std::string_view className, std::string_view methodName) {
    std::shared_ptr<MethodStatistics<std::string>> statistics =
            mediautils::getStatisticsForClass(className);

    if constexpr (is_ptr<T>) {
        if (!statistics) return T(new TimeCheck{}); // empty TimeCheck
        return T(new TimeCheck{
                FixedString62(className).append("::").append(methodName),
                [safeMethodName = FixedString30(methodName),
                        stats = std::move(statistics)]
                        (bool timeout, float elapsedMs) {
                    if (timeout) { ; // ignored, there is no timeout value.
                    } else {
                        stats->event(safeMethodName.asStringView(), elapsedMs);
                    }
                }, {} /* timeoutDuration */, {} /* secondChanceDuration */,
                false /* crashOnTimeout */});
    } else /* constexpr */ {
        if (!statistics) return TimeCheck{}; // empty TimeCheck
        return TimeCheck{
                FixedString62(className).append("::").append(methodName),
                [safeMethodName = FixedString30(methodName),
                        stats = std::move(statistics)]
                        (bool timeout, float elapsedMs) {
                    if (timeout) { ; // ignored, there is no timeout value.
                    } else {
                        stats->event(safeMethodName.asStringView(), elapsedMs);
                    }
                }, {} /* timeoutDuration */, {} /* secondChanceDuration */,
                false /* crashOnTimeout */};

    }
}

mediautils::TimeCheck makeTimeCheckStatsForClassMethod(
        std::string_view className, std::string_view methodName) {
    return makeTimeCheckStatsForClassMethodGeneric<mediautils::TimeCheck>(className, methodName);
}

std::unique_ptr<mediautils::TimeCheck> makeTimeCheckStatsForClassMethodUniquePtr(
        std::string_view className, std::string_view methodName) {
    return makeTimeCheckStatsForClassMethodGeneric<std::unique_ptr<mediautils::TimeCheck>>(
            className, methodName);
}

}  // namespace android::mediautils
