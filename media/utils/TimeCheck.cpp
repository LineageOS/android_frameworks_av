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

#define LOG_TAG "TimeCheck"

#include <optional>

#include <android-base/logging.h>
#include <audio_utils/clock.h>
#include <mediautils/EventLog.h>
#include <mediautils/MethodStatistics.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>
#include "debuggerd/handler.h"

namespace android::mediautils {

/**
 * Returns the std::string "HH:MM:SS.MSc" from a system_clock time_point.
 */
std::string formatTime(std::chrono::system_clock::time_point t) {
    auto time_string = audio_utils_time_string_from_ns(
            std::chrono::nanoseconds(t.time_since_epoch()).count());

    // The time string is 19 characters (including null termination).
    // Example: "03-27 16:47:06.187"
    //           MM DD HH MM SS MS
    // We offset by 6 to get HH:MM:SS.MSc
    //
    return time_string.time + 6; // offset to remove month/day.
}

/**
 * Finds the end of the common time prefix.
 *
 * This is as an option to remove the common time prefix to avoid
 * unnecessary duplicated strings.
 *
 * \param time1 a time string
 * \param time2 a time string
 * \return      the position where the common time prefix ends. For abbreviated
 *              printing of time2, offset the character pointer by this position.
 */
static size_t commonTimePrefixPosition(std::string_view time1, std::string_view time2) {
    const size_t endPos = std::min(time1.size(), time2.size());
    size_t i;

    // Find location of the first mismatch between strings
    for (i = 0; ; ++i) {
        if (i == endPos) {
            return i; // strings match completely to the length of one of the strings.
        }
        if (time1[i] != time2[i]) {
            break;
        }
        if (time1[i] == '\0') {
            return i; // "printed" strings match completely.  No need to check further.
        }
    }

    // Go backwards until we find a delimeter or space.
    for (; i > 0
           && isdigit(time1[i]) // still a number
           && time1[i - 1] != ' '
         ; --i) {
    }
    return i;
}

/**
 * Returns the unique suffix of time2 that isn't present in time1.
 *
 * If time2 is identical to time1, then an empty string_view is returned.
 * This method is used to elide the common prefix when printing times.
 */
std::string_view timeSuffix(std::string_view time1, std::string_view time2) {
    const size_t pos = commonTimePrefixPosition(time1, time2);
    return time2.substr(pos);
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
TimerThread& TimeCheck::getTimeCheckThread() {
    static TimerThread sTimeCheckThread{};
    return sTimeCheckThread;
}

/* static */
std::string TimeCheck::toString() {
    // note pending and retired are individually locked for maximum concurrency,
    // snapshot is not instantaneous at a single time.
    return getTimeCheckThread().toString();
}

TimeCheck::TimeCheck(std::string tag, OnTimerFunc&& onTimer, uint32_t timeoutMs,
        bool crashOnTimeout)
    : mTimeCheckHandler(new TimeCheckHandler{
            std::move(tag), std::move(onTimer), crashOnTimeout,
            std::chrono::system_clock::now(), gettid()})
    , mTimerHandle(timeoutMs == 0
              ? getTimeCheckThread().trackTask(mTimeCheckHandler->tag)
              : getTimeCheckThread().scheduleTask(
                      mTimeCheckHandler->tag,
                      // Pass in all the arguments by value to this task for safety.
                      // The thread could call the callback before the constructor is finished.
                      // The destructor is not blocked on callback.
                      [ timeCheckHandler = mTimeCheckHandler ] {
                          timeCheckHandler->onTimeout();
                      },
                      std::chrono::milliseconds(timeoutMs))) {}

TimeCheck::~TimeCheck() {
    if (mTimeCheckHandler) {
        mTimeCheckHandler->onCancel(mTimerHandle);
    }
}

void TimeCheck::TimeCheckHandler::onCancel(TimerThread::Handle timerHandle) const
{
    if (TimeCheck::getTimeCheckThread().cancelTask(timerHandle) && onTimer) {
        const std::chrono::system_clock::time_point endTime = std::chrono::system_clock::now();
        onTimer(false /* timeout */,
                std::chrono::duration_cast<std::chrono::duration<float, std::milli>>(
                        endTime - startTime).count());
    }
}

void TimeCheck::TimeCheckHandler::onTimeout() const
{
    const std::chrono::system_clock::time_point endTime = std::chrono::system_clock::now();
    if (onTimer) {
        onTimer(true /* timeout */,
                std::chrono::duration_cast<std::chrono::duration<float, std::milli>>(
                        endTime - startTime).count());
    }

    if (!crashOnTimeout) return;

    // Generate the TimerThread summary string early before sending signals to the
    // HAL processes which can affect thread behavior.
    const std::string summary = getTimeCheckThread().toString(4 /* retiredCount */);

    // Generate audio HAL processes tombstones and allow time to complete
    // before forcing restart
    std::vector<pid_t> pids = TimeCheck::getAudioHalPids();
    std::string halPids = "HAL pids [ ";
    if (pids.size() != 0) {
        for (const auto& pid : pids) {
            ALOGI("requesting tombstone for pid: %d", pid);
            halPids.append(std::to_string(pid)).append(" ");
            sigqueue(pid, DEBUGGER_SIGNAL, {.sival_int = 0});
        }
        sleep(1);
    } else {
        ALOGI("No HAL process pid available, skipping tombstones");
    }
    halPids.append("]");

    LOG_EVENT_STRING(LOGTAG_AUDIO_BINDER_TIMEOUT, tag.c_str());

    // Create abort message string - caution: this can be very large.
    const std::string abortMessage = std::string("TimeCheck timeout for ")
            .append(tag)
            .append(" scheduled ").append(formatTime(startTime))
            .append(" on thread ").append(std::to_string(tid)).append("\n")
            .append(halPids).append("\n")
            .append(summary);

    // Note: LOG_ALWAYS_FATAL limits the size of the string - per log/log.h:
    // Log message text may be truncated to less than an
    // implementation-specific limit (1023 bytes).
    //
    // Here, we send the string through android-base/logging.h LOG()
    // to avoid the size limitation. LOG(FATAL) does an abort whereas
    // LOG(FATAL_WITHOUT_ABORT) does not abort.

    LOG(FATAL) << abortMessage;
}

// Automatically create a TimeCheck class for a class and method.
// This is used for Audio HIDL support.
mediautils::TimeCheck makeTimeCheckStatsForClassMethod(
        std::string_view className, std::string_view methodName) {
    std::shared_ptr<MethodStatistics<std::string>> statistics =
            mediautils::getStatisticsForClass(className);
    if (!statistics) return {}; // empty TimeCheck.
    return mediautils::TimeCheck(
            std::string(className).append("::").append(methodName),
            [ clazz = std::string(className), method = std::string(methodName),
              stats = std::move(statistics) ]
            (bool timeout, float elapsedMs) {
                    if (timeout) {
                        ; // ignored, there is no timeout value.
                    } else {
                        stats->event(method, elapsedMs);
                    }
            }, 0 /* timeoutMs */);
}

}  // namespace android::mediautils
