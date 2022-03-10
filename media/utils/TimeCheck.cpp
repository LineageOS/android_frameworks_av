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
#include <sstream>

#include <mediautils/EventLog.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>
#include "debuggerd/handler.h"

namespace android::mediautils {

namespace {

std::string formatTime(std::chrono::system_clock::time_point t) {
    auto msSinceEpoch = std::chrono::round<std::chrono::milliseconds>(t.time_since_epoch());
    return (std::ostringstream() << msSinceEpoch.count()).str();
}

}  // namespace

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

TimeCheck::TimeCheck(std::string tag, OnTimerFunc&& onTimer, uint32_t timeoutMs,
        bool crashOnTimeout)
    : mTimeCheckHandler(new TimeCheckHandler{
            std::move(tag), std::move(onTimer), crashOnTimeout,
            std::chrono::system_clock::now(), gettid()})
    , mTimerHandle(getTimeCheckThread().scheduleTask(
              // Pass in all the arguments by value to this task for safety.
              // The thread could call the callback before the constructor is finished.
              // The destructor will be blocked on the callback, but that is implementation
              // dependent.
              [ timeCheckHandler = mTimeCheckHandler ] {
                  timeCheckHandler->onTimeout();
              },
              std::chrono::milliseconds(timeoutMs))) {}

TimeCheck::~TimeCheck() {
    mTimeCheckHandler->onCancel(mTimerHandle);
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

    // Generate audio HAL processes tombstones and allow time to complete
    // before forcing restart
    std::vector<pid_t> pids = TimeCheck::getAudioHalPids();
    if (pids.size() != 0) {
        for (const auto& pid : pids) {
            ALOGI("requesting tombstone for pid: %d", pid);
            sigqueue(pid, DEBUGGER_SIGNAL, {.sival_int = 0});
        }
        sleep(1);
    } else {
        ALOGI("No HAL process pid available, skipping tombstones");
    }
    LOG_EVENT_STRING(LOGTAG_AUDIO_BINDER_TIMEOUT, tag.c_str());
    LOG_ALWAYS_FATAL("TimeCheck timeout for %s on thread %d (start=%s, end=%s)",
            tag.c_str(), tid, formatTime(startTime).c_str(), formatTime(endTime).c_str());
}

}  // namespace android::mediautils
