/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "AudioToken"

#include "AudioToken.h"

// go/keep-sorted start
#include <android-base/logging.h>
#include <powermanager/PowerManager.h>
#include <psh_utils/AudioPowerManager.h>
#include <utils/Log.h>
// go/keep-sorted end

namespace android::media::psh_utils {

 BaseToken::BaseToken()
     : mStartElapsedTime(systemTime(SYSTEM_TIME_BOOTTIME))
 {}

/* static */
constinit std::atomic<size_t> AudioClientToken::sIdCounter{};

AudioClientToken::AudioClientToken(
        std::shared_ptr<PowerClientStats> powerClientStats, pid_t pid, uid_t uid,
        const std::string& additional)
    : mPowerClientStats(std::move(powerClientStats))
    , mPid(pid)
    , mAdditional(additional)
    , mId(sIdCounter.fetch_add(1, std::memory_order_relaxed)) {
        (void)uid;
}

AudioClientToken::~AudioClientToken() {
    auto& apm = AudioPowerManager::getAudioPowerManager();

    // APM has a back pointer to AudioToken, which is accessible on toString().
    // We first remove ourselves to prevent use after free.
    apm.clear_token_ptr(this);

    // The client token is released when it is no longer registered with AudioFlinger.
    // However, it is possible that AudioTrackTokens are still active when the client is released
    // after crashing and some of its tracks are draining.  Those track tokens also
    // maintain a pointer to the PowerClientStats keeping that consistent.

    // Stopping the client moves its PowerClientStats from active to historical
    // if it is the last pid associated with the client uid.
    apm.stopClient(mPid);
}

std::string AudioClientToken::toString() const {
    std::string result("Client-");
    result.append(std::to_string(mId)).append(": ")
            .append(" start: ").append(audio_utils::formatBootTime(mStartElapsedTime))
            .append(" pid: ").append(std::to_string(mPid));
    if (!mAdditional.empty()) {
        result.append(" ").append(mAdditional);
    }
    return result;
}

std::unique_ptr<Token> createAudioClientToken(pid_t pid, uid_t uid,
        const std::string& additional) {
    return AudioPowerManager::getAudioPowerManager().startClient(pid, uid, additional);
}

/* static */
constinit std::atomic<size_t> AudioThreadToken::sIdCounter{};

AudioThreadToken::AudioThreadToken(
        pid_t tid, const std::string& wakeLockName,
        WakeFlag wakeFlag, const std::string& additional)
    : mTid(tid)
    , mWakeLockName(wakeLockName)
    , mWakeFlag(wakeFlag)
    , mAdditional(additional)
    , mId(sIdCounter.fetch_add(1, std::memory_order_relaxed)) {
}

AudioThreadToken::~AudioThreadToken() {
    auto& apm = AudioPowerManager::getAudioPowerManager();

    // APM has a back pointer to AudioToken, which is accessible on toString().
    // We first remove ourselves to prevent use after free.
    apm.clear_token_ptr(this);
}

std::string AudioThreadToken::toString() const {
    std::string result("Thread-");
    result.append(std::to_string(mId)).append(": ")
            .append(" start: ").append(audio_utils::formatBootTime(mStartElapsedTime))
            .append(" ThreadBase-tid: ").append(std::to_string(mTid))
            .append(" wakeLockName: ").append(mWakeLockName)
            .append(" wakeFlag: ").append(::android::media::psh_utils::toString(mWakeFlag));
    if (!mAdditional.empty()) {
        result.append(" ").append(mAdditional);
    }
    return result;
}

std::unique_ptr<Token> createAudioThreadToken(
        pid_t pid, const std::string& wakeLockName,
        WakeFlag wakeFlag, const std::string& additional) {
    return AudioPowerManager::getAudioPowerManager().startThread(
            pid, wakeLockName, wakeFlag, additional);
}

/* static */
constinit std::atomic<size_t> AudioTrackToken::sIdCounter{};

AudioTrackToken::AudioTrackToken(
        std::shared_ptr<PowerClientStats> powerClientStats, const std::string& additional)
    : mPowerClientStats(std::move(powerClientStats))
    , mAdditional(additional)
    , mId(sIdCounter.fetch_add(1, std::memory_order_relaxed)) {
        if (mPowerClientStats){
            mPowerClientStats->getCommandThread().add(
                    "start",
                    [pas = mPowerClientStats, actualNs = mStartElapsedTime]() {
                        pas->start(actualNs);
                    });
        }
}

AudioTrackToken::~AudioTrackToken() {
    // APM has a back pointer to AudioToken, which is accessible on toString().
    // We first remove ourselves to prevent use after free.
    AudioPowerManager::getAudioPowerManager().clear_token_ptr(this);
    if (mPowerClientStats) {
        mPowerClientStats->getCommandThread().add(
                "stop",
                [pas = mPowerClientStats, actualNs = systemTime(SYSTEM_TIME_BOOTTIME)]() {
                    pas->stop(actualNs);
                });
    }
}

std::string AudioTrackToken::toString() const {
    std::string result("Track-");
    result.append(std::to_string(mId)).append(": ")
            .append(" start: ").append(audio_utils::formatBootTime(mStartElapsedTime)).append(" ")
            .append(mPowerClientStats ? mPowerClientStats->toString(
                    false /* statistics */, {} /* prefix */,
                    PowerClientStats::LogType::kLogForTrack)
                    : std::string("null"));
    if (!mAdditional.empty()) {
        result.append(" ").append(mAdditional);
    }
    return result;
}

std::unique_ptr<Token> createAudioTrackToken(uid_t uid, const std::string& additional) {
    return AudioPowerManager::getAudioPowerManager().startTrack(uid, additional);
}


} // namespace android::media::psh_utils
