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

#define LOG_TAG "AudioPowerManager"

#include <psh_utils/AudioPowerManager.h>

// go/keep-sorted start
#include "AudioToken.h"
#include <audio_utils/Time.h>
#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/Timers.h>
// go/keep-sorted end

namespace android::media::psh_utils {

/* static */
AudioPowerManager& AudioPowerManager::getAudioPowerManager() {
    [[clang::no_destroy]] static AudioPowerManager apm;
    return apm;
}

std::unique_ptr<Token> AudioPowerManager::startClient(pid_t pid, uid_t uid,
        const std::string& additional) {
    std::shared_ptr<PowerClientStats> powerClientStats;
    std::lock_guard l(mMutex);
    if (mPowerClientStats.count(uid) == 0) {
        const auto it = mHistoricalClients.find(uid);
        if (it == mHistoricalClients.end()) {
            powerClientStats = std::make_shared<PowerClientStats>(uid, additional);
        } else {
            powerClientStats = it->second;
            mHistoricalClients.erase(it);
        }
        mPowerClientStats[uid] = powerClientStats;
    } else {
        powerClientStats = mPowerClientStats[uid];
    }
    powerClientStats->addPid(pid);
    mPidToUid[pid] = uid;
    std::unique_ptr<Token> token =
            std::make_unique<AudioClientToken>(powerClientStats, pid, uid, additional);
    mOutstandingTokens.emplace(token.get());
    return token;
}

std::unique_ptr<Token> AudioPowerManager::startTrack(uid_t uid, const std::string& additional) {
    std::lock_guard l(mMutex);
    if (mPowerClientStats.count(uid) == 0) {
        ALOGW("%s: Cannot find uid: %d", __func__, uid);
        return {};
    }
    auto powerClientStats = mPowerClientStats[uid];
    std::unique_ptr<Token> token =
            std::make_unique<AudioTrackToken>(powerClientStats, additional);
    mOutstandingTokens.emplace(token.get());
    return token;
}

std::unique_ptr<Token> AudioPowerManager::startThread(
        pid_t pid, const std::string& wakeLockName,
        WakeFlag wakeFlag, const std::string& additional) {
    std::lock_guard l(mMutex);
    std::unique_ptr<Token> token =
            std::make_unique<AudioThreadToken>(pid, wakeLockName, wakeFlag, additional);
    mOutstandingTokens.emplace(token.get());
    return token;
}

bool AudioPowerManager::setFrozen(pid_t pid, bool frozen) {
    std::lock_guard l(mMutex);
    const auto stats = getPowerClientStatsFromPid_l(pid);
    if (stats == nullptr) return false;
    return stats->setFrozen(pid, frozen);
}

bool AudioPowerManager::isFrozen(pid_t pid) const {
    std::lock_guard l(mMutex);
    const auto stats = getPowerClientStatsFromPid_l(pid);
    if (stats == nullptr) return false;
    return stats->isFrozen(pid);
}

std::string AudioPowerManager::toString() const {
    const std::string prefix("  ");
    std::string result;
    std::lock_guard l(mMutex);
    result.append("Power Tokens:\n");
    std::vector<std::string> tokenInfo;
    for (const auto& token: mOutstandingTokens) {
        tokenInfo.emplace_back(token->toString());
    }
    std::sort(tokenInfo.begin(), tokenInfo.end());
    for (const auto& info: tokenInfo) {
        result.append(prefix).append(info).append("\n");
    }
    result.append("Power Clients: (some snapshots quantized in time)\n");
    for (const auto& [uid, powerClientStats]: mPowerClientStats) {
        result.append(powerClientStats->toString(true, prefix));
    }
    result.append("Power Client History:\n");
    for (const auto& [power, powerClientStats]: mHistoricalClients) {
        result.append(powerClientStats->toString(true, prefix));
    }
    return result;
}

void AudioPowerManager::stopClient(pid_t pid) {
    std::lock_guard l(mMutex);
    const auto pidit = mPidToUid.find(pid);
    if (pidit == mPidToUid.end()) return;
    const uid_t uid = pidit->second;
    const auto it = mPowerClientStats.find(uid);
    if (it == mPowerClientStats.end()) return;

    auto powerClientStats = it->second;
    size_t count = powerClientStats->removePid(pid);
    if (count == 0) {
        mHistoricalClients[uid] = powerClientStats;
        mPowerClientStats.erase(it);
        if (mHistoricalClients.size() > kHistory) {
            mHistoricalClients.erase(mHistoricalClients.begin()); // remove oldest.
        }
    }
    mPidToUid.erase(pid);
}

std::shared_ptr<PowerClientStats>
AudioPowerManager::getPowerClientStatsFromPid_l(pid_t pid) const {
    const auto pidit = mPidToUid.find(pid);
    if (pidit == mPidToUid.end()) {
        ALOGW("%s: pid %d doesn't exist (unexpected)", __func__, pid);
        return {};
    }

    const uid_t uid = pidit->second;
    const auto it = mPowerClientStats.find(uid);
    if (it == mPowerClientStats.end()) {
        ALOGW("%s: uid %d doesn't exist (unexpected)", __func__, uid);
        return {};
    }
    return it->second;
}

void AudioPowerManager::clear_token_ptr(Token* token) {
    if (token != nullptr) {
        std::lock_guard l(mMutex);
        (void)mOutstandingTokens.erase(token);
    }
}

/* static */
bool AudioPowerManager::enabled() {
    static const bool enabled = property_get_bool("persist.audio.power_stats.enabled", false);
    return enabled;
}

} // namespace android::media::psh_utils
