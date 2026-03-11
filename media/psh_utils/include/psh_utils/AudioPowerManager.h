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

#pragma once

#include "PowerClientStats.h"
#include "PowerStatsCollector.h"
#include "Token.h"

#include <android-base/thread_annotations.h>
#include <audio_utils/linked_hash_map.h>
#include <list>
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace android::media::psh_utils {

/**
 * AudioPowerManager is a singleton class that
 * serializes the power, wakelock, and performance
 * messages
 */
class AudioPowerManager {
    friend class AudioClientToken;
    friend class AudioThreadToken;
    friend class AudioTrackToken;

public:
    static AudioPowerManager& getAudioPowerManager();

    /**
     * Returns a token indicating that a client is started.
     * This is associated with an application.
     */
    std::unique_ptr<Token> startClient(pid_t pid, uid_t uid,
            const std::string& additional);

    /**
     * Returns a token that represents a start instance for uid.
     * This is typically associated with an AudioTrack / AudioRecord start.
     */
    std::unique_ptr<Token> startTrack(uid_t uid, const std::string& additional);

    /**
     * Returns a token that represents a wakelock for a Thread start.
     */
    std::unique_ptr<Token> startThread(
            pid_t pid, const std::string& wakeLockName,
            WakeFlag wakeFlag, const std::string& additional);

    /**
     * Sets the freeze state for a pid.
     * @param pid pid of app.
     * @param frozen true if frozen.
     * @return true if there is an active client track for the uid associated with the pid
     *         and either the prior state was frozen or the current state is frozen.
     */
    bool setFrozen(pid_t pid, bool frozen);

    /**
     * Returns true if the pid is currently frozen.
     */
    bool isFrozen(pid_t pid) const;

    std::string toString() const;

    static bool enabled();

private:
    // For AudioToken dtor only.
    void clear_token_ptr(Token* token);
    void stopClient(pid_t pid);

    std::shared_ptr<PowerClientStats>
    getPowerClientStatsFromPid_l(pid_t pid) const REQUIRES(mMutex);

    static constexpr size_t kHistory = 6;

    mutable std::mutex mMutex;
    std::unordered_set<Token *> mOutstandingTokens GUARDED_BY(mMutex);
    std::unordered_map<pid_t, uid_t> mPidToUid GUARDED_BY(mMutex);
    std::map<uid_t, std::shared_ptr<PowerClientStats>> mPowerClientStats GUARDED_BY(mMutex);
    audio_utils::linked_hash_map<uid_t, std::shared_ptr<PowerClientStats>>
            mHistoricalClients GUARDED_BY(mMutex);
};

} // namespace android::media::psh_utils
