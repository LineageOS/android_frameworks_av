
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

// go/keep-sorted start
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
// go/keep-sorted end

namespace android::media::psh_utils {

class Token {
public:
    virtual ~Token() = default;

    /**
     * Return start time in boottime nanos.
     */
    virtual int64_t getStartElapsedTime() const = 0;

    /**
     * Print a string.
     */
    virtual std::string toString() const = 0;
};

// Client tokens (one per Audio Client PID)
std::unique_ptr<Token> createAudioClientToken(pid_t pid, uid_t uid,
        const std::string& additional = {});

enum class WakeFlag {
    kNone = 0,
    kLowLatency = 1,
    kLowPower = 2,
};

inline std::string toString(WakeFlag wakeFlag) {
    std::string result;
    for (const auto& [flag, name] : std::initializer_list<std::pair<WakeFlag, std::string>> {
            {WakeFlag::kLowLatency, "kLowLatency"},
            {WakeFlag::kLowPower, "kLowPower"},
        }) {
        if (static_cast<int>(flag) & static_cast<int>(wakeFlag)) {
            if (!result.empty()) result.append("|");
            result.append(name);
        }
    }
    return result;
}

// Thread tokens (one per ThreadBase PID started).
std::unique_ptr<Token> createAudioThreadToken(
        pid_t pid, const std::string& wakeLockName,
        WakeFlag wakeFlag = WakeFlag::kNone, const std::string& additional = {});

// AudioTrack/AudioRecord tokens.
std::unique_ptr<Token> createAudioTrackToken(uid_t uid, const std::string& additional = {});

} // namespace android::media::psh_utils
