/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TRANSCODING_LOGGER_H
#define ANDROID_MEDIA_TRANSCODING_LOGGER_H

#include <media/NdkMediaFormat.h>
#include <utils/Condition.h>

#include <chrono>
#include <memory>
#include <mutex>
#include <queue>

namespace android {

/** Class for logging transcoding events. */
class TranscodingLogger {
public:
    /** The maximum number of atoms pushed to statsd per day. */
    static constexpr int kMaxAtomsPerDay = 50;

    /** The maximum number of successful transcoding atoms pushed to statsd per day. */
    static constexpr int kMaxSuccessfulAtomsPerDay = 35;

    /** Reason transcoding session ended. Maps to MediaTranscodingSessionEnded atom's Reason. */
    enum SessionEndedReason {
        UNKNOWN = 0,
        FINISHED,
        ERROR,
        PAUSED,
        CANCELLED,
        START_FAILED,
        RESUME_FAILED,
        CREATE_FAILED,
        CONFIG_SRC_FAILED,
        CONFIG_DST_FAILED,
        CONFIG_TRACK_FAILED,
        OPEN_SRC_FD_FAILED,
        OPEN_DST_FD_FAILED,
        NO_TRACKS,
    };

    TranscodingLogger();
    ~TranscodingLogger() = default;

    /**
     * Logs a transcoding session ended event (MediaTranscodingSessionEnded atom).
     * @param reason Reason for the transcoding session to end.
     * @param callingUid UID of the caller connecting to the transcoding service.
     * @param status Status (error code) of the transcoding session.
     * @param duration Duration of the transcoding session.
     * @param srcFormat The source video track format.
     * @param dstFormat The destination video track format.
     */
    void logSessionEnded(enum SessionEndedReason reason, uid_t callingUid, int status,
                         std::chrono::microseconds duration, AMediaFormat* srcFormat,
                         AMediaFormat* dstFormat);

private:
    friend class TranscodingLoggerTest;

    // Function prototype for writing out the session ended atom.
    using SessionEndedAtomWriter = std::function<int(
            int32_t, int32_t, int32_t, int32_t, int32_t, int32_t, int32_t, char const*, int32_t,
            int32_t, int32_t, int32_t, bool arg12, int32_t, int32_t, char const*, bool)>;

    std::mutex mLock;
    std::queue<std::pair<std::chrono::steady_clock::time_point, int>> mLastLoggedAtoms
            GUARDED_BY(mLock);
    uint32_t mSuccessfulCount = 0;
    SessionEndedAtomWriter mSessionEndedAtomWriter;

    void logSessionEnded(const std::chrono::steady_clock::time_point& now,
                         enum SessionEndedReason reason, uid_t callingUid, int status,
                         std::chrono::microseconds duration, AMediaFormat* srcFormat,
                         AMediaFormat* dstFormat);
    bool shouldLogAtom(const std::chrono::steady_clock::time_point& now, int status);
    // Used for testing to validate what gets sent to statsd.
    void setSessionEndedAtomWriter(const SessionEndedAtomWriter& writer);
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_LOGGER_H
