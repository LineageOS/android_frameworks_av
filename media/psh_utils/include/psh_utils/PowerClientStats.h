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

#include "PowerStats.h"
#include "PowerStatsCollector.h"

// go/keep-sorted start
#include <android-base/thread_annotations.h>
#include <audio_utils/CommandThread.h>
#include <deque>
#include <memory>
#include <set>
// go/keep-sorted end

namespace android::media::psh_utils {

/**
 * PowerClientStats accumulates power measurements based on start and stop events.
 *
 * The start and stop events must eventually be matched, but several start events
 * in a row only results in the power counted once.
 */
class PowerClientStats {
public:

    enum class LogType {
        kLogAll,
        kLogForTrack,
    };

    // A command thread is used for tokens to dispatch start and stop sequentially
    // with less overhead to the caller.
    static audio_utils::CommandThread& getCommandThread();

    /**
     * Creates an UID based power stat tracker.
     *
     * @param uid uid of app
     * @param additional string to be printed out.
     */
    PowerClientStats(uid_t uid, const std::string& additional);

    /**
     * Starts power tracking.
     */
    void start(int64_t actualNs) EXCLUDES(mMutex);

    /**
     * Stops power tracking (saves the difference) - must be paired with start().
     */
    void stop(int64_t actualNs) EXCLUDES(mMutex);

    /**
     * Sets the freeze state for a pid.
     * @param pid pid of app.
     * @param frozen true if frozen.
     * @return true if there is an active client track and the prior state was frozen or
     *         the current state is frozen.
     */
    bool setFrozen(pid_t pid, bool frozen) EXCLUDES(mMutex);

    /**
     * Returns true if the pid is currently frozen.
     */
    bool isFrozen(pid_t pid) const EXCLUDES(mMutex);

    /**
     * Adds a pid to the App for string printing.
     */
    void addPid(pid_t pid) EXCLUDES(mMutex);

    /**
     * Removes the pid from the App for string printing.
     */
    size_t removePid(pid_t pid) EXCLUDES(mMutex);

    /**
     * Returns the string info.
     * @param stats if true returns the stats.
     * @return stat string.
     */
    std::string toString(bool stats = false, const std::string& prefix = {},
            LogType logType = LogType::kLogAll) const EXCLUDES(mMutex);

private:
    // Snapshots are taken no more often than 500ms.
    static constexpr int64_t kStatTimeToleranceNs = 500'000'000;

    mutable std::mutex mMutex;
    const uid_t mUid;
    const std::string mName;
    const std::string mAdditional;
    const int64_t mStatTimeToleranceNs;
    std::set<pid_t> mPids GUARDED_BY(mMutex); // pids sharing same uid
    int64_t mStartCount GUARDED_BY(mMutex) = 0;  // audio sessions (including multiple tracks).
    int64_t mTokenCount GUARDED_BY(mMutex) = 0;
    int64_t mStartNs GUARDED_BY(mMutex) = 0;
    std::shared_ptr<const PowerStats> mStartStats GUARDED_BY(mMutex);

    static inline constexpr size_t kMaxHistory = 10;
    std::deque<std::pair<int64_t, int64_t>> mLastTimes GUARDED_BY(mMutex);

    // Cumulative time while active: sum of deltas of (stop - start).
    int64_t mCumulativeNs GUARDED_BY(mMutex) = 0;
    // Cumulative stats while active: sum of deltas of (stop - start),
    // where snapshots are quantized to ~500ms accuracy.
    std::shared_ptr<PowerStats> mCumulativeStats GUARDED_BY(mMutex) =
            std::make_shared<PowerStats>();
    std::shared_ptr<PowerStats> mMaxStats GUARDED_BY(mMutex);
    std::set<pid_t> mFrozenPids GUARDED_BY(mMutex);
    int64_t mFrozenWhileActive GUARDED_BY(mMutex) = 0;
    int64_t mLastFrozenWhileActiveRealTimeNs GUARDED_BY(mMutex) = 0;
};

} // namespace android::media::psh_utils
