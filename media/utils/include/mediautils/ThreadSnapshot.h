/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <mutex>
#include <string>

#include <android-base/thread_annotations.h>

namespace android::mediautils {

/**
 * Collect Thread performance statistics.
 *
 * An onBegin() and onEnd() signal a continuous "run".
 * Statistics are returned by toString().
 */
class ThreadSnapshot {
public:
    explicit ThreadSnapshot(pid_t tid = -1) { mState.reset(tid); };

    // Returns current tid
    pid_t getTid() const;

    // Sets the tid
    void setTid(pid_t tid);

    // Reset statistics, keep same tid.
    void reset();

    // Signal a timing run is beginning
    void onBegin();

    // Signal a timing run is ending
    void onEnd();

    // Return the thread snapshot statistics in a string
    std::string toString() const;

private:
    mutable std::mutex mLock;

    // State represents our statistics at a given point in time.
    // It is not thread-safe, so any locking must occur at the caller.
    struct State {
        pid_t mTid;
        int64_t mBeginTimeNs;  // when last run began
        int64_t mEndTimeNs;    // when last run ends (if less than begin time, not started)
        int64_t mCumulativeTimeNs;

        // Sched is the scheduler statistics obtained as a string.
        // This is parsed only when toString() is called.
        std::string mBeginSched;

        // Clears existing state.
        void reset(pid_t tid);

        // onBegin() takes a std::string sched should can be captured outside
        // of locking.
        void onBegin(std::string sched);
        void onEnd();
        std::string toString() const;
    };

    // Our current state. We only keep the current running state.
    State mState GUARDED_BY(mLock);
};

} // android::mediautils
