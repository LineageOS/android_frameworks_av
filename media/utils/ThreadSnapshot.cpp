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

#define LOG_TAG "ThreadSnapshot"
#include <utils/Log.h>
#include <utils/Timers.h>
#include <mediautils/ThreadSnapshot.h>

#include <mediautils/Process.h>

namespace android::mediautils {

pid_t ThreadSnapshot::getTid() const {
    std::lock_guard lg(mLock);
    return mState.mTid;
}

void ThreadSnapshot::setTid(pid_t tid) {
    std::lock_guard lg(mLock);
    if (mState.mTid == tid) return;
    mState.reset(tid);
}

void ThreadSnapshot::reset() {
    std::lock_guard lg(mLock);
    mState.reset(mState.mTid);
}

void ThreadSnapshot::onBegin() {
    std::string sched = getThreadSchedAsString(getTid()); // tid could race here,
                                                          // accept as benign.
    std::lock_guard lg(mLock);
    mState.onBegin(std::move(sched));
}

void ThreadSnapshot::onEnd() {
    std::lock_guard lg(mLock);
    mState.onEnd();
}

std::string ThreadSnapshot::toString() const {
    // Make a local copy of the stats data under lock.
    State state;
    {
        std::lock_guard lg(mLock);
        state = mState;
    }
    return state.toString();
}

void ThreadSnapshot::State::reset(pid_t tid) {
    mTid = tid;
    mBeginTimeNs = -2;
    mEndTimeNs = -1;
    mCumulativeTimeNs = 0;
    mBeginSched.clear();
}

void ThreadSnapshot::State::onBegin(std::string sched) {
    if (mBeginTimeNs < mEndTimeNs) {
        mBeginTimeNs = systemTime();
        mBeginSched = std::move(sched);
    }
}

void ThreadSnapshot::State::onEnd() {
    if (mEndTimeNs < mBeginTimeNs) {
        mEndTimeNs = systemTime();
        mCumulativeTimeNs += mEndTimeNs - mBeginTimeNs;
    }
}

std::string ThreadSnapshot::State::toString() const {
    if (mBeginTimeNs < 0) return {};  // never begun.

    // compute time intervals.
    const int64_t nowNs = systemTime();
    int64_t cumulativeTimeNs = mCumulativeTimeNs;
    int64_t diffNs = mEndTimeNs - mBeginTimeNs; // if onEnd() isn't matched, diffNs < 0.
    if (diffNs < 0) {
        diffNs = nowNs - mBeginTimeNs;
        cumulativeTimeNs += diffNs;
    }
    // normalization for rate variables
    const double lastRunPerSec =  1e9 / diffNs;
    const double totalPerSec = 1e9 / cumulativeTimeNs;

    // HANDLE THE SCHEDULER STATISTICS HERE
    // current and differential statistics for the scheduler.
    std::string schedNow = getThreadSchedAsString(mTid);
    const auto schedMapThen = parseThreadSchedString(mBeginSched);
    const auto schedMapNow = parseThreadSchedString(schedNow);
    static const char * schedDiffKeyList[] = {
        "se.sum_exec_runtime",
        "se.nr_migrations",
        "se.statistics.wait_sum",
        "se.statistics.wait_count",
        "se.statistics.iowait_sum",
        "se.statistics.iowait_count",
        "se.statistics.nr_forced_migrations",
        "nr_involuntary_switches",
    };

    // compute differential rate statistics.
    std::string diffString;
    for (const auto diffKey : schedDiffKeyList) {
        if (auto itThen = schedMapThen.find(diffKey);
                itThen != schedMapThen.end()) {

            if (auto itNow = schedMapNow.find(diffKey);
                    itNow != schedMapNow.end()) {
                auto diff = itNow->second - itThen->second;
                diff *= lastRunPerSec;
                auto total = itNow->second * totalPerSec;
                diffString.append(diffKey).append("  last-run:")
                        .append(std::to_string(diff))
                        .append("  cumulative:")
                        .append(std::to_string(total))
                        .append("\n");
            }
        }
    }

    if (!diffString.empty()) {
        schedNow.append("*** per second stats ***\n").append(diffString);
    }

    // Return snapshot string.
    return schedNow;
}

} // android::mediautils
