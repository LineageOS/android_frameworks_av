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

#include <psh_utils/PowerClientStats.h>

// go/keep-sorted start
#include <audio_utils/Time.h>
#include <mediautils/ServiceUtilities.h>
#include <psh_utils/AudioPowerManager.h>
// go/keep-sorted end

namespace android::media::psh_utils {

/* static */
audio_utils::CommandThread& PowerClientStats::getCommandThread() {
    [[clang::no_destroy]] static audio_utils::CommandThread ct;
    return ct;
}

PowerClientStats::PowerClientStats(uid_t uid, const std::string& additional)
        : mUid(uid)
        , mAdditional(additional)
        , mStatTimeToleranceNs(AudioPowerManager::enabled() ? kStatTimeToleranceNs : 0) {}

void PowerClientStats::start(int64_t actualNs) {
    std::lock_guard l(mMutex);
    ++mTokenCount;
    if (mStartNs == 0) {
        mStartNs = actualNs;
        mLastTimes.push_back({mStartNs, mStartNs});  // add entry for current time.
        if (mLastTimes.size() > kMaxHistory) mLastTimes.pop_front();
    }
    if (mStartStats) return;
    mStartStats = PowerStatsCollector::getCollector().getStats(mStatTimeToleranceNs);
    ++mStartCount;
}

void PowerClientStats::stop(int64_t actualNs) {
    std::lock_guard l(mMutex);
    if (--mTokenCount > 0) return;
    if (mStartNs != 0) {
        mCumulativeNs += actualNs - mStartNs;
        mLastTimes.back().second = actualNs;  // fill the actual completion time.
        mStartNs = 0;
    }
    if (!mStartStats) return;
    const auto stopStats = PowerStatsCollector::getCollector().getStats(mStatTimeToleranceNs);
    if (stopStats && stopStats != mStartStats) {
        const auto diffStats = std::make_shared<PowerStats>(*stopStats - *mStartStats);
        if (!mMaxStats || mMaxStats->metadata.duration_ms < diffStats->metadata.duration_ms) {
            mMaxStats = diffStats;
        }
        *mCumulativeStats += *diffStats;
    }
    mStartStats.reset();
}

bool PowerClientStats::setFrozen(pid_t pid, bool frozen) {
    std::lock_guard l(mMutex);
    const bool oldFrozen = mFrozenPids.count(pid) > 0;
    if (frozen) {
        mFrozenPids.emplace(pid);
    } else {
        mFrozenPids.erase(pid);
    }

    if (!oldFrozen && frozen && mTokenCount > 0) {
        // log specifically the entry to the frozen state.
        ++mFrozenWhileActive;
        mLastFrozenWhileActiveRealTimeNs = systemTime(SYSTEM_TIME_REALTIME);
    }

    // frozenAndActive is true if either the old state or the new state is frozen
    // and there is activity (mTokenCount is > 0).
    const bool frozenAndActive = (oldFrozen || frozen) && mTokenCount > 0;
    return frozenAndActive;
}

bool PowerClientStats::isFrozen(pid_t pid) const {
    std::lock_guard l(mMutex);
    return mFrozenPids.count(pid) > 0;
}

void PowerClientStats::addPid(pid_t pid) {
    std::lock_guard l(mMutex);
    mPids.emplace(pid);
}

size_t PowerClientStats::removePid(pid_t pid) {
    std::lock_guard l(mMutex);
    mPids.erase(pid);
    mFrozenPids.erase(pid);
    return mPids.size();
}

std::string PowerClientStats::toString(
        bool stats, const std::string& prefix, LogType logType) const {
    std::lock_guard l(mMutex);

    // Adjust delta time and stats if currently running.
    auto cumulativeStats = mCumulativeStats;
    auto cumulativeNs = mCumulativeNs;
    auto maxStats = mMaxStats;
    if (mStartNs) {
        auto currentTime = systemTime(SYSTEM_TIME_BOOTTIME);
        cumulativeNs += currentTime - mStartNs;
    }
    if (mStartStats) {
        const auto stopStats = PowerStatsCollector::getCollector().getStats(mStatTimeToleranceNs);
        if (stopStats && stopStats != mStartStats) {
            auto newStats = std::make_shared<PowerStats>(*cumulativeStats);
            const auto diffStats = std::make_shared<PowerStats>(*stopStats - *mStartStats);
            if (!maxStats || maxStats->metadata.duration_ms < diffStats->metadata.duration_ms) {
                maxStats = diffStats;
            }
            *newStats += *diffStats;
            cumulativeStats = newStats;
        }
    }

    // find state of the client
    const char* state;
    const bool anyFrozen = !mFrozenPids.empty();
    if (mTokenCount > 0) {
        state = anyFrozen ? "active-frozen" : "active";
    } else {
        state = anyFrozen ? "frozen" : "idle";
    }

    std::string result(prefix);
    result.append("(").append(state)
            .append(") uid: ").append(std::to_string(mUid))
            .append(" ").append(mediautils::UidInfo::getInfo(mUid)->package)
            .append("  sessions: ").append(std::to_string(mStartCount))
            .append("  actual_seconds: ").append(std::to_string(cumulativeNs * 1e-9));
    result.append(" {");
    for (auto pid : mPids) {
        result.append(" ").append(std::to_string(pid));
        if (mFrozenPids.count(pid) > 0) {
            result.append("(f)");
        }
    }
    result.append(" }");
    if (mFrozenWhileActive > 0) {
        result.append(" { frozen-while-active: ").append(std::to_string(mFrozenWhileActive))
                .append("  last: ")
                .append(audio_utils::formatSystemTime(mLastFrozenWhileActiveRealTimeNs))
                .append(" } ");
    }
    if (logType != LogType::kLogForTrack) {
        // If we don't set the last time, the entry for a currently running app will look like
        // ...  { 17:01:54.954, ~} }  where the last ~ indicates no difference from the stop time
        // to the start time.
        //
        // it is possible to copy mLastTimes and adjust, but not entirely clear it is worthwhile.
        result.append(audio_utils::bootTimePairsToString(mLastTimes));
    }
    if (!mAdditional.empty()) {
        result.append("\n").append(prefix).append(mAdditional);
    }
    if (stats && cumulativeStats->metadata.duration_ms) {
        std::string prefix2(prefix);
        prefix2.append("  ");
        result.append("\n").append("    Sum:");
        result.append(cumulativeStats->normalizedEnergy(prefix2));
    } else {
        result.append("\n");
    }
    if (stats && maxStats && maxStats->metadata.duration_ms) {
        std::string prefix2(prefix);
        prefix2.append("  ");
        result.append("    Max:");
        result.append(maxStats->normalizedEnergy(prefix2));
    }
    return result;
}

} // namespace android::media::psh_utils
