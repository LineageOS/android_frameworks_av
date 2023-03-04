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
#include <android-base/stringprintf.h>

#include "ModeSelector.h"

namespace android {
namespace media {
using android::base::StringAppendF;

ModeSelector::ModeSelector(const Options& options, HeadTrackingMode initialMode)
    : mOptions(options), mDesiredMode(initialMode), mActualMode(initialMode) {}

void ModeSelector::setDesiredMode(HeadTrackingMode mode) {
    mDesiredMode = mode;
}

void ModeSelector::setScreenToStagePose(const Pose3f& screenToStage) {
    mScreenToStage = screenToStage;
}

void ModeSelector::setScreenToHeadPose(int64_t timestamp,
                                       const std::optional<Pose3f>& screenToHead) {
    mScreenToHead = screenToHead;
    mScreenToHeadTimestamp = timestamp;
}

void ModeSelector::setWorldToHeadPose(int64_t timestamp, const Pose3f& worldToHead) {
    mWorldToHead = worldToHead;
    mWorldToHeadTimestamp = timestamp;
}

void ModeSelector::setScreenStable(int64_t timestamp, bool stable) {
    mScreenStable = stable;
    mScreenStableTimestamp = timestamp;
}

void ModeSelector::calculateActualMode(int64_t timestamp) {
    int64_t screenToHeadGap = timestamp - mScreenToHeadTimestamp;
    int64_t worldToHeadGap = timestamp - mWorldToHeadTimestamp;
    int64_t screenStableGap = timestamp - mScreenStableTimestamp;
    bool isValidScreenToHead =
            mScreenToHead.has_value() && screenToHeadGap < mOptions.freshnessTimeout;
    bool isValidWorldToHead =
            mWorldToHead.has_value() && worldToHeadGap < mOptions.freshnessTimeout;
    bool isValidScreenStable =
            mScreenStable.has_value() && screenStableGap < mOptions.freshnessTimeout;

    HeadTrackingMode mode = mDesiredMode;

    // Optional downgrade from screen-relative to world-relative.
    if (mode == HeadTrackingMode::SCREEN_RELATIVE) {
        if (!isValidScreenToHead) {
            mode = HeadTrackingMode::WORLD_RELATIVE;
        }
    }

    // Optional downgrade from world-relative to static.
    if (mode == HeadTrackingMode::WORLD_RELATIVE) {
        if (!isValidWorldToHead || !isValidScreenStable || !mScreenStable.value()) {
            mode = HeadTrackingMode::STATIC;
        }
    }

    if (mode != mActualMode) {
        mLocalLog.log(
                "HT mode change from %s to %s, this ts %0.4f ms, lastTs+gap [ScreenToHead %0.4f + "
                "%0.4f, WorldToHead %0.4f + %0.4f, ScreenStable %0.4f + %0.4f] ms",
                media::toString(mActualMode).c_str(), media::toString(mode).c_str(),
                media::nsToFloatMs(timestamp), media::nsToFloatMs(mScreenToHeadTimestamp),
                media::nsToFloatMs(screenToHeadGap), media::nsToFloatMs(mWorldToHeadTimestamp),
                media::nsToFloatMs(worldToHeadGap), media::nsToFloatMs(mScreenStableTimestamp),
                media::nsToFloatMs(screenStableGap));
        mActualMode = mode;
    }
}

void ModeSelector::calculate(int64_t timestamp) {
    calculateActualMode(timestamp);

    switch (mActualMode) {
        case HeadTrackingMode::STATIC:
            mHeadToStage = mScreenToStage;
            break;

        case HeadTrackingMode::WORLD_RELATIVE:
            mHeadToStage = mWorldToHead.value().inverse() * mScreenToStage;
            break;

        case HeadTrackingMode::SCREEN_RELATIVE:
            mHeadToStage = mScreenToHead.value().inverse() * mScreenToStage;
            break;
    }
}

Pose3f ModeSelector::getHeadToStagePose() const {
    return mHeadToStage;
}

HeadTrackingMode ModeSelector::getActualMode() const {
    return mActualMode;
}

std::string ModeSelector::toString(unsigned level) const {
    std::string prefixSpace(level, ' ');
    std::string ss(prefixSpace);
    ss.append("ModeSelector: ScreenToStage ")
        .append(mScreenToStage.toString())
        .append("\n")
        .append(prefixSpace)
        .append("Mode change history:\n")
        .append(mLocalLog.dumpToString((prefixSpace + " ").c_str(), sMaxLocalLogLine));
    return ss;
}

}  // namespace media
}  // namespace android
