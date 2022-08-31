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

#include "StillnessDetector.h"

namespace android {
namespace media {

StillnessDetector::StillnessDetector(const Options& options)
    : mOptions(options), mCosHalfRotationalThreshold(cos(mOptions.rotationalThreshold / 2)) {}

void StillnessDetector::reset() {
    mFifo.clear();
    mWindowFull = false;
    mSuppressionDeadline.reset();
    // A "true" state indicates stillness is detected (default = true)
    mCurrentState = true;
    mPreviousState = true;
}

void StillnessDetector::setInput(int64_t timestamp, const Pose3f& input) {
    mFifo.push_back(TimestampedPose{timestamp, input});
    discardOld(timestamp);
}

bool StillnessDetector::getPreviousState() const {
    return mPreviousState;
}

bool StillnessDetector::calculate(int64_t timestamp) {
    // Move the current stillness state to the previous state.
    // This allows us to detect transitions into and out of stillness.
    mPreviousState = mCurrentState;

    discardOld(timestamp);

    // Check whether all the poses in the queue are in the proximity of the new one. We want to do
    // this before checking the overriding conditions below, in order to update the suppression
    // deadline correctly. We always go from end to start, to find the most recent pose that
    // violated stillness and update the suppression deadline if it has not been set or if the new
    // one ends after the current one.
    bool moved = false;

    if (!mFifo.empty()) {
        for (auto iter = mFifo.rbegin() + 1; iter != mFifo.rend(); ++iter) {
            const auto& event = *iter;
            if (!areNear(event.pose, mFifo.back().pose)) {
                // Enable suppression for the duration of the window.
                int64_t deadline = event.timestamp + mOptions.windowDuration;
                if (!mSuppressionDeadline.has_value() || mSuppressionDeadline.value() < deadline) {
                    mSuppressionDeadline = deadline;
                }
                moved = true;
                break;
            }
        }
    }

    // If the window has not been full, return the default value.
    if (!mWindowFull) {
        mCurrentState = mOptions.defaultValue;
    }
    // Force "in motion" while the suppression deadline is active.
    else if (mSuppressionDeadline.has_value()) {
        mCurrentState = false;
    }
    else {
        mCurrentState = !moved;
    }

    return mCurrentState;
}

void StillnessDetector::discardOld(int64_t timestamp) {
    // Handle the special case of the window duration being zero (always considered full).
    if (mOptions.windowDuration == 0) {
        mFifo.clear();
        mWindowFull = true;
    }

    // Remove any events from the queue that are older than the window. If there were any such
    // events we consider the window full.
    const int64_t windowStart = timestamp - mOptions.windowDuration;
    while (!mFifo.empty() && mFifo.front().timestamp <= windowStart) {
        mWindowFull = true;
        mFifo.pop_front();
    }

    // Expire the suppression deadline.
    if (mSuppressionDeadline.has_value() && mSuppressionDeadline <= timestamp) {
        mSuppressionDeadline.reset();
    }
}

bool StillnessDetector::areNear(const Pose3f& pose1, const Pose3f& pose2) const {
    // Check translation. We use the L1 norm to reduce computational load on expense of accuracy.
    // The L1 norm is an upper bound for the actual (L2) norm, so this approach will err on the side
    // of "not near".
    if ((pose1.translation() - pose2.translation()).lpNorm<1>() > mOptions.translationalThreshold) {
        return false;
    }

    // Check orientation.
    // The angle x between the quaternions is greater than that threshold iff
    // cos(x/2) < cos(threshold/2).
    // cos(x/2) can be efficiently calculated as the dot product of both quaternions.
    if (pose1.rotation().dot(pose2.rotation()) < mCosHalfRotationalThreshold) {
        return false;
    }

    return true;
}

}  // namespace media
}  // namespace android
