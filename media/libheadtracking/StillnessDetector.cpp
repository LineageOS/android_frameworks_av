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

StillnessDetector::StillnessDetector(const Options& options) : mOptions(options) {}

void StillnessDetector::reset() {
    mFifo.clear();
    mWindowFull = false;
}

void StillnessDetector::setInput(int64_t timestamp, const Pose3f& input) {
    mFifo.push_back(TimestampedPose{timestamp, input});
    discardOld(timestamp);
}

bool StillnessDetector::calculate(int64_t timestamp) {
    discardOld(timestamp);

    // If the window has not been full, we don't consider ourselves still.
    if (!mWindowFull) {
        return false;
    }

    // An empty FIFO and window full is considered still (this will happen in the unlikely case when
    // the window duration is shorter than the gap between samples).
    if (mFifo.empty()) {
        return true;
    }

    // Otherwise, check whether all the poses remaining in the queue are in the proximity of the new
    // one.
    for (auto iter = mFifo.begin(); iter != mFifo.end() - 1; ++iter) {
        const auto& event = *iter;
        if (!areNear(event.pose, mFifo.back().pose)) {
            return false;
        }
    }

    return true;
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
}

bool StillnessDetector::areNear(const Pose3f& pose1, const Pose3f& pose2) const {
    // Check translation. We use the L1 norm to reduce computational load on expense of accuracy.
    // The L1 norm is an upper bound for the actual (L2) norm, so this approach will err on the side
    // of "not near".
    if ((pose1.translation() - pose2.translation()).lpNorm<1>() >=
        mOptions.translationalThreshold) {
        return false;
    }

    // Check orientation. We use the L1 norm of the imaginary components of the quaternion to reduce
    // computational load on expense of accuracy. For small angles, those components are approx.
    // equal to the angle of rotation and so the norm is approx. the total angle of rotation. The
    // L1 norm is an upper bound, so this approach will err on the side of "not near".
    if ((pose1.rotation().vec() - pose2.rotation().vec()).lpNorm<1>() >=
        mOptions.rotationalThreshold) {
        return false;
    }

    return true;
}

}  // namespace media
}  // namespace android
