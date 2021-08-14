/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "PoseRateLimiter.h"

namespace android {
namespace media {

PoseRateLimiter::PoseRateLimiter(const Options& options) : mOptions(options), mLimiting(false) {}

void PoseRateLimiter::enable() {
    mLimiting = true;
}

void PoseRateLimiter::reset(const Pose3f& target) {
    mLimiting = false;
    mTargetPose = target;
}

void PoseRateLimiter::setTarget(const Pose3f& target) {
    mTargetPose = target;
}

Pose3f PoseRateLimiter::calculatePose(int64_t timestamp) {
    assert(mTargetPose.has_value());
    Pose3f pose;
    if (mLimiting && mOutput.has_value()) {
        std::tie(pose, mLimiting) = moveWithRateLimit(
                mOutput->pose, mTargetPose.value(), timestamp - mOutput->timestamp,
                mOptions.maxTranslationalVelocity, mOptions.maxRotationalVelocity);
    } else {
        pose = mTargetPose.value();
    }
    mOutput = Point{pose, timestamp};
    return pose;
}

}  // namespace media
}  // namespace android
