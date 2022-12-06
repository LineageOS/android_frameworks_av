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
#pragma once

#include <optional>

#include "media/Pose.h"

namespace android {
namespace media {

/**
 * Limits a stream of poses to a given maximum translational and rotational velocities.
 *
 * Normal operation:
 *
 * Pose3f output;
 * PoseRateLimiter limiter(...);
 *
 * // Limiting is disabled. Output will be the same as last input.
 * limiter.setTarget(...);
 * output = limiter.calculatePose(...);
 * limiter.setTarget(...);
 * output = limiter.calculatePose(...);
 *
 * // Enable limiting. Output will no longer be necessarily the same as last input.
 * limiter.enable();
 * limiter.setTarget(...);
 * output = limiter.calculatePose(...);
 * limiter.setTarget(...);
 * output = limiter.calculatePose(...);
 *
 * // When eventually the output has been able to catch up with the last input, the limited will be
 * // automatically disabled again and the output will match the input again.
 * limiter.setTarget(...);
 * output = limiter.calculatePose(...);
 *
 * As shown above, the limiter is turned on manually via enable(), but turns off automatically as
 * soon as the output is able to catch up to the input. The intention is that rate limiting will be
 * turned on at specific times to smooth out any artificial discontinuities introduced to the pose
 * stream, but the rest of the time will be a simple passthrough.

 * setTarget(...) and calculatePose(...) don't have to be ordered in any particular way. However,
 * setTarget or reset() must be called at least once prior to the first calculatePose().
 *
 * Calling reset() instead of setTarget() forces the output to the given pose and disables rate
 * limiting.
 *
 * This implementation is thread-compatible, but not thread-safe.
 */
class PoseRateLimiter {
  public:
    struct Options {
        float maxTranslationalVelocity = std::numeric_limits<float>::infinity();
        float maxRotationalVelocity = std::numeric_limits<float>::infinity();
    };

    explicit PoseRateLimiter(const Options& options);

    void enable();

    void reset(const Pose3f& target);
    void setTarget(const Pose3f& target);

    Pose3f calculatePose(int64_t timestamp);

    std::string toString(unsigned level) const;

  private:
    struct Point {
        Pose3f pose;
        int64_t timestamp;
    };

    const Options mOptions;
    bool mLimiting;
    std::optional<Pose3f> mTargetPose;
    std::optional<Point> mOutput;
};

}  // namespace media
}  // namespace android
