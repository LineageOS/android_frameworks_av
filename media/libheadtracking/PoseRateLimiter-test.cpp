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

#include <gtest/gtest.h>

#include "PoseRateLimiter.h"

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;
using Options = PoseRateLimiter::Options;

TEST(PoseRateLimiter, Initial) {
    Pose3f target({1, 2, 3}, Quaternionf::UnitRandom());
    PoseRateLimiter limiter(Options{.maxTranslationalVelocity = 10, .maxRotationalVelocity = 10});
    limiter.setTarget(target);
    EXPECT_EQ(limiter.calculatePose(1000), target);
}

TEST(PoseRateLimiter, UnlimitedZeroTime) {
    Pose3f target1({1, 2, 3}, Quaternionf::UnitRandom());
    Pose3f target2({4, 5, 6}, Quaternionf::UnitRandom());
    PoseRateLimiter limiter(Options{});
    limiter.setTarget(target1);
    EXPECT_EQ(limiter.calculatePose(0), target1);
    limiter.setTarget(target2);
    EXPECT_EQ(limiter.calculatePose(0), target2);
    limiter.setTarget(target1);
    EXPECT_EQ(limiter.calculatePose(0), target1);
}

TEST(PoseRateLimiter, Limited) {
    Pose3f pose1({1, 2, 3}, Quaternionf::Identity());
    Pose3f pose2({1, 2, 8}, rotateZ(M_PI * 5 / 8));
    PoseRateLimiter limiter(Options{.maxTranslationalVelocity = 1, .maxRotationalVelocity = 10});
    limiter.setTarget(pose2);
    EXPECT_EQ(limiter.calculatePose(1000), pose2);

    // Rate limiting is inactive. Should track despite the violation.
    limiter.setTarget(pose1);
    EXPECT_EQ(limiter.calculatePose(1001), pose1);

    // Enable rate limiting and observe gradual motion from pose1 to pose2.
    limiter.enable();
    limiter.setTarget(pose2);
    EXPECT_EQ(limiter.calculatePose(1002), Pose3f({1, 2, 4}, rotateZ(M_PI * 1 / 8)));
    limiter.setTarget(pose2);
    EXPECT_EQ(limiter.calculatePose(1003), Pose3f({1, 2, 5}, rotateZ(M_PI * 2 / 8)));
    // Skip a tick.
    limiter.setTarget(pose2);
    EXPECT_EQ(limiter.calculatePose(1005), Pose3f({1, 2, 7}, rotateZ(M_PI * 4 / 8)));
    limiter.setTarget(pose2);
    EXPECT_EQ(limiter.calculatePose(1006), pose2);

    // We reached the target, so rate limiting should now be disabled.
    limiter.setTarget(pose1);
    EXPECT_EQ(limiter.calculatePose(1007), pose1);
}

TEST(PoseRateLimiter, Reset) {
    Pose3f pose1({1, 2, 3}, Quaternionf::Identity());
    Pose3f pose2({1, 2, 8}, rotateZ(M_PI * 5 / 8));
    PoseRateLimiter limiter(Options{.maxTranslationalVelocity = 1, .maxRotationalVelocity = 10});
    limiter.setTarget(pose1);
    EXPECT_EQ(limiter.calculatePose(1000), pose1);

    // Enable rate limiting and observe gradual motion from pose1 to pose2.
    limiter.enable();
    limiter.setTarget(pose2);
    EXPECT_EQ(limiter.calculatePose(1001), Pose3f({1, 2, 4}, rotateZ(M_PI * 1 / 8)));

    // Reset the pose and disable rate limiting.
    limiter.reset(pose2);
    EXPECT_EQ(limiter.calculatePose(1002), pose2);

    // Rate limiting should now be disabled.
    limiter.setTarget(pose1);
    EXPECT_EQ(limiter.calculatePose(1003), pose1);
}

}  // namespace
}  // namespace media
}  // namespace android
