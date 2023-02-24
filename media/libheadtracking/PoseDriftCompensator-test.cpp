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
#include <cmath>

#include "PoseDriftCompensator.h"

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;
using Options = PoseDriftCompensator::Options;

TEST(PoseDriftCompensator, Initial) {
    PoseDriftCompensator comp(Options{});
    EXPECT_EQ(comp.getOutput(), Pose3f());
}

TEST(PoseDriftCompensator, NoDrift) {
    Pose3f pose1({1, 2, 3}, Quaternionf::UnitRandom());
    Pose3f pose2({4, 5, 6}, Quaternionf::UnitRandom());
    PoseDriftCompensator comp(Options{});

    // First pose sets the baseline.
    comp.setInput(1000, pose1);
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(2000, pose2);
    EXPECT_EQ(comp.getOutput(), pose1.inverse() * pose2);

    // Recentering resets the baseline.
    comp.recenter();
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(3000, pose1);
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(4000, pose2);
    EXPECT_EQ(comp.getOutput(), pose1.inverse() * pose2);
}

TEST(PoseDriftCompensator, NoDriftZeroTime) {
    Pose3f pose1({1, 2, 3}, Quaternionf::UnitRandom());
    Pose3f pose2({4, 5, 6}, Quaternionf::UnitRandom());
    PoseDriftCompensator comp(Options{});

    comp.setInput(1000, pose1);
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(1000, pose2);
    EXPECT_EQ(comp.getOutput(), pose1.inverse() * pose2);

    comp.recenter();
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(1000, pose1);
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(1000, pose2);
    EXPECT_EQ(comp.getOutput(), pose1.inverse() * pose2);
}

TEST(PoseDriftCompensator, Asymptotic) {
    Pose3f pose({1, 2, 3}, Quaternionf::UnitRandom());

    PoseDriftCompensator comp(
            Options{.translationalDriftTimeConstant = 1, .rotationalDriftTimeConstant = 1});

    // Set the same pose for a long time.
    for (int64_t t = 0; t < 1000; ++t) {
        comp.setInput(t, pose);
    }

    // Output would have faded to approx. identity.
    EXPECT_EQ(comp.getOutput(), Pose3f());
}

TEST(PoseDriftCompensator, Fast) {
    Pose3f pose1({1, 2, 3}, Quaternionf::UnitRandom());
    Pose3f pose2({4, 5, 6}, Quaternionf::UnitRandom());
    PoseDriftCompensator comp(
            Options{.translationalDriftTimeConstant = 1e7, .rotationalDriftTimeConstant = 1e7});

    comp.setInput(0, pose1);
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(1, pose2);
    EXPECT_EQ(comp.getOutput(), pose1.inverse() * pose2);

    comp.recenter();
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(2, pose1);
    EXPECT_EQ(comp.getOutput(), Pose3f());

    comp.setInput(3, pose2);
    EXPECT_EQ(comp.getOutput(), pose1.inverse() * pose2);
}

TEST(PoseDriftCompensator, Drift) {
    Pose3f pose1({1, 2, 3}, rotateZ(-M_PI * 3 / 4));
    PoseDriftCompensator comp(
            Options{.translationalDriftTimeConstant = 500, .rotationalDriftTimeConstant = 1000});

    // Establish a baseline.
    comp.setInput(1000, Pose3f());

    // Initial pose is used as is.
    comp.setInput(1000, pose1);
    EXPECT_EQ(comp.getOutput(), pose1);

    // After 1000 ticks, our rotation should be exp(-1) and translation exp(-2) from identity.
    comp.setInput(2000, pose1);
    EXPECT_EQ(comp.getOutput(),
              Pose3f(Vector3f{1, 2, 3} * std::expf(-2), rotateZ(-M_PI * 3 / 4 * std::expf(-1))));

    // As long as the input stays the same, we'll continue to advance towards identity.
    comp.setInput(3000, pose1);
    EXPECT_EQ(comp.getOutput(),
              Pose3f(Vector3f{1, 2, 3} * std::expf(-4), rotateZ(-M_PI * 3 / 4 * std::expf(-2))));

    comp.recenter();
    EXPECT_EQ(comp.getOutput(), Pose3f());
}

}  // namespace
}  // namespace media
}  // namespace android
