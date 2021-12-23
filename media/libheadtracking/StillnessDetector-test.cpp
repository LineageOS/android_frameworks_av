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

#include "QuaternionUtil.h"
#include "StillnessDetector.h"
#include "TestUtil.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;
using Options = StillnessDetector::Options;

TEST(StillnessDetectorTest, Still) {
    StillnessDetector detector(Options{
            .windowDuration = 1000, .translationalThreshold = 1, .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.01) * rotateY(-0.01));

    EXPECT_FALSE(detector.calculate(0));
    detector.setInput(0, baseline);
    EXPECT_FALSE(detector.calculate(0));
    detector.setInput(300, withinThreshold);
    EXPECT_FALSE(detector.calculate(300));
    detector.setInput(600, baseline);
    EXPECT_FALSE(detector.calculate(600));
    detector.setInput(999, withinThreshold);
    EXPECT_FALSE(detector.calculate(999));
    detector.setInput(1000, baseline);
    EXPECT_TRUE(detector.calculate(1000));
}

TEST(StillnessDetectorTest, ZeroDuration) {
    StillnessDetector detector(Options{.windowDuration = 0});
    EXPECT_TRUE(detector.calculate(0));
    EXPECT_TRUE(detector.calculate(1000));
}

TEST(StillnessDetectorTest, NotStillTranslation) {
    StillnessDetector detector(Options{
            .windowDuration = 1000, .translationalThreshold = 1, .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.01) * rotateY(-0.01));
    const Pose3f outsideThreshold = baseline * Pose3f(Vector3f(1, 1, 0));

    EXPECT_FALSE(detector.calculate(0));
    detector.setInput(0, baseline);
    EXPECT_FALSE(detector.calculate(0));
    detector.setInput(300, outsideThreshold);
    EXPECT_FALSE(detector.calculate(300));
    detector.setInput(600, baseline);
    EXPECT_FALSE(detector.calculate(600));
    detector.setInput(900, withinThreshold);
    EXPECT_FALSE(detector.calculate(900));
    detector.setInput(1299, baseline);
    EXPECT_FALSE(detector.calculate(1299));
    EXPECT_TRUE(detector.calculate(1300));
}

TEST(StillnessDetectorTest, NotStillRotation) {
    StillnessDetector detector(Options{
            .windowDuration = 1000, .translationalThreshold = 1, .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.01) * rotateY(-0.01));
    const Pose3f outsideThreshold = baseline * Pose3f(rotateZ(0.08));
    EXPECT_FALSE(detector.calculate(0));
    detector.setInput(0, baseline);
    EXPECT_FALSE(detector.calculate(0));
    detector.setInput(300, outsideThreshold);
    EXPECT_FALSE(detector.calculate(300));
    detector.setInput(600, baseline);
    EXPECT_FALSE(detector.calculate(600));
    detector.setInput(900, withinThreshold);
    EXPECT_FALSE(detector.calculate(900));
    detector.setInput(1299, baseline);
    EXPECT_FALSE(detector.calculate(1299));
    EXPECT_TRUE(detector.calculate(1300));
}

TEST(StillnessDetectorTest, Reset) {
    StillnessDetector detector(Options{
            .windowDuration = 1000, .translationalThreshold = 1, .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.01) * rotateY(-0.01));
    EXPECT_FALSE(detector.calculate(0));
    detector.setInput(0, baseline);
    EXPECT_FALSE(detector.calculate(0));
    detector.reset();
    detector.setInput(600, baseline);
    EXPECT_FALSE(detector.calculate(600));
    detector.setInput(900, withinThreshold);
    EXPECT_FALSE(detector.calculate(900));
    detector.setInput(1200, baseline);
    EXPECT_FALSE(detector.calculate(1200));
    detector.setInput(1599, withinThreshold);
    EXPECT_FALSE(detector.calculate(1599));
    detector.setInput(1600, baseline);
    EXPECT_TRUE(detector.calculate(1600));
}

}  // namespace
}  // namespace media
}  // namespace android
