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

#include "StillnessDetector.h"

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;
using Options = StillnessDetector::Options;

class StillnessDetectorTest : public testing::TestWithParam<bool> {
  public:
    void SetUp() override { mDefaultValue = GetParam(); }

  protected:
    bool mDefaultValue;
};

TEST_P(StillnessDetectorTest, Still) {
    StillnessDetector detector(Options{.defaultValue = mDefaultValue,
                                       .windowDuration = 1000,
                                       .translationalThreshold = 1,
                                       .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.01) * rotateY(-0.01));

    EXPECT_EQ(mDefaultValue, detector.calculate(0));
    detector.setInput(0, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(0));
    detector.setInput(300, withinThreshold);
    EXPECT_EQ(mDefaultValue, detector.calculate(300));
    detector.setInput(600, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(600));
    detector.setInput(999, withinThreshold);
    EXPECT_EQ(mDefaultValue, detector.calculate(999));
    detector.setInput(1000, baseline);
    EXPECT_TRUE(detector.calculate(1000));
}

TEST_P(StillnessDetectorTest, ZeroDuration) {
    StillnessDetector detector(Options{.defaultValue = mDefaultValue, .windowDuration = 0});
    EXPECT_TRUE(detector.calculate(0));
    EXPECT_TRUE(detector.calculate(1000));
}

TEST_P(StillnessDetectorTest, NotStillTranslation) {
    StillnessDetector detector(Options{.defaultValue = mDefaultValue,
                                       .windowDuration = 1000,
                                       .translationalThreshold = 1,
                                       .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.01) * rotateY(-0.01));
    const Pose3f outsideThreshold = baseline * Pose3f(Vector3f(1, 1, 0));

    EXPECT_EQ(mDefaultValue, detector.calculate(0));
    detector.setInput(0, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(0));
    detector.setInput(300, outsideThreshold);
    EXPECT_EQ(mDefaultValue, detector.calculate(300));
    detector.setInput(600, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(600));
    detector.setInput(1299, withinThreshold);
    EXPECT_FALSE(detector.calculate(1299));
    detector.setInput(1300, baseline);
    EXPECT_TRUE(detector.calculate(1300));
}

TEST_P(StillnessDetectorTest, NotStillRotation) {
    StillnessDetector detector(Options{.defaultValue = mDefaultValue,
                                       .windowDuration = 1000,
                                       .translationalThreshold = 1,
                                       .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.03) * rotateY(-0.03));
    const Pose3f outsideThreshold = baseline * Pose3f(rotateZ(0.06));

    EXPECT_EQ(mDefaultValue, detector.calculate(0));
    detector.setInput(0, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(0));
    detector.setInput(300, outsideThreshold);
    EXPECT_EQ(mDefaultValue, detector.calculate(300));
    detector.setInput(600, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(600));
    detector.setInput(1299, withinThreshold);
    EXPECT_FALSE(detector.calculate(1299));
    detector.setInput(1300, baseline);
    EXPECT_TRUE(detector.calculate(1300));
}

TEST_P(StillnessDetectorTest, Suppression) {
    StillnessDetector detector(Options{.defaultValue = mDefaultValue,
                                       .windowDuration = 1000,
                                       .translationalThreshold = 1,
                                       .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f outsideThreshold = baseline * Pose3f(Vector3f(1.1, 0, 0));
    const Pose3f middlePoint = baseline * Pose3f(Vector3f(0.55, 0, 0));

    detector.setInput(0, baseline);
    detector.setInput(1000, baseline);
    EXPECT_TRUE(detector.calculate(1000));
    detector.setInput(1100, outsideThreshold);
    EXPECT_FALSE(detector.calculate(1100));
    detector.setInput(1500, middlePoint);
    EXPECT_FALSE(detector.calculate(1500));
    EXPECT_FALSE(detector.calculate(1999));
    EXPECT_TRUE(detector.calculate(2000));
}

TEST_P(StillnessDetectorTest, Reset) {
    StillnessDetector detector(Options{.defaultValue = mDefaultValue,
                                       .windowDuration = 1000,
                                       .translationalThreshold = 1,
                                       .rotationalThreshold = 0.05});

    const Pose3f baseline(Vector3f{1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f withinThreshold =
            baseline * Pose3f(Vector3f(0.3, -0.3, 0), rotateX(0.01) * rotateY(-0.01));
    EXPECT_EQ(mDefaultValue, detector.calculate(0));
    detector.setInput(300, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(300));
    detector.reset();
    detector.setInput(600, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(600));
    detector.setInput(900, withinThreshold);
    EXPECT_EQ(mDefaultValue, detector.calculate(900));
    detector.setInput(1200, baseline);
    EXPECT_EQ(mDefaultValue, detector.calculate(1200));
    detector.setInput(1599, withinThreshold);
    EXPECT_EQ(mDefaultValue, detector.calculate(1599));
    detector.setInput(1600, baseline);
    EXPECT_TRUE(detector.calculate(1600));
}

INSTANTIATE_TEST_SUITE_P(StillnessDetectorTestParametrized, StillnessDetectorTest,
                         testing::Values(false, true));

}  // namespace
}  // namespace media
}  // namespace android
