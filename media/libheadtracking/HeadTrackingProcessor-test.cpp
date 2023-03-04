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

#include "media/HeadTrackingProcessor.h"
#include "media/QuaternionUtil.h"

#include <gtest/gtest.h>

#include "TestUtil.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;
using Options = HeadTrackingProcessor::Options;

TEST(HeadTrackingProcessor, Initial) {
    for (auto mode : {HeadTrackingMode::STATIC, HeadTrackingMode::WORLD_RELATIVE,
                      HeadTrackingMode::SCREEN_RELATIVE}) {
        std::unique_ptr<HeadTrackingProcessor> processor =
                createHeadTrackingProcessor(Options{}, mode);
        processor->calculate(0);
        EXPECT_EQ(processor->getActualMode(), HeadTrackingMode::STATIC);
        EXPECT_EQ(processor->getHeadToStagePose(), Pose3f());
    }
}

TEST(HeadTrackingProcessor, BasicComposition) {
    const Pose3f worldToHead{{1, 2, 3}, Quaternionf::UnitRandom()};
    const Pose3f worldToScreen{{4, 5, 6}, Quaternionf::UnitRandom()};
    const Pose3f screenToStage{{7, 8, 9}, Quaternionf::UnitRandom()};
    const float physicalToLogical = M_PI_2;

    std::unique_ptr<HeadTrackingProcessor> processor =
            createHeadTrackingProcessor(Options{}, HeadTrackingMode::SCREEN_RELATIVE);

    // Establish a baseline for the drift compensators.
    processor->setWorldToHeadPose(0, Pose3f(), Twist3f());
    processor->setWorldToScreenPose(0, Pose3f());

    processor->setDisplayOrientation(physicalToLogical);
    processor->setWorldToHeadPose(0, worldToHead, Twist3f());
    processor->setWorldToScreenPose(0, worldToScreen);
    processor->setScreenToStagePose(screenToStage);
    processor->calculate(0);
    ASSERT_EQ(processor->getActualMode(), HeadTrackingMode::SCREEN_RELATIVE);
    EXPECT_EQ(processor->getHeadToStagePose(), worldToHead.inverse() * worldToScreen *
                                                       Pose3f(rotateY(-physicalToLogical)) *
                                                       screenToStage);

    processor->setDesiredMode(HeadTrackingMode::WORLD_RELATIVE);
    processor->calculate(0);
    ASSERT_EQ(processor->getActualMode(), HeadTrackingMode::WORLD_RELATIVE);
    EXPECT_EQ(processor->getHeadToStagePose(), worldToHead.inverse() * screenToStage);

    processor->setDesiredMode(HeadTrackingMode::STATIC);
    processor->calculate(0);
    ASSERT_EQ(processor->getActualMode(), HeadTrackingMode::STATIC);
    EXPECT_EQ(processor->getHeadToStagePose(), screenToStage);
}

TEST(HeadTrackingProcessor, Prediction) {
    const Pose3f worldToHead{{1, 2, 3}, Quaternionf::UnitRandom()};
    const Twist3f headTwist{{4, 5, 6}, quaternionToRotationVector(Quaternionf::UnitRandom()) / 10};
    const Pose3f worldToScreen{{4, 5, 6}, Quaternionf::UnitRandom()};

    std::unique_ptr<HeadTrackingProcessor> processor = createHeadTrackingProcessor(
            Options{.predictionDuration = 2.f}, HeadTrackingMode::WORLD_RELATIVE);

    processor->setPosePredictorType(PosePredictorType::TWIST);

    // Establish a baseline for the drift compensators.
    processor->setWorldToHeadPose(0, Pose3f(), Twist3f());
    processor->setWorldToScreenPose(0, Pose3f());

    processor->setWorldToHeadPose(0, worldToHead, headTwist);
    processor->setWorldToScreenPose(0, worldToScreen);
    processor->calculate(0);
    ASSERT_EQ(processor->getActualMode(), HeadTrackingMode::WORLD_RELATIVE);
    EXPECT_EQ(processor->getHeadToStagePose(), (worldToHead * integrate(headTwist, 2.f)).inverse());

    processor->setDesiredMode(HeadTrackingMode::SCREEN_RELATIVE);
    processor->calculate(0);
    ASSERT_EQ(processor->getActualMode(), HeadTrackingMode::SCREEN_RELATIVE);
    EXPECT_EQ(processor->getHeadToStagePose(),
              (worldToHead * integrate(headTwist, 2.f)).inverse() * worldToScreen);

    processor->setDesiredMode(HeadTrackingMode::STATIC);
    processor->calculate(0);
    ASSERT_EQ(processor->getActualMode(), HeadTrackingMode::STATIC);
    EXPECT_EQ(processor->getHeadToStagePose(), Pose3f());
}

TEST(HeadTrackingProcessor, SmoothModeSwitch) {
    const Pose3f targetHeadToWorld = Pose3f({4, 0, 0}, rotateZ(M_PI / 2));

    std::unique_ptr<HeadTrackingProcessor> processor = createHeadTrackingProcessor(
            Options{.maxTranslationalVelocity = 1}, HeadTrackingMode::STATIC);

    // Establish a baseline for the drift compensators.
    processor->setWorldToHeadPose(0, Pose3f(), Twist3f());
    processor->setWorldToScreenPose(0, Pose3f());

    processor->calculate(0);

    processor->setDesiredMode(HeadTrackingMode::WORLD_RELATIVE);
    processor->setWorldToHeadPose(0, targetHeadToWorld.inverse(), Twist3f());

    // We're expecting a gradual move to the target.
    processor->calculate(0);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, processor->getActualMode());
    EXPECT_EQ(processor->getHeadToStagePose(), Pose3f());

    processor->calculate(2);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, processor->getActualMode());
    EXPECT_EQ(processor->getHeadToStagePose(), Pose3f({2, 0, 0}, rotateZ(M_PI / 4)));

    processor->calculate(4);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, processor->getActualMode());
    EXPECT_EQ(processor->getHeadToStagePose(), targetHeadToWorld);

    // Now that we've reached the target, we should no longer be rate limiting.
    processor->setWorldToHeadPose(4, Pose3f(), Twist3f());
    processor->calculate(5);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, processor->getActualMode());
    EXPECT_EQ(processor->getHeadToStagePose(), Pose3f());
}

}  // namespace
}  // namespace media
}  // namespace android
