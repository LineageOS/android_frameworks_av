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

#include "ModeSelector.h"

#include <gtest/gtest.h>

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;

TEST(ModeSelector, Initial) {
    ModeSelector::Options options;
    ModeSelector selector(options);

    selector.calculate(0);
    EXPECT_EQ(HeadTrackingMode::STATIC, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), Pose3f());
}

TEST(ModeSelector, InitialWorldRelative) {
    const Pose3f worldToHead({1, 2, 3}, Quaternionf::UnitRandom());

    ModeSelector::Options options;
    ModeSelector selector(options, HeadTrackingMode::WORLD_RELATIVE);

    selector.setWorldToHeadPose(0, worldToHead);
    selector.setScreenStable(0, true);
    selector.calculate(0);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), worldToHead.inverse());
}

TEST(ModeSelector, InitialScreenRelative) {
    const Pose3f screenToHead({1, 2, 3}, Quaternionf::UnitRandom());

    ModeSelector::Options options;
    ModeSelector selector(options, HeadTrackingMode::SCREEN_RELATIVE);

    selector.setScreenToHeadPose(0, screenToHead);
    selector.calculate(0);
    EXPECT_EQ(HeadTrackingMode::SCREEN_RELATIVE, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), screenToHead.inverse());
}

TEST(ModeSelector, WorldRelative) {
    const Pose3f worldToHead({1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f screenToStage({4, 5, 6}, Quaternionf::UnitRandom());

    ModeSelector::Options options;
    ModeSelector selector(options);

    selector.setScreenToStagePose(screenToStage);
    selector.setDesiredMode(HeadTrackingMode::WORLD_RELATIVE);
    selector.setWorldToHeadPose(0, worldToHead);
    selector.setScreenStable(0, true);
    selector.calculate(0);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), worldToHead.inverse() * screenToStage);
}

TEST(ModeSelector, WorldRelativeUnstable) {
    const Pose3f worldToHead({1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f screenToStage({4, 5, 6}, Quaternionf::UnitRandom());

    ModeSelector::Options options{.freshnessTimeout = 100};
    ModeSelector selector(options);

    selector.setScreenToStagePose(screenToStage);
    selector.setDesiredMode(HeadTrackingMode::WORLD_RELATIVE);
    selector.setWorldToHeadPose(0, worldToHead);
    selector.setScreenStable(0, false);
    selector.calculate(10);
    EXPECT_EQ(HeadTrackingMode::STATIC, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), screenToStage);
}

TEST(ModeSelector, WorldRelativeStableStale) {
    const Pose3f worldToHead({1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f screenToStage({4, 5, 6}, Quaternionf::UnitRandom());

    ModeSelector::Options options{.freshnessTimeout = 100};
    ModeSelector selector(options);

    selector.setScreenToStagePose(screenToStage);
    selector.setDesiredMode(HeadTrackingMode::WORLD_RELATIVE);
    selector.setWorldToHeadPose(100, worldToHead);
    selector.setScreenStable(0, true);
    selector.calculate(101);
    EXPECT_EQ(HeadTrackingMode::STATIC, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), screenToStage);
}

TEST(ModeSelector, WorldRelativeStale) {
    const Pose3f worldToHead({1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f screenToStage({4, 5, 6}, Quaternionf::UnitRandom());

    ModeSelector::Options options{.freshnessTimeout = 100};
    ModeSelector selector(options);

    selector.setScreenToStagePose(screenToStage);
    selector.setDesiredMode(HeadTrackingMode::WORLD_RELATIVE);
    selector.setWorldToHeadPose(0, worldToHead);
    selector.calculate(101);
    EXPECT_EQ(HeadTrackingMode::STATIC, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), screenToStage);
}

TEST(ModeSelector, ScreenRelative) {
    const Pose3f screenToHead({1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f screenToStage({4, 5, 6}, Quaternionf::UnitRandom());

    ModeSelector::Options options;
    ModeSelector selector(options);

    selector.setScreenToStagePose(screenToStage);
    selector.setDesiredMode(HeadTrackingMode::SCREEN_RELATIVE);
    selector.setScreenToHeadPose(0, screenToHead);
    selector.calculate(0);
    EXPECT_EQ(HeadTrackingMode::SCREEN_RELATIVE, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), screenToHead.inverse() * screenToStage);
}

TEST(ModeSelector, ScreenRelativeStaleToWorldRelative) {
    const Pose3f screenToHead({1, 2, 3}, Quaternionf::UnitRandom());
    const Pose3f screenToStage({4, 5, 6}, Quaternionf::UnitRandom());
    const Pose3f worldToHead({7, 8, 9}, Quaternionf::UnitRandom());

    ModeSelector::Options options{.freshnessTimeout = 100};
    ModeSelector selector(options);

    selector.setScreenToStagePose(screenToStage);
    selector.setDesiredMode(HeadTrackingMode::SCREEN_RELATIVE);
    selector.setScreenToHeadPose(0, screenToHead);
    selector.setWorldToHeadPose(50, worldToHead);
    selector.setScreenStable(50, true);
    selector.calculate(101);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), worldToHead.inverse() * screenToStage);
}

TEST(ModeSelector, ScreenRelativeInvalidToWorldRelative) {
    const Pose3f screenToStage({4, 5, 6}, Quaternionf::UnitRandom());
    const Pose3f worldToHead({7, 8, 9}, Quaternionf::UnitRandom());

    ModeSelector::Options options;
    ModeSelector selector(options);

    selector.setScreenToStagePose(screenToStage);

    selector.setDesiredMode(HeadTrackingMode::SCREEN_RELATIVE);
    selector.setScreenToHeadPose(50, std::nullopt);
    selector.setWorldToHeadPose(50, worldToHead);
    selector.setScreenStable(50, true);
    selector.calculate(101);
    EXPECT_EQ(HeadTrackingMode::WORLD_RELATIVE, selector.getActualMode());
    EXPECT_EQ(selector.getHeadToStagePose(), worldToHead.inverse() * screenToStage);
}

}  // namespace
}  // namespace media
}  // namespace android
