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

#include "ScreenHeadFusion.h"
#include "TestUtil.h"

using Eigen::Quaternionf;
using Eigen::Vector3f;

namespace android {
namespace media {
namespace {

TEST(ScreenHeadFusion, Init) {
    ScreenHeadFusion fusion;
    EXPECT_FALSE(fusion.calculate().has_value());
}

TEST(ScreenHeadFusion, Calculate_NoHead) {
    ScreenHeadFusion fusion;
    fusion.setWorldToScreenPose(0, Pose3f());
    EXPECT_FALSE(fusion.calculate().has_value());
}

TEST(ScreenHeadFusion, Calculate_NoScreen) {
    ScreenHeadFusion fusion;
    fusion.setWorldToHeadPose(0, Pose3f());
    EXPECT_FALSE(fusion.calculate().has_value());
}

TEST(ScreenHeadFusion, Calculate) {
    Pose3f worldToScreen1({1, 2, 3}, Quaternionf::UnitRandom());
    Pose3f worldToHead1({4, 5, 6}, Quaternionf::UnitRandom());
    Pose3f worldToScreen2({11, 12, 13}, Quaternionf::UnitRandom());
    Pose3f worldToHead2({14, 15, 16}, Quaternionf::UnitRandom());

    ScreenHeadFusion fusion;
    fusion.setWorldToHeadPose(123, worldToHead1);
    fusion.setWorldToScreenPose(456, worldToScreen1);
    auto result = fusion.calculate();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(123, result->timestamp);
    EXPECT_EQ(worldToScreen1.inverse() * worldToHead1, result->pose);

    fusion.setWorldToHeadPose(567, worldToHead2);
    result = fusion.calculate();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(456, result->timestamp);
    EXPECT_EQ(worldToScreen1.inverse() * worldToHead2, result->pose);

    fusion.setWorldToScreenPose(678, worldToScreen2);
    result = fusion.calculate();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(567, result->timestamp);
    EXPECT_EQ(worldToScreen2.inverse() * worldToHead2, result->pose);
}

}  // namespace
}  // namespace media
}  // namespace android
