/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "PoseBias.h"

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

namespace android {
namespace media {
namespace {

using Eigen::Quaternionf;
using Eigen::Vector3f;

TEST(PoseBias, Initial) {
    PoseBias bias;
    EXPECT_EQ(bias.getOutput(), Pose3f());
}

TEST(PoseBias, Basic) {
    Pose3f pose1({1, 2, 3}, Quaternionf::UnitRandom());
    Pose3f pose2({4, 5, 6}, Quaternionf::UnitRandom());

    PoseBias bias;
    bias.setInput(pose1);
    EXPECT_EQ(pose1, bias.getOutput());
    bias.recenter();
    EXPECT_EQ(bias.getOutput(), Pose3f());
    bias.setInput(pose2);
    EXPECT_EQ(bias.getOutput(), pose1.inverse() * pose2);
    bias.recenter();
    EXPECT_EQ(bias.getOutput(), Pose3f());
}

}  // namespace
}  // namespace media
}  // namespace android
