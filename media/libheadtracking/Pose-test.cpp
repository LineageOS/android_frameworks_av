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

#include "media/Pose.h"

#include <gtest/gtest.h>

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

using android::media::Pose3f;
using Eigen::Quaternionf;
using Eigen::Vector3f;

namespace android {
namespace media {
namespace {

TEST(Pose, CtorDefault) {
    Pose3f pose;
    EXPECT_EQ(pose.translation(), Vector3f::Zero());
    EXPECT_EQ(pose.rotation(), Quaternionf::Identity());
}

TEST(Pose, CtorRotation) {
    Quaternionf rot = Quaternionf::UnitRandom();
    Pose3f pose(rot);
    EXPECT_EQ(pose.translation(), Vector3f::Zero());
    EXPECT_EQ(pose.rotation(), rot);
}

TEST(Pose, CtorTranslation) {
    Vector3f trans{1, 2, 3};
    Pose3f pose(trans);
    EXPECT_EQ(pose.translation(), trans);
    EXPECT_EQ(pose.rotation(), Quaternionf::Identity());
}

TEST(Pose, CtorTranslationRotation) {
    Quaternionf rot = Quaternionf::UnitRandom();
    Vector3f trans{1, 2, 3};
    Pose3f pose(trans, rot);
    EXPECT_EQ(pose.translation(), trans);
    EXPECT_EQ(pose.rotation(), rot);
}

TEST(Pose, Inverse) {
    Pose3f pose({1, 2, 3}, Quaternionf::UnitRandom());
    EXPECT_EQ(pose.inverse() * pose, Pose3f());
    EXPECT_EQ(pose * pose.inverse(), Pose3f());
}

TEST(Pose, IsApprox) {
    constexpr float eps = std::numeric_limits<float>::epsilon();

    EXPECT_EQ(Pose3f({1, 2, 3}, rotationVectorToQuaternion({4, 5, 6})),
              Pose3f({1 + eps, 2 + eps, 3 + eps},
                     rotationVectorToQuaternion({4 + eps, 5 + eps, 6 + eps})));

    EXPECT_NE(Pose3f({1, 2, 3}, rotationVectorToQuaternion({4, 5, 6})),
              Pose3f({1.01, 2, 3}, rotationVectorToQuaternion({4, 5, 6})));

    EXPECT_NE(Pose3f({1, 2, 3}, rotationVectorToQuaternion({4, 5, 6})),
              Pose3f({1, 2, 3}, rotationVectorToQuaternion({4.01, 5, 6})));
}

TEST(Pose, Compose) {
    Pose3f p1({1, 2, 3}, rotateZ(M_PI_2));
    Pose3f p2({4, 5, 6}, rotateX(M_PI_2));
    Pose3f p3({-4, 6, 9}, p1.rotation() * p2.rotation());
    EXPECT_EQ(p1 * p2, p3);
}

TEST(Pose, MoveWithRateLimit_NoLimit) {
    Pose3f from({1, 1, 1}, Quaternionf::Identity());
    Pose3f to({1, 1, 2}, rotateZ(M_PI_2));
    auto result = moveWithRateLimit(from, to, 1, 10, 10);
    EXPECT_EQ(std::get<0>(result), to);
    EXPECT_FALSE(std::get<1>(result));
}

TEST(Pose, MoveWithRateLimit_TranslationLimit) {
    Pose3f from({1, 1, 1}, Quaternionf::Identity());
    Pose3f to({1, 1, 2}, rotateZ(M_PI_2));
    auto result = moveWithRateLimit(from, to, 1, 0.5f, 10);
    Pose3f expected({1, 1, 1.5f}, rotateZ(M_PI_4));
    EXPECT_EQ(std::get<0>(result), expected);
    EXPECT_TRUE(std::get<1>(result));
}

TEST(Pose, MoveWithRateLimit_RotationLimit) {
    Pose3f from({1, 1, 1}, Quaternionf::Identity());
    Pose3f to({1, 1, 2}, rotateZ(M_PI_2));
    auto result = moveWithRateLimit(from, to, 1, 10, M_PI_4);
    Pose3f expected({1, 1, 1.5f}, rotateZ(M_PI_4));
    EXPECT_EQ(std::get<0>(result), expected);
    EXPECT_TRUE(std::get<1>(result));
}

TEST(Pose, FloatVectorRoundTrip1) {
    // Rotation vector magnitude must be less than Pi.
    std::vector<float> vec = { 1, 2, 3, 0.4, 0.5, 0.6};
    std::optional<Pose3f> pose = Pose3f::fromVector(vec);
    ASSERT_TRUE(pose.has_value());
    std::vector<float> reconstructed = pose->toVector();
    EXPECT_EQ(vec, reconstructed);
}

TEST(Pose, FloatVectorRoundTrip2) {
    Pose3f pose({1, 2, 3}, Quaternionf::UnitRandom());
    std::vector<float> vec = pose.toVector();
    std::optional<Pose3f> reconstructed = Pose3f::fromVector(vec);
    ASSERT_TRUE(reconstructed.has_value());
    EXPECT_EQ(pose, reconstructed.value());
}

TEST(Pose, FloatVectorInvalid) {
    EXPECT_FALSE(Pose3f::fromVector({}).has_value());
    EXPECT_FALSE(Pose3f::fromVector({1, 2, 3, 4, 5}).has_value());
    EXPECT_FALSE(Pose3f::fromVector({1, 2, 3, 4, 5, 6, 7}).has_value());
}

}  // namespace
}  // namespace media
}  // namespace android
