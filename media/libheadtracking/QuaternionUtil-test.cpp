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

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

using Eigen::Quaternionf;
using Eigen::Vector3f;

namespace android {
namespace media {
namespace {

TEST(QuaternionUtil, RotationVectorToQuaternion) {
    // 90 degrees around Z.
    Vector3f rot = {0, 0, M_PI_2};
    Quaternionf quat = rotationVectorToQuaternion(rot);
    ASSERT_EQ(quat * Vector3f(1, 0, 0), Vector3f(0, 1, 0));
    ASSERT_EQ(quat * Vector3f(0, 1, 0), Vector3f(-1, 0, 0));
    ASSERT_EQ(quat * Vector3f(0, 0, 1), Vector3f(0, 0, 1));
}

TEST(QuaternionUtil, QuaternionToRotationVector) {
    Quaternionf quat = Quaternionf::FromTwoVectors(Vector3f(1, 0, 0), Vector3f(0, 1, 0));
    Vector3f rot = quaternionToRotationVector(quat);
    ASSERT_EQ(rot, Vector3f(0, 0, M_PI_2));
}

TEST(QuaternionUtil, RoundTripFromQuaternion) {
    Quaternionf quaternion = Quaternionf::UnitRandom();
    EXPECT_EQ(quaternion, rotationVectorToQuaternion(quaternionToRotationVector(quaternion)));
}

TEST(QuaternionUtil, RoundTripFromVector) {
    Vector3f vec{0.1, 0.2, 0.3};
    EXPECT_EQ(vec, quaternionToRotationVector(rotationVectorToQuaternion(vec)));
}

// Float precision necessitates this precision (1e-4f fails)
constexpr float NEAR = 1e-3f;

TEST(QuaternionUtil, quaternionToAngles_basic) {
    float pitch, roll, yaw;

   // angles as reported.
   // choose 11 angles between -M_PI / 2 to M_PI / 2
    for (int step = -5; step <= 5; ++step) {
        const float angle = M_PI * step * 0.1f;

        quaternionToAngles(rotationVectorToQuaternion({angle, 0.f, 0.f}), &pitch, &roll, &yaw);
        EXPECT_NEAR(angle, pitch, NEAR);
        EXPECT_NEAR(0.f, roll, NEAR);
        EXPECT_NEAR(0.f, yaw, NEAR);

        quaternionToAngles(rotationVectorToQuaternion({0.f, angle, 0.f}), &pitch, &roll, &yaw);
        EXPECT_NEAR(0.f, pitch, NEAR);
        EXPECT_NEAR(angle, roll, NEAR);
        EXPECT_NEAR(0.f, yaw, NEAR);

        quaternionToAngles(rotationVectorToQuaternion({0.f, 0.f, angle}), &pitch, &roll, &yaw);
        EXPECT_NEAR(0.f, pitch, NEAR);
        EXPECT_NEAR(0.f, roll, NEAR);
        EXPECT_NEAR(angle, yaw, NEAR);
    }

    // Generates a debug string
    const std::string s = quaternionToAngles<true /* DEBUG */>(
            rotationVectorToQuaternion({M_PI, 0.f, 0.f}), &pitch, &roll, &yaw);
    ASSERT_FALSE(s.empty());
}

TEST(QuaternionUtil, quaternionToAngles_zaxis) {
    float pitch, roll, yaw;

    for (int rot_step = -10; rot_step <= 10; ++rot_step) {
        const float rot_angle = M_PI * rot_step * 0.1f;
        // pitch independent of world Z rotation

        // We don't test the boundaries of pitch +-M_PI/2 as roll can become
        // degenerate and atan(0, 0) may report 0, PI, or -PI.
        for (int step = -4; step <= 4; ++step) {
            const float angle = M_PI * step * 0.1f;
            auto q = rotationVectorToQuaternion({angle, 0.f, 0.f});
            auto world_z = rotationVectorToQuaternion({0.f, 0.f, rot_angle});

            // Sequential active rotations (on world frame) compose as R_2 * R_1.
            quaternionToAngles(world_z * q, &pitch, &roll, &yaw);

            EXPECT_NEAR(angle, pitch, NEAR);
            EXPECT_NEAR(0.f, roll, NEAR);
       }

        // roll independent of world Z rotation
        for (int step = -5; step <= 5; ++step) {
            const float angle = M_PI * step * 0.1f;
            auto q = rotationVectorToQuaternion({0.f, angle, 0.f});
            auto world_z = rotationVectorToQuaternion({0.f, 0.f, rot_angle});

            // Sequential active rotations (on world frame) compose as R_2 * R_1.
            quaternionToAngles(world_z * q, &pitch, &roll, &yaw);

            EXPECT_NEAR(0.f, pitch, NEAR);
            EXPECT_NEAR(angle, roll, NEAR);

            // Convert extrinsic (world-based) active rotations to a sequence of
            // intrinsic rotations (each rotation based off of previous rotation
            // frame).
            //
            // R_1 * R_intrinsic = R_extrinsic * R_1
            //    implies
            // R_intrinsic = (R_1)^-1 R_extrinsic R_1
            //
            auto world_z_intrinsic = rotationVectorToQuaternion(
                    q.inverse() * Vector3f(0.f, 0.f, rot_angle));

            // Sequential intrinsic rotations compose as R_1 * R_2.
            quaternionToAngles(q * world_z_intrinsic, &pitch, &roll, &yaw);

            EXPECT_NEAR(0.f, pitch, NEAR);
            EXPECT_NEAR(angle, roll, NEAR);
        }
    }
}

}  // namespace
}  // namespace media
}  // namespace android
