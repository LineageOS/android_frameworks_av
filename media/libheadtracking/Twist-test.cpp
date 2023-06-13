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

#include "media/Twist.h"

#include "media/QuaternionUtil.h"
#include "TestUtil.h"

using Eigen::Quaternionf;
using Eigen::Vector3f;

namespace android {
namespace media {
namespace {

TEST(Twist, DefaultCtor) {
    Twist3f twist;
    EXPECT_EQ(twist.translationalVelocity(), Vector3f::Zero());
    EXPECT_EQ(twist.rotationalVelocity(), Vector3f::Zero());
    EXPECT_FLOAT_EQ(twist.scalarRotationalVelocity(), 0);
    EXPECT_FLOAT_EQ(twist.scalarTranslationalVelocity(), 0);
}

TEST(Twist, FullCtor) {
    Vector3f rot{1, 2, 3};
    Vector3f trans{4, 5, 6};
    Twist3f twist(trans, rot);
    EXPECT_EQ(twist.translationalVelocity(), trans);
    EXPECT_EQ(twist.rotationalVelocity(), rot);
    EXPECT_FLOAT_EQ(twist.scalarRotationalVelocity(), std::sqrt(14.f));
    EXPECT_FLOAT_EQ(twist.scalarTranslationalVelocity(), std::sqrt(77.f));
}

TEST(Twist, Integrate) {
    Vector3f trans{1, 2, 3};
    // 45 deg/sec around Z.
    Vector3f rot{0, 0, M_PI_4};
    Twist3f twist(trans, rot);
    Pose3f pose = integrate(twist, 2.f);

    EXPECT_EQ(pose, Pose3f(Vector3f{2, 4, 6}, rotateZ(M_PI_2)));
}

TEST(Twist, Differentiate) {
    Pose3f pose(Vector3f{2, 4, 6}, rotateZ(M_PI_2));
    Twist3f twist = differentiate(pose, 2.f);
    EXPECT_EQ(twist, Twist3f(Vector3f(1, 2, 3), Vector3f(0, 0, M_PI_4)));
}

}  // namespace
}  // namespace media
}  // namespace android
