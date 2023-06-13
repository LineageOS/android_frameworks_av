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
#include <android-base/stringprintf.h>
#include "media/QuaternionUtil.h"

namespace android {
namespace media {

Pose3f integrate(const Twist3f& twist, float dt) {
    Eigen::Vector3f translation = twist.translationalVelocity() * dt;
    Eigen::Vector3f rotationVector = twist.rotationalVelocity() * dt;
    return Pose3f(translation, rotationVectorToQuaternion(rotationVector));
}

Twist3f differentiate(const Pose3f& pose, float dt) {
    Eigen::Vector3f translationalVelocity = pose.translation() / dt;
    Eigen::Vector3f rotationalVelocity = quaternionToRotationVector(pose.rotation()) / dt;
    return Twist3f(translationalVelocity, rotationalVelocity);
}

std::ostream& operator<<(std::ostream& os, const Twist3f& twist) {
    os << "translation: " << twist.translationalVelocity().transpose()
       << " rotation vector: " << twist.rotationalVelocity().transpose();
    return os;
}

std::string Twist3f::toString() const {
    return base::StringPrintf("[%0.2f, %0.2f, %0.2f, %0.2f, %0.2f, %0.2f]",
        mTranslationalVelocity[0], mTranslationalVelocity[1], mTranslationalVelocity[2],
        mRotationalVelocity[0], mRotationalVelocity[1], mRotationalVelocity[2]);
}

}  // namespace media
}  // namespace android
