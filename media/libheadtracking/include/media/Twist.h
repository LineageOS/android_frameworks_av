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
#pragma once

#include <Eigen/Geometry>

#include "Pose.h"

namespace android {
namespace media {

/**
 * A 6-DoF twist.
 * This class represents the translational and rotational velocity of a rigid object, typically
 * relative to its own coordinate-frame.
 * It is created by two 3-vectors, one representing linear motion per time-unit and the other, a
 * rotation-vector in radians per time-unit (right-handed).
 */
class Twist3f {
  public:
    Twist3f(const Eigen::Vector3f& translationalVelocity, const Eigen::Vector3f& rotationalVelocity)
        : mTranslationalVelocity(translationalVelocity), mRotationalVelocity(rotationalVelocity) {}

    Twist3f() : Twist3f(Eigen::Vector3f::Zero(), Eigen::Vector3f::Zero()) {}

    Twist3f(const Twist3f& other) { *this = other; }

    Twist3f& operator=(const Twist3f& other) {
        mTranslationalVelocity = other.mTranslationalVelocity;
        mRotationalVelocity = other.mRotationalVelocity;
        return *this;
    }

    Eigen::Vector3f translationalVelocity() const { return mTranslationalVelocity; }
    Eigen::Vector3f rotationalVelocity() const { return mRotationalVelocity; }

    float scalarTranslationalVelocity() const { return mTranslationalVelocity.norm(); }
    float scalarRotationalVelocity() const { return mRotationalVelocity.norm(); }

    bool isApprox(const Twist3f& other,
                  float prec = Eigen::NumTraits<float>::dummy_precision()) const {
        return mTranslationalVelocity.isApprox(other.mTranslationalVelocity, prec) &&
               mRotationalVelocity.isApprox(other.mRotationalVelocity, prec);
    }

    template<typename T>
    Twist3f operator*(const T& s) const {
        return Twist3f(mTranslationalVelocity * s, mRotationalVelocity * s);
    }

    template<typename T>
    Twist3f operator/(const T& s) const {
        return Twist3f(mTranslationalVelocity / s, mRotationalVelocity / s);
    }

    // Convert instance to a string representation.
    std::string toString() const;

  private:
    Eigen::Vector3f mTranslationalVelocity;
    Eigen::Vector3f mRotationalVelocity;
};

/**
 * Integrate a twist over time to obtain a pose.
 * dt is the time over which to integration.
 * The resulting pose represents the transformation between the starting point and the ending point
 * of the motion over the time period.
 */
Pose3f integrate(const Twist3f& twist, float dt);

/**
 * Differentiate pose to obtain a twist.
 * dt is the time of the motion between the reference and the target frames of the pose.
 */
Twist3f differentiate(const Pose3f& pose, float dt);

/**
 * Pretty-printer for twist.
 */
std::ostream& operator<<(std::ostream& os, const Twist3f& twist);

}  // namespace media
}  // namespace android
