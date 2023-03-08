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

#include "media/QuaternionUtil.h"

#include <cassert>

namespace android {
namespace media {

using Eigen::NumTraits;
using Eigen::Quaternionf;
using Eigen::Vector3f;

namespace {

Vector3f LogSU2(const Quaternionf& q) {
    // Implementation of the logarithmic map of SU(2) using atan.
    // This follows Hertzberg et al. "Integrating Generic Sensor Fusion Algorithms
    // with Sound State Representations through Encapsulation of Manifolds", Eq.
    // (31)
    // We use asin and acos instead of atan to enable the use of Eigen Autodiff
    // with SU2.
    const float sign_of_w = q.w() < 0.f ? -1.f : 1.f;
    const float abs_w = sign_of_w * q.w();
    const Vector3f v = sign_of_w * q.vec();
    const float squared_norm_of_v = v.squaredNorm();

    assert(abs(1.f - abs_w * abs_w - squared_norm_of_v) < NumTraits<float>::dummy_precision());

    if (squared_norm_of_v > NumTraits<float>::dummy_precision()) {
        const float norm_of_v = sqrt(squared_norm_of_v);
        if (abs_w > NumTraits<float>::dummy_precision()) {
            // asin(x) = acos(x) at x = 1/sqrt(2).
            if (norm_of_v <= float(M_SQRT1_2)) {
                return (asin(norm_of_v) / norm_of_v) * v;
            }
            return (acos(abs_w) / norm_of_v) * v;
        }
        return (M_PI_2 / norm_of_v) * v;
    }

    // Taylor expansion at squared_norm_of_v == 0
    return (1.f / abs_w - squared_norm_of_v / (3.f * pow(abs_w, 3))) * v;
}

Quaternionf ExpSU2(const Vector3f& delta) {
    Quaternionf q_delta;
    const float theta_squared = delta.squaredNorm();
    if (theta_squared > NumTraits<float>::dummy_precision()) {
        const float theta = sqrt(theta_squared);
        q_delta.w() = cos(theta);
        q_delta.vec() = (sin(theta) / theta) * delta;
    } else {
        // taylor expansions around theta == 0
        q_delta.w() = 1.f - 0.5f * theta_squared;
        q_delta.vec() = (1.f - 1.f / 6.f * theta_squared) * delta;
    }
    return q_delta;
}

}  // namespace

Quaternionf rotationVectorToQuaternion(const Vector3f& rotationVector) {
    //  SU(2) is a double cover of SO(3), thus we have to half the tangent vector
    //  delta
    const Vector3f half_delta = 0.5f * rotationVector;
    return ExpSU2(half_delta);
}

Vector3f quaternionToRotationVector(const Quaternionf& quaternion) {
    // SU(2) is a double cover of SO(3), thus we have to multiply the tangent
    // vector delta by two
    return 2.f * LogSU2(quaternion);
}

Quaternionf rotateX(float angle) {
    return rotationVectorToQuaternion(Vector3f(1, 0, 0) * angle);
}

Quaternionf rotateY(float angle) {
    return rotationVectorToQuaternion(Vector3f(0, 1, 0) * angle);
}

Quaternionf rotateZ(float angle) {
    return rotationVectorToQuaternion(Vector3f(0, 0, 1) * angle);
}

}  // namespace media
}  // namespace android
