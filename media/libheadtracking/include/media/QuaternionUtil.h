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

namespace android {
namespace media {

/**
 * Converts a rotation vector to an equivalent quaternion.
 * The rotation vector is given as a 3-vector whose direction represents the rotation axis and its
 * magnitude the rotation angle (in radians) around that axis.
 */
Eigen::Quaternionf rotationVectorToQuaternion(const Eigen::Vector3f& rotationVector);

/**
 * Converts a quaternion to an equivalent rotation vector.
 * The rotation vector is given as a 3-vector whose direction represents the rotation axis and its
 * magnitude the rotation angle (in radians) around that axis.
 */
Eigen::Vector3f quaternionToRotationVector(const Eigen::Quaternionf& quaternion);

/**
 * Returns a quaternion representing a rotation around the X-axis with the given amount (in
 * radians).
 */
Eigen::Quaternionf rotateX(float angle);

/**
 * Returns a quaternion representing a rotation around the Y-axis with the given amount (in
 * radians).
 */
Eigen::Quaternionf rotateY(float angle);

/**
 * Returns a quaternion representing a rotation around the Z-axis with the given amount (in
 * radians).
 */
Eigen::Quaternionf rotateZ(float angle);

}  // namespace media
}  // namespace android
