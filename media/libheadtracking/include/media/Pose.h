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

#include <optional>
#include <string>
#include <vector>
#include <Eigen/Geometry>

namespace android {
namespace media {

/**
 * A 6-DoF pose.
 * This class represents a proper rigid transformation (translation + rotation) between a reference
 * frame and a target frame,
 *
 * See https://en.wikipedia.org/wiki/Six_degrees_of_freedom
 */
class Pose3f {
  public:
    /** Typical precision for isApprox comparisons. */
    static constexpr float kDummyPrecision = 1e-5f;

    Pose3f(const Eigen::Vector3f& translation, const Eigen::Quaternionf& rotation)
        : mTranslation(translation), mRotation(rotation) {}

    explicit Pose3f(const Eigen::Vector3f& translation)
        : Pose3f(translation, Eigen::Quaternionf::Identity()) {}

    explicit Pose3f(const Eigen::Quaternionf& rotation)
        : Pose3f(Eigen::Vector3f::Zero(), rotation) {}

    Pose3f() : Pose3f(Eigen::Vector3f::Zero(), Eigen::Quaternionf::Identity()) {}

    Pose3f(const Pose3f& other) { *this = other; }

    /**
     * Create instance from a vector-of-floats representation.
     * The vector is expected to have exactly 6 elements, where the first three are a translation
     * vector and the last three are a rotation vector.
     *
     * Returns nullopt if the input vector is illegal.
     */
    static std::optional<Pose3f> fromVector(const std::vector<float>& vec);

    /**
     * Convert instance to a vector-of-floats representation.
     * The vector will have exactly 6 elements, where the first three are a translation vector and
     * the last three are a rotation vector.
     */
    std::vector<float> toVector() const;

    // Convert instance to a string representation.
    std::string toString() const;

    Pose3f& operator=(const Pose3f& other) {
        mTranslation = other.mTranslation;
        mRotation = other.mRotation;
        return *this;
    }

    Eigen::Vector3f translation() const { return mTranslation; };
    Eigen::Quaternionf rotation() const { return mRotation; };

    /**
     * Reverses the reference and target frames.
     */
    Pose3f inverse() const {
        Eigen::Quaternionf invRotation = mRotation.inverse();
        return Pose3f(-(invRotation * translation()), invRotation);
    }

    /**
     * Composes (chains) together two poses. By convention, this only makes sense if the target
     * frame of the left-hand pose is the same the reference frame of the right-hand pose.
     * Note that this operator is not commutative.
     */
    Pose3f operator*(const Pose3f& other) const {
        Pose3f result = *this;
        result *= other;
        return result;
    }

    Pose3f& operator*=(const Pose3f& other) {
        mTranslation += mRotation * other.mTranslation;
        mRotation *= other.mRotation;
        return *this;
    }

    /**
     * This is an imprecise "fuzzy" comparison, which is only to be used for validity-testing
     * purposes.
     */
    bool isApprox(const Pose3f& other, float prec = kDummyPrecision) const {
        return (mTranslation - other.mTranslation).norm() < prec &&
               // Quaternions are equivalent under sign inversion.
               ((mRotation.coeffs() - other.mRotation.coeffs()).norm() < prec ||
                (mRotation.coeffs() + other.mRotation.coeffs()).norm() < prec);
    }

  private:
    Eigen::Vector3f mTranslation;
    Eigen::Quaternionf mRotation;
};

/**
 * Pretty-printer for Pose3f.
 */
std::ostream& operator<<(std::ostream& os, const Pose3f& pose);

/**
 * Move between the 'from' pose and the 'to' pose, while making sure velocity limits are enforced.
 * If velocity limits are not violated, returns the 'to' pose and false.
 * If velocity limits are violated, returns pose farthest along the path that can be reached within
 * the limits, and true.
 */
std::tuple<Pose3f, bool> moveWithRateLimit(const Pose3f& from, const Pose3f& to, float t,
                                           float maxTranslationalVelocity,
                                           float maxRotationalVelocity);

template <typename T>
static float nsToFloatMs(T ns) {
    return ns * 1e-6f;
}

}  // namespace media
}  // namespace android
