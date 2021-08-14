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

#include <gtest/gtest.h>

#include "media/Pose.h"
#include "media/Twist.h"

namespace {

constexpr float kPoseComparisonPrecision = 1e-5;

}  // namespace

// These specializations make {EXPECT,ASSERT}_{EQ,NE} work correctly for Pose3f, Twist3f, Vector3f
// and Quaternionf.
namespace testing {
namespace internal {

template <>
inline AssertionResult CmpHelperEQ<android::media::Pose3f, android::media::Pose3f>(
        const char* lhs_expression, const char* rhs_expression, const android::media::Pose3f& lhs,
        const android::media::Pose3f& rhs) {
    if (lhs.isApprox(rhs, kPoseComparisonPrecision)) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

template <>
inline AssertionResult CmpHelperNE<android::media::Pose3f, android::media::Pose3f>(
        const char* lhs_expression, const char* rhs_expression, const android::media::Pose3f& lhs,
        const android::media::Pose3f& rhs) {
    if (!lhs.isApprox(rhs, kPoseComparisonPrecision)) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

template <>
inline AssertionResult CmpHelperEQ<android::media::Twist3f, android::media::Twist3f>(
        const char* lhs_expression, const char* rhs_expression, const android::media::Twist3f& lhs,
        const android::media::Twist3f& rhs) {
    if (lhs.isApprox(rhs, kPoseComparisonPrecision)) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

template <>
inline AssertionResult CmpHelperNE<android::media::Twist3f, android::media::Twist3f>(
        const char* lhs_expression, const char* rhs_expression, const android::media::Twist3f& lhs,
        const android::media::Twist3f& rhs) {
    if (!lhs.isApprox(rhs, kPoseComparisonPrecision)) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

template <>
inline AssertionResult CmpHelperEQ<Eigen::Vector3f, Eigen::Vector3f>(const char* lhs_expression,
                                                                     const char* rhs_expression,
                                                                     const Eigen::Vector3f& lhs,
                                                                     const Eigen::Vector3f& rhs) {
    if (lhs.isApprox(rhs)) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

template <>
inline AssertionResult CmpHelperNE<Eigen::Vector3f, Eigen::Vector3f>(const char* lhs_expression,
                                                                     const char* rhs_expression,
                                                                     const Eigen::Vector3f& lhs,
                                                                     const Eigen::Vector3f& rhs) {
    if (!lhs.isApprox(rhs)) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

template <>
inline AssertionResult CmpHelperEQ<Eigen::Quaternionf, Eigen::Quaternionf>(
        const char* lhs_expression, const char* rhs_expression, const Eigen::Quaternionf& lhs,
        const Eigen::Quaternionf& rhs) {
    // Negating the coefs results in an equivalent quaternion.
    if (lhs.isApprox(rhs) || lhs.isApprox(Eigen::Quaternionf(-rhs.coeffs()))) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

template <>
inline AssertionResult CmpHelperNE<Eigen::Quaternionf, Eigen::Quaternionf>(
        const char* lhs_expression, const char* rhs_expression, const Eigen::Quaternionf& lhs,
        const Eigen::Quaternionf& rhs) {
    // Negating the coefs results in an equivalent quaternion.
    if (!(lhs.isApprox(rhs) || lhs.isApprox(Eigen::Quaternionf(-rhs.coeffs())))) {
        return AssertionSuccess();
    }

    return CmpHelperEQFailure(lhs_expression, rhs_expression, lhs, rhs);
}

}  // namespace internal
}  // namespace testing
