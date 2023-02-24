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
#include <android-base/stringprintf.h>

#include "media/Pose.h"
#include "media/QuaternionUtil.h"
#include "media/Twist.h"

namespace android {
namespace media {

using android::base::StringAppendF;
using Eigen::Vector3f;

std::optional<Pose3f> Pose3f::fromVector(const std::vector<float>& vec) {
    if (vec.size() != 6) {
        return std::nullopt;
    }
    return Pose3f({vec[0], vec[1], vec[2]}, rotationVectorToQuaternion({vec[3], vec[4], vec[5]}));
}

std::vector<float> Pose3f::toVector() const {
    Eigen::Vector3f rot = quaternionToRotationVector(mRotation);
    return {mTranslation[0], mTranslation[1], mTranslation[2], rot[0], rot[1], rot[2]};
}

std::string Pose3f::toString() const {
    const auto& vec = this->toVector();
    std::string ss = "[";
    for (auto f = vec.begin(); f != vec.end(); ++f) {
        if (f != vec.begin()) {
            ss.append(", ");
        }
        StringAppendF(&ss, "%0.2f", *f);
    }
    ss.append("]");
    return ss;
}

std::tuple<Pose3f, bool> moveWithRateLimit(const Pose3f& from, const Pose3f& to, float t,
                                           float maxTranslationalVelocity,
                                           float maxRotationalVelocity) {
    // Never rate limit if both limits are set to infinity.
    if (isinf(maxTranslationalVelocity) && isinf(maxRotationalVelocity)) {
        return {to, false};
    }
    // Always rate limit if t is 0 (required to avoid division by 0).
    if (t == 0 || maxTranslationalVelocity == 0 || maxRotationalVelocity == 0) {
        return {from, true};
    }

    Pose3f fromToTo = from.inverse() * to;
    Twist3f twist = differentiate(fromToTo, t);
    float angularRotationalRatio = twist.scalarRotationalVelocity() / maxRotationalVelocity;
    float translationalVelocityRatio =
            twist.scalarTranslationalVelocity() / maxTranslationalVelocity;
    float maxRatio = std::max(angularRotationalRatio, translationalVelocityRatio);
    if (maxRatio <= 1) {
        return {to, false};
    }
    return {from * integrate(twist, t / maxRatio), true};
}

std::ostream& operator<<(std::ostream& os, const Pose3f& pose) {
    os << "translation: " << pose.translation().transpose()
       << " quaternion: " << pose.rotation().coeffs().transpose();
    return os;
}

}  // namespace media
}  // namespace android
