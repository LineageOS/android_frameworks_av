/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "PoseDriftCompensator.h"

#include <cmath>

#include "media/QuaternionUtil.h"

namespace android {
namespace media {

using Eigen::Quaternionf;
using Eigen::Vector3f;

PoseDriftCompensator::PoseDriftCompensator(const Options& options) : mOptions(options) {}

void PoseDriftCompensator::setInput(int64_t timestamp, const Pose3f& input) {
    if (mTimestamp.has_value()) {
        // Avoid computation upon first input (only sets the initial state).
        Pose3f prevInputToInput = mPrevInput.inverse() * input;
        mOutput = scale(mOutput, timestamp - mTimestamp.value()) * prevInputToInput;
    }
    mPrevInput = input;
    mTimestamp = timestamp;
}

void PoseDriftCompensator::recenter() {
    mTimestamp.reset();
    mOutput = Pose3f();
}

Pose3f PoseDriftCompensator::getOutput() const {
    return mOutput;
}

Pose3f PoseDriftCompensator::scale(const Pose3f& pose, int64_t dt) {
    // Translation.
    Vector3f translation = pose.translation();
    translation *= std::expf(-static_cast<float>(dt) / mOptions.translationalDriftTimeConstant);

    // Rotation.
    Vector3f rotationVec = quaternionToRotationVector(pose.rotation());
    rotationVec *= std::expf(-static_cast<float>(dt) / mOptions.rotationalDriftTimeConstant);

    return Pose3f(translation, rotationVectorToQuaternion(rotationVec));
}

}  // namespace media
}  // namespace android
