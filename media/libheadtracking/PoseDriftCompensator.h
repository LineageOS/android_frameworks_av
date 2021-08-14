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

#include "media/Pose.h"

namespace android {
namespace media {

/**
 * Drift compensator for a stream of poses.
 *
 * This is effectively a high-pass filter for a pose stream, removing any DC-offset / bias. The
 * provided input stream will be "pulled" toward identity with an exponential decay filter with a
 * configurable time constant. Rotation and translation are handled separately.
 *
 * Typical usage:
 * PoseDriftCompensator comp(...);
 *
 * while (...) {
 *   comp.setInput(...);
 *   Pose3f output = comp.getOutput();
 * }
 *
 * There doesn't need to be a 1:1 correspondence between setInput() and getOutput() calls. The
 * output timestamp is always that of the last setInput() call. Calling recenter() will reset the
 * bias to the current output, causing the output to be identity.
 *
 * The initial bias point is identity.
 *
 * This implementation is thread-compatible, but not thread-safe.
 */
class PoseDriftCompensator {
  public:
    struct Options {
        float translationalDriftTimeConstant = std::numeric_limits<float>::infinity();
        float rotationalDriftTimeConstant = std::numeric_limits<float>::infinity();
    };

    explicit PoseDriftCompensator(const Options& options);

    void setInput(int64_t timestamp, const Pose3f& input);

    void recenter();

    Pose3f getOutput() const;

  private:
    const Options mOptions;

    Pose3f mPrevInput;
    Pose3f mOutput;
    std::optional<int64_t> mTimestamp;

    Pose3f scale(const Pose3f& pose, int64_t dt);
};

}  // namespace media
}  // namespace android
