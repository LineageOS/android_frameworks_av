/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "media/Pose.h"

namespace android {
namespace media {

/**
 * Biasing for a stream of poses.
 *
 * This filter takes a stream of poses and at any time during the stream, can change the frame of
 * reference for the stream to be that of the last pose received, via the recenter() operation.
 *
 * Typical usage:
 * PoseBias bias;
 *
 * bias.setInput(...);
 * output = bias.getOutput();
 * bias.setInput(...);
 * output = bias.getOutput();
 * bias.setInput(...);
 * output = bias.getOutput();
 * bias.recenter();  // Reference frame is now equal to the last input.
 * output = bias.getOutput();  // This is now the identity pose.
 *
 * There doesn't need to be a 1:1 correspondence between setInput() and getOutput() calls.
 * The initial bias point is identity.
 *
 * This implementation is thread-compatible, but not thread-safe.
 */
class PoseBias {
  public:
    void setInput(const Pose3f& input);

    void recenter();

    Pose3f getOutput() const;

  private:
    Pose3f mLastWorldToInput;
    Pose3f mBiasToWorld;
};

}  // namespace media
}  // namespace android
