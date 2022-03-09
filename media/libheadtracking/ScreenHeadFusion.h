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
 * Combines world-to-head pose with world-to-screen pose to obtain screen-to-head.
 *
 * Input poses may arrive separately. The last pose of each kind is taken into account. The
 * timestamp of the output is the ealier (older) timestamp of the two inputs.
 *
 * Output may be nullopt in the following cases:
 * - Either one of the inputs has not yet been provided.
 * - It is estimated that the user is no longer facing the screen.
 *
 * Typical usage:
 *
 * ScreenHeadFusion fusion(...);
 * fusion.setWorldToHeadPose(...);
 * fusion.setWorldToScreenPose(...);
 * auto output = fusion.calculate();
 *
 * This class is not thread-safe, but thread-compatible.
 */
class ScreenHeadFusion {
  public:
    struct TimestampedPose {
        int64_t timestamp;
        Pose3f pose;
    };

    void setWorldToHeadPose(int64_t timestamp, const Pose3f& worldToHead);

    void setWorldToScreenPose(int64_t timestamp, const Pose3f& worldToScreen);

    /**
     * Returns the screen-to-head pose, or nullopt if invalid.
     */
    std::optional<TimestampedPose> calculate();

  private:
    std::optional<TimestampedPose> mWorldToHead;
    std::optional<TimestampedPose> mWorldToScreen;
};

}  // namespace media
}  // namespace android
