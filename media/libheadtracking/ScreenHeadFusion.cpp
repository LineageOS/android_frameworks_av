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

#include "ScreenHeadFusion.h"

namespace android {
namespace media {

void ScreenHeadFusion::setWorldToHeadPose(int64_t timestamp, const Pose3f& worldToHead) {
    mWorldToHead = TimestampedPose{.timestamp = timestamp, .pose = worldToHead};
}

void ScreenHeadFusion::setWorldToScreenPose(int64_t timestamp, const Pose3f& worldToScreen) {
    mWorldToScreen = TimestampedPose{.timestamp = timestamp, .pose = worldToScreen};
}

std::optional<ScreenHeadFusion::TimestampedPose> ScreenHeadFusion::calculate() {
    // TODO: this is temporary, simplistic logic.
    if (!mWorldToHead.has_value() || !mWorldToScreen.has_value()) {
        return std::nullopt;
    }
    return TimestampedPose{
            .timestamp = std::min(mWorldToHead->timestamp, mWorldToScreen->timestamp),
            .pose = mWorldToScreen->pose.inverse() * mWorldToHead->pose};
}

}  // namespace media
}  // namespace android
