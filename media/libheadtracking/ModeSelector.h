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
#include <audio_utils/SimpleLog.h>

#include "media/HeadTrackingMode.h"
#include "media/Pose.h"

#include "PoseRateLimiter.h"

namespace android {
namespace media {

/**
 * Head-tracking mode selector.
 *
 * This class is responsible for production of the determining pose for audio virtualization, based
 * on a number of available sources and a selectable mode.
 *
 * Typical flow is:
 * ModeSelector selector(...);
 * while (...) {
 *     // Set inputs.
 *     selector.setFoo(...);
 *     selector.setBar(...);
 *
 *     // Update outputs based on inputs.
 *     selector.calculate(...);
 *
 *     // Get outputs.
 *     Pose3f pose = selector.getHeadToStagePose();
 * }
 *
 * This class is not thread-safe, but thread-compatible.
 *
 * For details on the frames of reference involved, their composition and the definitions to the
 * different modes, refer to:
 * go/immersive-audio-frames
 *
 * The actual mode may deviate from the desired mode in the following cases:
 * - When we cannot get a valid and fresh estimate of the screen-to-head pose, we will fall back
 *   from screen-relative to world-relative.
 * - When we cannot get a fresh estimate of the world-to-head pose, we will fall back from
 *   world-relative to static.
 * - In world-relative mode, if the screen is unstable, we will fall back to static.
 *
 * All the timestamps used here are of arbitrary units and origin. They just need to be consistent
 * between all the calls and with the Options provided for determining freshness and rate limiting.
 */
class ModeSelector {
  public:
    struct Options {
        int64_t freshnessTimeout = std::numeric_limits<int64_t>::max();
    };

    ModeSelector(const Options& options, HeadTrackingMode initialMode = HeadTrackingMode::STATIC);

    /** Sets the desired head-tracking mode. */
    void setDesiredMode(HeadTrackingMode mode);

    /**
     * Set the screen-to-stage pose, used in all modes.
     */
    void setScreenToStagePose(const Pose3f& screenToStage);

    /**
     * Set the screen-to-head pose, used in screen-relative mode.
     * The timestamp needs to reflect how fresh the sample is (not necessarily which point in time
     * it applies to). nullopt can be used if it is determined that the listener is not in front of
     * the screen.
     */
    void setScreenToHeadPose(int64_t timestamp, const std::optional<Pose3f>& screenToHead);

    /**
     * Set the world-to-head pose, used in world-relative mode.
     * The timestamp needs to reflect how fresh the sample is (not necessarily which point in time
     * it applies to).
     */
    void setWorldToHeadPose(int64_t timestamp, const Pose3f& worldToHead);

    /**
     * Set whether the screen is considered stable.
     * The timestamp needs to reflect how fresh the sample is.
     */
     void setScreenStable(int64_t timestamp, bool stable);

    /**
     * Process all the previous inputs and update the outputs.
     */
    void calculate(int64_t timestamp);

    /**
     * Get the aggregate head-to-stage pose (primary output of this module).
     */
    Pose3f getHeadToStagePose() const;

    /**
     * Get the actual head-tracking mode (which may deviate from the desired one as mentioned in the
     * class documentation above).
     */
    HeadTrackingMode getActualMode() const;

    std::string toString(unsigned level) const;

  private:
    const Options mOptions;

    HeadTrackingMode mDesiredMode;
    Pose3f mScreenToStage;
    std::optional<Pose3f> mScreenToHead;
    int64_t mScreenToHeadTimestamp;
    std::optional<Pose3f> mWorldToHead;
    int64_t mWorldToHeadTimestamp;
    std::optional<bool> mScreenStable;
    int64_t mScreenStableTimestamp;

    HeadTrackingMode mActualMode;
    Pose3f mHeadToStage;

    static constexpr std::size_t sMaxLocalLogLine = 10;
    SimpleLog mLocalLog{sMaxLocalLogLine};

    void calculateActualMode(int64_t timestamp);
};

}  // namespace media
}  // namespace android
