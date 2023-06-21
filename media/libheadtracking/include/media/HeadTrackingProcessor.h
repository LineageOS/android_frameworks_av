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

#include <limits>

#include "HeadTrackingMode.h"
#include "Pose.h"
#include "PosePredictorType.h"
#include "Twist.h"

namespace android {
namespace media {

/**
 * Main entry-point for this library.
 * This interfaces encompasses all the processing required for determining the head-to-stage pose
 * used for audio virtualization.
 * The usage involves periodic setting of the inputs, calling calculate() and obtaining the outputs.
 * This class is not thread-safe, but thread-compatible.
 */
class HeadTrackingProcessor {
  public:
    virtual ~HeadTrackingProcessor() = default;

    struct Options {
        float maxTranslationalVelocity = std::numeric_limits<float>::infinity();
        float maxRotationalVelocity = std::numeric_limits<float>::infinity();
        int64_t freshnessTimeout = std::numeric_limits<int64_t>::max();
        float predictionDuration = 0;
        int64_t autoRecenterWindowDuration = std::numeric_limits<int64_t>::max();
        float autoRecenterTranslationalThreshold = std::numeric_limits<float>::infinity();
        float autoRecenterRotationalThreshold = std::numeric_limits<float>::infinity();
        int64_t screenStillnessWindowDuration = 0;
        float screenStillnessTranslationalThreshold = std::numeric_limits<float>::infinity();
        float screenStillnessRotationalThreshold = std::numeric_limits<float>::infinity();
    };

    /** Sets the desired head-tracking mode. */
    virtual void setDesiredMode(HeadTrackingMode mode) = 0;

    /**
     * Sets the world-to-head pose and head twist (velocity).
     * headTwist is given in the head coordinate frame.
     */
    virtual void setWorldToHeadPose(int64_t timestamp, const Pose3f& worldToHead,
                                    const Twist3f& headTwist) = 0;

    /**
     * Sets the world-to-screen pose.
     */
    virtual void setWorldToScreenPose(int64_t timestamp, const Pose3f& worldToScreen) = 0;

    /**
     * Set the screen-to-stage pose, used in all modes.
     */
    virtual void setScreenToStagePose(const Pose3f& screenToStage) = 0;

    /**
     * Sets the display orientation.
     * Orientation is expressed in the angle of rotation from the physical "up" side of the screen
     * to the logical "up" side of the content displayed the screen. Counterclockwise angles, as
     * viewed while facing the screen are positive.
     */
    virtual void setDisplayOrientation(float physicalToLogicalAngle) = 0;

    /**
     * Process all the previous inputs and update the outputs.
     */
    virtual void calculate(int64_t timestamp) = 0;

    /**
     * Get the aggregate head-to-stage pose (primary output of this module).
     */
    virtual Pose3f getHeadToStagePose() const = 0;

    /**
     * Get the actual head-tracking mode (which may deviate from the desired one as mentioned in the
     * class documentation above).
     */
    virtual HeadTrackingMode getActualMode() const = 0;

    /**
     * This causes the current poses for both the head and/or screen to be considered "center".
     */
    virtual void recenter(
            bool recenterHead = true, bool recenterScreen = true, std::string source = "") = 0;

    /**
     * Set the predictor type.
     */
    virtual void setPosePredictorType(PosePredictorType type) = 0;

    /**
     * Dump HeadTrackingProcessor parameters under caller lock.
     */
    virtual std::string toString_l(unsigned level) const = 0;
};
/**
 * Creates an instance featuring a default implementation of the HeadTrackingProcessor interface.
 */
std::unique_ptr<HeadTrackingProcessor> createHeadTrackingProcessor(
        const HeadTrackingProcessor::Options& options,
        HeadTrackingMode initialMode = HeadTrackingMode::STATIC);

}  // namespace media
}  // namespace android
