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

#include <deque>

#include <media/Pose.h>

namespace android {
namespace media {

/**
 * Given a stream of poses, determines if the pose is stable ("still").
 * Stillness is defined as all poses in the recent history ("window") being near the most recent
 * sample.
 *
 * Typical usage:
 *
 * StillnessDetector detector(StilnessDetector::Options{...});
 *
 * while (...) {
 *    detector.setInput(timestamp, pose);
 *    bool still = detector.calculate(timestamp);
 * }
 *
 * The detection is not considered reliable until a sufficient number of samples has been provided
 * for an initial fill-up of the window. During that time, the detector will return whatever default
 * value has been configured.
 * The reset() method can be used to empty the window again and get back to this initial state.
 * In the special case of the window size being 0, the state will always be considered "still".
 */
class StillnessDetector {
  public:
    /**
     * Configuration options for the detector.
     */
    struct Options {
        /**
         * During the initial fill of the window, should we consider the state still?
         */
         bool defaultValue;
        /**
         * How long is the window, in ticks. The special value of 0 indicates that the stream is
         * always considered still.
         */
        int64_t windowDuration;
        /**
         * How much of a translational deviation from the target (in meters) is considered motion.
         * This is an approximate quantity - the actual threshold might be a little different as we
         * trade-off accuracy with computational efficiency.
         */
        float translationalThreshold;
        /**
         * How much of a rotational deviation from the target (in radians) is considered motion.
         * This is an approximate quantity - the actual threshold might be a little different as we
         * trade-off accuracy with computational efficiency.
         */
        float rotationalThreshold;
    };

    /** Ctor. */
    explicit StillnessDetector(const Options& options);

    /** Clear the window. */
    void reset();
    /** Push a new sample. */
    void setInput(int64_t timestamp, const Pose3f& input);
    /** Calculate whether the stream is still at the given timestamp. */
    bool calculate(int64_t timestamp);
    /** Return the stillness state from the previous call to calculate() */
    bool getPreviousState() const;
  private:
    struct TimestampedPose {
        int64_t timestamp;
        Pose3f pose;
    };

    const Options mOptions;
    // Precalculated cos(mOptions.rotationalThreshold / 2)
    const float mCosHalfRotationalThreshold;
    std::deque<TimestampedPose> mFifo;
    bool mWindowFull = false;
    bool mCurrentState = true;
    bool mPreviousState = true;
    // As soon as motion is detected, this will be set for the time of detection + window duration,
    // and during this time we will always consider outselves in motion without checking. This is
    // used for hyteresis purposes, since because of the approximate method we use for determining
    // stillness, we may toggle back and forth at a rate faster than the window side.
    std::optional<int64_t> mSuppressionDeadline;

    bool areNear(const Pose3f& pose1, const Pose3f& pose2) const;
    void discardOld(int64_t timestamp);
};

}  // namespace media
}  // namespace android
