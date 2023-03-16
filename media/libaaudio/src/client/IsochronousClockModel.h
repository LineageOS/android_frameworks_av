/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_AAUDIO_ISOCHRONOUS_CLOCK_MODEL_H
#define ANDROID_AAUDIO_ISOCHRONOUS_CLOCK_MODEL_H

#include <stdint.h>

#include <audio_utils/Histogram.h>

#include "utility/AudioClock.h"

namespace aaudio {

/**
 * Model an isochronous data stream using occasional timestamps as input.
 * This can be used to predict the position of the stream at a given time.
 *
 * This class is not thread safe and should only be called from one thread.
 */
class IsochronousClockModel {

public:
    IsochronousClockModel();
    virtual ~IsochronousClockModel() = default;

    void start(int64_t nanoTime);
    void stop(int64_t nanoTime);

    /**
     * @return true if the model is starting up
     */
    bool isStarting() const;

    /**
     * @return true if the model is running and producing valid results
     */
    bool isRunning() const;

    void processTimestamp(int64_t framePosition, int64_t nanoTime);

    /**
     * @param sampleRate rate of the stream in frames per second
     */
    void setSampleRate(int32_t sampleRate);

    void setPositionAndTime(int64_t framePosition, int64_t nanoTime);

    int32_t getSampleRate() const {
        return mSampleRate;
    }

    /**
     * This must be set accurately in order to track the isochronous stream.
     *
     * @param framesPerBurst number of frames that stream advance at one time.
     */
    void setFramesPerBurst(int32_t framesPerBurst);

    int32_t getFramesPerBurst() const {
        return mFramesPerBurst;
    }

    /**
     * Calculate an estimated time when the stream will be at that position.
     *
     * @param framePosition position of the stream in frames
     * @return time in nanoseconds
     */
    int64_t convertPositionToTime(int64_t framePosition) const;

    /**
     * Calculate the latest estimated time that the stream will be at that position.
     * The more jittery the clock is then the later this will be.
     *
     * @param framePosition
     * @return time in nanoseconds
     */
    int64_t convertPositionToLatestTime(int64_t framePosition) const;

    /**
     * Calculate an estimated position where the stream will be at the specified time.
     *
     * @param nanoTime time of interest
     * @return position in frames
     */
    int64_t convertTimeToPosition(int64_t nanoTime) const;

    /**
     * Calculate the corresponding estimated position based on the specified time being
     * the latest possible time.
     *
     * For the same nanoTime, this may return an earlier position than
     * convertTimeToPosition().
     *
     * @param nanoTime
     * @return position in frames
     */
    int64_t convertLatestTimeToPosition(int64_t nanoTime) const;

    /**
     * @param framesDelta difference in frames
     * @return duration in nanoseconds
     */
    int64_t convertDeltaPositionToTime(int64_t framesDelta) const;

    /**
     * @param nanosDelta duration in nanoseconds
     * @return frames that stream will advance in that time
     */
    int64_t convertDeltaTimeToPosition(int64_t nanosDelta) const;

    void dump() const;

    void dumpHistogram() const;

private:

    void driftForward(int64_t latenessNanos,
                      int64_t expectedNanosDelta,
                      int64_t framePosition);
    int32_t getLateTimeOffsetNanos() const;
    void update();

    enum clock_model_state_t {
        STATE_STOPPED,
        STATE_STARTING,
        STATE_SYNCING,
        STATE_RUNNING
    };

    // Maximum amount of time to drift forward when we get a late timestamp.
    static constexpr int64_t   kMaxDriftNanos      = 10 * AAUDIO_NANOS_PER_MICROSECOND;
    // Safety margin to add to the late edge of the timestamp window.
    static constexpr int32_t   kExtraLatenessNanos = 100 * AAUDIO_NANOS_PER_MICROSECOND;
    // Predicted lateness due to scheduling jitter in the HAL timestamp collection.
    static constexpr int32_t   kLatenessMarginForSchedulingJitter
            = 1000 * AAUDIO_NANOS_PER_MICROSECOND;
    // Amount we multiply mLatenessForDriftNanos to get mLatenessForJumpNanos.
    // This determines when we go from thinking the clock is drifting to
    // when it has actually paused briefly.
    static constexpr int32_t   kScalerForJumpLateness = 5;
    // Amount to divide lateness past the expected burst window to generate
    // the drift value for the window. This is meant to be a very slight nudge forward.
    static constexpr int32_t   kShifterForDrift = 6; // divide by 2^N
    static constexpr int32_t   kVeryLateCountsNeededToTriggerJump = 2;

    static constexpr int32_t   kHistogramBinWidthMicros = 50;
    static constexpr int32_t   kHistogramBinCount       = 128;

    int64_t             mMarkerFramePosition{0}; // Estimated HW position.
    int64_t             mMarkerNanoTime{0};      // Estimated HW time.
    int64_t             mBurstPeriodNanos{0};    // Time between HW bursts.
    // Includes mBurstPeriodNanos because we sample randomly over time.
    int64_t             mMaxMeasuredLatenessNanos{0};
    // Threshold for lateness that triggers a drift later in time.
    int64_t             mLatenessForDriftNanos{0}; // Set in update()
    // Based on the observed lateness when the DSP is paused for playing a touch sound.
    int64_t             mLatenessForJumpNanos{0}; // Set in update()
    int64_t             mLastJumpWarningTimeNanos{0}; // For throttling warnings.

    int32_t             mSampleRate{48000};
    int32_t             mFramesPerBurst{48};     // number of frames transferred at one time.
    int32_t             mConsecutiveVeryLateCount{0};  // To detect persistent DSP lateness.

    clock_model_state_t mState{STATE_STOPPED};   // State machine handles startup sequence.

    int32_t             mTimestampCount = 0;  // For logging.
    int32_t             mDspStallCount = 0;  // For logging.

    // distribution of timestamps relative to earliest
    std::unique_ptr<android::audio_utils::Histogram>   mHistogramMicros;

};

} /* namespace aaudio */

#endif //ANDROID_AAUDIO_ISOCHRONOUS_CLOCK_MODEL_H
