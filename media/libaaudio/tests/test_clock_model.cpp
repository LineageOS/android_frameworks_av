/*
 * Copyright (C) 2018 The Android Open Source Project
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

// Unit tests for Isochronous Clock Model

#include <math.h>
#include <stdlib.h>


#include <aaudio/AAudio.h>
#include <audio_utils/clock.h>
#include <client/IsochronousClockModel.h>
#include <gtest/gtest.h>

using namespace aaudio;

// We can use arbitrary values here because we are not opening a real audio stream.
#define SAMPLE_RATE             48000
#define HW_FRAMES_PER_BURST     48
// Sometimes we need a (double) value to avoid misguided Build warnings.
#define NANOS_PER_BURST         ((double) NANOS_PER_SECOND * HW_FRAMES_PER_BURST / SAMPLE_RATE)

class ClockModelTestFixture: public ::testing::Test {
public:
    ClockModelTestFixture() {
    }

    void SetUp() {
        model.setSampleRate(SAMPLE_RATE);
        model.setFramesPerBurst(HW_FRAMES_PER_BURST);
    }

    void TearDown() {
    }

    ~ClockModelTestFixture()  {
        // cleanup any pending stuff, but no exceptions allowed
    }

    /** Test processing of timestamps when the hardware may be slightly off from
     * the expected sample rate.
     * @param hardwareFramesPerSecond  sample rate that may be slightly off
     * @param numLoops number of iterations
     * @param hardwarePauseTime  number of seconds to jump forward at halfway point
     */
    void checkDriftingClock(double hardwareFramesPerSecond,
                            int numLoops,
                            double hardwarePauseTime = 0.0) {
        int checksToSkip = 0;
        const int64_t startTimeNanos = 500000000; // arbitrary
        int64_t jumpOffsetNanos = 0;

        srand48(123456); // arbitrary seed for repeatable test results
        model.start(startTimeNanos);

        const int64_t startPositionFrames = HW_FRAMES_PER_BURST; // hardware
        // arbitrary time for first burst
        const int64_t markerTime = startTimeNanos + NANOS_PER_MILLISECOND
                + (200 * NANOS_PER_MICROSECOND);

        // Should set initial marker.
        model.processTimestamp(startPositionFrames, markerTime);
        ASSERT_EQ(startPositionFrames, model.convertTimeToPosition(markerTime));

        double elapsedTimeSeconds = 0.0;
        for (int i = 0; i < numLoops; i++) {
            // Calculate random delay over several bursts.
            const double timeDelaySeconds = 10.0 * drand48() * NANOS_PER_BURST / NANOS_PER_SECOND;
            elapsedTimeSeconds += timeDelaySeconds;
            const int64_t elapsedTimeNanos = (int64_t)(elapsedTimeSeconds * NANOS_PER_SECOND);
            const int64_t currentTimeNanos = startTimeNanos + elapsedTimeNanos;
            // Simulate DSP running at the specified rate.
            const int64_t currentTimeFrames = startPositionFrames +
                                        (int64_t)(hardwareFramesPerSecond * elapsedTimeSeconds);
            const int64_t numBursts = currentTimeFrames / HW_FRAMES_PER_BURST;
            const int64_t hardwarePosition = startPositionFrames
                    + (numBursts * HW_FRAMES_PER_BURST);

            // Simulate a pause in the DSP where the position freezes for a length of time.
            if (i == numLoops / 2) {
                jumpOffsetNanos = (int64_t)(hardwarePauseTime * NANOS_PER_SECOND);
                checksToSkip = 5; // Give the model some time to catch up.
            }

            // Apply drifting timestamp. Add a random time to simulate the
            // random sampling of the clock that occurs when polling the DSP clock.
            int64_t sampledTimeNanos = (int64_t) (currentTimeNanos
                    + jumpOffsetNanos
                    + (drand48() * NANOS_PER_BURST));
            model.processTimestamp(hardwarePosition, sampledTimeNanos);

            if (checksToSkip > 0) {
                checksToSkip--;
            } else {
                // When the model is drifting it may be pushed forward or backward.
                const int64_t modelPosition = model.convertTimeToPosition(sampledTimeNanos);
                if (hardwareFramesPerSecond >= SAMPLE_RATE) { // fast hardware
                    ASSERT_LE(hardwarePosition - HW_FRAMES_PER_BURST, modelPosition);
                    ASSERT_GE(hardwarePosition + HW_FRAMES_PER_BURST, modelPosition);
                } else {
                    // Slow hardware. If this fails then the model may be drifting
                    // forward in time too slowly. Increase kDriftNanos.
                    ASSERT_LE(hardwarePosition, modelPosition);
                    ASSERT_GE(hardwarePosition + (2 * HW_FRAMES_PER_BURST), modelPosition);
                }
            }
        }
    }

    IsochronousClockModel model;
};

// Check default setup.
TEST_F(ClockModelTestFixture, clock_setup) {
    ASSERT_EQ(SAMPLE_RATE, model.getSampleRate());
    ASSERT_EQ(HW_FRAMES_PER_BURST, model.getFramesPerBurst());
}

// Test delta calculations.
TEST_F(ClockModelTestFixture, clock_deltas) {
    int64_t position = model.convertDeltaTimeToPosition(NANOS_PER_SECOND);
    ASSERT_EQ(SAMPLE_RATE, position);

    // Deltas are not quantized.
    // Compare time to the equivalent position in frames.
    constexpr int64_t kNanosPerBurst = HW_FRAMES_PER_BURST * NANOS_PER_SECOND / SAMPLE_RATE;
    position = model.convertDeltaTimeToPosition(NANOS_PER_SECOND + (kNanosPerBurst / 2));
    ASSERT_EQ(SAMPLE_RATE + (HW_FRAMES_PER_BURST / 2), position);

    int64_t time = model.convertDeltaPositionToTime(SAMPLE_RATE);
    ASSERT_EQ(NANOS_PER_SECOND, time);

    // Compare position in frames to the equivalent time.
    time = model.convertDeltaPositionToTime(SAMPLE_RATE + (HW_FRAMES_PER_BURST / 2));
    ASSERT_EQ(NANOS_PER_SECOND + (kNanosPerBurst / 2), time);
}

// start() should force the internal markers
TEST_F(ClockModelTestFixture, clock_start) {
    const int64_t startTime = 100000;
    model.start(startTime);

    int64_t position = model.convertTimeToPosition(startTime);
    EXPECT_EQ(0, position);

    int64_t time = model.convertPositionToTime(position);
    EXPECT_EQ(startTime, time);

    time = startTime + (500 * NANOS_PER_MICROSECOND);
    position = model.convertTimeToPosition(time);
    EXPECT_EQ(0, position);
}

// timestamps moves the window if outside the bounds
TEST_F(ClockModelTestFixture, clock_timestamp) {
    const int64_t startTime = 100000000;
    model.start(startTime);

    const int64_t position = HW_FRAMES_PER_BURST; // hardware
    int64_t markerTime = startTime + NANOS_PER_MILLISECOND + (200 * NANOS_PER_MICROSECOND);

    // Should set marker.
    model.processTimestamp(position, markerTime);
    EXPECT_EQ(position, model.convertTimeToPosition(markerTime));

    // convertTimeToPosition rounds down
    EXPECT_EQ(position, model.convertTimeToPosition(markerTime + (73 * NANOS_PER_MICROSECOND)));

    // convertPositionToTime rounds up
    EXPECT_EQ(markerTime + (int64_t)NANOS_PER_BURST, model.convertPositionToTime(position + 17));
}

#define NUM_LOOPS_DRIFT   200000

TEST_F(ClockModelTestFixture, clock_no_drift) {
    checkDriftingClock(SAMPLE_RATE, NUM_LOOPS_DRIFT);
}

// Test drifting hardware clocks.
// It is unlikely that real hardware would be off by more than this amount.

// Test a slow clock. This will cause the times to be later than expected.
// This will push the clock model window forward and cause it to drift.
TEST_F(ClockModelTestFixture, clock_slow_drift) {
    checkDriftingClock(0.99998 * SAMPLE_RATE, NUM_LOOPS_DRIFT);
}

// Test a fast hardware clock. This will cause the times to be earlier
// than expected. This will cause the clock model to jump backwards quickly.
TEST_F(ClockModelTestFixture, clock_fast_drift) {
    checkDriftingClock(1.00002 * SAMPLE_RATE, NUM_LOOPS_DRIFT);
}

// Simulate a pause in the DSP, which can occur if the DSP reroutes the audio.
TEST_F(ClockModelTestFixture, clock_jump_forward_500) {
    checkDriftingClock(SAMPLE_RATE, NUM_LOOPS_DRIFT, 0.500);
}
