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

// Unit tests for AAudio 'C' API.

#include <stdlib.h>
#include <math.h>

#include <gtest/gtest.h>

#include <aaudio/AAudioDefinitions.h>
#include <aaudio/AAudio.h>
#include "AAudioUtilities.h"

#define DEFAULT_STATE_TIMEOUT  (500 * AAUDIO_NANOS_PER_MILLISECOND)

// Test AAudioStreamBuilder
TEST(test_aaudio_api, aaudio_stream_builder) {
    const aaudio_sample_rate_t requestedSampleRate1 = 48000;
    const aaudio_sample_rate_t requestedSampleRate2 = 44100;
    const int32_t requestedSamplesPerFrame = 2;
    const aaudio_audio_format_t requestedDataFormat = AAUDIO_FORMAT_PCM16;

    aaudio_sample_rate_t sampleRate = 0;
    int32_t samplesPerFrame = 0;
    aaudio_audio_format_t actualDataFormat;
    AAudioStreamBuilder aaudioBuilder1;
    AAudioStreamBuilder aaudioBuilder2;

    aaudio_result_t result = AAUDIO_OK;

    // Use an AAudioStreamBuilder to define the stream.
    result = AAudio_createStreamBuilder(&aaudioBuilder1);
    ASSERT_EQ(AAUDIO_OK, result);

    // Request stream properties.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setSampleRate(aaudioBuilder1, requestedSampleRate1));
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setSamplesPerFrame(aaudioBuilder1, requestedSamplesPerFrame));
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setFormat(aaudioBuilder1, requestedDataFormat));

    // Check to make sure builder saved the properties.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_getSampleRate(aaudioBuilder1, &sampleRate));
    EXPECT_EQ(requestedSampleRate1, sampleRate);

    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_getSamplesPerFrame(aaudioBuilder1, &samplesPerFrame));
    EXPECT_EQ(requestedSamplesPerFrame, samplesPerFrame);

    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_getFormat(aaudioBuilder1, &actualDataFormat));
    EXPECT_EQ(requestedDataFormat, actualDataFormat);

    result = AAudioStreamBuilder_getSampleRate(0x0BADCAFE, &sampleRate); // ridiculous token
    EXPECT_EQ(AAUDIO_ERROR_INVALID_HANDLE, result);

    // Create a second builder and make sure they do not collide.
    ASSERT_EQ(AAUDIO_OK, AAudio_createStreamBuilder(&aaudioBuilder2));
    ASSERT_NE(aaudioBuilder1, aaudioBuilder2);

    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setSampleRate(aaudioBuilder2, requestedSampleRate2));
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_getSampleRate(aaudioBuilder1, &sampleRate));
    EXPECT_EQ(requestedSampleRate1, sampleRate);
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_getSampleRate(aaudioBuilder2, &sampleRate));
    EXPECT_EQ(requestedSampleRate2, sampleRate);

    // Delete the builder.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_delete(aaudioBuilder1));

    // Now it should no longer be valid.
    // Note that test assumes we are using the HandleTracker. If we use plain pointers
    // then it will be difficult to detect this kind of error.
    result = AAudioStreamBuilder_getSampleRate(aaudioBuilder1, &sampleRate); // stale token
    EXPECT_EQ(AAUDIO_ERROR_INVALID_HANDLE, result);

    // Second builder should still be valid.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_getSampleRate(aaudioBuilder2, &sampleRate));
    EXPECT_EQ(requestedSampleRate2, sampleRate);

    // Delete the second builder.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_delete(aaudioBuilder2));

    // Now it should no longer be valid. Assumes HandlerTracker used.
    EXPECT_EQ(AAUDIO_ERROR_INVALID_HANDLE, AAudioStreamBuilder_getSampleRate(aaudioBuilder2, &sampleRate));
}

// Test creating a default stream with everything unspecified.
TEST(test_aaudio_api, aaudio_stream_unspecified) {
    AAudioStreamBuilder aaudioBuilder;
    AAudioStream aaudioStream;
    aaudio_result_t result = AAUDIO_OK;

    // Use an AAudioStreamBuilder to define the stream.
    result = AAudio_createStreamBuilder(&aaudioBuilder);
    ASSERT_EQ(AAUDIO_OK, result);

    // Create an AAudioStream using the Builder.
    ASSERT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));

    // Cleanup
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_delete(aaudioBuilder));
    EXPECT_EQ(AAUDIO_OK, AAudioStream_close(aaudioStream));
}

// Test Writing to an AAudioStream
void runtest_aaudio_stream(aaudio_sharing_mode_t requestedSharingMode) {
    const aaudio_sample_rate_t requestedSampleRate = 48000;
    const aaudio_sample_rate_t requestedSamplesPerFrame = 2;
    const aaudio_audio_format_t requestedDataFormat = AAUDIO_FORMAT_PCM16;

    aaudio_sample_rate_t actualSampleRate = -1;
    int32_t actualSamplesPerFrame = -1;
    aaudio_audio_format_t actualDataFormat = AAUDIO_FORMAT_INVALID;
    aaudio_sharing_mode_t actualSharingMode;
    aaudio_size_frames_t framesPerBurst = -1;
    int writeLoops = 0;

    aaudio_size_frames_t framesWritten = 0;
    aaudio_size_frames_t framesPrimed = 0;
    aaudio_position_frames_t framesTotal = 0;
    aaudio_position_frames_t aaudioFramesRead = 0;
    aaudio_position_frames_t aaudioFramesRead1 = 0;
    aaudio_position_frames_t aaudioFramesRead2 = 0;
    aaudio_position_frames_t aaudioFramesWritten = 0;

    aaudio_nanoseconds_t timeoutNanos;

    aaudio_stream_state_t state = AAUDIO_STREAM_STATE_UNINITIALIZED;
    AAudioStreamBuilder aaudioBuilder;
    AAudioStream aaudioStream;

    aaudio_result_t result = AAUDIO_OK;

    // Use an AAudioStreamBuilder to define the stream.
    result = AAudio_createStreamBuilder(&aaudioBuilder);
    ASSERT_EQ(AAUDIO_OK, result);

    // Request stream properties.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setSampleRate(aaudioBuilder, requestedSampleRate));
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setSamplesPerFrame(aaudioBuilder, requestedSamplesPerFrame));
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setFormat(aaudioBuilder, requestedDataFormat));
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_setSharingMode(aaudioBuilder, requestedSharingMode));

    // Create an AAudioStream using the Builder.
    ASSERT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_delete(aaudioBuilder));

    EXPECT_EQ(AAUDIO_OK, AAudioStream_getState(aaudioStream, &state));
    EXPECT_EQ(AAUDIO_STREAM_STATE_OPEN, state);

    // Check to see what kind of stream we actually got.
    EXPECT_EQ(AAUDIO_OK, AAudioStream_getSampleRate(aaudioStream, &actualSampleRate));
    ASSERT_TRUE(actualSampleRate >= 44100 && actualSampleRate <= 96000);  // TODO what is range?

    EXPECT_EQ(AAUDIO_OK, AAudioStream_getSamplesPerFrame(aaudioStream, &actualSamplesPerFrame));
    ASSERT_TRUE(actualSamplesPerFrame >= 1 && actualSamplesPerFrame <= 16); // TODO what is max?

    EXPECT_EQ(AAUDIO_OK, AAudioStream_getSharingMode(aaudioStream, &actualSharingMode));
    ASSERT_TRUE(actualSharingMode == AAUDIO_SHARING_MODE_EXCLUSIVE
                || actualSharingMode == AAUDIO_SHARING_MODE_LEGACY);

    EXPECT_EQ(AAUDIO_OK, AAudioStream_getFormat(aaudioStream, &actualDataFormat));
    EXPECT_NE(AAUDIO_FORMAT_INVALID, actualDataFormat);

    EXPECT_EQ(AAUDIO_OK, AAudioStream_getFramesPerBurst(aaudioStream, &framesPerBurst));
    ASSERT_TRUE(framesPerBurst >= 16 && framesPerBurst <= 1024); // TODO what is min/max?

    // Allocate a buffer for the audio data.
    // TODO handle possibility of other data formats
    ASSERT_TRUE(actualDataFormat == AAUDIO_FORMAT_PCM16);
    size_t dataSizeSamples = framesPerBurst * actualSamplesPerFrame;
    int16_t *data = new int16_t[dataSizeSamples];
    ASSERT_TRUE(nullptr != data);
    memset(data, 0, sizeof(int16_t) * dataSizeSamples);

    // Prime the buffer.
    timeoutNanos = 0;
    do {
        framesWritten = AAudioStream_write(aaudioStream, data, framesPerBurst, timeoutNanos);
        // There should be some room for priming the buffer.
        framesTotal += framesWritten;
        ASSERT_GE(framesWritten, 0);
        ASSERT_LE(framesWritten, framesPerBurst);
    } while (framesWritten > 0);
    ASSERT_TRUE(framesTotal > 0);

    // Start/write/pause more than once to see if it fails after the first time.
    // Write some data and measure the rate to see if the timing is OK.
    for (int numLoops = 0; numLoops < 2; numLoops++) {
        // Start and wait for server to respond.
        ASSERT_EQ(AAUDIO_OK, AAudioStream_requestStart(aaudioStream));
        ASSERT_EQ(AAUDIO_OK, AAudioStream_waitForStateChange(aaudioStream,
                                                         AAUDIO_STREAM_STATE_STARTING,
                                                         &state,
                                                         DEFAULT_STATE_TIMEOUT));
        EXPECT_EQ(AAUDIO_STREAM_STATE_STARTED, state);

        // Write some data while we are running. Read counter should be advancing.
        writeLoops = 1 * actualSampleRate / framesPerBurst; // 1 second
        ASSERT_LT(2, writeLoops); // detect absurdly high framesPerBurst
        timeoutNanos = 10 * AAUDIO_NANOS_PER_SECOND * framesPerBurst / actualSampleRate; // bursts
        framesWritten = 1;
        ASSERT_EQ(AAUDIO_OK, AAudioStream_getFramesRead(aaudioStream, &aaudioFramesRead));
        aaudioFramesRead1 = aaudioFramesRead;
        aaudio_nanoseconds_t beginTime = AAudio_getNanoseconds(AAUDIO_CLOCK_MONOTONIC);
        do {
            framesWritten = AAudioStream_write(aaudioStream, data, framesPerBurst, timeoutNanos);
            ASSERT_GE(framesWritten, 0);
            ASSERT_LE(framesWritten, framesPerBurst);

            framesTotal += framesWritten;
            EXPECT_EQ(AAUDIO_OK, AAudioStream_getFramesWritten(aaudioStream, &aaudioFramesWritten));
            EXPECT_EQ(framesTotal, aaudioFramesWritten);

            // Try to get a more accurate measure of the sample rate.
            if (beginTime == 0) {
                EXPECT_EQ(AAUDIO_OK, AAudioStream_getFramesRead(aaudioStream, &aaudioFramesRead));
                if (aaudioFramesRead > aaudioFramesRead1) { // is read pointer advancing
                    beginTime = AAudio_getNanoseconds(AAUDIO_CLOCK_MONOTONIC);
                    aaudioFramesRead1 = aaudioFramesRead;
                }
            }
        } while (framesWritten > 0 && writeLoops-- > 0);

        EXPECT_EQ(AAUDIO_OK, AAudioStream_getFramesRead(aaudioStream, &aaudioFramesRead2));
        aaudio_nanoseconds_t endTime = AAudio_getNanoseconds(AAUDIO_CLOCK_MONOTONIC);
        ASSERT_GT(aaudioFramesRead2, 0);
        ASSERT_GT(aaudioFramesRead2, aaudioFramesRead1);
        ASSERT_LE(aaudioFramesRead2, aaudioFramesWritten);

        // TODO why is legacy so inaccurate?
        const double rateTolerance = 200.0; // arbitrary tolerance for sample rate
        if (requestedSharingMode != AAUDIO_SHARING_MODE_LEGACY) {
            // Calculate approximate sample rate and compare with stream rate.
            double seconds = (endTime - beginTime) / (double) AAUDIO_NANOS_PER_SECOND;
            double measuredRate = (aaudioFramesRead2 - aaudioFramesRead1) / seconds;
            ASSERT_NEAR(actualSampleRate, measuredRate, rateTolerance);
        }

        // Request async pause and wait for server to say that it has completed the pause.
        ASSERT_EQ(AAUDIO_OK, AAudioStream_requestPause(aaudioStream));
        EXPECT_EQ(AAUDIO_OK, AAudioStream_waitForStateChange(aaudioStream,
                                                AAUDIO_STREAM_STATE_PAUSING,
                                                &state,
                                                DEFAULT_STATE_TIMEOUT));
        EXPECT_EQ(AAUDIO_STREAM_STATE_PAUSED, state);
    }

    // Make sure the read counter is not advancing when we are paused.
    ASSERT_EQ(AAUDIO_OK, AAudioStream_getFramesRead(aaudioStream, &aaudioFramesRead));
    ASSERT_GE(aaudioFramesRead, aaudioFramesRead2); // monotonic increase

    // Use this to sleep by waiting for something that won't happen.
    AAudioStream_waitForStateChange(aaudioStream, AAUDIO_STREAM_STATE_PAUSED, &state, timeoutNanos);
    ASSERT_EQ(AAUDIO_OK, AAudioStream_getFramesRead(aaudioStream, &aaudioFramesRead2));
    EXPECT_EQ(aaudioFramesRead, aaudioFramesRead2);

    // ------------------- TEST FLUSH -----------------
    // Prime the buffer.
    timeoutNanos = 0;
    writeLoops = 100;
    do {
        framesWritten = AAudioStream_write(aaudioStream, data, framesPerBurst, timeoutNanos);
        framesTotal += framesWritten;
    } while (framesWritten > 0 && writeLoops-- > 0);
    EXPECT_EQ(0, framesWritten);

    // Flush and wait for server to respond.
    ASSERT_EQ(AAUDIO_OK, AAudioStream_requestFlush(aaudioStream));
    EXPECT_EQ(AAUDIO_OK, AAudioStream_waitForStateChange(aaudioStream,
                                                     AAUDIO_STREAM_STATE_FLUSHING,
                                                     &state,
                                                     DEFAULT_STATE_TIMEOUT));
    EXPECT_EQ(AAUDIO_STREAM_STATE_FLUSHED, state);

    // After a flush, the read counter should be caught up with the write counter.
    EXPECT_EQ(AAUDIO_OK, AAudioStream_getFramesWritten(aaudioStream, &aaudioFramesWritten));
    EXPECT_EQ(framesTotal, aaudioFramesWritten);
    EXPECT_EQ(AAUDIO_OK, AAudioStream_getFramesRead(aaudioStream, &aaudioFramesRead));
    EXPECT_EQ(aaudioFramesRead, aaudioFramesWritten);

    // The buffer should be empty after a flush so we should be able to write.
    framesWritten = AAudioStream_write(aaudioStream, data, framesPerBurst, timeoutNanos);
    // There should be some room for priming the buffer.
    ASSERT_TRUE(framesWritten > 0 && framesWritten <= framesPerBurst);

    EXPECT_EQ(AAUDIO_OK, AAudioStream_close(aaudioStream));
}

// Test Writing to an AAudioStream using LEGACY sharing mode.
TEST(test_aaudio_api, aaudio_stream_legacy) {
    runtest_aaudio_stream(AAUDIO_SHARING_MODE_LEGACY);
}

// Test Writing to an AAudioStream using EXCLUSIVE sharing mode.
TEST(test_aaudio_api, aaudio_stream_exclusive) {
    runtest_aaudio_stream(AAUDIO_SHARING_MODE_EXCLUSIVE);
}

#define AAUDIO_THREAD_ANSWER          1826375
#define AAUDIO_THREAD_DURATION_MSEC       500

static void *TestAAudioStreamThreadProc(void *arg) {
    AAudioStream aaudioStream = (AAudioStream) reinterpret_cast<size_t>(arg);
    aaudio_stream_state_t state;

    // Use this to sleep by waiting for something that won't happen.
    EXPECT_EQ(AAUDIO_OK, AAudioStream_getState(aaudioStream, &state));
    AAudioStream_waitForStateChange(aaudioStream, AAUDIO_STREAM_STATE_PAUSED, &state,
            AAUDIO_THREAD_DURATION_MSEC * AAUDIO_NANOS_PER_MILLISECOND);
    return reinterpret_cast<void *>(AAUDIO_THREAD_ANSWER);
}

// Test creating a stream related thread.
TEST(test_aaudio_api, aaudio_stream_thread_basic) {
    AAudioStreamBuilder aaudioBuilder;
    AAudioStream aaudioStream;
    aaudio_result_t result = AAUDIO_OK;
    void *threadResult;

    // Use an AAudioStreamBuilder to define the stream.
    result = AAudio_createStreamBuilder(&aaudioBuilder);
    ASSERT_EQ(AAUDIO_OK, result);

    // Create an AAudioStream using the Builder.
    ASSERT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));

    // Start a thread.
    ASSERT_EQ(AAUDIO_OK, AAudioStream_createThread(aaudioStream,
            10 * AAUDIO_NANOS_PER_MILLISECOND,
            TestAAudioStreamThreadProc,
            reinterpret_cast<void *>(aaudioStream)));
    // Thread already started.
    ASSERT_NE(AAUDIO_OK, AAudioStream_createThread(aaudioStream,   // should fail!
            10 * AAUDIO_NANOS_PER_MILLISECOND,
            TestAAudioStreamThreadProc,
            reinterpret_cast<void *>(aaudioStream)));

    // Wait for the thread to finish.
    ASSERT_EQ(AAUDIO_OK, AAudioStream_joinThread(aaudioStream,
            &threadResult, 2 * AAUDIO_THREAD_DURATION_MSEC * AAUDIO_NANOS_PER_MILLISECOND));
    // The thread returns a special answer.
    ASSERT_EQ(AAUDIO_THREAD_ANSWER, (int)reinterpret_cast<size_t>(threadResult));

    // Thread should already be joined.
    ASSERT_NE(AAUDIO_OK, AAudioStream_joinThread(aaudioStream,  // should fail!
            &threadResult, 2 * AAUDIO_THREAD_DURATION_MSEC * AAUDIO_NANOS_PER_MILLISECOND));

    // Cleanup
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_delete(aaudioBuilder));
    EXPECT_EQ(AAUDIO_OK, AAudioStream_close(aaudioStream));
}
