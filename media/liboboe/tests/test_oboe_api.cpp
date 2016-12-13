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

// Unit tests for Oboe 'C' API.

#include <stdlib.h>
#include <math.h>

#include <gtest/gtest.h>

#include <oboe/OboeDefinitions.h>
#include <oboe/OboeAudio.h>
#include "OboeUtilities.h"

#define DEFAULT_STATE_TIMEOUT  (500 * OBOE_NANOS_PER_MILLISECOND)

// Test OboeStreamBuilder
TEST(test_oboe_api, oboe_stream_builder) {
    const oboe_sample_rate_t requestedSampleRate1 = 48000;
    const oboe_sample_rate_t requestedSampleRate2 = 44100;
    const int32_t requestedSamplesPerFrame = 2;
    const oboe_audio_format_t requestedDataFormat = OBOE_AUDIO_DATATYPE_INT16;

    oboe_sample_rate_t sampleRate = 0;
    int32_t samplesPerFrame = 0;
    oboe_audio_format_t actualDataFormat;
    OboeStreamBuilder oboeBuilder1;
    OboeStreamBuilder oboeBuilder2;

    oboe_result_t result = OBOE_OK;

    // Use an OboeStreamBuilder to define the stream.
    result = Oboe_createStreamBuilder(&oboeBuilder1);
    ASSERT_EQ(OBOE_OK, result);

    // Request stream properties.
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setSampleRate(oboeBuilder1, requestedSampleRate1));
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setSamplesPerFrame(oboeBuilder1, requestedSamplesPerFrame));
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setFormat(oboeBuilder1, requestedDataFormat));

    // Check to make sure builder saved the properties.
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_getSampleRate(oboeBuilder1, &sampleRate));
    EXPECT_EQ(requestedSampleRate1, sampleRate);

    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_getSamplesPerFrame(oboeBuilder1, &samplesPerFrame));
    EXPECT_EQ(requestedSamplesPerFrame, samplesPerFrame);

    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_getFormat(oboeBuilder1, &actualDataFormat));
    EXPECT_EQ(requestedDataFormat, actualDataFormat);

    result = OboeStreamBuilder_getSampleRate(0x0BADCAFE, &sampleRate); // ridiculous token
    EXPECT_EQ(OBOE_ERROR_INVALID_HANDLE, result);

    // Create a second builder and make sure they do not collide.
    ASSERT_EQ(OBOE_OK, Oboe_createStreamBuilder(&oboeBuilder2));
    ASSERT_NE(oboeBuilder1, oboeBuilder2);

    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setSampleRate(oboeBuilder2, requestedSampleRate2));
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_getSampleRate(oboeBuilder1, &sampleRate));
    EXPECT_EQ(requestedSampleRate1, sampleRate);
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_getSampleRate(oboeBuilder2, &sampleRate));
    EXPECT_EQ(requestedSampleRate2, sampleRate);

    // Delete the builder.
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_delete(oboeBuilder1));

    // Now it should no longer be valid.
    // Note that test assumes we are using the HandleTracker. If we use plain pointers
    // then it will be difficult to detect this kind of error.
    result = OboeStreamBuilder_getSampleRate(oboeBuilder1, &sampleRate); // stale token
    EXPECT_EQ(OBOE_ERROR_INVALID_HANDLE, result);

    // Second builder should still be valid.
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_getSampleRate(oboeBuilder2, &sampleRate));
    EXPECT_EQ(requestedSampleRate2, sampleRate);

    // Delete the second builder.
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_delete(oboeBuilder2));

    // Now it should no longer be valid. Assumes HandlerTracker used.
    EXPECT_EQ(OBOE_ERROR_INVALID_HANDLE, OboeStreamBuilder_getSampleRate(oboeBuilder2, &sampleRate));
}


// Test creating a default stream with everything unspecified.
TEST(test_oboe_api, oboe_stream_unspecified) {
    OboeStreamBuilder oboeBuilder;
    OboeStream oboeStream;
    oboe_result_t result = OBOE_OK;

    // Use an OboeStreamBuilder to define the stream.
    result = Oboe_createStreamBuilder(&oboeBuilder);
    ASSERT_EQ(OBOE_OK, result);

    // Create an OboeStream using the Builder.
    ASSERT_EQ(OBOE_OK, OboeStreamBuilder_openStream(oboeBuilder, &oboeStream));

    // Cleanup
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_delete(oboeBuilder));
    EXPECT_EQ(OBOE_OK, OboeStream_close(oboeStream));
}

// Test Writing to an OboeStream
TEST(test_oboe_api, oboe_stream) {
    const oboe_sample_rate_t requestedSampleRate = 48000;
    const oboe_sample_rate_t requestedSamplesPerFrame = 2;
    const oboe_audio_format_t requestedDataFormat = OBOE_AUDIO_DATATYPE_INT16;
    //const oboe_sharing_mode_t requestedSharingMode = OBOE_SHARING_MODE_EXCLUSIVE; // MMAP NOIRQ
    const oboe_sharing_mode_t requestedSharingMode = OBOE_SHARING_MODE_LEGACY; // AudioTrack

    oboe_sample_rate_t actualSampleRate = -1;
    int32_t actualSamplesPerFrame = -1;
    oboe_audio_format_t actualDataFormat = OBOE_AUDIO_FORMAT_PCM824;
    oboe_sharing_mode_t actualSharingMode;
    oboe_size_frames_t framesPerBurst = -1;

    oboe_size_frames_t framesWritten = 0;
    oboe_size_frames_t framesPrimed = 0;
    oboe_position_frames_t framesTotal = 0;
    oboe_position_frames_t oboeFramesRead = 0;
    oboe_position_frames_t oboeFramesRead1 = 0;
    oboe_position_frames_t oboeFramesRead2 = 0;
    oboe_position_frames_t oboeFramesWritten = 0;

    oboe_nanoseconds_t timeoutNanos;

    oboe_stream_state_t state = OBOE_STREAM_STATE_UNINITIALIZED;
    OboeStreamBuilder oboeBuilder;
    OboeStream oboeStream;

    oboe_result_t result = OBOE_OK;

    // Use an OboeStreamBuilder to define the stream.
    result = Oboe_createStreamBuilder(&oboeBuilder);
    ASSERT_EQ(OBOE_OK, result);

    // Request stream properties.
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setSampleRate(oboeBuilder, requestedSampleRate));
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setSamplesPerFrame(oboeBuilder, requestedSamplesPerFrame));
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setFormat(oboeBuilder, requestedDataFormat));
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_setSharingMode(oboeBuilder, requestedSharingMode));

    // Create an OboeStream using the Builder.
    ASSERT_EQ(OBOE_OK, OboeStreamBuilder_openStream(oboeBuilder, &oboeStream));
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_delete(oboeBuilder));

    EXPECT_EQ(OBOE_OK, OboeStream_getState(oboeStream, &state));
    EXPECT_EQ(OBOE_STREAM_STATE_OPEN, state);

    // Check to see what kind of stream we actually got.
    EXPECT_EQ(OBOE_OK, OboeStream_getSampleRate(oboeStream, &actualSampleRate));
    EXPECT_TRUE(actualSampleRate >= 44100 && actualSampleRate <= 96000);  // TODO what is range?

    EXPECT_EQ(OBOE_OK, OboeStream_getSamplesPerFrame(oboeStream, &actualSamplesPerFrame));
    EXPECT_TRUE(actualSamplesPerFrame >= 1 && actualSamplesPerFrame <= 16); // TODO what is max?

    EXPECT_EQ(OBOE_OK, OboeStream_getSharingMode(oboeStream, &actualSharingMode));
    EXPECT_TRUE(actualSharingMode == OBOE_SHARING_MODE_EXCLUSIVE
            || actualSharingMode == OBOE_SHARING_MODE_LEGACY);

    EXPECT_EQ(OBOE_OK, OboeStream_getFramesPerBurst(oboeStream, &framesPerBurst));
    EXPECT_TRUE(framesPerBurst >= 16 && framesPerBurst <= 1024); // TODO what is min/max?

    // Allocate a buffer for the audio data.
    int16_t *data = new int16_t[framesPerBurst * actualSamplesPerFrame];
    ASSERT_TRUE(NULL != data);

    timeoutNanos = 0;
    do {
        framesWritten = OboeStream_write(oboeStream, data, framesPerBurst, timeoutNanos);
        // There should be some room for priming the buffer.
        framesTotal += framesWritten;
        ASSERT_GE(framesWritten, 0);
        ASSERT_LE(framesWritten, framesPerBurst);
    } while(framesWritten > 0);
    ASSERT_TRUE(framesTotal > 0);

    // Start and wait for server to respond.
    ASSERT_EQ(OBOE_OK, OboeStream_requestStart(oboeStream));
    ASSERT_EQ(OBOE_OK, OboeStream_waitForStateChange(oboeStream,
                                                     OBOE_STREAM_STATE_STARTING,
                                                     &state,
                                                     DEFAULT_STATE_TIMEOUT));
    EXPECT_EQ(OBOE_STREAM_STATE_STARTED, state);

    // Write some data while we are running. Read counter should be advancing.
    int loops = 1 * actualSampleRate / framesPerBurst; // 1 second
    ASSERT_LT(2, loops); // detect absurdly high framesPerBurst
    timeoutNanos = 10 * OBOE_NANOS_PER_SECOND * framesPerBurst / actualSampleRate; // bursts
    framesWritten = 1;
    ASSERT_EQ(OBOE_OK, OboeStream_getFramesRead(oboeStream, &oboeFramesRead));
    oboeFramesRead1 = oboeFramesRead;
    oboe_nanoseconds_t beginTime = Oboe_getNanoseconds(OBOE_CLOCK_MONOTONIC);
    do {
        framesWritten = OboeStream_write(oboeStream, data, framesPerBurst, timeoutNanos);
        ASSERT_GE(framesWritten, 0);
        ASSERT_LE(framesWritten, framesPerBurst);

        framesTotal += framesWritten;
        EXPECT_EQ(OBOE_OK, OboeStream_getFramesWritten(oboeStream, &oboeFramesWritten));
        EXPECT_EQ(framesTotal, oboeFramesWritten);

        // Try to get a more accurate measure of the sample rate.
        if (beginTime == 0) {
            EXPECT_EQ(OBOE_OK, OboeStream_getFramesRead(oboeStream, &oboeFramesRead));
            if (oboeFramesRead > oboeFramesRead1) { // is read pointer advancing
                beginTime = Oboe_getNanoseconds(OBOE_CLOCK_MONOTONIC);
                oboeFramesRead1 = oboeFramesRead;
            }
        }
    } while (framesWritten > 0 && loops-- > 0);

    EXPECT_EQ(OBOE_OK, OboeStream_getFramesRead(oboeStream, &oboeFramesRead2));
    oboe_nanoseconds_t endTime = Oboe_getNanoseconds(OBOE_CLOCK_MONOTONIC);
    ASSERT_GT(oboeFramesRead2, 0);
    ASSERT_GT(oboeFramesRead2, oboeFramesRead1);
    ASSERT_LE(oboeFramesRead2, oboeFramesWritten);

    // TODO why is legacy so inaccurate?
    const double rateTolerance = 200.0; // arbitrary tolerance for sample rate
    if (requestedSharingMode != OBOE_SHARING_MODE_LEGACY) {
        // Calculate approximate sample rate and compare with stream rate.
        double seconds = (endTime - beginTime) / (double) OBOE_NANOS_PER_SECOND;
        double measuredRate = (oboeFramesRead2 - oboeFramesRead1) / seconds;
        ASSERT_NEAR(actualSampleRate, measuredRate, rateTolerance);
    }

    // Request async pause and wait for server to say that it has completed the pause.
    ASSERT_EQ(OBOE_OK, OboeStream_requestPause(oboeStream));
    EXPECT_EQ(OBOE_OK, OboeStream_waitForStateChange(oboeStream,
                                            OBOE_STREAM_STATE_PAUSING,
                                            &state,
                                            DEFAULT_STATE_TIMEOUT));
    EXPECT_EQ(OBOE_STREAM_STATE_PAUSED, state);

    // Make sure the read counter is not advancing when we are paused.
    ASSERT_EQ(OBOE_OK, OboeStream_getFramesRead(oboeStream, &oboeFramesRead));
    ASSERT_GE(oboeFramesRead, oboeFramesRead2); // monotonic increase

    // Use this to sleep by waiting for something that won't happen.
    OboeStream_waitForStateChange(oboeStream, OBOE_STREAM_STATE_PAUSED, &state, timeoutNanos);
    ASSERT_EQ(OBOE_OK, OboeStream_getFramesRead(oboeStream, &oboeFramesRead2));
    EXPECT_EQ(oboeFramesRead, oboeFramesRead2);

    // Fill up the buffer.
    timeoutNanos = 0;
    loops = 100;
    do {
        framesWritten = OboeStream_write(oboeStream, data, framesPerBurst, timeoutNanos);
        framesTotal += framesWritten;
    } while (framesWritten > 0 && loops-- > 0);
    EXPECT_EQ(0, framesWritten);

    // Flush and wait for server to respond.
    ASSERT_EQ(OBOE_OK, OboeStream_requestFlush(oboeStream));
    EXPECT_EQ(OBOE_OK, OboeStream_waitForStateChange(oboeStream,
                                                     OBOE_STREAM_STATE_FLUSHING,
                                                     &state,
                                                     DEFAULT_STATE_TIMEOUT));
    EXPECT_EQ(OBOE_STREAM_STATE_FLUSHED, state);

    // After a flush, the read counter should be caught up with the write counter.
    EXPECT_EQ(OBOE_OK, OboeStream_getFramesWritten(oboeStream, &oboeFramesWritten));
    EXPECT_EQ(framesTotal, oboeFramesWritten);
    EXPECT_EQ(OBOE_OK, OboeStream_getFramesRead(oboeStream, &oboeFramesRead));
    EXPECT_EQ(oboeFramesRead, oboeFramesWritten);

    // The buffer should be empty after a flush so we should be able to write.
    framesWritten = OboeStream_write(oboeStream, data, framesPerBurst, timeoutNanos);
    // There should be some room for priming the buffer.
    ASSERT_TRUE(framesWritten > 0 && framesWritten <= framesPerBurst);

    EXPECT_EQ(OBOE_OK, OboeStream_close(oboeStream));
}

#define OBOE_THREAD_ANSWER          1826375
#define OBOE_THREAD_DURATION_MSEC       500

static void *TestOboeStreamThreadProc(void *arg) {
    OboeStream oboeStream = (OboeStream) reinterpret_cast<size_t>(arg);
    oboe_stream_state_t state;

    // Use this to sleep by waiting for something that won't happen.
    EXPECT_EQ(OBOE_OK, OboeStream_getState(oboeStream, &state));
    OboeStream_waitForStateChange(oboeStream, OBOE_STREAM_STATE_PAUSED, &state,
            OBOE_THREAD_DURATION_MSEC * OBOE_NANOS_PER_MILLISECOND);
    return reinterpret_cast<void *>(OBOE_THREAD_ANSWER);
}

// Test creating a stream related thread.
TEST(test_oboe_api, oboe_stream_thread_basic) {
    OboeStreamBuilder oboeBuilder;
    OboeStream oboeStream;
    oboe_result_t result = OBOE_OK;
    void *threadResult;

    // Use an OboeStreamBuilder to define the stream.
    result = Oboe_createStreamBuilder(&oboeBuilder);
    ASSERT_EQ(OBOE_OK, result);

    // Create an OboeStream using the Builder.
    ASSERT_EQ(OBOE_OK, OboeStreamBuilder_openStream(oboeBuilder, &oboeStream));

    // Start a thread.
    ASSERT_EQ(OBOE_OK, OboeStream_createThread(oboeStream,
            10 * OBOE_NANOS_PER_MILLISECOND,
            TestOboeStreamThreadProc,
            reinterpret_cast<void *>(oboeStream)));
    // Thread already started.
    ASSERT_NE(OBOE_OK, OboeStream_createThread(oboeStream,   // should fail!
            10 * OBOE_NANOS_PER_MILLISECOND,
            TestOboeStreamThreadProc,
            reinterpret_cast<void *>(oboeStream)));

    // Wait for the thread to finish.
    ASSERT_EQ(OBOE_OK, OboeStream_joinThread(oboeStream,
            &threadResult, 2 * OBOE_THREAD_DURATION_MSEC * OBOE_NANOS_PER_MILLISECOND));
    // The thread returns a special answer.
    ASSERT_EQ(OBOE_THREAD_ANSWER, (int)reinterpret_cast<size_t>(threadResult));

    // Thread should already be joined.
    ASSERT_NE(OBOE_OK, OboeStream_joinThread(oboeStream,  // should fail!
            &threadResult, 2 * OBOE_THREAD_DURATION_MSEC * OBOE_NANOS_PER_MILLISECOND));

    // Cleanup
    EXPECT_EQ(OBOE_OK, OboeStreamBuilder_delete(oboeBuilder));
    EXPECT_EQ(OBOE_OK, OboeStream_close(oboeStream));
}
