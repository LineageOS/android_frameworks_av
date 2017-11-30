/*
 * Copyright (C) 2017 The Android Open Source Project
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

// Test various AAudio features including AAudioStream_setBufferSizeInFrames().

#include <stdio.h>
//#include <stdlib.h>
//#include <math.h>

#include <android-base/macros.h>
#include <aaudio/AAudio.h>

#include <gtest/gtest.h>

// Callback function that does nothing.
aaudio_data_callback_result_t MyDataCallbackProc(
        AAudioStream *stream,
        void *userData,
        void *audioData,
        int32_t numFrames
) {
    (void) stream;
    (void) userData;
    (void) audioData;
    (void) numFrames;
    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}

// Test AAudioStream_setBufferSizeInFrames()

constexpr int64_t NANOS_PER_MILLISECOND = 1000 * 1000;

//int foo() { // To fix Android Studio formatting when editing.
TEST(test_various, aaudio_stop_when_open) {
    AAudioStreamBuilder *aaudioBuilder = nullptr;
    AAudioStream *aaudioStream = nullptr;

// Use an AAudioStreamBuilder to contain requested parameters.
    ASSERT_EQ(AAUDIO_OK, AAudio_createStreamBuilder(&aaudioBuilder));

// Request stream properties.
    AAudioStreamBuilder_setDataCallback(aaudioBuilder, MyDataCallbackProc, nullptr);
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);

// Create an AAudioStream using the Builder.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));


    aaudio_stream_state_t state = AAUDIO_STREAM_STATE_UNKNOWN;
    EXPECT_EQ(AAUDIO_OK, AAudioStream_waitForStateChange(aaudioStream,
                                                         AAUDIO_STREAM_STATE_UNKNOWN, &state,
                                                         1000 * NANOS_PER_MILLISECOND));
    EXPECT_EQ(AAUDIO_STREAM_STATE_OPEN, state);

    EXPECT_EQ(AAUDIO_OK, AAudioStream_requestStop(aaudioStream));

    state = AAUDIO_STREAM_STATE_UNKNOWN;
    EXPECT_EQ(AAUDIO_OK, AAudioStream_waitForStateChange(aaudioStream,
                                                         AAUDIO_STREAM_STATE_UNKNOWN, &state, 0));
    EXPECT_EQ(AAUDIO_STREAM_STATE_OPEN, state);

    AAudioStream_close(aaudioStream);
    AAudioStreamBuilder_delete(aaudioBuilder);
}

//int boo() { // To fix Android Studio formatting when editing.
TEST(test_various, aaudio_flush_when_started) {
    AAudioStreamBuilder *aaudioBuilder = nullptr;
    AAudioStream *aaudioStream = nullptr;

// Use an AAudioStreamBuilder to contain requested parameters.
    ASSERT_EQ(AAUDIO_OK, AAudio_createStreamBuilder(&aaudioBuilder));

// Request stream properties.
    AAudioStreamBuilder_setDataCallback(aaudioBuilder, MyDataCallbackProc, nullptr);
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);

// Create an AAudioStream using the Builder.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));
    EXPECT_EQ(AAUDIO_OK, AAudioStream_requestStart(aaudioStream));

    aaudio_stream_state_t state = AAUDIO_STREAM_STATE_UNKNOWN;
    EXPECT_EQ(AAUDIO_OK, AAudioStream_waitForStateChange(aaudioStream,
                                                         AAUDIO_STREAM_STATE_STARTING, &state,
                                                         1000 * NANOS_PER_MILLISECOND));
    EXPECT_EQ(AAUDIO_STREAM_STATE_STARTED, state);

    EXPECT_EQ(AAUDIO_ERROR_INVALID_STATE, AAudioStream_requestFlush(aaudioStream));

    state = AAUDIO_STREAM_STATE_UNKNOWN;
    EXPECT_EQ(AAUDIO_OK, AAudioStream_waitForStateChange(aaudioStream,
                                                         AAUDIO_STREAM_STATE_UNKNOWN, &state, 0));
    EXPECT_EQ(AAUDIO_STREAM_STATE_STARTED, state);

    AAudioStream_close(aaudioStream);
    AAudioStreamBuilder_delete(aaudioBuilder);
}

//int main() { // To fix Android Studio formatting when editing.
TEST(test_various, aaudio_set_buffer_size) {
    int32_t bufferCapacity;
    int32_t framesPerBurst = 0;
    int32_t actualSize = 0;

    AAudioStreamBuilder *aaudioBuilder = nullptr;
    AAudioStream *aaudioStream = nullptr;

    // Use an AAudioStreamBuilder to contain requested parameters.
    ASSERT_EQ(AAUDIO_OK, AAudio_createStreamBuilder(&aaudioBuilder));

    // Request stream properties.
    AAudioStreamBuilder_setDataCallback(aaudioBuilder, MyDataCallbackProc, nullptr);
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);

    // Create an AAudioStream using the Builder.
    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));

    // This is the number of frames that are read in one chunk by a DMA controller
    // or a DSP or a mixer.
    framesPerBurst = AAudioStream_getFramesPerBurst(aaudioStream);
    bufferCapacity = AAudioStream_getBufferCapacityInFrames(aaudioStream);
    printf("          bufferCapacity = %d, remainder = %d\n",
           bufferCapacity, bufferCapacity % framesPerBurst);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, 0);
    EXPECT_GT(actualSize, 0);
    EXPECT_LE(actualSize, bufferCapacity);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, 2 * framesPerBurst);
    EXPECT_GT(actualSize, framesPerBurst);
    EXPECT_LE(actualSize, bufferCapacity);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, bufferCapacity - 1);
    EXPECT_GT(actualSize, framesPerBurst);
    EXPECT_LE(actualSize, bufferCapacity);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, bufferCapacity);
    EXPECT_GT(actualSize, framesPerBurst);
    EXPECT_LE(actualSize, bufferCapacity);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, bufferCapacity + 1);
    EXPECT_GT(actualSize, framesPerBurst);
    EXPECT_LE(actualSize, bufferCapacity);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, 1234567);
    EXPECT_GT(actualSize, framesPerBurst);
    EXPECT_LE(actualSize, bufferCapacity);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, INT32_MAX);
    EXPECT_GT(actualSize, framesPerBurst);
    EXPECT_LE(actualSize, bufferCapacity);

    actualSize = AAudioStream_setBufferSizeInFrames(aaudioStream, INT32_MIN);
    EXPECT_GT(actualSize, 0);
    EXPECT_LE(actualSize, bufferCapacity);

    AAudioStream_close(aaudioStream);
    AAudioStreamBuilder_delete(aaudioBuilder);
}
