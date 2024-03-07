/*
 * Copyright (C) 2019 The Android Open Source Project
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

// Test whether a stream dies if it is written to after a delay.
// Maybe because the message queue from the AAudio service fills up.

#define LOG_TAG "test_full_queue"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdio.h>
#include <unistd.h>

#include <aaudio/AAudio.h>
#include <gtest/gtest.h>
#include <cstdlib>
#include <algorithm>

constexpr int64_t kNanosPerMillisecond = 1e6;
constexpr int64_t kMicrosPerMillisecond = 1000;
constexpr int64_t kTimeoutNanos = 50 * kNanosPerMillisecond;
constexpr int kNumFrames = 256;
constexpr int kChannelCount = 2;
constexpr int kNumSamples = kChannelCount * kNumFrames;

static void checkFullQueue(aaudio_performance_mode_t perfMode,
                           aaudio_sharing_mode_t sharingMode,
                           int32_t sleepMillis) {
    aaudio_result_t result;
    std::unique_ptr<float[]> buffer = std::make_unique<float[]>(kNumSamples);
    for (int i = 0; i < kNumSamples; i++) {
        buffer[i] = (drand48() - 0.5) * 0.05; // random buzzy waveform
    }

    AAudioStreamBuilder *aaudioBuilder = nullptr;

    // Use an AAudioStreamBuilder to contain requested parameters.
    ASSERT_EQ(AAUDIO_OK, AAudio_createStreamBuilder(&aaudioBuilder));

    // Request stream properties.
    AAudioStreamBuilder_setChannelCount(aaudioBuilder, kChannelCount);
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, perfMode);
    AAudioStreamBuilder_setSharingMode(aaudioBuilder, sharingMode);

    // Create an AAudioStream using the Builder.
    AAudioStream *aaudioStream = nullptr;
    ASSERT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder,
            &aaudioStream));
    AAudioStreamBuilder_delete(aaudioBuilder);

    int bufferSize = std::max(
            2 * AAudioStream_getFramesPerBurst(aaudioStream),
            2 * kNumFrames
            );
    AAudioStream_setBufferSizeInFrames(aaudioStream, bufferSize);

    EXPECT_EQ(AAUDIO_OK, AAudioStream_requestStart(aaudioStream));

#if 0
    int32_t capacity = AAudioStream_getBufferCapacityInFrames(aaudioStream);
    ASSERT_LT(20, capacity);
    int numWrites = 30 * capacity / kNumFrames;
#else
    int32_t sampleRate = AAudioStream_getSampleRate(aaudioStream);
    EXPECT_LT(7000, sampleRate);
    int numWrites = 1 * sampleRate / kNumFrames;
#endif

    for (int i = 0; i < numWrites/2; i++) {
        result = AAudioStream_write(aaudioStream,
                buffer.get(),
                kNumFrames,
                kTimeoutNanos);
        EXPECT_EQ(kNumFrames, result);
        if (kNumFrames != result) break;
    }

    // Sleep for awhile. This might kill the stream.
    ALOGD("%s() start sleeping %d millis", __func__, sleepMillis);
    usleep(sleepMillis * kMicrosPerMillisecond);
    ALOGD("%s() start writing", __func__);

    // Let CPU catch up with the hardware.
    int64_t framesRead = AAudioStream_getFramesRead(aaudioStream);
    int64_t framesWritten = AAudioStream_getFramesWritten(aaudioStream);

    ALOGD("%s() after hang, read = %jd, written = %jd, w-r = %jd",
          __func__, (intmax_t) framesRead, (intmax_t) framesWritten,
          (intmax_t)(framesWritten - framesRead));
    int countDown = 2 * sleepMillis * sampleRate / (kNumFrames * 1000);
    do {
        result = AAudioStream_write(aaudioStream,
                buffer.get(),
                kNumFrames,
                kTimeoutNanos);

        ALOGD("%s() catching up, wrote %d frames", __func__, result);
        framesRead = AAudioStream_getFramesRead(aaudioStream);
        framesWritten = AAudioStream_getFramesWritten(aaudioStream);
        countDown--;
    } while ((framesRead > framesWritten)
        && (countDown > 0)
        && (kNumFrames == result));
    EXPECT_LE(framesRead, framesWritten);
    EXPECT_GT(countDown, 0);
    EXPECT_EQ(kNumFrames, result);
    ALOGD("%s() after catch up, read = %jd, written = %jd, w-r = %jd",
          __func__, (intmax_t) framesRead, (intmax_t) framesWritten,
          (intmax_t)(framesWritten - framesRead));

    // Try to keep the stream full.
    for (int i = 0; i < numWrites; i++) {
        ALOGD("%s() try to write", __func__);
        result = AAudioStream_write(aaudioStream,
                buffer.get(),
                kNumFrames,
                kTimeoutNanos);
        ALOGD("%s() wrote %d frames", __func__, result);
        EXPECT_EQ(kNumFrames, result);
        if (kNumFrames != result) break;
    }

    EXPECT_EQ(AAUDIO_OK, AAudioStream_requestStop(aaudioStream));

    EXPECT_EQ(AAUDIO_OK, AAudioStream_close(aaudioStream));
}

// ==== Default Latency, SHARED ===========
TEST(test_full_queue, aaudio_full_queue_perf_none_sh_50) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_NONE,
                   AAUDIO_SHARING_MODE_SHARED, 50 /* sleepMillis */);
}

TEST(test_full_queue, aaudio_full_queue_perf_none_sh_400) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_NONE,
                   AAUDIO_SHARING_MODE_SHARED, 400 /* sleepMillis */);
}

TEST(test_full_queue, aaudio_full_queue_perf_none_sh_1000) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_NONE,
                   AAUDIO_SHARING_MODE_SHARED, 1000 /* sleepMillis */);
}

// ==== Low Latency, SHARED ===========
TEST(test_full_queue, aaudio_full_queue_low_latency_sh_50) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
                   AAUDIO_SHARING_MODE_SHARED, 50 /* sleepMillis */);
}

TEST(test_full_queue, aaudio_full_queue_low_latency_sh_400) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
                   AAUDIO_SHARING_MODE_SHARED, 400 /* sleepMillis */);
}

TEST(test_full_queue, aaudio_full_queue_low_latency_sh_1000) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
                   AAUDIO_SHARING_MODE_SHARED, 1000 /* sleepMillis */);
}

// ==== Low Latency, EXCLUSIVE ===========
TEST(test_full_queue, aaudio_full_queue_low_latency_excl_50) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
                   AAUDIO_SHARING_MODE_EXCLUSIVE, 50 /* sleepMillis */);
}

TEST(test_full_queue, aaudio_full_queue_low_latency_excl_400) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
                   AAUDIO_SHARING_MODE_EXCLUSIVE, 400 /* sleepMillis */);
}

TEST(test_full_queue, aaudio_full_queue_low_latency_excl_1000) {
    checkFullQueue(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
                   AAUDIO_SHARING_MODE_EXCLUSIVE, 1000 /* sleepMillis */);
}
