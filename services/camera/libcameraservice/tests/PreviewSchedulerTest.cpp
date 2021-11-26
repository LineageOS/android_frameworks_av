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

//#define LOG_NDEBUG 0
#define LOG_TAG "PreviewSchedulerTest"

#include <chrono>
#include <thread>
#include <utility>

#include <gtest/gtest.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/Mutex.h>

#include <gui/BufferItemConsumer.h>
#include <gui/BufferQueue.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IGraphicBufferConsumer.h>
#include <gui/Surface.h>

#include "../device3/Camera3OutputStream.h"
#include "../device3/PreviewFrameScheduler.h"

using namespace android;
using namespace android::camera3;

// Consumer buffer available listener
class SimpleListener : public BufferItemConsumer::FrameAvailableListener {
public:
    SimpleListener(size_t frameCount): mFrameCount(frameCount) {}

    void waitForFrames() {
        Mutex::Autolock lock(mMutex);
        while (mFrameCount > 0) {
            mCondition.wait(mMutex);
        }
    }

    void onFrameAvailable(const BufferItem& /*item*/) override {
        Mutex::Autolock lock(mMutex);
        if (mFrameCount > 0) {
            mFrameCount--;
            mCondition.signal();
        }
    }

    void reset(size_t frameCount) {
        Mutex::Autolock lock(mMutex);
        mFrameCount = frameCount;
    }
private:
    size_t mFrameCount;
    Mutex mMutex;
    Condition mCondition;
};

// Test the PreviewFrameScheduler functionatliy of re-timing buffers
TEST(PreviewSchedulerTest, BasicPreviewSchedulerTest) {
    const int ID = 0;
    const int FORMAT = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
    const uint32_t WIDTH = 640;
    const uint32_t HEIGHT = 480;
    const int32_t TRANSFORM = 0;
    const nsecs_t T_OFFSET = 0;
    const android_dataspace DATASPACE = HAL_DATASPACE_UNKNOWN;
    const camera_stream_rotation_t ROTATION = CAMERA_STREAM_ROTATION_0;
    const String8 PHY_ID;
    const std::unordered_set<int32_t> PIX_MODES;
    const int BUFFER_COUNT = 4;
    const int TOTAL_BUFFER_COUNT = BUFFER_COUNT * 2;

    // Create buffer queue
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    ASSERT_NE(producer, nullptr);
    ASSERT_NE(consumer, nullptr);
    ASSERT_EQ(NO_ERROR, consumer->setDefaultBufferSize(WIDTH, HEIGHT));

    // Set up consumer
    sp<BufferItemConsumer> bufferConsumer = new BufferItemConsumer(consumer,
            GRALLOC_USAGE_HW_COMPOSER, BUFFER_COUNT);
    ASSERT_NE(bufferConsumer, nullptr);
    sp<SimpleListener> consumerListener = new SimpleListener(BUFFER_COUNT);
    bufferConsumer->setFrameAvailableListener(consumerListener);

    // Set up producer
    sp<Surface> surface = new Surface(producer);
    sp<StubProducerListener> listener = new StubProducerListener();
    ASSERT_EQ(NO_ERROR, surface->connect(NATIVE_WINDOW_API_CPU, listener));
    sp<ANativeWindow> anw(surface);
    ASSERT_EQ(NO_ERROR, native_window_set_buffer_count(anw.get(), TOTAL_BUFFER_COUNT));

    // Create Camera3OutputStream and PreviewFrameScheduler
    sp<Camera3OutputStream> stream = new Camera3OutputStream(ID, surface, WIDTH, HEIGHT,
            FORMAT, DATASPACE, ROTATION, T_OFFSET, PHY_ID, PIX_MODES);
    ASSERT_NE(stream, nullptr);
    std::unique_ptr<PreviewFrameScheduler> scheduler =
            std::make_unique<PreviewFrameScheduler>(*stream, surface);
    ASSERT_NE(scheduler, nullptr);

    // The pair of nsecs_t: camera timestamp delta (negative means in the past) and frame interval
    const std::pair<nsecs_t, nsecs_t> inputTimestamps[][BUFFER_COUNT] = {
        // 30fps, no interval
        {{-100000000LL, 0}, {-66666667LL, 0},
          {-33333333LL, 0}, {0, 0}},
        // 30fps, 33ms interval
        {{-100000000LL, 33333333LL}, {-66666667LL, 33333333LL},
          {-33333333LL, 33333333LL}, {0, 0}},
        // 30fps, variable interval
        {{-100000000LL, 16666667LL}, {-66666667LL, 33333333LL},
          {-33333333LL, 50000000LL}, {0, 0}},
        // 60fps, 16.7ms interval
        {{-50000000LL, 16666667LL}, {-33333333LL, 16666667LL},
          {-16666667LL, 16666667LL}, {0, 0}},
        // 60fps, variable interval
        {{-50000000LL, 8666667LL}, {-33333333LL, 19666667LL},
          {-16666667LL, 20666667LL}, {0, 0}},
    };

    const nsecs_t USE_AS_IS = -1; // Use the producer set timestamp
    const nsecs_t USE_OVERRIDE = -2; // Use the scheduler overridden timestamp
    const nsecs_t expectedTimestamps[][BUFFER_COUNT] = {
        // 30fps, no interval: first 2 frames as is, and last 2 frames are
        // overridden.
        {USE_AS_IS, USE_AS_IS, USE_OVERRIDE, USE_OVERRIDE},
        // 30fps, 33ms interval: all frames are overridden
        {USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE},
        // 30fps, variable interval: all frames are overridden
        {USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE},
        // 60fps, 16.7ms interval: all frames are overridden
        {USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE},
        // 60fps, variable interval: all frames are overridden
        {USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE, USE_OVERRIDE},
    };

    // Go through different use cases, and check the buffer timestamp
    size_t iterations = sizeof(inputTimestamps)/sizeof(inputTimestamps[0]);
    for (size_t i = 0; i < iterations; i++) {
        // Space out different test sets to reset the frame scheduler
        nsecs_t timeBase = systemTime() - s2ns(1) * (iterations - i);
        nsecs_t lastQueueTime = 0;
        nsecs_t duration = 0;
        for (size_t j = 0; j < BUFFER_COUNT; j++) {
            ANativeWindowBuffer* buffer = nullptr;
            int fenceFd;
            ASSERT_EQ(NO_ERROR, anw->dequeueBuffer(anw.get(), &buffer, &fenceFd));

            // Sleep to space out queuePreviewBuffer
            nsecs_t currentTime = systemTime();
            if (duration > 0 && duration > currentTime - lastQueueTime) {
                std::this_thread::sleep_for(
                        std::chrono::nanoseconds(duration + lastQueueTime - currentTime));
            }
            nsecs_t timestamp = timeBase + inputTimestamps[i][j].first;
            ASSERT_EQ(NO_ERROR,
                    scheduler->queuePreviewBuffer(timestamp, TRANSFORM, buffer, fenceFd));

            lastQueueTime = systemTime();
            duration = inputTimestamps[i][j].second;
        }

        // Collect output timestamps, making sure they are either set by
        // producer, or set by the scheduler.
        consumerListener->waitForFrames();
        nsecs_t outputTimestamps[BUFFER_COUNT];
        for (size_t j = 0; j < BUFFER_COUNT; j++) {
            BufferItem bufferItem;
            ASSERT_EQ(NO_ERROR, bufferConsumer->acquireBuffer(&bufferItem, 0/*presentWhen*/));

            outputTimestamps[j] = bufferItem.mTimestamp;
            ALOGV("%s: [%zu][%zu]: input: %" PRId64 ", output: %" PRId64, __FUNCTION__,
                  i, j, timeBase + inputTimestamps[i][j].first, bufferItem.mTimestamp);
            if (expectedTimestamps[i][j] == USE_OVERRIDE) {
                ASSERT_GT(bufferItem.mTimestamp, inputTimestamps[i][j].first);
            } else if (expectedTimestamps[i][j] == USE_AS_IS) {
                ASSERT_EQ(bufferItem.mTimestamp, timeBase + inputTimestamps[i][j].first);
            }

            ASSERT_EQ(NO_ERROR, bufferConsumer->releaseBuffer(bufferItem));
        }

        // Check the output timestamp intervals are aligned with input intervals
        const nsecs_t SHIFT_THRESHOLD = ms2ns(2);
        for (size_t j = 0; j < BUFFER_COUNT - 1; j ++) {
            if (expectedTimestamps[i][j] == USE_OVERRIDE &&
                    expectedTimestamps[i][j+1] == USE_OVERRIDE) {
                nsecs_t interval_shift = outputTimestamps[j+1] - outputTimestamps[j] -
                        (inputTimestamps[i][j+1].first - inputTimestamps[i][j].first);
                ASSERT_LE(std::abs(interval_shift), SHIFT_THRESHOLD);
            }
        }

        consumerListener->reset(BUFFER_COUNT);
    }

    // Disconnect the surface
    ASSERT_EQ(NO_ERROR, surface->disconnect(NATIVE_WINDOW_API_CPU));
}
