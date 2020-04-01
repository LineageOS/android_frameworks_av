/*
 * Copyright (C) 2020 The Android Open Source Project
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

// Unit Test for MediaSampleQueue

// #define LOG_NDEBUG 0
#define LOG_TAG "MediaSampleQueueTests"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <media/MediaSampleQueue.h>

#include <thread>

namespace android {

/** Duration to use when delaying threads to order operations. */
static constexpr int64_t kThreadDelayDurationMs = 100;

class MediaSampleQueueTests : public ::testing::Test {
public:
    MediaSampleQueueTests() { LOG(DEBUG) << "MediaSampleQueueTests created"; }
    ~MediaSampleQueueTests() { LOG(DEBUG) << "MediaSampleQueueTests destroyed"; }
};

static std::shared_ptr<MediaSample> newSample(uint32_t id) {
    return MediaSample::createWithReleaseCallback(nullptr /* buffer */, 0 /* offset */, id,
                                                  nullptr /* callback */);
}

TEST_F(MediaSampleQueueTests, TestSequentialDequeueOrder) {
    LOG(DEBUG) << "TestSequentialDequeueOrder Starts";

    static constexpr int kNumSamples = 4;
    MediaSampleQueue sampleQueue;

    // Enqueue loop.
    for (int i = 0; i < kNumSamples; ++i) {
        sampleQueue.enqueue(newSample(i));
    }

    // Dequeue loop.
    for (int i = 0; i < kNumSamples; ++i) {
        std::shared_ptr<MediaSample> sample;
        bool aborted = sampleQueue.dequeue(&sample);
        EXPECT_NE(sample, nullptr);
        EXPECT_EQ(sample->bufferId, i);
        EXPECT_FALSE(aborted);
    }
}

TEST_F(MediaSampleQueueTests, TestInterleavedDequeueOrder) {
    LOG(DEBUG) << "TestInterleavedDequeueOrder Starts";

    static constexpr int kNumSamples = 4;
    MediaSampleQueue sampleQueue;

    // Enqueue and dequeue.
    for (int i = 0; i < kNumSamples; ++i) {
        sampleQueue.enqueue(newSample(i));

        std::shared_ptr<MediaSample> sample;
        bool aborted = sampleQueue.dequeue(&sample);
        EXPECT_NE(sample, nullptr);
        EXPECT_EQ(sample->bufferId, i);
        EXPECT_FALSE(aborted);
    }
}

TEST_F(MediaSampleQueueTests, TestBlockingDequeue) {
    LOG(DEBUG) << "TestBlockingDequeue Starts";

    MediaSampleQueue sampleQueue;

    std::thread enqueueThread([&sampleQueue] {
        // Note: This implementation is a bit racy. Any amount of sleep will not guarantee that the
        // main thread will be blocked on the sample queue by the time this thread calls enqueue.
        // But we can say with high confidence that it will and the test will not fail regardless.
        std::this_thread::sleep_for(std::chrono::milliseconds(kThreadDelayDurationMs));
        sampleQueue.enqueue(newSample(1));
    });

    std::shared_ptr<MediaSample> sample;
    bool aborted = sampleQueue.dequeue(&sample);
    EXPECT_NE(sample, nullptr);
    EXPECT_EQ(sample->bufferId, 1);
    EXPECT_FALSE(aborted);

    enqueueThread.join();
}

TEST_F(MediaSampleQueueTests, TestDequeueBufferRelease) {
    LOG(DEBUG) << "TestDequeueBufferRelease Starts";

    static constexpr int kNumSamples = 4;
    std::vector<bool> bufferReleased(kNumSamples, false);

    MediaSample::OnSampleReleasedCallback callback = [&bufferReleased](MediaSample* sample) {
        bufferReleased[sample->bufferId] = true;
    };

    MediaSampleQueue sampleQueue;
    for (int i = 0; i < kNumSamples; ++i) {
        bool aborted = sampleQueue.enqueue(
                MediaSample::createWithReleaseCallback(nullptr, 0, i, callback));
        EXPECT_FALSE(aborted);
    }

    for (int i = 0; i < kNumSamples; ++i) {
        EXPECT_FALSE(bufferReleased[i]);
    }

    for (int i = 0; i < kNumSamples; ++i) {
        {
            std::shared_ptr<MediaSample> sample;
            bool aborted = sampleQueue.dequeue(&sample);
            EXPECT_NE(sample, nullptr);
            EXPECT_EQ(sample->bufferId, i);
            EXPECT_FALSE(bufferReleased[i]);
            EXPECT_FALSE(aborted);
        }

        for (int j = 0; j < kNumSamples; ++j) {
            EXPECT_EQ(bufferReleased[j], j <= i);
        }
    }
}

TEST_F(MediaSampleQueueTests, TestAbortBufferRelease) {
    LOG(DEBUG) << "TestAbortBufferRelease Starts";

    static constexpr int kNumSamples = 4;
    std::vector<bool> bufferReleased(kNumSamples, false);

    MediaSample::OnSampleReleasedCallback callback = [&bufferReleased](MediaSample* sample) {
        bufferReleased[sample->bufferId] = true;
    };

    MediaSampleQueue sampleQueue;
    for (int i = 0; i < kNumSamples; ++i) {
        bool aborted = sampleQueue.enqueue(
                MediaSample::createWithReleaseCallback(nullptr, 0, i, callback));
        EXPECT_FALSE(aborted);
    }

    for (int i = 0; i < kNumSamples; ++i) {
        EXPECT_FALSE(bufferReleased[i]);
    }

    sampleQueue.abort();

    for (int i = 0; i < kNumSamples; ++i) {
        EXPECT_TRUE(bufferReleased[i]);
    }
}

TEST_F(MediaSampleQueueTests, TestNonEmptyAbort) {
    LOG(DEBUG) << "TestNonEmptyAbort Starts";

    MediaSampleQueue sampleQueue;
    bool aborted = sampleQueue.enqueue(newSample(1));
    EXPECT_FALSE(aborted);

    sampleQueue.abort();

    std::shared_ptr<MediaSample> sample;
    aborted = sampleQueue.dequeue(&sample);
    EXPECT_TRUE(aborted);
    EXPECT_EQ(sample, nullptr);

    aborted = sampleQueue.enqueue(sample);
    EXPECT_TRUE(aborted);
}

TEST_F(MediaSampleQueueTests, TestEmptyAbort) {
    LOG(DEBUG) << "TestEmptyAbort Starts";

    MediaSampleQueue sampleQueue;
    sampleQueue.abort();

    std::shared_ptr<MediaSample> sample;
    bool aborted = sampleQueue.dequeue(&sample);
    EXPECT_TRUE(aborted);
    EXPECT_EQ(sample, nullptr);

    aborted = sampleQueue.enqueue(sample);
    EXPECT_TRUE(aborted);
}

TEST_F(MediaSampleQueueTests, TestBlockingAbort) {
    LOG(DEBUG) << "TestBlockingAbort Starts";

    MediaSampleQueue sampleQueue;

    std::thread abortingThread([&sampleQueue] {
        // Note: This implementation is a bit racy. Any amount of sleep will not guarantee that the
        // main thread will be blocked on the sample queue by the time this thread calls abort.
        // But we can say with high confidence that it will and the test will not fail regardless.
        std::this_thread::sleep_for(std::chrono::milliseconds(kThreadDelayDurationMs));
        sampleQueue.abort();
    });

    std::shared_ptr<MediaSample> sample;
    bool aborted = sampleQueue.dequeue(&sample);
    EXPECT_TRUE(aborted);
    EXPECT_EQ(sample, nullptr);

    abortingThread.join();
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
