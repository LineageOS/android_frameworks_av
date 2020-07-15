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

// Unit Test for MediaTrackTranscoder

// #define LOG_NDEBUG 0
#define LOG_TAG "MediaTrackTranscoderTests"

#include <android-base/logging.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/MediaTrackTranscoder.h>
#include <media/PassthroughTrackTranscoder.h>
#include <media/VideoTrackTranscoder.h>

#include "TrackTranscoderTestUtils.h"

namespace android {

/** TrackTranscoder types to test. */
enum TrackTranscoderType {
    VIDEO,
    PASSTHROUGH,
};

class MediaTrackTranscoderTests : public ::testing::TestWithParam<TrackTranscoderType> {
public:
    MediaTrackTranscoderTests() { LOG(DEBUG) << "MediaTrackTranscoderTests created"; }

    void SetUp() override {
        LOG(DEBUG) << "MediaTrackTranscoderTests set up";

        // Need to start a thread pool to prevent AMediaExtractor binder calls from starving
        // (b/155663561).
        ABinderProcess_startThreadPool();

        mCallback = std::make_shared<TestCallback>();

        switch (GetParam()) {
        case VIDEO:
            mTranscoder = VideoTrackTranscoder::create(mCallback);
            break;
        case PASSTHROUGH:
            mTranscoder = std::make_shared<PassthroughTrackTranscoder>(mCallback);
            break;
        }
        ASSERT_NE(mTranscoder, nullptr);
        mTranscoderOutputQueue = mTranscoder->getOutputQueue();

        initSampleReader();
    }

    void initSampleReader() {
        const char* sourcePath =
                "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

        const int sourceFd = open(sourcePath, O_RDONLY);
        ASSERT_GT(sourceFd, 0);

        const size_t fileSize = lseek(sourceFd, 0, SEEK_END);
        lseek(sourceFd, 0, SEEK_SET);

        mMediaSampleReader = MediaSampleReaderNDK::createFromFd(sourceFd, 0 /* offset */, fileSize);
        ASSERT_NE(mMediaSampleReader, nullptr);
        close(sourceFd);

        for (size_t trackIndex = 0; trackIndex < mMediaSampleReader->getTrackCount();
             ++trackIndex) {
            AMediaFormat* trackFormat = mMediaSampleReader->getTrackFormat(trackIndex);
            ASSERT_NE(trackFormat, nullptr);

            const char* mime = nullptr;
            AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);
            ASSERT_NE(mime, nullptr);

            if (GetParam() == VIDEO && strncmp(mime, "video/", 6) == 0) {
                mTrackIndex = trackIndex;

                mSourceFormat = std::shared_ptr<AMediaFormat>(
                        trackFormat, std::bind(AMediaFormat_delete, std::placeholders::_1));
                ASSERT_NE(mSourceFormat, nullptr);

                mDestinationFormat =
                        TrackTranscoderTestUtils::getDefaultVideoDestinationFormat(trackFormat);
                ASSERT_NE(mDestinationFormat, nullptr);
                break;
            } else if (GetParam() == PASSTHROUGH && strncmp(mime, "audio/", 6) == 0) {
                // TODO(lnilsson): Test metadata track passthrough after hkuang@ provides sample.
                mTrackIndex = trackIndex;

                mSourceFormat = std::shared_ptr<AMediaFormat>(
                        trackFormat, std::bind(AMediaFormat_delete, std::placeholders::_1));
                ASSERT_NE(mSourceFormat, nullptr);
                break;
            }

            AMediaFormat_delete(trackFormat);
        }

        ASSERT_NE(mSourceFormat, nullptr);
    }

    // Drains the transcoder's output queue in a loop.
    void drainOutputSampleQueue() {
        mSampleQueueDrainThread = std::thread{[this] {
            std::shared_ptr<MediaSample> sample;
            bool aborted = false;
            do {
                aborted = mTranscoderOutputQueue->dequeue(&sample);
            } while (!aborted && !(sample->info.flags & SAMPLE_FLAG_END_OF_STREAM));
            mQueueWasAborted = aborted;
            mGotEndOfStream =
                    sample != nullptr && (sample->info.flags & SAMPLE_FLAG_END_OF_STREAM) != 0;
        }};
    }

    void joinDrainThread() {
        if (mSampleQueueDrainThread.joinable()) {
            mSampleQueueDrainThread.join();
        }
    }
    void TearDown() override {
        LOG(DEBUG) << "MediaTrackTranscoderTests tear down";
        joinDrainThread();
    }

    ~MediaTrackTranscoderTests() { LOG(DEBUG) << "MediaTrackTranscoderTests destroyed"; }

protected:
    std::shared_ptr<MediaTrackTranscoder> mTranscoder;
    std::shared_ptr<MediaSampleQueue> mTranscoderOutputQueue;
    std::shared_ptr<TestCallback> mCallback;

    std::shared_ptr<MediaSampleReader> mMediaSampleReader;
    int mTrackIndex;

    std::shared_ptr<AMediaFormat> mSourceFormat;
    std::shared_ptr<AMediaFormat> mDestinationFormat;

    std::thread mSampleQueueDrainThread;
    bool mQueueWasAborted = false;
    bool mGotEndOfStream = false;
};

TEST_P(MediaTrackTranscoderTests, WaitNormalOperation) {
    LOG(DEBUG) << "Testing WaitNormalOperation";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());
    drainOutputSampleQueue();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    joinDrainThread();
    EXPECT_TRUE(mTranscoder->stop());
    EXPECT_FALSE(mQueueWasAborted);
    EXPECT_TRUE(mGotEndOfStream);
}

TEST_P(MediaTrackTranscoderTests, StopNormalOperation) {
    LOG(DEBUG) << "Testing StopNormalOperation";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    EXPECT_TRUE(mTranscoder->start());
    EXPECT_TRUE(mTranscoder->stop());
}

TEST_P(MediaTrackTranscoderTests, StartWithoutConfigure) {
    LOG(DEBUG) << "Testing StartWithoutConfigure";
    EXPECT_FALSE(mTranscoder->start());
}

TEST_P(MediaTrackTranscoderTests, StopWithoutStart) {
    LOG(DEBUG) << "Testing StopWithoutStart";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    EXPECT_FALSE(mTranscoder->stop());
}

TEST_P(MediaTrackTranscoderTests, DoubleStartStop) {
    LOG(DEBUG) << "Testing DoubleStartStop";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    EXPECT_TRUE(mTranscoder->start());
    EXPECT_FALSE(mTranscoder->start());
    EXPECT_TRUE(mTranscoder->stop());
    EXPECT_FALSE(mTranscoder->stop());
}

TEST_P(MediaTrackTranscoderTests, DoubleConfigure) {
    LOG(DEBUG) << "Testing DoubleConfigure";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_ERROR_UNSUPPORTED);
}

TEST_P(MediaTrackTranscoderTests, ConfigureAfterFail) {
    LOG(DEBUG) << "Testing ConfigureAfterFail";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, -1, mDestinationFormat),
              AMEDIA_ERROR_INVALID_PARAMETER);
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
}

TEST_P(MediaTrackTranscoderTests, RestartAfterStop) {
    LOG(DEBUG) << "Testing RestartAfterStop";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    EXPECT_TRUE(mTranscoder->start());
    EXPECT_TRUE(mTranscoder->stop());
    EXPECT_FALSE(mTranscoder->start());
}

TEST_P(MediaTrackTranscoderTests, RestartAfterFinish) {
    LOG(DEBUG) << "Testing RestartAfterFinish";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());
    drainOutputSampleQueue();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    joinDrainThread();
    EXPECT_TRUE(mTranscoder->stop());
    EXPECT_FALSE(mTranscoder->start());
    EXPECT_FALSE(mQueueWasAborted);
    EXPECT_TRUE(mGotEndOfStream);
}

TEST_P(MediaTrackTranscoderTests, AbortOutputQueue) {
    LOG(DEBUG) << "Testing AbortOutputQueue";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());
    mTranscoderOutputQueue->abort();
    drainOutputSampleQueue();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_ERROR_IO);
    joinDrainThread();
    EXPECT_TRUE(mTranscoder->stop());
    EXPECT_TRUE(mQueueWasAborted);
    EXPECT_FALSE(mGotEndOfStream);
}

TEST_P(MediaTrackTranscoderTests, HoldSampleAfterTranscoderRelease) {
    LOG(DEBUG) << "Testing HoldSampleAfterTranscoderRelease";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());

    std::shared_ptr<MediaSample> sample;
    EXPECT_FALSE(mTranscoderOutputQueue->dequeue(&sample));

    drainOutputSampleQueue();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    joinDrainThread();
    EXPECT_TRUE(mTranscoder->stop());
    EXPECT_FALSE(mQueueWasAborted);
    EXPECT_TRUE(mGotEndOfStream);

    mTranscoder.reset();
    mTranscoderOutputQueue.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    sample.reset();
}

TEST_P(MediaTrackTranscoderTests, HoldSampleAfterTranscoderStop) {
    LOG(DEBUG) << "Testing HoldSampleAfterTranscoderStop";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());

    std::shared_ptr<MediaSample> sample;
    EXPECT_FALSE(mTranscoderOutputQueue->dequeue(&sample));
    EXPECT_TRUE(mTranscoder->stop());

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    sample.reset();
}

TEST_P(MediaTrackTranscoderTests, NullSampleReader) {
    LOG(DEBUG) << "Testing NullSampleReader";
    std::shared_ptr<MediaSampleReader> nullSampleReader;
    EXPECT_NE(mTranscoder->configure(nullSampleReader, mTrackIndex, mDestinationFormat), AMEDIA_OK);
    ASSERT_FALSE(mTranscoder->start());
}

TEST_P(MediaTrackTranscoderTests, InvalidTrackIndex) {
    LOG(DEBUG) << "Testing InvalidTrackIndex";
    EXPECT_NE(mTranscoder->configure(mMediaSampleReader, -1, mDestinationFormat), AMEDIA_OK);
    EXPECT_NE(mTranscoder->configure(mMediaSampleReader, mMediaSampleReader->getTrackCount(),
                                     mDestinationFormat),
              AMEDIA_OK);
}

};  // namespace android

using namespace android;

INSTANTIATE_TEST_SUITE_P(MediaTrackTranscoderTestsAll, MediaTrackTranscoderTests,
                         ::testing::Values(VIDEO, PASSTHROUGH));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
