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

#include "TranscoderTestUtils.h"

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

        mCallback = std::make_shared<TestTrackTranscoderCallback>();

        switch (GetParam()) {
        case VIDEO:
            mTranscoder = VideoTrackTranscoder::create(mCallback);
            break;
        case PASSTHROUGH:
            mTranscoder = std::make_shared<PassthroughTrackTranscoder>(mCallback);
            break;
        }
        ASSERT_NE(mTranscoder, nullptr);

        initSampleReader("/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4");
    }

    void initSampleReader(const char* sourcePath) {
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

                mSourceFormat = std::shared_ptr<AMediaFormat>(trackFormat, &AMediaFormat_delete);
                ASSERT_NE(mSourceFormat, nullptr);

                mDestinationFormat =
                        TrackTranscoderTestUtils::getDefaultVideoDestinationFormat(trackFormat);
                ASSERT_NE(mDestinationFormat, nullptr);
                break;
            } else if (GetParam() == PASSTHROUGH && strncmp(mime, "audio/", 6) == 0) {
                // TODO(lnilsson): Test metadata track passthrough after hkuang@ provides sample.
                mTrackIndex = trackIndex;

                mSourceFormat = std::shared_ptr<AMediaFormat>(trackFormat, &AMediaFormat_delete);
                ASSERT_NE(mSourceFormat, nullptr);
                break;
            }

            AMediaFormat_delete(trackFormat);
        }

        ASSERT_NE(mSourceFormat, nullptr);
        EXPECT_EQ(mMediaSampleReader->selectTrack(mTrackIndex), AMEDIA_OK);
    }

    // Drains the transcoder's output queue in a loop.
    void drainOutputSamples(int numSamplesToSave = 0) {
        mTranscoder->setSampleConsumer(
                [this, numSamplesToSave](const std::shared_ptr<MediaSample>& sample) {
                    ASSERT_NE(sample, nullptr);

                    mGotEndOfStream = (sample->info.flags & SAMPLE_FLAG_END_OF_STREAM) != 0;

                    if (mSavedSamples.size() < numSamplesToSave) {
                        mSavedSamples.push_back(sample);
                    }

                    if (mSavedSamples.size() == numSamplesToSave || mGotEndOfStream) {
                        mSamplesSavedSemaphore.signal();
                    }
                });
    }

    void TearDown() override { LOG(DEBUG) << "MediaTrackTranscoderTests tear down"; }

    ~MediaTrackTranscoderTests() { LOG(DEBUG) << "MediaTrackTranscoderTests destroyed"; }

protected:
    std::shared_ptr<MediaTrackTranscoder> mTranscoder;
    std::shared_ptr<TestTrackTranscoderCallback> mCallback;

    std::shared_ptr<MediaSampleReader> mMediaSampleReader;
    int mTrackIndex;

    std::shared_ptr<AMediaFormat> mSourceFormat;
    std::shared_ptr<AMediaFormat> mDestinationFormat;

    std::vector<std::shared_ptr<MediaSample>> mSavedSamples;
    OneShotSemaphore mSamplesSavedSemaphore;
    bool mGotEndOfStream = false;
};

TEST_P(MediaTrackTranscoderTests, WaitNormalOperation) {
    LOG(DEBUG) << "Testing WaitNormalOperation";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());
    drainOutputSamples();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    EXPECT_TRUE(mCallback->transcodingFinished());
    EXPECT_TRUE(mGotEndOfStream);
}

TEST_P(MediaTrackTranscoderTests, StopNormalOperation) {
    LOG(DEBUG) << "Testing StopNormalOperation";

    // Use a longer test asset to make sure that transcoding can be stopped.
    initSampleReader("/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4");

    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    EXPECT_TRUE(mTranscoder->start());
    mCallback->waitUntilTrackFormatAvailable();
    mTranscoder->stop();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    EXPECT_TRUE(mCallback->transcodingWasStopped());
}

TEST_P(MediaTrackTranscoderTests, StartWithoutConfigure) {
    LOG(DEBUG) << "Testing StartWithoutConfigure";
    EXPECT_FALSE(mTranscoder->start());
}

TEST_P(MediaTrackTranscoderTests, StopWithoutStart) {
    LOG(DEBUG) << "Testing StopWithoutStart";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    mTranscoder->stop();
}

TEST_P(MediaTrackTranscoderTests, DoubleStartStop) {
    LOG(DEBUG) << "Testing DoubleStartStop";

    // Use a longer test asset to make sure that transcoding can be stopped.
    initSampleReader("/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4");

    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    EXPECT_TRUE(mTranscoder->start());
    EXPECT_FALSE(mTranscoder->start());
    mTranscoder->stop();
    mTranscoder->stop();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    EXPECT_TRUE(mCallback->transcodingWasStopped());
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
    mTranscoder->stop();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    EXPECT_FALSE(mTranscoder->start());
}

TEST_P(MediaTrackTranscoderTests, RestartAfterFinish) {
    LOG(DEBUG) << "Testing RestartAfterFinish";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());
    drainOutputSamples();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    mTranscoder->stop();
    EXPECT_FALSE(mTranscoder->start());
    EXPECT_TRUE(mGotEndOfStream);
}

TEST_P(MediaTrackTranscoderTests, HoldSampleAfterTranscoderRelease) {
    LOG(DEBUG) << "Testing HoldSampleAfterTranscoderRelease";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());
    drainOutputSamples(1 /* numSamplesToSave */);
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);
    mTranscoder->stop();
    EXPECT_TRUE(mGotEndOfStream);

    mTranscoder.reset();

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    mSavedSamples.clear();
}

TEST_P(MediaTrackTranscoderTests, HoldSampleAfterTranscoderStop) {
    LOG(DEBUG) << "Testing HoldSampleAfterTranscoderStop";
    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(mTranscoder->start());
    drainOutputSamples(1 /* numSamplesToSave */);
    mSamplesSavedSemaphore.wait();
    mTranscoder->stop();
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    mSavedSamples.clear();
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

TEST_P(MediaTrackTranscoderTests, StopOnSync) {
    LOG(DEBUG) << "Testing StopOnSync";

    // Use a longer test asset to make sure there is a GOP to finish.
    initSampleReader("/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4");

    EXPECT_EQ(mTranscoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);

    bool lastSampleWasEos = false;
    bool lastRealSampleWasSync = false;
    OneShotSemaphore samplesReceivedSemaphore;
    uint32_t sampleCount = 0;

    mTranscoder->setSampleConsumer([&](const std::shared_ptr<MediaSample>& sample) {
        ASSERT_NE(sample, nullptr);

        if ((lastSampleWasEos = sample->info.flags & SAMPLE_FLAG_END_OF_STREAM)) {
            samplesReceivedSemaphore.signal();
            return;
        }
        lastRealSampleWasSync = sample->info.flags & SAMPLE_FLAG_SYNC_SAMPLE;

        if (++sampleCount >= 10) {  // Wait for a few samples before stopping.
            samplesReceivedSemaphore.signal();
        }
    });

    ASSERT_TRUE(mTranscoder->start());
    samplesReceivedSemaphore.wait();
    mTranscoder->stop(true /* stopOnSync */);
    EXPECT_EQ(mCallback->waitUntilFinished(), AMEDIA_OK);

    EXPECT_TRUE(lastSampleWasEos);
    EXPECT_TRUE(lastRealSampleWasSync);
    EXPECT_TRUE(mCallback->transcodingWasStopped());
}

};  // namespace android

using namespace android;

INSTANTIATE_TEST_SUITE_P(MediaTrackTranscoderTestsAll, MediaTrackTranscoderTests,
                         ::testing::Values(VIDEO, PASSTHROUGH));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
