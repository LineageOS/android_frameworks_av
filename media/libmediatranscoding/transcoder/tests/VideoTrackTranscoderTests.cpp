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

// Unit Test for VideoTrackTranscoder

// #define LOG_NDEBUG 0
#define LOG_TAG "VideoTrackTranscoderTests"

#include <android-base/logging.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/NdkCommon.h>
#include <media/VideoTrackTranscoder.h>
#include <utils/Timers.h>

#include "TrackTranscoderTestUtils.h"

namespace android {

// TODO(b/155304421): Implement more advanced video specific tests:
//  - Codec conversions (HEVC -> AVC).
//  - Bitrate validation.
//  - Output frame validation through PSNR.

class VideoTrackTranscoderTests : public ::testing::Test {
public:
    VideoTrackTranscoderTests() { LOG(DEBUG) << "VideoTrackTranscoderTests created"; }

    void SetUp() override {
        LOG(DEBUG) << "VideoTrackTranscoderTests set up";
        const char* sourcePath =
                "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

        const int sourceFd = open(sourcePath, O_RDONLY);
        ASSERT_GT(sourceFd, 0);

        const off_t fileSize = lseek(sourceFd, 0, SEEK_END);
        lseek(sourceFd, 0, SEEK_SET);

        mMediaSampleReader = MediaSampleReaderNDK::createFromFd(sourceFd, 0, fileSize);
        ASSERT_NE(mMediaSampleReader, nullptr);
        close(sourceFd);

        for (size_t trackIndex = 0; trackIndex < mMediaSampleReader->getTrackCount();
             ++trackIndex) {
            AMediaFormat* trackFormat = mMediaSampleReader->getTrackFormat(trackIndex);
            ASSERT_NE(trackFormat, nullptr);

            const char* mime = nullptr;
            AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);
            ASSERT_NE(mime, nullptr);

            if (strncmp(mime, "video/", 6) == 0) {
                mTrackIndex = trackIndex;

                mSourceFormat = std::shared_ptr<AMediaFormat>(trackFormat, &AMediaFormat_delete);
                ASSERT_NE(mSourceFormat, nullptr);

                mDestinationFormat =
                        TrackTranscoderTestUtils::getDefaultVideoDestinationFormat(trackFormat);
                ASSERT_NE(mDestinationFormat, nullptr);
                break;
            }

            AMediaFormat_delete(trackFormat);
        }

        ASSERT_NE(mSourceFormat, nullptr);
    }

    void TearDown() override { LOG(DEBUG) << "VideoTrackTranscoderTests tear down"; }

    ~VideoTrackTranscoderTests() { LOG(DEBUG) << "VideoTrackTranscoderTests destroyed"; }

    std::shared_ptr<MediaSampleReader> mMediaSampleReader;
    int mTrackIndex;
    std::shared_ptr<AMediaFormat> mSourceFormat;
    std::shared_ptr<AMediaFormat> mDestinationFormat;
};

TEST_F(VideoTrackTranscoderTests, SampleSoundness) {
    LOG(DEBUG) << "Testing SampleSoundness";
    std::shared_ptr<TestCallback> callback = std::make_shared<TestCallback>();
    auto transcoder = VideoTrackTranscoder::create(callback);

    EXPECT_EQ(transcoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(transcoder->start());

    std::shared_ptr<MediaSampleQueue> outputQueue = transcoder->getOutputQueue();
    std::thread sampleConsumerThread{[&outputQueue] {
        uint64_t sampleCount = 0;
        std::shared_ptr<MediaSample> sample;
        while (!outputQueue->dequeue(&sample)) {
            ASSERT_NE(sample, nullptr);
            const uint32_t flags = sample->info.flags;

            if (sampleCount == 0) {
                // Expect first sample to be a codec config.
                EXPECT_TRUE((flags & SAMPLE_FLAG_CODEC_CONFIG) != 0);
                EXPECT_TRUE((flags & SAMPLE_FLAG_SYNC_SAMPLE) == 0);
                EXPECT_TRUE((flags & SAMPLE_FLAG_END_OF_STREAM) == 0);
                EXPECT_TRUE((flags & SAMPLE_FLAG_PARTIAL_FRAME) == 0);
            } else if (sampleCount == 1) {
                // Expect second sample to be a sync sample.
                EXPECT_TRUE((flags & SAMPLE_FLAG_CODEC_CONFIG) == 0);
                EXPECT_TRUE((flags & SAMPLE_FLAG_SYNC_SAMPLE) != 0);
                EXPECT_TRUE((flags & SAMPLE_FLAG_END_OF_STREAM) == 0);
            }

            if (!(flags & SAMPLE_FLAG_END_OF_STREAM)) {
                // Expect a valid buffer unless it is EOS.
                EXPECT_NE(sample->buffer, nullptr);
                EXPECT_NE(sample->bufferId, 0xBAADF00D);
                EXPECT_GT(sample->info.size, 0);
            }

            ++sampleCount;
            if (sample->info.flags & SAMPLE_FLAG_END_OF_STREAM) {
                break;
            }
            sample.reset();
        }
    }};

    EXPECT_EQ(callback->waitUntilFinished(), AMEDIA_OK);
    EXPECT_TRUE(transcoder->stop());

    sampleConsumerThread.join();
}

TEST_F(VideoTrackTranscoderTests, PreserveBitrate) {
    LOG(DEBUG) << "Testing PreserveBitrate";
    std::shared_ptr<TestCallback> callback = std::make_shared<TestCallback>();
    std::shared_ptr<MediaTrackTranscoder> transcoder = VideoTrackTranscoder::create(callback);

    auto destFormat = TrackTranscoderTestUtils::getDefaultVideoDestinationFormat(
            mSourceFormat.get(), false /* includeBitrate*/);
    EXPECT_NE(destFormat, nullptr);

    ASSERT_EQ(transcoder->configure(mMediaSampleReader, mTrackIndex, destFormat), AMEDIA_OK);
    ASSERT_TRUE(transcoder->start());

    callback->waitUntilTrackFormatAvailable();

    auto outputFormat = transcoder->getOutputFormat();
    ASSERT_NE(outputFormat, nullptr);

    ASSERT_TRUE(transcoder->stop());
    transcoder->getOutputQueue()->abort();

    int32_t outBitrate;
    EXPECT_TRUE(AMediaFormat_getInt32(outputFormat.get(), AMEDIAFORMAT_KEY_BIT_RATE, &outBitrate));

    int32_t srcBitrate;
    EXPECT_EQ(mMediaSampleReader->getEstimatedBitrateForTrack(mTrackIndex, &srcBitrate), AMEDIA_OK);

    EXPECT_EQ(srcBitrate, outBitrate);
}

// VideoTrackTranscoder needs a valid destination format.
TEST_F(VideoTrackTranscoderTests, NullDestinationFormat) {
    LOG(DEBUG) << "Testing NullDestinationFormat";
    std::shared_ptr<TestCallback> callback = std::make_shared<TestCallback>();
    std::shared_ptr<AMediaFormat> nullFormat;

    auto transcoder = VideoTrackTranscoder::create(callback);
    EXPECT_EQ(transcoder->configure(mMediaSampleReader, 0 /* trackIndex */, nullFormat),
              AMEDIA_ERROR_INVALID_PARAMETER);
}

TEST_F(VideoTrackTranscoderTests, LingeringEncoder) {
    struct {
        void wait() {
            std::unique_lock<std::mutex> lock(mMutex);
            while (!mSignaled) {
                mCondition.wait(lock);
            }
        }

        void signal() {
            std::unique_lock<std::mutex> lock(mMutex);
            mSignaled = true;
            mCondition.notify_all();
        }

        std::mutex mMutex;
        std::condition_variable mCondition;
        bool mSignaled = false;
    } semaphore;

    auto callback = std::make_shared<TestCallback>();
    auto transcoder = VideoTrackTranscoder::create(callback);

    EXPECT_EQ(transcoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(transcoder->start());

    std::shared_ptr<MediaSampleQueue> outputQueue = transcoder->getOutputQueue();
    std::vector<std::shared_ptr<MediaSample>> samples;
    std::thread sampleConsumerThread([&outputQueue, &samples, &semaphore] {
        std::shared_ptr<MediaSample> sample;
        while (samples.size() < 10 && !outputQueue->dequeue(&sample)) {
            ASSERT_NE(sample, nullptr);
            samples.push_back(sample);

            if (sample->info.flags & SAMPLE_FLAG_END_OF_STREAM) {
                break;
            }
            sample.reset();
        }

        semaphore.signal();
    });

    // Wait for the encoder to output samples before stopping and releasing the transcoder.
    semaphore.wait();

    EXPECT_TRUE(transcoder->stop());
    transcoder.reset();
    sampleConsumerThread.join();

    // Return buffers to the codec so that it can resume processing, but keep one buffer to avoid
    // the codec being released.
    samples.resize(1);

    // Wait for async codec events.
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
