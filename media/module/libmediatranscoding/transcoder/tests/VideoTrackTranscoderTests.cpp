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
#include <android/binder_process.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/NdkCommon.h>
#include <media/VideoTrackTranscoder.h>
#include <utils/Timers.h>

#include "TranscoderTestUtils.h"

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

    static int32_t getConfiguredBitrate(const std::shared_ptr<VideoTrackTranscoder>& transcoder) {
        return transcoder->mConfiguredBitrate;
    }

    std::shared_ptr<MediaSampleReader> mMediaSampleReader;
    int mTrackIndex;
    std::shared_ptr<AMediaFormat> mSourceFormat;
    std::shared_ptr<AMediaFormat> mDestinationFormat;
};

TEST_F(VideoTrackTranscoderTests, SampleSoundness) {
    LOG(DEBUG) << "Testing SampleSoundness";
    auto callback = std::make_shared<TestTrackTranscoderCallback>();
    auto transcoder = VideoTrackTranscoder::create(callback);

    EXPECT_EQ(mMediaSampleReader->selectTrack(mTrackIndex), AMEDIA_OK);
    EXPECT_EQ(transcoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(transcoder->start());

    bool eos = false;
    uint64_t sampleCount = 0;
    transcoder->setSampleConsumer([&sampleCount, &eos](const std::shared_ptr<MediaSample>& sample) {
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
        } else {
            EXPECT_FALSE(eos);
            eos = true;
        }

        ++sampleCount;
    });

    EXPECT_EQ(callback->waitUntilFinished(), AMEDIA_OK);
}

TEST_F(VideoTrackTranscoderTests, PreserveBitrate) {
    LOG(DEBUG) << "Testing PreserveBitrate";
    auto callback = std::make_shared<TestTrackTranscoderCallback>();
    auto transcoder = VideoTrackTranscoder::create(callback);

    auto destFormat = TrackTranscoderTestUtils::getDefaultVideoDestinationFormat(
            mSourceFormat.get(), false /* includeBitrate*/);
    EXPECT_NE(destFormat, nullptr);

    EXPECT_EQ(mMediaSampleReader->selectTrack(mTrackIndex), AMEDIA_OK);

    int32_t srcBitrate;
    EXPECT_EQ(mMediaSampleReader->getEstimatedBitrateForTrack(mTrackIndex, &srcBitrate), AMEDIA_OK);

    ASSERT_EQ(transcoder->configure(mMediaSampleReader, mTrackIndex, destFormat), AMEDIA_OK);
    ASSERT_TRUE(transcoder->start());

    callback->waitUntilTrackFormatAvailable();
    transcoder->stop();
    EXPECT_EQ(callback->waitUntilFinished(), AMEDIA_OK);

    int32_t outBitrate = getConfiguredBitrate(transcoder);
    ASSERT_GT(outBitrate, 0);

    EXPECT_EQ(srcBitrate, outBitrate);
}

// VideoTrackTranscoder needs a valid destination format.
TEST_F(VideoTrackTranscoderTests, NullDestinationFormat) {
    LOG(DEBUG) << "Testing NullDestinationFormat";
    auto callback = std::make_shared<TestTrackTranscoderCallback>();
    std::shared_ptr<AMediaFormat> nullFormat;

    auto transcoder = VideoTrackTranscoder::create(callback);
    EXPECT_EQ(transcoder->configure(mMediaSampleReader, 0 /* trackIndex */, nullFormat),
              AMEDIA_ERROR_INVALID_PARAMETER);
}

TEST_F(VideoTrackTranscoderTests, LingeringEncoder) {
    OneShotSemaphore semaphore;
    auto callback = std::make_shared<TestTrackTranscoderCallback>();
    auto transcoder = VideoTrackTranscoder::create(callback);

    EXPECT_EQ(mMediaSampleReader->selectTrack(mTrackIndex), AMEDIA_OK);
    EXPECT_EQ(transcoder->configure(mMediaSampleReader, mTrackIndex, mDestinationFormat),
              AMEDIA_OK);
    ASSERT_TRUE(transcoder->start());

    std::vector<std::shared_ptr<MediaSample>> samples;
    transcoder->setSampleConsumer(
            [&samples, &semaphore](const std::shared_ptr<MediaSample>& sample) {
                if (samples.size() >= 4) return;

                ASSERT_NE(sample, nullptr);
                samples.push_back(sample);

                if (samples.size() == 4 || sample->info.flags & SAMPLE_FLAG_END_OF_STREAM) {
                    semaphore.signal();
                }
            });

    // Wait for the encoder to output samples before stopping and releasing the transcoder.
    semaphore.wait();

    transcoder->stop();
    EXPECT_EQ(callback->waitUntilFinished(), AMEDIA_OK);
    transcoder.reset();

    // Return buffers to the codec so that it can resume processing, but keep one buffer to avoid
    // the codec being released.
    samples.resize(1);

    // Wait for async codec events.
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ABinderProcess_startThreadPool();
    return RUN_ALL_TESTS();
}
