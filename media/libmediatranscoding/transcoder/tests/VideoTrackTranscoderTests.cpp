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
                "/data/local/tmp/TranscoderTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

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

                mSourceFormat = std::shared_ptr<AMediaFormat>(
                        trackFormat, std::bind(AMediaFormat_delete, std::placeholders::_1));
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

TEST_F(VideoTrackTranscoderTests, SampleSanity) {
    LOG(DEBUG) << "Testing SampleSanity";
    std::shared_ptr<TestCallback> callback = std::make_shared<TestCallback>();
    VideoTrackTranscoder transcoder{callback};

    EXPECT_EQ(transcoder.configure(mMediaSampleReader, mTrackIndex, mDestinationFormat), AMEDIA_OK);
    ASSERT_TRUE(transcoder.start());

    std::thread sampleConsumerThread{[&transcoder] {
        uint64_t sampleCount = 0;
        std::shared_ptr<MediaSample> sample;
        while (!transcoder.mOutputQueue.dequeue(&sample)) {
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
    EXPECT_TRUE(transcoder.stop());

    sampleConsumerThread.join();
}

// VideoTrackTranscoder needs a valid destination format.
TEST_F(VideoTrackTranscoderTests, NullDestinationFormat) {
    LOG(DEBUG) << "Testing NullDestinationFormat";
    std::shared_ptr<TestCallback> callback = std::make_shared<TestCallback>();
    std::shared_ptr<AMediaFormat> nullFormat;

    VideoTrackTranscoder transcoder{callback};
    EXPECT_EQ(transcoder.configure(mMediaSampleReader, 0 /* trackIndex */, nullFormat),
              AMEDIA_ERROR_INVALID_PARAMETER);
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
