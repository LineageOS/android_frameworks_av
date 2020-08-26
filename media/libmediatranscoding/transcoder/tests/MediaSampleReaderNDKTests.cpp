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

// Unit Test for MediaSampleReaderNDK

// #define LOG_NDEBUG 0
#define LOG_TAG "MediaSampleReaderNDKTests"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <utils/Timers.h>
#include <cmath>
#include <mutex>
#include <thread>

// TODO(b/153453392): Test more asset types and validate sample data from readSampleDataForTrack.
// TODO(b/153453392): Test for sequential and parallel (single thread and multi thread) access.
// TODO(b/153453392): Test for switching between sequential and parallel access in different points
//  of time.

namespace android {

#define SEC_TO_USEC(s) ((s)*1000 * 1000)

class MediaSampleReaderNDKTests : public ::testing::Test {
public:
    MediaSampleReaderNDKTests() { LOG(DEBUG) << "MediaSampleReaderNDKTests created"; }

    void SetUp() override {
        LOG(DEBUG) << "MediaSampleReaderNDKTests set up";
        const char* sourcePath =
                "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

        mExtractor = AMediaExtractor_new();
        ASSERT_NE(mExtractor, nullptr);

        mSourceFd = open(sourcePath, O_RDONLY);
        ASSERT_GT(mSourceFd, 0);

        mFileSize = lseek(mSourceFd, 0, SEEK_END);
        lseek(mSourceFd, 0, SEEK_SET);

        media_status_t status =
                AMediaExtractor_setDataSourceFd(mExtractor, mSourceFd, 0, mFileSize);
        ASSERT_EQ(status, AMEDIA_OK);

        mTrackCount = AMediaExtractor_getTrackCount(mExtractor);
        for (size_t trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            AMediaExtractor_selectTrack(mExtractor, trackIndex);
        }
    }

    void initExtractorTimestamps() {
        // Save all sample timestamps, per track, as reported by the extractor.
        mExtractorTimestamps.resize(mTrackCount);
        do {
            const int trackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
            const int64_t sampleTime = AMediaExtractor_getSampleTime(mExtractor);

            mExtractorTimestamps[trackIndex].push_back(sampleTime);
        } while (AMediaExtractor_advance(mExtractor));

        AMediaExtractor_seekTo(mExtractor, 0, AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC);
    }

    std::vector<int32_t> getTrackBitrates() {
        size_t totalSize[mTrackCount];
        memset(totalSize, 0, sizeof(totalSize));

        do {
            const int trackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
            totalSize[trackIndex] += AMediaExtractor_getSampleSize(mExtractor);
        } while (AMediaExtractor_advance(mExtractor));

        AMediaExtractor_seekTo(mExtractor, 0, AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC);

        std::vector<int32_t> bitrates;
        for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            int64_t durationUs;
            AMediaFormat* trackFormat = AMediaExtractor_getTrackFormat(mExtractor, trackIndex);
            EXPECT_NE(trackFormat, nullptr);
            EXPECT_TRUE(AMediaFormat_getInt64(trackFormat, AMEDIAFORMAT_KEY_DURATION, &durationUs));
            bitrates.push_back(roundf((float)totalSize[trackIndex] * 8 * 1000000 / durationUs));
        }

        return bitrates;
    }

    void TearDown() override {
        LOG(DEBUG) << "MediaSampleReaderNDKTests tear down";
        AMediaExtractor_delete(mExtractor);
        close(mSourceFd);
    }

    ~MediaSampleReaderNDKTests() { LOG(DEBUG) << "MediaSampleReaderNDKTests destroyed"; }

    AMediaExtractor* mExtractor = nullptr;
    size_t mTrackCount;
    int mSourceFd;
    size_t mFileSize;
    std::vector<std::vector<int64_t>> mExtractorTimestamps;
};

TEST_F(MediaSampleReaderNDKTests, TestSampleTimes) {
    LOG(DEBUG) << "TestSampleTimes Starts";

    std::shared_ptr<MediaSampleReader> sampleReader =
            MediaSampleReaderNDK::createFromFd(mSourceFd, 0, mFileSize);
    ASSERT_TRUE(sampleReader);

    for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
        EXPECT_EQ(sampleReader->selectTrack(trackIndex), AMEDIA_OK);
    }

    // Initialize the extractor timestamps.
    initExtractorTimestamps();

    std::mutex timestampMutex;
    std::vector<std::thread> trackThreads;
    std::vector<std::vector<int64_t>> readerTimestamps(mTrackCount);

    for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
        trackThreads.emplace_back([sampleReader, trackIndex, &timestampMutex, &readerTimestamps] {
            MediaSampleInfo info;
            while (true) {
                media_status_t status = sampleReader->getSampleInfoForTrack(trackIndex, &info);
                if (status != AMEDIA_OK) {
                    EXPECT_EQ(status, AMEDIA_ERROR_END_OF_STREAM);
                    EXPECT_TRUE((info.flags & SAMPLE_FLAG_END_OF_STREAM) != 0);
                    break;
                }
                ASSERT_TRUE((info.flags & SAMPLE_FLAG_END_OF_STREAM) == 0);
                timestampMutex.lock();
                readerTimestamps[trackIndex].push_back(info.presentationTimeUs);
                timestampMutex.unlock();
                sampleReader->advanceTrack(trackIndex);
            }
        });
    }

    for (auto& thread : trackThreads) {
        thread.join();
    }

    for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
        LOG(DEBUG) << "Track " << trackIndex << ", comparing "
                   << readerTimestamps[trackIndex].size() << " samples.";
        EXPECT_EQ(readerTimestamps[trackIndex].size(), mExtractorTimestamps[trackIndex].size());
        for (size_t sampleIndex = 0; sampleIndex < readerTimestamps[trackIndex].size();
             sampleIndex++) {
            EXPECT_EQ(readerTimestamps[trackIndex][sampleIndex],
                      mExtractorTimestamps[trackIndex][sampleIndex]);
        }
    }
}

TEST_F(MediaSampleReaderNDKTests, TestEstimatedBitrateAccuracy) {
    // Just put a somewhat reasonable upper bound on the estimated bitrate expected in our test
    // assets. This is mostly to make sure the estimation is not way off.
    static constexpr int32_t kMaxEstimatedBitrate = 100 * 1000 * 1000;  // 100 Mbps

    auto sampleReader = MediaSampleReaderNDK::createFromFd(mSourceFd, 0, mFileSize);
    ASSERT_TRUE(sampleReader);

    std::vector<int32_t> actualTrackBitrates = getTrackBitrates();
    for (int trackIndex = 0; trackIndex < mTrackCount; ++trackIndex) {
        EXPECT_EQ(sampleReader->selectTrack(trackIndex), AMEDIA_OK);

        int32_t bitrate;
        EXPECT_EQ(sampleReader->getEstimatedBitrateForTrack(trackIndex, &bitrate), AMEDIA_OK);
        EXPECT_GT(bitrate, 0);
        EXPECT_LT(bitrate, kMaxEstimatedBitrate);

        // Note: The test asset currently used in this test is shorter than the sampling duration
        // used to estimate the bitrate in the sample reader. So for now the estimation should be
        // exact but if/when a longer asset is used a reasonable delta needs to be defined.
        EXPECT_EQ(bitrate, actualTrackBitrates[trackIndex]);
    }
}

TEST_F(MediaSampleReaderNDKTests, TestInvalidFd) {
    std::shared_ptr<MediaSampleReader> sampleReader =
            MediaSampleReaderNDK::createFromFd(0, 0, mFileSize);
    ASSERT_TRUE(sampleReader == nullptr);

    sampleReader = MediaSampleReaderNDK::createFromFd(-1, 0, mFileSize);
    ASSERT_TRUE(sampleReader == nullptr);
}

TEST_F(MediaSampleReaderNDKTests, TestZeroSize) {
    std::shared_ptr<MediaSampleReader> sampleReader =
            MediaSampleReaderNDK::createFromFd(mSourceFd, 0, 0);
    ASSERT_TRUE(sampleReader == nullptr);
}

TEST_F(MediaSampleReaderNDKTests, TestInvalidOffset) {
    std::shared_ptr<MediaSampleReader> sampleReader =
            MediaSampleReaderNDK::createFromFd(mSourceFd, mFileSize, mFileSize);
    ASSERT_TRUE(sampleReader == nullptr);
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
