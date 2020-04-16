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

// TODO(b/153453392): Test more asset types and validate sample data from readSampleDataForTrack.

namespace android {

#define SEC_TO_USEC(s) ((s)*1000 * 1000)

class MediaSampleReaderNDKTests : public ::testing::Test {
public:
    MediaSampleReaderNDKTests() { LOG(DEBUG) << "MediaSampleReaderNDKTests created"; }

    void SetUp() override {
        LOG(DEBUG) << "MediaSampleReaderNDKTests set up";
        const char* sourcePath =
                "/data/local/tmp/TranscoderTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

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

    MediaSampleInfo info;
    int trackEosCount = 0;
    std::vector<bool> trackReachedEos(mTrackCount, false);
    std::vector<std::vector<int64_t>> readerTimestamps(mTrackCount);

    // Initialize the extractor timestamps.
    initExtractorTimestamps();

    // Read 5s of each track at a time.
    const int64_t chunkDurationUs = SEC_TO_USEC(5);
    int64_t chunkEndTimeUs = chunkDurationUs;

    // Loop until all tracks have reached End Of Stream.
    while (trackEosCount < mTrackCount) {
        for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            if (trackReachedEos[trackIndex]) continue;

            // Advance current track to next chunk end time.
            do {
                media_status_t status = sampleReader->getSampleInfoForTrack(trackIndex, &info);
                if (status != AMEDIA_OK) {
                    ASSERT_EQ(status, AMEDIA_ERROR_END_OF_STREAM);
                    ASSERT_TRUE((info.flags & SAMPLE_FLAG_END_OF_STREAM) != 0);
                    trackReachedEos[trackIndex] = true;
                    trackEosCount++;
                    break;
                }
                ASSERT_TRUE((info.flags & SAMPLE_FLAG_END_OF_STREAM) == 0);
                readerTimestamps[trackIndex].push_back(info.presentationTimeUs);
                sampleReader->advanceTrack(trackIndex);
            } while (info.presentationTimeUs < chunkEndTimeUs);
        }
        chunkEndTimeUs += chunkDurationUs;
    }

    for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
        LOG(DEBUG) << "Track " << trackIndex << ", comparing "
                   << readerTimestamps[trackIndex].size() << " samples.";
        ASSERT_EQ(readerTimestamps[trackIndex].size(), mExtractorTimestamps[trackIndex].size());
        for (size_t sampleIndex = 0; sampleIndex < readerTimestamps[trackIndex].size();
             sampleIndex++) {
            ASSERT_EQ(readerTimestamps[trackIndex][sampleIndex],
                      mExtractorTimestamps[trackIndex][sampleIndex]);
        }
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
