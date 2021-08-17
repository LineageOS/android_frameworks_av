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
#include <openssl/md5.h>
#include <utils/Timers.h>

#include <cmath>
#include <mutex>
#include <thread>

// TODO(b/153453392): Test more asset types (frame reordering?).

namespace android {

#define SEC_TO_USEC(s) ((s)*1000 * 1000)

/** Helper class for comparing sample data using checksums. */
class Sample {
public:
    Sample(uint32_t flags, int64_t timestamp, size_t size, const uint8_t* buffer)
          : mFlags{flags}, mTimestamp{timestamp}, mSize{size} {
        initChecksum(buffer);
    }

    Sample(AMediaExtractor* extractor) {
        mFlags = AMediaExtractor_getSampleFlags(extractor);
        mTimestamp = AMediaExtractor_getSampleTime(extractor);
        mSize = static_cast<size_t>(AMediaExtractor_getSampleSize(extractor));

        auto buffer = std::make_unique<uint8_t[]>(mSize);
        AMediaExtractor_readSampleData(extractor, buffer.get(), mSize);

        initChecksum(buffer.get());
    }

    void initChecksum(const uint8_t* buffer) {
        MD5_CTX md5Ctx;
        MD5_Init(&md5Ctx);
        MD5_Update(&md5Ctx, buffer, mSize);
        MD5_Final(mChecksum, &md5Ctx);
    }

    bool operator==(const Sample& rhs) const {
        return mSize == rhs.mSize && mFlags == rhs.mFlags && mTimestamp == rhs.mTimestamp &&
               memcmp(mChecksum, rhs.mChecksum, MD5_DIGEST_LENGTH) == 0;
    }

    uint32_t mFlags;
    int64_t mTimestamp;
    size_t mSize;
    uint8_t mChecksum[MD5_DIGEST_LENGTH];
};

/** Constant for selecting all samples. */
static constexpr int SAMPLE_COUNT_ALL = -1;

/**
 * Utility class to test different sample access patterns combined with sequential or parallel
 * sample access modes.
 */
class SampleAccessTester {
public:
    SampleAccessTester(int sourceFd, size_t fileSize) {
        mSampleReader = MediaSampleReaderNDK::createFromFd(sourceFd, 0, fileSize);
        EXPECT_TRUE(mSampleReader);

        mTrackCount = mSampleReader->getTrackCount();

        for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            EXPECT_EQ(mSampleReader->selectTrack(trackIndex), AMEDIA_OK);
        }

        mSamples.resize(mTrackCount);
        mTrackThreads.resize(mTrackCount);
    }

    void getSampleInfo(int trackIndex) {
        MediaSampleInfo info;
        media_status_t status = mSampleReader->getSampleInfoForTrack(trackIndex, &info);
        EXPECT_EQ(status, AMEDIA_OK);
    }

    void readSamplesAsync(int trackIndex, int sampleCount) {
        mTrackThreads[trackIndex] = std::thread{[this, trackIndex, sampleCount] {
            int samplesRead = 0;
            MediaSampleInfo info;
            while (samplesRead < sampleCount || sampleCount == SAMPLE_COUNT_ALL) {
                media_status_t status = mSampleReader->getSampleInfoForTrack(trackIndex, &info);
                if (status != AMEDIA_OK) {
                    EXPECT_EQ(status, AMEDIA_ERROR_END_OF_STREAM);
                    EXPECT_TRUE((info.flags & SAMPLE_FLAG_END_OF_STREAM) != 0);
                    break;
                }
                ASSERT_TRUE((info.flags & SAMPLE_FLAG_END_OF_STREAM) == 0);

                auto buffer = std::make_unique<uint8_t[]>(info.size);
                status = mSampleReader->readSampleDataForTrack(trackIndex, buffer.get(), info.size);
                EXPECT_EQ(status, AMEDIA_OK);

                mSampleMutex.lock();
                const uint8_t* bufferPtr = buffer.get();
                mSamples[trackIndex].emplace_back(info.flags, info.presentationTimeUs, info.size,
                                                  bufferPtr);
                mSampleMutex.unlock();
                ++samplesRead;
            }
        }};
    }

    void readSamplesAsync(int sampleCount) {
        for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            readSamplesAsync(trackIndex, sampleCount);
        }
    }

    void waitForTrack(int trackIndex) {
        ASSERT_TRUE(mTrackThreads[trackIndex].joinable());
        mTrackThreads[trackIndex].join();
    }

    void waitForTracks() {
        for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            waitForTrack(trackIndex);
        }
    }

    void setEnforceSequentialAccess(bool enforce) {
        media_status_t status = mSampleReader->setEnforceSequentialAccess(enforce);
        EXPECT_EQ(status, AMEDIA_OK);
    }

    std::vector<std::vector<Sample>>& getSamples() { return mSamples; }

    std::shared_ptr<MediaSampleReader> mSampleReader;
    size_t mTrackCount;
    std::mutex mSampleMutex;
    std::vector<std::thread> mTrackThreads;
    std::vector<std::vector<Sample>> mSamples;
};

class MediaSampleReaderNDKTests : public ::testing::Test {
public:
    MediaSampleReaderNDKTests() { LOG(DEBUG) << "MediaSampleReaderNDKTests created"; }

    void SetUp() override {
        LOG(DEBUG) << "MediaSampleReaderNDKTests set up";

        // Need to start a thread pool to prevent AMediaExtractor binder calls from starving
        // (b/155663561).
        ABinderProcess_startThreadPool();

        const char* sourcePath =
                "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

        mSourceFd = open(sourcePath, O_RDONLY);
        ASSERT_GT(mSourceFd, 0);

        mFileSize = lseek(mSourceFd, 0, SEEK_END);
        lseek(mSourceFd, 0, SEEK_SET);

        mExtractor = AMediaExtractor_new();
        ASSERT_NE(mExtractor, nullptr);

        media_status_t status =
                AMediaExtractor_setDataSourceFd(mExtractor, mSourceFd, 0, mFileSize);
        ASSERT_EQ(status, AMEDIA_OK);

        mTrackCount = AMediaExtractor_getTrackCount(mExtractor);
        for (size_t trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            AMediaExtractor_selectTrack(mExtractor, trackIndex);
        }
    }

    void initExtractorSamples() {
        if (mExtractorSamples.size() == mTrackCount) return;

        // Save sample information, per track, as reported by the extractor.
        mExtractorSamples.resize(mTrackCount);
        do {
            const int trackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
            mExtractorSamples[trackIndex].emplace_back(mExtractor);
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

    void compareSamples(std::vector<std::vector<Sample>>& readerSamples) {
        initExtractorSamples();
        EXPECT_EQ(readerSamples.size(), mTrackCount);

        for (int trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            LOG(DEBUG) << "Track " << trackIndex << ", comparing "
                       << readerSamples[trackIndex].size() << " samples.";
            EXPECT_EQ(readerSamples[trackIndex].size(), mExtractorSamples[trackIndex].size());
            for (size_t sampleIndex = 0; sampleIndex < readerSamples[trackIndex].size();
                 sampleIndex++) {
                EXPECT_EQ(readerSamples[trackIndex][sampleIndex],
                          mExtractorSamples[trackIndex][sampleIndex]);
            }
        }
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
    std::vector<std::vector<Sample>> mExtractorSamples;
};

/** Reads all samples from all tracks in parallel. */
TEST_F(MediaSampleReaderNDKTests, TestParallelSampleAccess) {
    LOG(DEBUG) << "TestParallelSampleAccess Starts";

    SampleAccessTester tester{mSourceFd, mFileSize};
    tester.readSamplesAsync(SAMPLE_COUNT_ALL);
    tester.waitForTracks();
    compareSamples(tester.getSamples());
}

/** Reads all samples except the last in each track, before finishing. */
TEST_F(MediaSampleReaderNDKTests, TestLastSampleBeforeEOS) {
    LOG(DEBUG) << "TestLastSampleBeforeEOS Starts";
    initExtractorSamples();

    {  // Natural track order
        SampleAccessTester tester{mSourceFd, mFileSize};
        for (int trackIndex = 0; trackIndex < mTrackCount; ++trackIndex) {
            tester.readSamplesAsync(trackIndex, mExtractorSamples[trackIndex].size() - 1);
        }
        tester.waitForTracks();
        for (int trackIndex = 0; trackIndex < mTrackCount; ++trackIndex) {
            tester.readSamplesAsync(trackIndex, SAMPLE_COUNT_ALL);
            tester.waitForTrack(trackIndex);
        }
        compareSamples(tester.getSamples());
    }

    {  // Reverse track order
        SampleAccessTester tester{mSourceFd, mFileSize};
        for (int trackIndex = mTrackCount - 1; trackIndex >= 0; --trackIndex) {
            tester.readSamplesAsync(trackIndex, mExtractorSamples[trackIndex].size() - 1);
        }
        tester.waitForTracks();
        for (int trackIndex = mTrackCount - 1; trackIndex >= 0; --trackIndex) {
            tester.readSamplesAsync(trackIndex, SAMPLE_COUNT_ALL);
            tester.waitForTrack(trackIndex);
        }
        compareSamples(tester.getSamples());
    }
}

/** Reads all samples from all tracks sequentially. */
TEST_F(MediaSampleReaderNDKTests, TestSequentialSampleAccess) {
    LOG(DEBUG) << "TestSequentialSampleAccess Starts";

    SampleAccessTester tester{mSourceFd, mFileSize};
    tester.setEnforceSequentialAccess(true);
    tester.readSamplesAsync(SAMPLE_COUNT_ALL);
    tester.waitForTracks();
    compareSamples(tester.getSamples());
}

/** Reads all samples from one track in parallel mode before switching to sequential mode. */
TEST_F(MediaSampleReaderNDKTests, TestMixedSampleAccessTrackEOS) {
    LOG(DEBUG) << "TestMixedSampleAccessTrackEOS Starts";

    for (int readSampleInfoFlag = 0; readSampleInfoFlag <= 1; readSampleInfoFlag++) {
        for (int trackIndToEOS = 0; trackIndToEOS < mTrackCount; ++trackIndToEOS) {
            LOG(DEBUG) << "Testing EOS of track " << trackIndToEOS;

            SampleAccessTester tester{mSourceFd, mFileSize};

            // If the flag is set, read sample info from a different track before draining the track
            // under test to force the reader to save the extractor position.
            if (readSampleInfoFlag) {
                tester.getSampleInfo((trackIndToEOS + 1) % mTrackCount);
            }

            // Read all samples from one track before enabling sequential access
            tester.readSamplesAsync(trackIndToEOS, SAMPLE_COUNT_ALL);
            tester.waitForTrack(trackIndToEOS);
            tester.setEnforceSequentialAccess(true);

            for (int trackIndex = 0; trackIndex < mTrackCount; ++trackIndex) {
                if (trackIndex == trackIndToEOS) continue;

                tester.readSamplesAsync(trackIndex, SAMPLE_COUNT_ALL);
                tester.waitForTrack(trackIndex);
            }

            compareSamples(tester.getSamples());
        }
    }
}

/**
 * Reads different combinations of sample counts from all tracks in parallel mode before switching
 * to sequential mode and reading the rest of the samples.
 */
TEST_F(MediaSampleReaderNDKTests, TestMixedSampleAccess) {
    LOG(DEBUG) << "TestMixedSampleAccess Starts";
    initExtractorSamples();

    for (int trackIndToTest = 0; trackIndToTest < mTrackCount; ++trackIndToTest) {
        for (int sampleCount = 0; sampleCount <= (mExtractorSamples[trackIndToTest].size() + 1);
             ++sampleCount) {
            SampleAccessTester tester{mSourceFd, mFileSize};

            for (int trackIndex = 0; trackIndex < mTrackCount; ++trackIndex) {
                if (trackIndex == trackIndToTest) {
                    tester.readSamplesAsync(trackIndex, sampleCount);
                } else {
                    tester.readSamplesAsync(trackIndex, mExtractorSamples[trackIndex].size() / 2);
                }
            }

            tester.waitForTracks();
            tester.setEnforceSequentialAccess(true);

            tester.readSamplesAsync(SAMPLE_COUNT_ALL);
            tester.waitForTracks();

            compareSamples(tester.getSamples());
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
