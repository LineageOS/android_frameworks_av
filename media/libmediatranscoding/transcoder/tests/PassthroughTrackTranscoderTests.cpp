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

// Unit Test for PassthroughTrackTranscoder

// #define LOG_NDEBUG 0
#define LOG_TAG "PassthroughTrackTranscoderTests"

#include <android-base/logging.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/NdkMediaExtractor.h>
#include <media/PassthroughTrackTranscoder.h>
#include <openssl/md5.h>

#include <vector>

#include "TranscoderTestUtils.h"

namespace android {

class PassthroughTrackTranscoderTests : public ::testing::Test {
public:
    PassthroughTrackTranscoderTests() { LOG(DEBUG) << "PassthroughTrackTranscoderTests created"; }

    void SetUp() override { LOG(DEBUG) << "PassthroughTrackTranscoderTests set up"; }

    void initSourceAndExtractor() {
        const char* sourcePath =
                "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

        mExtractor = AMediaExtractor_new();
        ASSERT_NE(mExtractor, nullptr);

        mSourceFd = open(sourcePath, O_RDONLY);
        ASSERT_GT(mSourceFd, 0);

        mSourceFileSize = lseek(mSourceFd, 0, SEEK_END);
        lseek(mSourceFd, 0, SEEK_SET);

        media_status_t status =
                AMediaExtractor_setDataSourceFd(mExtractor, mSourceFd, 0, mSourceFileSize);
        ASSERT_EQ(status, AMEDIA_OK);

        const size_t trackCount = AMediaExtractor_getTrackCount(mExtractor);
        for (size_t trackIndex = 0; trackIndex < trackCount; trackIndex++) {
            AMediaFormat* trackFormat = AMediaExtractor_getTrackFormat(mExtractor, trackIndex);
            ASSERT_NE(trackFormat, nullptr);

            const char* mime = nullptr;
            AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);
            ASSERT_NE(mime, nullptr);

            if (strncmp(mime, "audio/", 6) == 0) {
                mTrackIndex = trackIndex;
                AMediaExtractor_selectTrack(mExtractor, trackIndex);
                break;
            }

            AMediaFormat_delete(trackFormat);
        }
    }

    void TearDown() override {
        LOG(DEBUG) << "PassthroughTrackTranscoderTests tear down";
        if (mExtractor != nullptr) {
            AMediaExtractor_delete(mExtractor);
            mExtractor = nullptr;
        }
        if (mSourceFd > 0) {
            close(mSourceFd);
            mSourceFd = -1;
        }
    }

    ~PassthroughTrackTranscoderTests() {
        LOG(DEBUG) << "PassthroughTrackTranscoderTests destroyed";
    }

    int mSourceFd = -1;
    size_t mSourceFileSize;
    int mTrackIndex;
    AMediaExtractor* mExtractor = nullptr;
};

/** Helper class for comparing sample data using checksums. */
class SampleID {
public:
    SampleID(const uint8_t* sampleData, ssize_t sampleSize) : mSize{sampleSize} {
        MD5_CTX md5Ctx;
        MD5_Init(&md5Ctx);
        MD5_Update(&md5Ctx, sampleData, sampleSize);
        MD5_Final(mChecksum, &md5Ctx);
    }

    bool operator==(const SampleID& rhs) const {
        return mSize == rhs.mSize && memcmp(mChecksum, rhs.mChecksum, MD5_DIGEST_LENGTH) == 0;
    }

    uint8_t mChecksum[MD5_DIGEST_LENGTH];
    ssize_t mSize;
};

/**
 * Tests that the output samples of PassthroughTrackTranscoder are identical to the source samples
 * and in correct order.
 */
TEST_F(PassthroughTrackTranscoderTests, SampleEquality) {
    LOG(DEBUG) << "Testing SampleEquality";

    ssize_t bufferSize = 1024;
    auto buffer = std::make_unique<uint8_t[]>(bufferSize);

    initSourceAndExtractor();

    // Loop through all samples of a track and store size and checksums.
    std::vector<SampleID> sampleChecksums;

    int64_t sampleTime = AMediaExtractor_getSampleTime(mExtractor);
    while (sampleTime != -1) {
        if (AMediaExtractor_getSampleTrackIndex(mExtractor) == mTrackIndex) {
            ssize_t sampleSize = AMediaExtractor_getSampleSize(mExtractor);
            if (bufferSize < sampleSize) {
                bufferSize = sampleSize;
                buffer = std::make_unique<uint8_t[]>(bufferSize);
            }

            ssize_t bytesRead =
                    AMediaExtractor_readSampleData(mExtractor, buffer.get(), bufferSize);
            ASSERT_EQ(bytesRead, sampleSize);

            SampleID sampleId{buffer.get(), sampleSize};
            sampleChecksums.push_back(sampleId);
        }

        AMediaExtractor_advance(mExtractor);
        sampleTime = AMediaExtractor_getSampleTime(mExtractor);
    }

    // Create and start the transcoder.
    auto callback = std::make_shared<TestTrackTranscoderCallback>();
    PassthroughTrackTranscoder transcoder{callback};

    std::shared_ptr<MediaSampleReader> mediaSampleReader =
            MediaSampleReaderNDK::createFromFd(mSourceFd, 0, mSourceFileSize);
    EXPECT_NE(mediaSampleReader, nullptr);

    EXPECT_EQ(mediaSampleReader->selectTrack(mTrackIndex), AMEDIA_OK);
    EXPECT_EQ(transcoder.configure(mediaSampleReader, mTrackIndex, nullptr /* destinationFormat */),
              AMEDIA_OK);
    ASSERT_TRUE(transcoder.start());

    // Pull transcoder's output samples and compare against input checksums.
    bool eos = false;
    uint64_t sampleCount = 0;
    transcoder.setSampleConsumer(
            [&sampleCount, &sampleChecksums, &eos](const std::shared_ptr<MediaSample>& sample) {
                ASSERT_NE(sample, nullptr);
                EXPECT_FALSE(eos);

                if (sample->info.flags & SAMPLE_FLAG_END_OF_STREAM) {
                    eos = true;
                } else {
                    SampleID sampleId{sample->buffer, static_cast<ssize_t>(sample->info.size)};
                    EXPECT_TRUE(sampleId == sampleChecksums[sampleCount]);
                    ++sampleCount;
                }
            });

    callback->waitUntilFinished();
    EXPECT_EQ(sampleCount, sampleChecksums.size());
}

/** Class for testing PassthroughTrackTranscoder's built in buffer pool. */
class BufferPoolTests : public ::testing::Test {
public:
    static constexpr int kMaxBuffers = 5;

    void SetUp() override {
        LOG(DEBUG) << "BufferPoolTests set up";
        mBufferPool = std::make_shared<PassthroughTrackTranscoder::BufferPool>(kMaxBuffers);
    }

    void TearDown() override {
        LOG(DEBUG) << "BufferPoolTests tear down";
        mBufferPool.reset();
    }

    std::shared_ptr<PassthroughTrackTranscoder::BufferPool> mBufferPool;
};

TEST_F(BufferPoolTests, BufferReuse) {
    LOG(DEBUG) << "Testing BufferReuse";

    uint8_t* buffer1 = mBufferPool->getBufferWithSize(10);
    EXPECT_NE(buffer1, nullptr);

    uint8_t* buffer2 = mBufferPool->getBufferWithSize(10);
    EXPECT_NE(buffer2, nullptr);
    EXPECT_NE(buffer2, buffer1);

    mBufferPool->returnBuffer(buffer1);

    uint8_t* buffer3 = mBufferPool->getBufferWithSize(10);
    EXPECT_NE(buffer3, nullptr);
    EXPECT_NE(buffer3, buffer2);
    EXPECT_EQ(buffer3, buffer1);

    mBufferPool->returnBuffer(buffer2);

    uint8_t* buffer4 = mBufferPool->getBufferWithSize(10);
    EXPECT_NE(buffer4, nullptr);
    EXPECT_NE(buffer4, buffer1);
    EXPECT_EQ(buffer4, buffer2);
}

TEST_F(BufferPoolTests, SmallestAvailableBuffer) {
    LOG(DEBUG) << "Testing SmallestAvailableBuffer";

    uint8_t* buffer1 = mBufferPool->getBufferWithSize(10);
    EXPECT_NE(buffer1, nullptr);

    uint8_t* buffer2 = mBufferPool->getBufferWithSize(15);
    EXPECT_NE(buffer2, nullptr);
    EXPECT_NE(buffer2, buffer1);

    uint8_t* buffer3 = mBufferPool->getBufferWithSize(20);
    EXPECT_NE(buffer3, nullptr);
    EXPECT_NE(buffer3, buffer1);
    EXPECT_NE(buffer3, buffer2);

    mBufferPool->returnBuffer(buffer1);
    mBufferPool->returnBuffer(buffer2);
    mBufferPool->returnBuffer(buffer3);

    uint8_t* buffer4 = mBufferPool->getBufferWithSize(11);
    EXPECT_NE(buffer4, nullptr);
    EXPECT_EQ(buffer4, buffer2);

    uint8_t* buffer5 = mBufferPool->getBufferWithSize(11);
    EXPECT_NE(buffer5, nullptr);
    EXPECT_EQ(buffer5, buffer3);
}

TEST_F(BufferPoolTests, AddAfterAbort) {
    LOG(DEBUG) << "Testing AddAfterAbort";

    uint8_t* buffer1 = mBufferPool->getBufferWithSize(10);
    EXPECT_NE(buffer1, nullptr);
    mBufferPool->returnBuffer(buffer1);

    mBufferPool->abort();
    uint8_t* buffer2 = mBufferPool->getBufferWithSize(10);
    EXPECT_EQ(buffer2, nullptr);
}

TEST_F(BufferPoolTests, MaximumBuffers) {
    LOG(DEBUG) << "Testing MaximumBuffers";

    static constexpr size_t kBufferBaseSize = 10;
    std::unordered_map<uint8_t*, size_t> addressSizeMap;

    // Get kMaxBuffers * 2 new buffers with increasing size.
    // (Note: Once kMaxBuffers have been allocated, the pool will delete old buffers to accommodate
    // new ones making the deleted buffers free to be reused by the system's heap memory allocator.
    // So we cannot test that each new pointer is unique here.)
    for (int i = 0; i < kMaxBuffers * 2; i++) {
        size_t size = kBufferBaseSize + i;
        uint8_t* buffer = mBufferPool->getBufferWithSize(size);
        EXPECT_NE(buffer, nullptr);
        addressSizeMap[buffer] = size;
        mBufferPool->returnBuffer(buffer);
    }

    // Verify that the pool now contains the kMaxBuffers largest buffers allocated above and that
    // the buffer of matching size is returned.
    for (int i = kMaxBuffers; i < kMaxBuffers * 2; i++) {
        size_t size = kBufferBaseSize + i;
        uint8_t* buffer = mBufferPool->getBufferWithSize(size);
        EXPECT_NE(buffer, nullptr);

        auto it = addressSizeMap.find(buffer);
        ASSERT_NE(it, addressSizeMap.end());
        EXPECT_EQ(it->second, size);
        mBufferPool->returnBuffer(buffer);
    }
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
