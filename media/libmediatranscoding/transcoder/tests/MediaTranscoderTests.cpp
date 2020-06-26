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

// Unit Test for MediaTranscoder

// #define LOG_NDEBUG 0
#define LOG_TAG "MediaTranscoderTests"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>

namespace android {

#define DEFINE_FORMAT_VALUE_EQUAL_FUNC(_type, _typeName)                                  \
    static bool equal##_typeName(const char* key, AMediaFormat* src, AMediaFormat* dst) { \
        _type srcVal, dstVal;                                                             \
        bool srcPresent = AMediaFormat_get##_typeName(src, key, &srcVal);                 \
        bool dstPresent = AMediaFormat_get##_typeName(dst, key, &dstVal);                 \
        return (srcPresent == dstPresent) && (!srcPresent || (srcVal == dstVal));         \
    }

DEFINE_FORMAT_VALUE_EQUAL_FUNC(int64_t, Int64);
DEFINE_FORMAT_VALUE_EQUAL_FUNC(int32_t, Int32);

struct FormatVerifierEntry {
    const char* key;
    std::function<bool(const char*, AMediaFormat*, AMediaFormat*)> equal;
};

static const FormatVerifierEntry kFieldsToPreserve[] = {
        {AMEDIAFORMAT_KEY_DURATION, equalInt64},       {AMEDIAFORMAT_KEY_WIDTH, equalInt32},
        {AMEDIAFORMAT_KEY_HEIGHT, equalInt32},         {AMEDIAFORMAT_KEY_FRAME_RATE, equalInt32},
        {AMEDIAFORMAT_KEY_FRAME_COUNT, equalInt32},    {AMEDIAFORMAT_KEY_DISPLAY_WIDTH, equalInt32},
        {AMEDIAFORMAT_KEY_DISPLAY_HEIGHT, equalInt32}, {AMEDIAFORMAT_KEY_SAR_WIDTH, equalInt32},
        {AMEDIAFORMAT_KEY_SAR_HEIGHT, equalInt32},     {AMEDIAFORMAT_KEY_ROTATION, equalInt32},
};

class TestCallbacks : public MediaTranscoder::CallbackInterface {
public:
    virtual void onFinished(const MediaTranscoder* transcoder __unused) override {
        std::unique_lock<std::mutex> lock(mMutex);
        EXPECT_FALSE(mFinished);
        mFinished = true;
        mCondition.notify_all();
    }

    virtual void onError(const MediaTranscoder* transcoder __unused,
                         media_status_t error) override {
        std::unique_lock<std::mutex> lock(mMutex);
        EXPECT_NE(error, AMEDIA_OK);
        EXPECT_FALSE(mFinished);
        mFinished = true;
        mStatus = error;
        mCondition.notify_all();
    }

    virtual void onProgressUpdate(const MediaTranscoder* transcoder __unused,
                                  int32_t progress __unused) override {}

    virtual void onCodecResourceLost(const MediaTranscoder* transcoder __unused,
                                     const std::shared_ptr<const Parcelable>& pausedState
                                             __unused) override {}

    void waitForTranscodingFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mFinished) {
            mCondition.wait(lock);
        }
    }

    media_status_t mStatus = AMEDIA_OK;

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mFinished = false;
};

// Write-only, create file if non-existent, don't overwrite existing file.
static constexpr int kOpenFlags = O_WRONLY | O_CREAT | O_EXCL;
// User R+W permission.
static constexpr int kFileMode = S_IRUSR | S_IWUSR;

class MediaTranscoderTests : public ::testing::Test {
public:
    MediaTranscoderTests() { LOG(DEBUG) << "MediaTranscoderTests created"; }
    ~MediaTranscoderTests() { LOG(DEBUG) << "MediaTranscoderTests destroyed"; }

    void SetUp() override {
        LOG(DEBUG) << "MediaTranscoderTests set up";
        mCallbacks = std::make_shared<TestCallbacks>();
    }

    void TearDown() override {
        LOG(DEBUG) << "MediaTranscoderTests tear down";
        mCallbacks.reset();
    }

    void deleteFile(const char* path) { unlink(path); }

    using FormatConfigurationCallback = std::function<AMediaFormat*(AMediaFormat*)>;
    media_status_t transcodeHelper(const char* srcPath, const char* destPath,
                                   FormatConfigurationCallback formatCallback) {
        auto transcoder = MediaTranscoder::create(mCallbacks, nullptr);
        EXPECT_NE(transcoder, nullptr);

        const int srcFd = open(srcPath, O_RDONLY);
        EXPECT_EQ(transcoder->configureSource(srcFd), AMEDIA_OK);

        std::vector<std::shared_ptr<AMediaFormat>> trackFormats = transcoder->getTrackFormats();
        EXPECT_GT(trackFormats.size(), 0);

        for (int i = 0; i < trackFormats.size(); ++i) {
            AMediaFormat* format = formatCallback(trackFormats[i].get());
            EXPECT_EQ(transcoder->configureTrackFormat(i, format), AMEDIA_OK);

            // Save original video track format for verification.
            const char* mime = nullptr;
            AMediaFormat_getString(trackFormats[i].get(), AMEDIAFORMAT_KEY_MIME, &mime);
            if (strncmp(mime, "video/", 6) == 0) {
                mSourceVideoFormat = trackFormats[i];
            }

            if (format != nullptr) {
                AMediaFormat_delete(format);
            }
        }
        deleteFile(destPath);
        const int dstFd = open(destPath, kOpenFlags, kFileMode);
        EXPECT_EQ(transcoder->configureDestination(dstFd), AMEDIA_OK);

        media_status_t startStatus = transcoder->start();
        EXPECT_EQ(startStatus, AMEDIA_OK);
        if (startStatus == AMEDIA_OK) {
            mCallbacks->waitForTranscodingFinished();
        }
        close(srcFd);
        close(dstFd);

        return mCallbacks->mStatus;
    }

    void testTranscodeVideo(const char* srcPath, const char* destPath, const char* dstMime) {
        const int32_t kBitRate = 8 * 1000 * 1000;  // 8Mbs

        EXPECT_EQ(
                transcodeHelper(
                        srcPath, destPath,
                        [dstMime](AMediaFormat* sourceFormat) {
                            AMediaFormat* format = nullptr;
                            const char* mime = nullptr;
                            AMediaFormat_getString(sourceFormat, AMEDIAFORMAT_KEY_MIME, &mime);

                            if (strncmp(mime, "video/", 6) == 0) {
                                format = AMediaFormat_new();
                                AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, kBitRate);

                                if (dstMime != nullptr) {
                                    AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, dstMime);
                                }
                            }
                            return format;
                        }),
                AMEDIA_OK);

        if (dstMime != nullptr) {
            std::vector<FormatVerifierEntry> extraVerifiers = {
                    {AMEDIAFORMAT_KEY_MIME,
                     [dstMime](const char* key, AMediaFormat* src __unused, AMediaFormat* dst) {
                         const char* mime = nullptr;
                         AMediaFormat_getString(dst, key, &mime);
                         return !strcmp(mime, dstMime);
                     }},
            };
            verifyOutputFormat(destPath, &extraVerifiers);
        } else {
            verifyOutputFormat(destPath);
        }
    }

    void verifyOutputFormat(const char* destPath,
                            const std::vector<FormatVerifierEntry>* extraVerifiers = nullptr) {
        int dstFd = open(destPath, O_RDONLY);
        EXPECT_GT(dstFd, 0);
        ssize_t fileSize = lseek(dstFd, 0, SEEK_END);
        lseek(dstFd, 0, SEEK_SET);

        std::shared_ptr<MediaSampleReader> sampleReader =
                MediaSampleReaderNDK::createFromFd(dstFd, 0, fileSize);

        std::shared_ptr<AMediaFormat> videoFormat;
        const size_t trackCount = sampleReader->getTrackCount();
        for (size_t trackIndex = 0; trackIndex < trackCount; ++trackIndex) {
            AMediaFormat* trackFormat = sampleReader->getTrackFormat(static_cast<int>(trackIndex));
            if (trackFormat != nullptr) {
                const char* mime = nullptr;
                AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);
                if (strncmp(mime, "video/", 6) == 0) {
                    LOG(INFO) << "Track # " << trackIndex << ": "
                              << AMediaFormat_toString(trackFormat);
                    videoFormat = std::shared_ptr<AMediaFormat>(trackFormat, &AMediaFormat_delete);
                    break;
                }
            }
        }

        EXPECT_NE(videoFormat, nullptr);

        LOG(INFO) << "source video format: " << AMediaFormat_toString(mSourceVideoFormat.get());
        LOG(INFO) << "transcoded video format: " << AMediaFormat_toString(videoFormat.get());

        for (int i = 0; i < (sizeof(kFieldsToPreserve) / sizeof(kFieldsToPreserve[0])); ++i) {
            EXPECT_TRUE(kFieldsToPreserve[i].equal(kFieldsToPreserve[i].key,
                                                   mSourceVideoFormat.get(), videoFormat.get()))
                    << "Failed at key " << kFieldsToPreserve[i].key;
        }

        if (extraVerifiers != nullptr) {
            for (int i = 0; i < extraVerifiers->size(); ++i) {
                const FormatVerifierEntry& entry = (*extraVerifiers)[i];
                EXPECT_TRUE(entry.equal(entry.key, mSourceVideoFormat.get(), videoFormat.get()));
            }
        }

        close(dstFd);
    }

    std::shared_ptr<TestCallbacks> mCallbacks;
    std::shared_ptr<AMediaFormat> mSourceVideoFormat;
};

TEST_F(MediaTranscoderTests, TestPassthrough) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_Passthrough.MP4";

    EXPECT_EQ(transcodeHelper(srcPath, destPath, [](AMediaFormat*) { return nullptr; }), AMEDIA_OK);

    verifyOutputFormat(destPath);
}

TEST_F(MediaTranscoderTests, TestVideoTranscode_AvcToAvc_Basic) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_VideoTranscode_AvcToAvc_Basic.MP4";
    testTranscodeVideo(srcPath, destPath, nullptr /*dstMime*/);
}

TEST_F(MediaTranscoderTests, TestVideoTranscode_HevcToAvc_Basic) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/jets_hevc_1280x720_20Mbps.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_VideoTranscode_HevcToAvc_Basic.MP4";
    testTranscodeVideo(srcPath, destPath, AMEDIA_MIMETYPE_VIDEO_AVC);
}

TEST_F(MediaTranscoderTests, TestVideoTranscode_HevcToAvc_Rotation) {
    const char* srcPath =
            "/data/local/tmp/TranscodingTestAssets/desk_hevc_1920x1080_aac_48KHz_rot90.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_VideoTranscode_HevcToAvc_Rotation.MP4";
    testTranscodeVideo(srcPath, destPath, AMEDIA_MIMETYPE_VIDEO_AVC);
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
