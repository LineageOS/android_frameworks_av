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
#include <android/binder_process.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>

#include "TranscoderTestUtils.h"

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
        mCallbacks = std::make_shared<TestTranscoderCallbacks>();
        ABinderProcess_startThreadPool();
    }

    void TearDown() override {
        LOG(DEBUG) << "MediaTranscoderTests tear down";
        mCallbacks.reset();
    }

    void deleteFile(const char* path) { unlink(path); }

    float getFileSizeDiffPercent(const char* path1, const char* path2, bool absolute = false) {
        struct stat s1, s2;
        EXPECT_EQ(stat(path1, &s1), 0);
        EXPECT_EQ(stat(path2, &s2), 0);

        int64_t diff = s2.st_size - s1.st_size;
        if (absolute && diff < 0) diff = -diff;

        return (float)diff * 100.0f / s1.st_size;
    }

    typedef enum {
        kRunToCompletion,
        kCheckHeartBeat,
        kCancelAfterProgress,
        kCancelAfterStart,
        kPauseAfterProgress,
        kPauseAfterStart,
    } TranscodeExecutionControl;

    using FormatConfigurationCallback = std::function<AMediaFormat*(AMediaFormat*)>;
    media_status_t transcodeHelper(const char* srcPath, const char* destPath,
                                   FormatConfigurationCallback formatCallback,
                                   TranscodeExecutionControl executionControl = kRunToCompletion,
                                   int64_t heartBeatIntervalUs = -1) {
        auto transcoder = MediaTranscoder::create(mCallbacks, heartBeatIntervalUs);
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
            std::shared_ptr<ndk::ScopedAParcel> pausedState;

            switch (executionControl) {
            case kCancelAfterProgress:
                mCallbacks->waitForProgressMade();
                FALLTHROUGH_INTENDED;
            case kCancelAfterStart:
                transcoder->cancel();
                break;
            case kPauseAfterProgress:
                mCallbacks->waitForProgressMade();
                FALLTHROUGH_INTENDED;
            case kPauseAfterStart:
                transcoder->pause(&pausedState);
                break;
            case kCheckHeartBeat: {
                mCallbacks->waitForProgressMade();
                auto startTime = std::chrono::system_clock::now();
                mCallbacks->waitForTranscodingFinished();
                auto finishTime = std::chrono::system_clock::now();
                int32_t expectedCount =
                        (finishTime - startTime) / std::chrono::microseconds(heartBeatIntervalUs);
                // Here we relax the expected count by 1, in case the last heart-beat just
                // missed the window, other than that the count should be exact.
                EXPECT_GE(mCallbacks->mHeartBeatCount, expectedCount - 1);
                break;
            }
            case kRunToCompletion:
            default:
                mCallbacks->waitForTranscodingFinished();
                break;
            }
        }
        close(srcFd);
        close(dstFd);

        return mCallbacks->mStatus;
    }

    void testTranscodeVideo(const char* srcPath, const char* destPath, const char* dstMime,
                            int32_t bitrate = 0) {
        EXPECT_EQ(transcodeHelper(srcPath, destPath,
                                  [dstMime, bitrate](AMediaFormat* sourceFormat) {
                                      AMediaFormat* format = nullptr;
                                      const char* mime = nullptr;
                                      AMediaFormat_getString(sourceFormat, AMEDIAFORMAT_KEY_MIME,
                                                             &mime);

                                      if (strncmp(mime, "video/", 6) == 0 &&
                                          (bitrate > 0 || dstMime != nullptr)) {
                                          format = AMediaFormat_new();

                                          if (bitrate > 0) {
                                              AMediaFormat_setInt32(
                                                      format, AMEDIAFORMAT_KEY_BIT_RATE, bitrate);
                                          }

                                          if (dstMime != nullptr) {
                                              AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME,
                                                                     dstMime);
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
        ASSERT_NE(sampleReader, nullptr);

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
        if (videoFormat != nullptr) {
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
                    EXPECT_TRUE(
                            entry.equal(entry.key, mSourceVideoFormat.get(), videoFormat.get()));
                }
            }
        }

        close(dstFd);
    }

    std::shared_ptr<TestTranscoderCallbacks> mCallbacks;
    std::shared_ptr<AMediaFormat> mSourceVideoFormat;
};

TEST_F(MediaTranscoderTests, TestPassthrough) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_Passthrough.MP4";
    testTranscodeVideo(srcPath, destPath, nullptr);
}

TEST_F(MediaTranscoderTests, TestVideoTranscode_AvcToAvc_Basic) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_VideoTranscode_AvcToAvc_Basic.MP4";
    testTranscodeVideo(srcPath, destPath, AMEDIA_MIMETYPE_VIDEO_AVC);
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

TEST_F(MediaTranscoderTests, TestVideoTranscode_4K) {
#if defined(__i386__) || defined(__x86_64__)
    LOG(WARNING) << "Skipping 4K test on x86 as SW encoder does not support 4K.";
    return;
#else
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/Video_4K_HEVC_10Frames_Audio.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_4K.MP4";
    testTranscodeVideo(srcPath, destPath, AMEDIA_MIMETYPE_VIDEO_AVC);
#endif
}

TEST_F(MediaTranscoderTests, TestPreserveBitrate) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_PreserveBitrate.MP4";
    testTranscodeVideo(srcPath, destPath, AMEDIA_MIMETYPE_VIDEO_AVC);

    // Require maximum of 25% difference in file size.
    // TODO(b/174678336): Find a better test asset to tighten the threshold.
    EXPECT_LT(getFileSizeDiffPercent(srcPath, destPath, true /* absolute*/), 25);
}

TEST_F(MediaTranscoderTests, TestCustomBitrate) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";
    const char* destPath1 = "/data/local/tmp/MediaTranscoder_CustomBitrate_2Mbps.MP4";
    const char* destPath2 = "/data/local/tmp/MediaTranscoder_CustomBitrate_8Mbps.MP4";
    testTranscodeVideo(srcPath, destPath1, AMEDIA_MIMETYPE_VIDEO_AVC, 2 * 1000 * 1000);
    mCallbacks = std::make_shared<TestTranscoderCallbacks>();
    testTranscodeVideo(srcPath, destPath2, AMEDIA_MIMETYPE_VIDEO_AVC, 8 * 1000 * 1000);

    // The source asset is very short and heavily compressed from the beginning so don't expect the
    // requested bitrate to be exactly matched. However the 8mbps should at least be larger.
    // TODO(b/174678336): Find a better test asset to tighten the threshold.
    EXPECT_GT(getFileSizeDiffPercent(destPath1, destPath2), 10);
}

static AMediaFormat* getAVCVideoFormat(AMediaFormat* sourceFormat) {
    AMediaFormat* format = nullptr;
    const char* mime = nullptr;
    AMediaFormat_getString(sourceFormat, AMEDIAFORMAT_KEY_MIME, &mime);

    if (strncmp(mime, "video/", 6) == 0) {
        format = AMediaFormat_new();
        AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, AMEDIA_MIMETYPE_VIDEO_AVC);
    }

    return format;
}

TEST_F(MediaTranscoderTests, TestCancelAfterProgress) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_Cancel.MP4";

    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(transcodeHelper(srcPath, destPath, getAVCVideoFormat, kCancelAfterProgress),
                  AMEDIA_OK);
        EXPECT_FALSE(mCallbacks->mFinished);
        mCallbacks = std::make_shared<TestTranscoderCallbacks>();
    }
}

TEST_F(MediaTranscoderTests, TestCancelAfterStart) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_Cancel.MP4";

    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(transcodeHelper(srcPath, destPath, getAVCVideoFormat, kCancelAfterStart),
                  AMEDIA_OK);
        EXPECT_FALSE(mCallbacks->mFinished);
        mCallbacks = std::make_shared<TestTranscoderCallbacks>();
    }
}

TEST_F(MediaTranscoderTests, TestPauseAfterProgress) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_Pause.MP4";

    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(transcodeHelper(srcPath, destPath, getAVCVideoFormat, kPauseAfterProgress),
                  AMEDIA_OK);
        EXPECT_FALSE(mCallbacks->mFinished);
        mCallbacks = std::make_shared<TestTranscoderCallbacks>();
    }
}

TEST_F(MediaTranscoderTests, TestPauseAfterStart) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_Pause.MP4";

    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(transcodeHelper(srcPath, destPath, getAVCVideoFormat, kPauseAfterStart),
                  AMEDIA_OK);
        EXPECT_FALSE(mCallbacks->mFinished);
        mCallbacks = std::make_shared<TestTranscoderCallbacks>();
    }
}

TEST_F(MediaTranscoderTests, TestHeartBeat) {
    const char* srcPath = "/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4";
    const char* destPath = "/data/local/tmp/MediaTranscoder_HeartBeat.MP4";

    // Use a shorter value of 500ms than the default 1000ms to get more heart beat for testing.
    const int64_t heartBeatIntervalUs = 500000LL;
    EXPECT_EQ(transcodeHelper(srcPath, destPath, getAVCVideoFormat, kCheckHeartBeat,
                              heartBeatIntervalUs),
              AMEDIA_OK);
    EXPECT_TRUE(mCallbacks->mFinished);
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
