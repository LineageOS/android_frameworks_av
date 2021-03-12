/*
 * Copyright (C) 2021 The Android Open Source Project
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

// Unit Test for HDR to SDR transcoding.

// #define LOG_NDEBUG 0
#define LOG_TAG "HdrTranscodeTests"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>

#include "TranscoderTestUtils.h"

namespace android {

// Debug property to load the sample HDR plugin.
static const std::string kLoadSamplePluginProperty{"debug.codec2.force-sample-plugin"};

// SDR color standard, from MediaFormat.
static constexpr int COLOR_STANDARD_BT709 = 1;

class HdrTranscodeTests : public ::testing::Test {
public:
    HdrTranscodeTests() { LOG(DEBUG) << "HdrTranscodeTests created"; }
    ~HdrTranscodeTests() { LOG(DEBUG) << "HdrTranscodeTests destroyed"; }

    void SetUp() override {
        LOG(DEBUG) << "HdrTranscodeTests set up";
        mCallbacks = std::make_shared<TestTranscoderCallbacks>();
        ABinderProcess_startThreadPool();
    }

    void TearDown() override {
        LOG(DEBUG) << "HdrTranscodeTests tear down";
        mCallbacks.reset();
    }

    media_status_t transcode(const char* srcFile, const char* dstFile, const char* dstMime) {
        std::string srcPath = mSrcDir + srcFile;
        std::string dstPath = mDstDir + dstFile;

        auto transcoder = MediaTranscoder::create(mCallbacks, -1 /*heartBeatIntervalUs*/);
        EXPECT_NE(transcoder, nullptr);

        const int srcFd = open(srcPath.c_str(), O_RDONLY);
        EXPECT_EQ(transcoder->configureSource(srcFd), AMEDIA_OK);
        close(srcFd);

        std::vector<std::shared_ptr<AMediaFormat>> trackFormats = transcoder->getTrackFormats();
        EXPECT_GT(trackFormats.size(), 0);

        for (int i = 0; i < trackFormats.size(); ++i) {
            std::shared_ptr<AMediaFormat> format;
            const char* mime = nullptr;

            AMediaFormat_getString(trackFormats[i].get(), AMEDIAFORMAT_KEY_MIME, &mime);
            if (strncmp(mime, "video/", 6) == 0) {
                format = std::shared_ptr<AMediaFormat>(AMediaFormat_new(), &AMediaFormat_delete);
                AMediaFormat_setString(format.get(), AMEDIAFORMAT_KEY_MIME, dstMime);
            }

            media_status_t status = transcoder->configureTrackFormat(i, format.get());
            if (status != AMEDIA_OK) {
                return status;
            }
        }

        const int dstFd = open(dstPath.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        EXPECT_EQ(transcoder->configureDestination(dstFd), AMEDIA_OK);
        close(dstFd);

        media_status_t startStatus = transcoder->start();
        EXPECT_EQ(startStatus, AMEDIA_OK);
        if (startStatus != AMEDIA_OK) {
            return startStatus;
        }

        mCallbacks->waitForTranscodingFinished();
        return mCallbacks->mStatus;
    }

    media_status_t validateOutput(const char* dstFile __unused) {
        std::string path = mDstDir + dstFile;

        auto format = TranscoderTestUtils::GetVideoFormat(path);
        EXPECT_NE(format.get(), nullptr);

        int32_t value;
        EXPECT_TRUE(AMediaFormat_getInt32(format.get(), AMEDIAFORMAT_KEY_COLOR_STANDARD, &value));
        EXPECT_EQ(value, COLOR_STANDARD_BT709);

        EXPECT_TRUE(AMediaFormat_getInt32(format.get(), AMEDIAFORMAT_KEY_COLOR_TRANSFER, &value));
        EXPECT_EQ(value, COLOR_TRANSFER_SDR_VIDEO);

        // TODO(lnilsson): Validate decoded pixels as well. Either by comparing similarity against a
        //  known good "golden master" corresponding SDR video, or by looking at the histogram.
        return AMEDIA_OK;
    }

    bool hdrToSdrConversionSupported(const char* hdrFile) {
        std::string srcPath = mSrcDir + hdrFile;

        std::string mime;
        auto format = TranscoderTestUtils::GetVideoFormat(srcPath, &mime);
        EXPECT_NE(format.get(), nullptr);

        AMediaCodec* decoder = AMediaCodec_createDecoderByType(mime.c_str());
        EXPECT_NE(decoder, nullptr);

        AMediaFormat_setInt32(format.get(), TBD_AMEDIACODEC_PARAMETER_KEY_COLOR_TRANSFER_REQUEST,
                              COLOR_TRANSFER_SDR_VIDEO);

        EXPECT_EQ(AMediaCodec_configure(decoder, format.get(), nullptr /*surface*/,
                                        nullptr /*crypto*/, 0 /*flags*/),
                  AMEDIA_OK);

        AMediaFormat* inputFormat = AMediaCodec_getInputFormat(decoder);
        EXPECT_NE(inputFormat, nullptr);

        int32_t transferFunc;
        bool conversionSupported =
                AMediaFormat_getInt32(inputFormat,
                                      TBD_AMEDIACODEC_PARAMETER_KEY_COLOR_TRANSFER_REQUEST,
                                      &transferFunc) &&
                transferFunc == COLOR_TRANSFER_SDR_VIDEO;

        AMediaFormat_delete(inputFormat);
        AMediaCodec_delete(decoder);

        return conversionSupported;
    }

    std::shared_ptr<TestTranscoderCallbacks> mCallbacks;
    const std::string mSrcDir{"/data/local/tmp/TranscodingTestAssets/"};
    const std::string mDstDir{"/data/local/tmp/"};
};

TEST_F(HdrTranscodeTests, TestHdrSamplePluginTranscode) {
    const char* hdrFile = "video_1280x720_hevc_hdr10_static_3mbps.mp4";
    const char* dstFile = "video_1280x720_hevc_hdr10_static_3mbps_transcoded.mp4";

    EXPECT_TRUE(android::base::SetProperty(kLoadSamplePluginProperty, "true"));

    if (hdrToSdrConversionSupported(hdrFile)) {
        LOG(INFO) << "HDR -> SDR supported, validating output..";
        EXPECT_EQ(transcode(hdrFile, dstFile, AMEDIA_MIMETYPE_VIDEO_AVC), AMEDIA_OK);
        EXPECT_EQ(validateOutput(dstFile), AMEDIA_OK);
    } else {
        LOG(INFO) << "HDR -> SDR *not* supported";
        EXPECT_EQ(transcode(hdrFile, dstFile, AMEDIA_MIMETYPE_VIDEO_AVC), AMEDIA_ERROR_UNSUPPORTED);
    }

    EXPECT_TRUE(android::base::SetProperty(kLoadSamplePluginProperty, "false"));
}
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
