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
#include <media/MediaTranscoder.h>

namespace android {

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

static const char* SOURCE_PATH =
        "/data/local/tmp/TranscoderTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

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
    media_status_t transcodeHelper(const char* destPath,
                                   FormatConfigurationCallback formatCallback) {
        auto transcoder = MediaTranscoder::create(mCallbacks, nullptr);
        EXPECT_NE(transcoder, nullptr);

        EXPECT_EQ(transcoder->configureSource(SOURCE_PATH), AMEDIA_OK);

        std::vector<std::shared_ptr<AMediaFormat>> trackFormats = transcoder->getTrackFormats();
        EXPECT_GT(trackFormats.size(), 0);

        for (int i = 0; i < trackFormats.size(); ++i) {
            AMediaFormat* format = formatCallback(trackFormats[i].get());
            EXPECT_EQ(transcoder->configureTrackFormat(i, format), AMEDIA_OK);
            if (format != nullptr) {
                AMediaFormat_delete(format);
            }
        }
        deleteFile(destPath);
        EXPECT_EQ(transcoder->configureDestination(destPath), AMEDIA_OK);

        media_status_t startStatus = transcoder->start();
        EXPECT_EQ(startStatus, AMEDIA_OK);
        if (startStatus == AMEDIA_OK) {
            mCallbacks->waitForTranscodingFinished();
        }

        return mCallbacks->mStatus;
    }

    std::shared_ptr<TestCallbacks> mCallbacks;
};

TEST_F(MediaTranscoderTests, TestPassthrough) {
    const char* destPath = "/data/local/tmp/MediaTranscoder_Passthrough.MP4";

    EXPECT_EQ(transcodeHelper(destPath, [](AMediaFormat*) { return nullptr; }), AMEDIA_OK);

    // TODO: Validate output file
}

TEST_F(MediaTranscoderTests, TestBasicVideoTranscode) {
    const char* destPath = "/data/local/tmp/MediaTranscoder_VideoTranscode.MP4";

    EXPECT_EQ(transcodeHelper(
                      destPath,
                      [](AMediaFormat* sourceFormat) {
                          AMediaFormat* format = nullptr;
                          const char* mime = nullptr;
                          AMediaFormat_getString(sourceFormat, AMEDIAFORMAT_KEY_MIME, &mime);

                          if (strncmp(mime, "video/", 6) == 0) {
                              const int32_t kBitRate = 8 * 1000 * 1000;  // 8Mbs
                              format = AMediaFormat_new();
                              AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, kBitRate);
                          }
                          return format;
                      }),
              AMEDIA_OK);

    // TODO: Validate output file
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
