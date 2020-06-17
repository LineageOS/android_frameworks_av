/*
 * Copyright (C) 2019 The Android Open Source Project
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

// Unit Test for MediaTranscodingService.

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaTranscodingServiceRealTest"

#include "MediaTranscodingServiceTestHelper.h"

/*
 * Tests media transcoding service with real transcoder.
 *
 * Uses the same test assets as the MediaTranscoder unit tests. Before running the test,
 * please make sure to push the test assets to /sdcard:
 *
 * adb push $TOP/frameworks/av/media/libmediatranscoding/transcoder/tests/assets /data/local/tmp/TranscodingTestAssets
 */
namespace android {

namespace media {

constexpr int64_t kPaddingUs = 200000;
constexpr int64_t kJobWithPaddingUs = 10000000 + kPaddingUs;

constexpr const char* kSrcPath =
        "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

class MediaTranscodingServiceRealTest : public MediaTranscodingServiceTestBase {
public:
    MediaTranscodingServiceRealTest() {}

    void deleteFile(const char* path) { unlink(path); }
};

TEST_F(MediaTranscodingServiceRealTest, TestTranscodePassthru) {
    registerMultipleClients();

    const char* dstPath = "/data/local/tmp/MediaTranscodingService_Passthru.MP4";
    deleteFile(dstPath);

    // Submit one job.
    EXPECT_TRUE(submit(mClient1, 0, kSrcPath, dstPath));

    // Wait for job to finish.
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceRealTest, TestTranscodeVideo) {
    registerMultipleClients();

    const char* dstPath = "/data/local/tmp/MediaTranscodingService_Video.MP4";
    deleteFile(dstPath);

    const int32_t kBitRate = 8 * 1000 * 1000;  // 8Mbs
    // Submit one job.
    EXPECT_TRUE(submit(mClient1, 0, kSrcPath, dstPath, TranscodingJobPriority::kNormal, kBitRate));

    // Wait for job to finish.
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));

    // TODO: verify output file format.

    unregisterMultipleClients();
}

}  // namespace media
}  // namespace android
