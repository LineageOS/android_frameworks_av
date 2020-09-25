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

constexpr int64_t kPaddingUs = 400000;
constexpr int32_t kBitRate = 8 * 1000 * 1000;  // 8Mbs

constexpr const char* kLongSrcPath = "/data/local/tmp/TranscodingTestAssets/longtest_15s.mp4";

constexpr const char* kResourcePolicyTestActivity =
        "/com.android.tests.transcoding.ResourcePolicyTestActivity";

#define OUTPATH(name) "/data/local/tmp/MediaTranscodingService_" #name ".MP4"

class MediaTranscodingServiceResourceTest : public MediaTranscodingServiceTestBase {
public:
    MediaTranscodingServiceResourceTest() { ALOGI("MediaTranscodingServiceResourceTest created"); }

    virtual ~MediaTranscodingServiceResourceTest() {
        ALOGI("MediaTranscodingServiceResourceTest destroyed");
    }
};

/**
 * Basic testing for handling resource lost.
 *
 * This test starts a transcoding job (that's somewhat long and takes several seconds),
 * then launches an activity that allocates video codec instances until it hits insufficient
 * resource error. Because the activity is running in foreground,
 * ResourceManager would reclaim codecs from transcoding service which should
 * cause the job to be paused. The activity will hold the codecs for a few seconds
 * before releasing them, and the transcoding service should be able to resume
 * and complete the job.
 */
TEST_F(MediaTranscodingServiceResourceTest, TestResourceLost) {
    ALOGD("TestResourceLost starting...");

    EXPECT_TRUE(ShellHelper::RunCmd("input keyevent KEYCODE_WAKEUP"));
    EXPECT_TRUE(ShellHelper::RunCmd("wm dismiss-keyguard"));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));

    registerMultipleClients();

    const char* srcPath0 = kLongSrcPath;
    const char* dstPath0 = OUTPATH(TestPauseResumeMultiClients_Client0);
    deleteFile(dstPath0);

    ALOGD("Moving app A to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kTestActivityName));

    // Submit job to Client1.
    ALOGD("Submitting job to client1 (app A) ...");
    EXPECT_TRUE(mClient1->submit(0, srcPath0, dstPath0, TranscodingJobPriority::kNormal, kBitRate));

    // Client1's job should start immediately.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    // Launch ResourcePolicyTestActivity, which will try to allocate up to 32
    // instances, which should trigger insufficient resources on most devices.
    // (Note that it's possible that the device supports a very high number of
    // resource instances, in which case we'll simply require that the job completes.)
    ALOGD("Launch ResourcePolicyTestActivity...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kResourcePolicyTestActivity));

    // The basic requirement is that the job should complete. Wait for finish
    // event to come and pop up all events received.
    std::list<EventTracker::Event> events;
    EXPECT_TRUE(mClient1->waitForSpecificEventAndPop(EventTracker::Finished(CLIENT(1), 0), &events,
                                                     15000000));

    // If there is only 1 event, it must be finish (otherwise waitForSpecificEventAndPop
    // woudldn't pop up anything), and we're ok.
    //
    // TODO: If there is only 1 event (finish), and no pause/resume happened, we need
    // to verify that the ResourcePolicyTestActivity actually was able to allocate
    // all 32 instances without hitting insufficient resources. Otherwise, it could
    // be that ResourceManager was not able to reclaim codecs from the transcoding
    // service at all, which means the resource management is broken.
    if (events.size() > 1) {
        EXPECT_TRUE(events.size() >= 3);
        size_t i = 0;
        for (auto& event : events) {
            if (i == 0) {
                EXPECT_EQ(event, EventTracker::Pause(CLIENT(1), 0));
            } else if (i == events.size() - 2) {
                EXPECT_EQ(event, EventTracker::Resume(CLIENT(1), 0));
            } else if (i == events.size() - 1) {
                EXPECT_EQ(event, EventTracker::Finished(CLIENT(1), 0));
            } else {
                EXPECT_TRUE(event == EventTracker::Pause(CLIENT(1), 0) ||
                            event == EventTracker::Resume(CLIENT(1), 0));
            }
            i++;
        }
    }

    unregisterMultipleClients();

    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));
}

}  // namespace media
}  // namespace android
