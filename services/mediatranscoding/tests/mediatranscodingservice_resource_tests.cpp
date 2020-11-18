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
#define LOG_TAG "MediaTranscodingServiceResourceTest"

#include <aidl/android/media/BnResourceManagerClient.h>
#include <aidl/android/media/IResourceManagerService.h>
#include <binder/ActivityManager.h>

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

/*
 * The OOM score we're going to ask ResourceManager to use for our native transcoding
 * service. ResourceManager issues reclaims based on these scores. It gets the scores
 * from ActivityManagerService, which doesn't track native services. The values of the
 * OOM scores are defined in:
 * frameworks/base/services/core/java/com/android/server/am/ProcessList.java
 * We use SERVICE_ADJ which is lower priority than an app possibly visible to the
 * user, but higher priority than a cached app (which could be killed without disruption
 * to the user).
 */
constexpr static int32_t SERVICE_ADJ = 500;

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnResourceManagerClient;
using aidl::android::media::IResourceManagerService;

/*
 * Placeholder ResourceManagerClient for registering process info override
 * with the IResourceManagerService. This is only used as a token by the service
 * to get notifications about binder death, not used for reclaiming resources.
 */
struct ResourceManagerClient : public BnResourceManagerClient {
    explicit ResourceManagerClient() = default;

    Status reclaimResource(bool* _aidl_return) override {
        *_aidl_return = false;
        return Status::ok();
    }

    Status getName(::std::string* _aidl_return) override {
        _aidl_return->clear();
        return Status::ok();
    }

    virtual ~ResourceManagerClient() = default;
};

static std::shared_ptr<ResourceManagerClient> gResourceManagerClient =
        ::ndk::SharedRefBase::make<ResourceManagerClient>();

void TranscodingHelper_setProcessInfoOverride(int32_t procState, int32_t oomScore) {
    ::ndk::SpAIBinder binder(AServiceManager_getService("media.resource_manager"));
    std::shared_ptr<IResourceManagerService> service = IResourceManagerService::fromBinder(binder);
    if (service == nullptr) {
        ALOGE("Failed to get IResourceManagerService");
        return;
    }
    Status status =
            service->overrideProcessInfo(gResourceManagerClient, getpid(), procState, oomScore);
    if (!status.isOk()) {
        ALOGW("Failed to setProcessInfoOverride.");
    }
}

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
 * This test starts a transcoding session (that's somewhat long and takes several seconds),
 * then launches an activity that allocates video codec instances until it hits insufficient
 * resource error. Because the activity is running in foreground,
 * ResourceManager would reclaim codecs from transcoding service which should
 * cause the session to be paused. The activity will hold the codecs for a few seconds
 * before releasing them, and the transcoding service should be able to resume
 * and complete the session.
 *
 * Note that this test must run as root. We need to simulate submitting a request for a
 * client {uid,pid} running at lower priority. As a cmd line test, it's not easy to get the
 * pid of a living app, so we use our own {uid,pid} to submit. However, since we're a native
 * process, RM doesn't have our proc info and the reclaim will fail. So we need to use
 * RM's setProcessInfoOverride to override our proc info, which requires permission (unless root).
 */
TEST_F(MediaTranscodingServiceResourceTest, TestResourceLost) {
    ALOGD("TestResourceLost starting..., pid %d", ::getpid());

    // We're going to submit the request using our own {uid,pid}. Since we're a native
    // process, RM doesn't have our proc info and the reclaim will fail. So we need to use
    // RM's setProcessInfoOverride to override our proc info.
    TranscodingHelper_setProcessInfoOverride(ActivityManager::PROCESS_STATE_SERVICE, SERVICE_ADJ);

    EXPECT_TRUE(ShellHelper::RunCmd("input keyevent KEYCODE_WAKEUP"));
    EXPECT_TRUE(ShellHelper::RunCmd("wm dismiss-keyguard"));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));

    registerMultipleClients();

    const char* srcPath0 = kLongSrcPath;
    const char* dstPath0 = OUTPATH(TestPauseResumeMultiClients_Client0);
    deleteFile(dstPath0);

    ALOGD("Moving app A to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kTestActivityName));

    // Submit session to Client1.
    ALOGD("Submitting session to client1 (app A) ...");
    EXPECT_TRUE(mClient1->submit(0, srcPath0, dstPath0, TranscodingSessionPriority::kNormal,
                                 kBitRate, ::getpid(), ::getuid()));

    // Client1's session should start immediately.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    // Launch ResourcePolicyTestActivity, which will try to allocate up to 32
    // instances, which should trigger insufficient resources on most devices.
    // (Note that it's possible that the device supports a very high number of
    // resource instances, in which case we'll simply require that the session completes.)
    ALOGD("Launch ResourcePolicyTestActivity...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kResourcePolicyTestActivity));

    // The basic requirement is that the session should complete. Wait for finish
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
