/*
 * Copyright 2015 The Android Open Source Project
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

#include <gtest/gtest.h>

#include "ResourceManagerService.h"
#include <aidl/android/media/BnResourceManagerClient.h>
#include <media/MediaResource.h>
#include <media/MediaResourcePolicy.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/ProcessInfoInterface.h>

namespace android {

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::BnResourceManagerClient;
using ::aidl::android::media::IResourceManagerService;
using ::aidl::android::media::IResourceManagerClient;
using ::aidl::android::media::MediaResourceParcel;

static int64_t getId(const std::shared_ptr<IResourceManagerClient>& client) {
    return (int64_t) client.get();
}

struct TestProcessInfo : public ProcessInfoInterface {
    TestProcessInfo() {}
    virtual ~TestProcessInfo() {}

    virtual bool getPriority(int pid, int *priority) {
        // For testing, use pid as priority.
        // Lower the value higher the priority.
        *priority = pid;
        return true;
    }

    virtual bool isValidPid(int /* pid */) {
        return true;
    }

    virtual bool overrideProcessInfo(
            int /* pid */, int /* procState */, int /* oomScore */) {
        return true;
    }

    virtual void removeProcessInfoOverride(int /* pid */) {
    }

private:
    DISALLOW_EVIL_CONSTRUCTORS(TestProcessInfo);
};

struct TestSystemCallback :
        public ResourceManagerService::SystemCallbackInterface {
    TestSystemCallback() :
        mLastEvent({EventType::INVALID, 0}), mEventCount(0) {}

    enum EventType {
        INVALID          = -1,
        VIDEO_ON         = 0,
        VIDEO_OFF        = 1,
        VIDEO_RESET      = 2,
        CPUSET_ENABLE    = 3,
        CPUSET_DISABLE   = 4,
    };

    struct EventEntry {
        EventType type;
        int arg;
    };

    virtual void noteStartVideo(int uid) override {
        mLastEvent = {EventType::VIDEO_ON, uid};
        mEventCount++;
    }

    virtual void noteStopVideo(int uid) override {
        mLastEvent = {EventType::VIDEO_OFF, uid};
        mEventCount++;
    }

    virtual void noteResetVideo() override {
        mLastEvent = {EventType::VIDEO_RESET, 0};
        mEventCount++;
    }

    virtual bool requestCpusetBoost(bool enable) override {
        mLastEvent = {enable ? EventType::CPUSET_ENABLE : EventType::CPUSET_DISABLE, 0};
        mEventCount++;
        return true;
    }

    size_t eventCount() { return mEventCount; }
    EventType lastEventType() { return mLastEvent.type; }
    EventEntry lastEvent() { return mLastEvent; }

protected:
    virtual ~TestSystemCallback() {}

private:
    EventEntry mLastEvent;
    size_t mEventCount;

    DISALLOW_EVIL_CONSTRUCTORS(TestSystemCallback);
};


struct TestClient : public BnResourceManagerClient {
    TestClient(int pid, const std::shared_ptr<ResourceManagerService> &service)
        : mReclaimed(false), mPid(pid), mService(service) {}

    Status reclaimResource(bool* _aidl_return) override {
        mService->removeClient(mPid, getId(ref<TestClient>()));
        mReclaimed = true;
        *_aidl_return = true;
        return Status::ok();
    }

    Status getName(::std::string* _aidl_return) override {
        *_aidl_return = "test_client";
        return Status::ok();
    }

    bool reclaimed() const {
        return mReclaimed;
    }

    void reset() {
        mReclaimed = false;
    }

    virtual ~TestClient() {}

private:
    bool mReclaimed;
    int mPid;
    std::shared_ptr<ResourceManagerService> mService;
    DISALLOW_EVIL_CONSTRUCTORS(TestClient);
};

static const int kTestPid1 = 30;
static const int kTestUid1 = 1010;

static const int kTestPid2 = 20;
static const int kTestUid2 = 1011;

static const int kLowPriorityPid = 40;
static const int kMidPriorityPid = 25;
static const int kHighPriorityPid = 10;

using EventType = TestSystemCallback::EventType;
using EventEntry = TestSystemCallback::EventEntry;
bool operator== (const EventEntry& lhs, const EventEntry& rhs) {
    return lhs.type == rhs.type && lhs.arg == rhs.arg;
}

#define CHECK_STATUS_TRUE(condition) \
    EXPECT_TRUE((condition).isOk() && (result))

#define CHECK_STATUS_FALSE(condition) \
    EXPECT_TRUE((condition).isOk() && !(result))

class ResourceManagerServiceTestBase : public ::testing::Test {
public:
    ResourceManagerServiceTestBase()
        : mSystemCB(new TestSystemCallback()),
          mService(::ndk::SharedRefBase::make<ResourceManagerService>(
                  new TestProcessInfo, mSystemCB)),
          mTestClient1(::ndk::SharedRefBase::make<TestClient>(kTestPid1, mService)),
          mTestClient2(::ndk::SharedRefBase::make<TestClient>(kTestPid2, mService)),
          mTestClient3(::ndk::SharedRefBase::make<TestClient>(kTestPid2, mService)) {
    }

    sp<TestSystemCallback> mSystemCB;
    std::shared_ptr<ResourceManagerService> mService;
    std::shared_ptr<IResourceManagerClient> mTestClient1;
    std::shared_ptr<IResourceManagerClient> mTestClient2;
    std::shared_ptr<IResourceManagerClient> mTestClient3;

protected:
    static bool isEqualResources(const std::vector<MediaResourceParcel> &resources1,
            const ResourceList &resources2) {
        // convert resource1 to ResourceList
        ResourceList r1;
        for (size_t i = 0; i < resources1.size(); ++i) {
            const auto &res = resources1[i];
            const auto resType = std::tuple(res.type, res.subType, res.id);
            r1[resType] = res;
        }
        return r1 == resources2;
    }

    static void expectEqResourceInfo(const ResourceInfo &info,
            int uid,
            std::shared_ptr<IResourceManagerClient> client,
            const std::vector<MediaResourceParcel> &resources) {
        EXPECT_EQ(uid, info.uid);
        EXPECT_EQ(client, info.client);
        EXPECT_TRUE(isEqualResources(resources, info.resources));
    }
};

} // namespace android
