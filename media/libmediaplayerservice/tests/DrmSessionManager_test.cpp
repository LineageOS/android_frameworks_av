/*
 * Copyright (C) 2015 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "DrmSessionManager_test"
#include <android/binder_auto_utils.h>
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <aidl/android/media/BnResourceManagerClient.h>
#include <aidl/android/media/BnResourceManagerService.h>
#include <android/media/BnResourceManagerClient.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/ProcessInfoInterface.h>
#include <mediadrm/DrmSessionManager.h>

#include <algorithm>
#include <iostream>
#include <vector>

#include "ResourceManagerService.h"

namespace android {

using ::android::binder::Status;
using ::android::media::ResourceManagerService;
using ::ndk::ScopedAStatus;

using NdkBnResourceManagerClient = ::aidl::android::media::BnResourceManagerClient;
using NdkBnResourceManagerService = ::aidl::android::media::BnResourceManagerService;
using NdkMediaResource = ::aidl::android::media::MediaResourceParcel;
using NdkResourceManagerClient = ::aidl::android::media::IResourceManagerClient;

using FwkBnResourceManagerClient = ::android::media::BnResourceManagerClient;
using FwkMediaResource = ::android::media::MediaResourceParcel;

namespace {

struct FwkResourceManagerClientImpl : public FwkBnResourceManagerClient {
    FwkResourceManagerClientImpl(const std::shared_ptr<NdkResourceManagerClient> &client)
        : mClient(client) {
    }

    Status reclaimResource(bool* _aidl_return) override {
        mClient->reclaimResource(_aidl_return);
        return Status::ok();
    }

    Status getName(std::string* _aidl_return) override {
        mClient->getName(_aidl_return);
        return Status::ok();
    }

private:
    std::shared_ptr<NdkResourceManagerClient> mClient;
};

FwkMediaResource NdkToFwkMediaResource(const NdkMediaResource &in) {
    FwkMediaResource out{};
    out.type = static_cast<decltype(out.type)>(in.type);
    out.subType = static_cast<decltype(out.subType)>(in.subType);
    auto v(reinterpret_cast<const uint8_t *>(in.id.data()));
    out.id.assign(v, v + in.id.size());
    out.value = in.value;
    return out;
}

std::vector<FwkMediaResource> NdkToFwkMediaResourceVec(const std::vector<NdkMediaResource> &in) {
    std::vector<FwkMediaResource> out;
    for (auto e : in) {
        out.push_back(NdkToFwkMediaResource(e));
    }
    return out;
}

ScopedAStatus FwkToNdkStatus(Status err) {
    return ScopedAStatus(AStatus_fromExceptionCode(err.serviceSpecificErrorCode()));
}

struct NdkResourceManagerServiceImpl : public NdkBnResourceManagerService {
    using NdkMediaResourcePolicy = ::aidl::android::media::MediaResourcePolicyParcel;

    NdkResourceManagerServiceImpl(const sp<ResourceManagerService> &service)
        : mService(service) {}

    ScopedAStatus config(const std::vector<NdkMediaResourcePolicy>& in_policies) override {
        (void)in_policies;
        return ScopedAStatus::ok();
    }

    ScopedAStatus addResource(int32_t in_pid, int32_t in_uid, int64_t in_clientId,
            const std::shared_ptr<NdkResourceManagerClient>& in_client,
            const std::vector<NdkMediaResource>& in_resources) override {
        sp<FwkBnResourceManagerClient> client(new FwkResourceManagerClientImpl(in_client));
        std::vector<FwkMediaResource> resources(NdkToFwkMediaResourceVec(in_resources));
        auto err = mService->addResource(in_pid, in_uid, in_clientId, client, resources);
        return FwkToNdkStatus(err);
    }

    ScopedAStatus removeResource(int32_t in_pid, int64_t in_clientId,
            const std::vector<NdkMediaResource>& in_resources) override {
        std::vector<FwkMediaResource> resources(NdkToFwkMediaResourceVec(in_resources));
        auto err = mService->removeResource(in_pid, in_clientId, resources);
        return FwkToNdkStatus(err);
    }

    ScopedAStatus removeClient(int32_t in_pid, int64_t in_clientId) override{
        auto err = mService->removeClient(in_pid, in_clientId);
        return FwkToNdkStatus(err);
    }

    ScopedAStatus reclaimResource(int32_t in_callingPid,
            const std::vector<NdkMediaResource>& in_resources, bool* _aidl_return) override {
        std::vector<FwkMediaResource> resources(NdkToFwkMediaResourceVec(in_resources));
        auto err = mService->reclaimResource(in_callingPid, resources, _aidl_return);
        return FwkToNdkStatus(err);
    }

private:
    sp<ResourceManagerService> mService;
};

template <typename Impl>
std::shared_ptr<NdkResourceManagerClient> NdkImplToIface(const Impl &impl) {
    return std::static_pointer_cast<NdkResourceManagerClient>(impl);
}

}

static Vector<uint8_t> toAndroidVector(const std::vector<uint8_t> &vec) {
    Vector<uint8_t> aVec;
    for (auto b : vec) {
        aVec.push_back(b);
    }
    return aVec;
}

struct FakeProcessInfo : public ProcessInfoInterface {
    FakeProcessInfo() {}
    virtual ~FakeProcessInfo() {}

    virtual bool getPriority(int pid, int* priority) {
        // For testing, use pid as priority.
        // Lower the value higher the priority.
        *priority = pid;
        return true;
    }

    virtual bool isValidPid(int /* pid */) {
        return true;
    }

private:
    DISALLOW_EVIL_CONSTRUCTORS(FakeProcessInfo);
};

struct FakeDrm : public NdkBnResourceManagerClient {
    FakeDrm(const std::vector<uint8_t>& sessionId, const sp<DrmSessionManager>& manager)
        : mSessionId(toAndroidVector(sessionId)),
          mReclaimed(false),
          mDrmSessionManager(manager) {}

    ScopedAStatus reclaimResource(bool* _aidl_return) {
        mReclaimed = true;
        mDrmSessionManager->removeSession(mSessionId);
        *_aidl_return = true;
        return ScopedAStatus::ok();
    }

    ScopedAStatus getName(::std::string* _aidl_return) {
        String8 name("FakeDrm[");
        for (size_t i = 0; i < mSessionId.size(); ++i) {
            name.appendFormat("%02x", mSessionId[i]);
        }
        name.append("]");
        *_aidl_return = name;
        return ScopedAStatus::ok();
    }

    bool isReclaimed() const {
        return mReclaimed;
    }

    const Vector<uint8_t> mSessionId;

private:
    bool mReclaimed;
    const sp<DrmSessionManager> mDrmSessionManager;

    DISALLOW_EVIL_CONSTRUCTORS(FakeDrm);
};

struct FakeSystemCallback :
        public ResourceManagerService::SystemCallbackInterface {
    FakeSystemCallback() {}

    virtual void noteStartVideo(int /*uid*/) override {}

    virtual void noteStopVideo(int /*uid*/) override {}

    virtual void noteResetVideo() override {}

    virtual bool requestCpusetBoost(
            bool /*enable*/, const sp<IInterface> &/*client*/) override {
        return true;
    }

protected:
    virtual ~FakeSystemCallback() {}

private:

    DISALLOW_EVIL_CONSTRUCTORS(FakeSystemCallback);
};

static const int kTestPid1 = 30;
static const int kTestPid2 = 20;
static const std::vector<uint8_t> kTestSessionId1{1, 2, 3};
static const std::vector<uint8_t> kTestSessionId2{4, 5, 6, 7, 8};
static const std::vector<uint8_t> kTestSessionId3{9, 0};

class DrmSessionManagerTest : public ::testing::Test {
public:
    DrmSessionManagerTest()
        : mService(new ResourceManagerService(new FakeProcessInfo(), new FakeSystemCallback())),
          mDrmSessionManager(new DrmSessionManager(std::shared_ptr<NdkBnResourceManagerService>(new NdkResourceManagerServiceImpl(mService)))),
          mTestDrm1(new FakeDrm(kTestSessionId1, mDrmSessionManager)),
          mTestDrm2(new FakeDrm(kTestSessionId2, mDrmSessionManager)),
          mTestDrm3(new FakeDrm(kTestSessionId3, mDrmSessionManager)) {
    }

protected:
    void addSession() {
        mDrmSessionManager->addSession(kTestPid1, NdkImplToIface(mTestDrm1), mTestDrm1->mSessionId);
        mDrmSessionManager->addSession(kTestPid2, NdkImplToIface(mTestDrm2), mTestDrm2->mSessionId);
        mDrmSessionManager->addSession(kTestPid2, NdkImplToIface(mTestDrm3), mTestDrm3->mSessionId);
    }

    sp<ResourceManagerService> mService;
    sp<DrmSessionManager> mDrmSessionManager;
    std::shared_ptr<FakeDrm> mTestDrm1;
    std::shared_ptr<FakeDrm> mTestDrm2;
    std::shared_ptr<FakeDrm> mTestDrm3;
};

TEST_F(DrmSessionManagerTest, addSession) {
    addSession();

    EXPECT_EQ(3u, mDrmSessionManager->getSessionCount());
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm1->mSessionId));
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm2->mSessionId));
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm3->mSessionId));
}

TEST_F(DrmSessionManagerTest, useSession) {
    addSession();

    mDrmSessionManager->useSession(mTestDrm1->mSessionId);
    mDrmSessionManager->useSession(mTestDrm3->mSessionId);

    EXPECT_EQ(3u, mDrmSessionManager->getSessionCount());
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm1->mSessionId));
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm2->mSessionId));
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm3->mSessionId));
}

TEST_F(DrmSessionManagerTest, removeSession) {
    addSession();

    mDrmSessionManager->removeSession(mTestDrm2->mSessionId);

    EXPECT_EQ(2u, mDrmSessionManager->getSessionCount());
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm1->mSessionId));
    EXPECT_FALSE(mDrmSessionManager->containsSession(mTestDrm2->mSessionId));
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm3->mSessionId));
}

TEST_F(DrmSessionManagerTest, reclaimSession) {
    EXPECT_FALSE(mDrmSessionManager->reclaimSession(kTestPid1));
    addSession();

    // calling pid priority is too low
    EXPECT_FALSE(mDrmSessionManager->reclaimSession(50));

    EXPECT_TRUE(mDrmSessionManager->reclaimSession(10));
    EXPECT_TRUE(mTestDrm1->isReclaimed());

    // add a session from a higher priority process.
    const std::vector<uint8_t> sid{1, 3, 5};
    std::shared_ptr<FakeDrm> drm(new FakeDrm(sid, mDrmSessionManager));
    mDrmSessionManager->addSession(15, NdkImplToIface(drm), drm->mSessionId);

    // make sure mTestDrm2 is reclaimed next instead of mTestDrm3
    mDrmSessionManager->useSession(mTestDrm3->mSessionId);
    EXPECT_TRUE(mDrmSessionManager->reclaimSession(18));
    EXPECT_TRUE(mTestDrm2->isReclaimed());

    EXPECT_EQ(2u, mDrmSessionManager->getSessionCount());
    EXPECT_FALSE(mDrmSessionManager->containsSession(mTestDrm1->mSessionId));
    EXPECT_FALSE(mDrmSessionManager->containsSession(mTestDrm2->mSessionId));
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm3->mSessionId));
    EXPECT_TRUE(mDrmSessionManager->containsSession(drm->mSessionId));
}

TEST_F(DrmSessionManagerTest, reclaimAfterUse) {
    // nothing to reclaim yet
    EXPECT_FALSE(mDrmSessionManager->reclaimSession(kTestPid1));
    EXPECT_FALSE(mDrmSessionManager->reclaimSession(kTestPid2));

    // add sessions from same pid
    mDrmSessionManager->addSession(kTestPid2, NdkImplToIface(mTestDrm1), mTestDrm1->mSessionId);
    mDrmSessionManager->addSession(kTestPid2, NdkImplToIface(mTestDrm2), mTestDrm2->mSessionId);
    mDrmSessionManager->addSession(kTestPid2, NdkImplToIface(mTestDrm3), mTestDrm3->mSessionId);

    // use some but not all sessions
    mDrmSessionManager->useSession(mTestDrm1->mSessionId);
    mDrmSessionManager->useSession(mTestDrm1->mSessionId);
    mDrmSessionManager->useSession(mTestDrm2->mSessionId);

    // calling pid priority is too low
    int lowPriorityPid = kTestPid2 + 1;
    EXPECT_FALSE(mDrmSessionManager->reclaimSession(lowPriorityPid));

    // unused session is reclaimed first
    int highPriorityPid = kTestPid2 - 1;
    EXPECT_TRUE(mDrmSessionManager->reclaimSession(highPriorityPid));
    EXPECT_FALSE(mTestDrm1->isReclaimed());
    EXPECT_FALSE(mTestDrm2->isReclaimed());
    EXPECT_TRUE(mTestDrm3->isReclaimed());
    mDrmSessionManager->removeSession(mTestDrm3->mSessionId);

    // less-used session is reclaimed next
    EXPECT_TRUE(mDrmSessionManager->reclaimSession(highPriorityPid));
    EXPECT_FALSE(mTestDrm1->isReclaimed());
    EXPECT_TRUE(mTestDrm2->isReclaimed());
    EXPECT_TRUE(mTestDrm3->isReclaimed());

    // most-used session still open
    EXPECT_EQ(1u, mDrmSessionManager->getSessionCount());
    EXPECT_TRUE(mDrmSessionManager->containsSession(mTestDrm1->mSessionId));
    EXPECT_FALSE(mDrmSessionManager->containsSession(mTestDrm2->mSessionId));
    EXPECT_FALSE(mDrmSessionManager->containsSession(mTestDrm3->mSessionId));
}

} // namespace android
