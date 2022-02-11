/******************************************************************************
 *
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */

#include <ServiceLog.h>
#include <aidl/android/media/BnResourceManagerClient.h>
#include <media/MediaResource.h>
#include <media/MediaResourcePolicy.h>
#include <media/stagefright/ProcessInfoInterface.h>
#include <media/stagefright/foundation/ADebug.h>
#include "ResourceManagerService.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace android;
using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::BnResourceManagerClient;
using ::aidl::android::media::IResourceManagerClient;
using ::aidl::android::media::IResourceManagerService;
using MedResType = aidl::android::media::MediaResourceType;
using MedResSubType = aidl::android::media::MediaResourceSubType;

const size_t kMaxStringLength = 100;
const int32_t kMaxServiceLog = 100;
const int32_t kMinServiceLog = 1;
const int32_t kMinResourceType = 0;
const int32_t kMaxResourceType = 10;
const int32_t kMinThreadPairs = 1;
const int32_t kMaxThreadPairs = 3;

const string kPolicyType[] = {IResourceManagerService::kPolicySupportsMultipleSecureCodecs,
                              IResourceManagerService::kPolicySupportsSecureWithNonSecureCodec};

struct resourceThreadArgs {
    int32_t pid;
    int32_t uid;
    int64_t testClientId;
    shared_ptr<ResourceManagerService> service;
    shared_ptr<IResourceManagerClient> testClient;
    vector<MediaResourceParcel> mediaResource;
};

static int64_t getId(const shared_ptr<IResourceManagerClient>& client) {
    return (int64_t)client.get();
}

struct TestProcessInfo : public ProcessInfoInterface {
    TestProcessInfo() {}
    virtual ~TestProcessInfo() {}

    virtual bool getPriority(int pid, int* priority) {
        // For testing, use pid as priority.
        // Lower the value higher the priority.
        *priority = pid;
        return true;
    }

    virtual bool isValidPid(int /* pid */) { return true; }
    virtual bool overrideProcessInfo(int /* pid */, int /*procState*/, int /*oomScore*/) {
        return true;
    }
    virtual void removeProcessInfoOverride(int /* pid */) { return; }

   private:
    DISALLOW_EVIL_CONSTRUCTORS(TestProcessInfo);
};

struct TestSystemCallback : public ResourceManagerService::SystemCallbackInterface {
    TestSystemCallback() : mLastEvent({EventType::INVALID, 0}), mEventCount(0) {}

    enum EventType {
        INVALID = -1,
        VIDEO_ON = 0,
        VIDEO_OFF = 1,
        VIDEO_RESET = 2,
        CPUSET_ENABLE = 3,
        CPUSET_DISABLE = 4,
    };

    struct EventEntry {
        EventType type;
        int arg;
    };

    virtual void noteStartVideo(int uid) override {
        mLastEvent = {EventType::VIDEO_ON, uid};
        ++mEventCount;
    }

    virtual void noteStopVideo(int uid) override {
        mLastEvent = {EventType::VIDEO_OFF, uid};
        ++mEventCount;
    }

    virtual void noteResetVideo() override {
        mLastEvent = {EventType::VIDEO_RESET, 0};
        ++mEventCount;
    }

    virtual bool requestCpusetBoost(bool enable) override {
        mLastEvent = {enable ? EventType::CPUSET_ENABLE : EventType::CPUSET_DISABLE, 0};
        ++mEventCount;
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
    TestClient(int pid, const shared_ptr<ResourceManagerService>& service)
        : mReclaimed(false), mPid(pid), mService(service) {}

    Status reclaimResource(bool* aidlReturn) override {
        mService->removeClient(mPid, getId(ref<TestClient>()));
        mReclaimed = true;
        *aidlReturn = true;
        return Status::ok();
    }

    Status getName(string* aidlReturn) override {
        *aidlReturn = "test_client";
        return Status::ok();
    }

    virtual ~TestClient() {}

   private:
    bool mReclaimed;
    int mPid;
    shared_ptr<ResourceManagerService> mService;
    DISALLOW_EVIL_CONSTRUCTORS(TestClient);
};

class ResourceManagerServiceFuzzer {
   public:
    ResourceManagerServiceFuzzer() = default;
    ~ResourceManagerServiceFuzzer() {
        mService = nullptr;
        delete mFuzzedDataProvider;
    }
    void process(const uint8_t* data, size_t size);

   private:
    void setConfig();
    void setResources();
    void setServiceLog();

    static void* addResource(void* arg) {
        resourceThreadArgs* tArgs = (resourceThreadArgs*)arg;
        if (tArgs) {
            (tArgs->service)
                ->addResource(tArgs->pid, tArgs->uid, tArgs->testClientId, tArgs->testClient,
                              tArgs->mediaResource);
        }
        return nullptr;
    }

    static void* removeResource(void* arg) {
        resourceThreadArgs* tArgs = (resourceThreadArgs*)arg;
        if (tArgs) {
            bool result;
            (tArgs->service)->markClientForPendingRemoval(tArgs->pid, tArgs->testClientId);
            (tArgs->service)->removeResource(tArgs->pid, tArgs->testClientId, tArgs->mediaResource);
            (tArgs->service)->reclaimResource(tArgs->pid, tArgs->mediaResource, &result);
            (tArgs->service)->removeClient(tArgs->pid, tArgs->testClientId);
            (tArgs->service)->overridePid(tArgs->pid, tArgs->pid - 1);
        }
        return nullptr;
    }

    shared_ptr<ResourceManagerService> mService =
        ::ndk::SharedRefBase::make<ResourceManagerService>(new TestProcessInfo(),
                                                           new TestSystemCallback());
    FuzzedDataProvider* mFuzzedDataProvider = nullptr;
};

void ResourceManagerServiceFuzzer::process(const uint8_t* data, size_t size) {
    mFuzzedDataProvider = new FuzzedDataProvider(data, size);
    setConfig();
    setResources();
    setServiceLog();
}

void ResourceManagerServiceFuzzer::setConfig() {
    bool policyTypeIndex = mFuzzedDataProvider->ConsumeBool();
    string policyValue = mFuzzedDataProvider->ConsumeRandomLengthString(kMaxStringLength);
    if (mService) {
        vector<MediaResourcePolicyParcel> policies;
        policies.push_back(MediaResourcePolicy(kPolicyType[policyTypeIndex], policyValue));
        mService->config(policies);
    }
}

void ResourceManagerServiceFuzzer::setResources() {
    if (!mService) {
        return;
    }
    size_t numThreadPairs =
        mFuzzedDataProvider->ConsumeIntegralInRange<size_t>(kMinThreadPairs, kMaxThreadPairs);
    // Make even number of threads
    size_t numThreads = numThreadPairs * 2;
    resourceThreadArgs threadArgs[numThreadPairs];
    vector<MediaResourceParcel> mediaResource[numThreadPairs];
    pthread_t pt[numThreads];
    for (int k = 0; k < numThreadPairs; ++k) {
        threadArgs[k].pid = mFuzzedDataProvider->ConsumeIntegral<int32_t>();
        threadArgs[k].uid = mFuzzedDataProvider->ConsumeIntegral<int32_t>();
        int32_t mediaResourceType = mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(
            kMinResourceType, kMaxResourceType);
        int32_t mediaResourceSubType = mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(
            kMinResourceType, kMaxResourceType);
        uint64_t mediaResourceValue = mFuzzedDataProvider->ConsumeIntegral<uint64_t>();
        threadArgs[k].service = mService;
        shared_ptr<IResourceManagerClient> testClient =
                ::ndk::SharedRefBase::make<TestClient>(threadArgs[k].pid, mService);
        threadArgs[k].testClient = testClient;
        threadArgs[k].testClientId = getId(testClient);
        mediaResource[k].push_back(MediaResource(static_cast<MedResType>(mediaResourceType),
                                                 static_cast<MedResSubType>(mediaResourceSubType),
                                                 mediaResourceValue));
        threadArgs[k].mediaResource = mediaResource[k];
        pthread_create(&pt[2 * k], nullptr, addResource, &threadArgs[k]);
        pthread_create(&pt[2 * k + 1], nullptr, removeResource, &threadArgs[k]);
    }

    for (int i = 0; i < numThreads; ++i) {
        pthread_join(pt[i], nullptr);
    }

    // No resource was added with pid = 0
    int32_t pidZero = 0;
    shared_ptr<IResourceManagerClient> testClient =
        ::ndk::SharedRefBase::make<TestClient>(pidZero, mService);
    int32_t mediaResourceType =
        mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(kMinResourceType, kMaxResourceType);
    int32_t mediaResourceSubType =
        mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(kMinResourceType, kMaxResourceType);
    uint64_t mediaResourceValue = mFuzzedDataProvider->ConsumeIntegral<uint64_t>();
    vector<MediaResourceParcel> mediaRes;
    mediaRes.push_back(MediaResource(static_cast<MedResType>(mediaResourceType),
                                     static_cast<MedResSubType>(mediaResourceSubType),
                                     mediaResourceValue));
    bool result;
    mService->reclaimResource(pidZero, mediaRes, &result);
    mService->removeResource(pidZero, getId(testClient), mediaRes);
    mService->removeClient(pidZero, getId(testClient));
}

void ResourceManagerServiceFuzzer::setServiceLog() {
    size_t maxNum =
        mFuzzedDataProvider->ConsumeIntegralInRange<int32_t>(kMinServiceLog, kMaxServiceLog);
    sp<ServiceLog> serviceLog = new ServiceLog(maxNum);
    if (serviceLog) {
        serviceLog->add(String8("log"));
        serviceLog->toString();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }
    ResourceManagerServiceFuzzer* rmFuzzer = new ResourceManagerServiceFuzzer();
    if (!rmFuzzer) {
        return 0;
    }
    rmFuzzer->process(data, size);
    delete rmFuzzer;
    return 0;
}
