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

// Unit Test for TranscodingClientManager

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingClientManagerTest"

#include <aidl/android/media/BnTranscodingServiceClient.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <aidl/android/media/ITranscodingServiceClient.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <media/TranscodingClientManager.h>
#include <utils/Log.h>

namespace android {

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnTranscodingServiceClient;
using aidl::android::media::IMediaTranscodingService;
using aidl::android::media::ITranscodingServiceClient;

constexpr int32_t kInvalidClientId = -1;
constexpr int32_t kInvalidClientPid = -1;
constexpr int32_t kInvalidClientUid = -1;
constexpr const char* kInvalidClientOpPackageName = "";

constexpr int32_t kClientId = 1;
constexpr int32_t kClientPid = 2;
constexpr int32_t kClientUid = 3;
constexpr const char* kClientOpPackageName = "TestClient";

struct TestClient : public BnTranscodingServiceClient {
    TestClient(const std::shared_ptr<IMediaTranscodingService>& service) : mService(service) {
        ALOGD("TestClient Created");
    }

    Status getName(std::string* _aidl_return) override {
        *_aidl_return = "test_client";
        return Status::ok();
    }

    Status onTranscodingFinished(
            int32_t /* in_jobId */,
            const ::aidl::android::media::TranscodingResultParcel& /* in_result */) override {
        return Status::ok();
    }

    Status onTranscodingFailed(
            int32_t /* in_jobId */,
            ::aidl::android::media::TranscodingErrorCode /*in_errorCode */) override {
        return Status::ok();
    }

    Status onAwaitNumberOfJobsChanged(int32_t /* in_jobId */, int32_t /* in_oldAwaitNumber */,
                                      int32_t /* in_newAwaitNumber */) override {
        return Status::ok();
    }

    Status onProgressUpdate(int32_t /* in_jobId */, int32_t /* in_progress */) override {
        return Status::ok();
    }

    virtual ~TestClient() { ALOGI("TestClient destroyed"); };

   private:
    std::shared_ptr<IMediaTranscodingService> mService;
    TestClient(const TestClient&) = delete;
    TestClient& operator=(const TestClient&) = delete;
};

class TranscodingClientManagerTest : public ::testing::Test {
   public:
    TranscodingClientManagerTest() : mClientManager(TranscodingClientManager::getInstance()) {
        ALOGD("TranscodingClientManagerTest created");
    }

    void SetUp() override {
        ::ndk::SpAIBinder binder(AServiceManager_getService("media.transcoding"));
        mService = IMediaTranscodingService::fromBinder(binder);
        if (mService == nullptr) {
            ALOGE("Failed to connect to the media.trascoding service.");
            return;
        }

        mTestClient = ::ndk::SharedRefBase::make<TestClient>(mService);
    }

    void TearDown() override {
        ALOGI("TranscodingClientManagerTest tear down");
        mService = nullptr;
    }

    ~TranscodingClientManagerTest() { ALOGD("TranscodingClientManagerTest destroyed"); }

    TranscodingClientManager& mClientManager;
    std::shared_ptr<ITranscodingServiceClient> mTestClient = nullptr;
    std::shared_ptr<IMediaTranscodingService> mService = nullptr;
};

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientId) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    // Create a client with invalid client id.
    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client, kInvalidClientId, kClientPid, kClientUid, kClientOpPackageName);

    // Add the client to the manager and expect failure.
    status_t err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err != OK);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPid) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    // Create a client with invalid Pid.
    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client, kClientId, kInvalidClientPid, kClientUid, kClientOpPackageName);

    // Add the client to the manager and expect failure.
    status_t err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err != OK);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientUid) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    // Create a client with invalid Uid.
    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client, kClientId, kClientPid, kInvalidClientUid, kClientOpPackageName);

    // Add the client to the manager and expect failure.
    status_t err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err != OK);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPackageName) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    // Create a client with invalid packagename.
    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client, kClientId, kClientPid, kClientUid, kInvalidClientOpPackageName);

    // Add the client to the manager and expect failure.
    status_t err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err != OK);
}

TEST_F(TranscodingClientManagerTest, TestAddingValidClient) {
    std::shared_ptr<ITranscodingServiceClient> client1 =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client1, kClientId, kClientPid, kClientUid, kClientOpPackageName);

    status_t err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err == OK);

    size_t numOfClients = mClientManager.getNumOfClients();
    EXPECT_EQ(numOfClients, 1);

    err = mClientManager.removeClient(kClientId);
    EXPECT_TRUE(err == OK);
}

TEST_F(TranscodingClientManagerTest, TestAddingDupliacteClient) {
    std::shared_ptr<ITranscodingServiceClient> client1 =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client1, kClientId, kClientPid, kClientUid, kClientOpPackageName);

    status_t err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err == OK);

    err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err != OK);

    err = mClientManager.removeClient(kClientId);
    EXPECT_TRUE(err == OK);
}

TEST_F(TranscodingClientManagerTest, TestAddingMultipleClient) {
    std::shared_ptr<ITranscodingServiceClient> client1 =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo1 =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client1, kClientId, kClientPid, kClientUid, kClientOpPackageName);

    status_t err = mClientManager.addClient(std::move(clientInfo1));
    EXPECT_TRUE(err == OK);

    std::shared_ptr<ITranscodingServiceClient> client2 =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo2 =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client2, kClientId + 1, kClientPid, kClientUid, kClientOpPackageName);

    err = mClientManager.addClient(std::move(clientInfo2));
    EXPECT_TRUE(err == OK);

    std::shared_ptr<ITranscodingServiceClient> client3 =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    // Create a client with invalid packagename.
    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo3 =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client3, kClientId + 2, kClientPid, kClientUid, kClientOpPackageName);

    err = mClientManager.addClient(std::move(clientInfo3));
    EXPECT_TRUE(err == OK);

    size_t numOfClients = mClientManager.getNumOfClients();
    EXPECT_EQ(numOfClients, 3);

    err = mClientManager.removeClient(kClientId);
    EXPECT_TRUE(err == OK);

    err = mClientManager.removeClient(kClientId + 1);
    EXPECT_TRUE(err == OK);

    err = mClientManager.removeClient(kClientId + 2);
    EXPECT_TRUE(err == OK);
}

TEST_F(TranscodingClientManagerTest, TestRemovingNonExistClient) {
    status_t err = mClientManager.removeClient(kInvalidClientId);
    EXPECT_TRUE(err != OK);

    err = mClientManager.removeClient(1000 /* clientId */);
    EXPECT_TRUE(err != OK);
}

TEST_F(TranscodingClientManagerTest, TestCheckClientWithClientId) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);

    std::unique_ptr<TranscodingClientManager::ClientInfo> clientInfo =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    client, kClientId, kClientPid, kClientUid, kClientOpPackageName);

    status_t err = mClientManager.addClient(std::move(clientInfo));
    EXPECT_TRUE(err == OK);

    bool res = mClientManager.isClientIdRegistered(kClientId);
    EXPECT_TRUE(res);

    res = mClientManager.isClientIdRegistered(kInvalidClientId);
    EXPECT_FALSE(res);
}

}  // namespace android