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

#include <aidl/android/media/BnTranscodingClientListener.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <media/TranscodingClientManager.h>
#include <utils/Log.h>

namespace android {

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnTranscodingClientListener;
using aidl::android::media::IMediaTranscodingService;

constexpr int32_t kInvalidClientPid = -1;
constexpr int32_t kInvalidClientUid = -1;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientPackage = "";

constexpr int32_t kClientPid = 2;
constexpr int32_t kClientUid = 3;
constexpr const char* kClientName = "TestClientName";
constexpr const char* kClientPackage = "TestClientPackage";

struct TestClient : public BnTranscodingClientListener {
    TestClient() {
        ALOGD("TestClient Created");
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
    TestClient(const TestClient&) = delete;
    TestClient& operator=(const TestClient&) = delete;
};

class TranscodingClientManagerTest : public ::testing::Test {
   public:
    TranscodingClientManagerTest() : mClientManager(TranscodingClientManager::getInstance()) {
        ALOGD("TranscodingClientManagerTest created");
    }

    void SetUp() override {
        mClientListener = ::ndk::SharedRefBase::make<TestClient>();
        mClientListener2 = ::ndk::SharedRefBase::make<TestClient>();
        mClientListener3 = ::ndk::SharedRefBase::make<TestClient>();
    }

    void TearDown() override {
        ALOGI("TranscodingClientManagerTest tear down");
    }

    ~TranscodingClientManagerTest() { ALOGD("TranscodingClientManagerTest destroyed"); }

    TranscodingClientManager& mClientManager;
    std::shared_ptr<ITranscodingClientListener> mClientListener;
    std::shared_ptr<ITranscodingClientListener> mClientListener2;
    std::shared_ptr<ITranscodingClientListener> mClientListener3;
};

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientListener) {
    // Add a client with null listener and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager.addClient(nullptr,
            kClientPid, kClientUid, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, BAD_VALUE);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPid) {
    // Add a client with invalid Pid and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager.addClient(mClientListener,
            kInvalidClientPid, kClientUid, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, BAD_VALUE);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientUid) {
    // Add a client with invalid Uid and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager.addClient(mClientListener,
            kClientPid, kInvalidClientUid, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, BAD_VALUE);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientName) {
    // Add a client with invalid name and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager.addClient(mClientListener,
            kClientPid, kClientUid, kInvalidClientName, kClientPackage, &client);
    EXPECT_EQ(err, BAD_VALUE);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPackageName) {
    // Add a client with invalid packagename and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager.addClient(mClientListener,
            kClientPid, kClientUid, kClientName, kInvalidClientPackage, &client);
    EXPECT_EQ(err, BAD_VALUE);
}

TEST_F(TranscodingClientManagerTest, TestAddingValidClient) {
    // Add a valid client, should succeed
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager.addClient(mClientListener,
            kClientPid, kClientUid, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, OK);
    EXPECT_NE(client.get(), nullptr);
    EXPECT_EQ(mClientManager.getNumOfClients(), 1);

    // unregister client, should succeed
    Status status = client->unregister();
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(mClientManager.getNumOfClients(), 0);
}

TEST_F(TranscodingClientManagerTest, TestAddingDupliacteClient) {
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager.addClient(mClientListener,
            kClientPid, kClientUid, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, OK);
    EXPECT_NE(client.get(), nullptr);
    EXPECT_EQ(mClientManager.getNumOfClients(), 1);

    std::shared_ptr<ITranscodingClient> dupClient;
    err = mClientManager.addClient(mClientListener,
            kClientPid, kClientUid, "dupClient", "dupPackage", &dupClient);
    EXPECT_EQ(err, ALREADY_EXISTS);
    EXPECT_EQ(dupClient.get(), nullptr);
    EXPECT_EQ(mClientManager.getNumOfClients(), 1);

    Status status = client->unregister();
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(mClientManager.getNumOfClients(), 0);

    err = mClientManager.addClient(mClientListener,
            kClientPid, kClientUid, "dupClient", "dupPackage", &dupClient);
    EXPECT_EQ(err, OK);
    EXPECT_NE(dupClient.get(), nullptr);
    EXPECT_EQ(mClientManager.getNumOfClients(), 1);

    status = dupClient->unregister();
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(mClientManager.getNumOfClients(), 0);
}

TEST_F(TranscodingClientManagerTest, TestAddingMultipleClient) {
    std::shared_ptr<ITranscodingClient> client1, client2, client3;

    EXPECT_EQ(mClientManager.addClient(mClientListener,
            kClientPid, kClientUid, kClientName, kClientPackage, &client1), OK);
    EXPECT_NE(client1, nullptr);

    EXPECT_EQ(mClientManager.addClient(mClientListener2,
            kClientPid, kClientUid, kClientName, kClientPackage, &client2), OK);
    EXPECT_NE(client2, nullptr);

    EXPECT_EQ(mClientManager.addClient(mClientListener3,
            kClientPid, kClientUid, kClientName, kClientPackage, &client3), OK);
    EXPECT_NE(client3, nullptr);

    EXPECT_EQ(mClientManager.getNumOfClients(), 3);
    EXPECT_TRUE(client1->unregister().isOk());
    EXPECT_TRUE(client2->unregister().isOk());
    EXPECT_TRUE(client3->unregister().isOk());
    EXPECT_EQ(mClientManager.getNumOfClients(), 0);
}

}  // namespace android
