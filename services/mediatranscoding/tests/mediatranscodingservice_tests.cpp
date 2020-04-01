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

// Unit Test for MediaTranscoding Service.

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaTranscodingServiceTest"

#include <aidl/android/media/BnTranscodingClientListener.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <aidl/android/media/ITranscodingClient.h>
#include <aidl/android/media/ITranscodingClientListener.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/binder_ibinder_jni.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <cutils/ashmem.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <utils/Log.h>

namespace android {

namespace media {

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnTranscodingClientListener;
using aidl::android::media::ITranscodingClient;
using aidl::android::media::ITranscodingClientListener;
using aidl::android::media::IMediaTranscodingService;

// Note that -1 is valid and means using calling pid/uid for the service. But only privilege caller could
// use them. This test is not a privilege caller.
constexpr int32_t kInvalidClientPid = -5;
constexpr int32_t kInvalidClientUid = -5;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientOpPackageName = "";

constexpr int32_t kClientUseCallingPid = -1;
constexpr int32_t kClientUseCallingUid = -1;
constexpr const char* kClientName = "TestClient";
constexpr const char* kClientOpPackageName = "TestClientPackage";

struct TestClient : public BnTranscodingClientListener {
    TestClient() {
        ALOGD("TestClient Created");
    }

    virtual ~TestClient() {
        ALOGI("TestClient destroyed");
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
};

class MediaTranscodingServiceTest : public ::testing::Test {
public:
    MediaTranscodingServiceTest() {
        ALOGD("MediaTranscodingServiceTest created");
    }

    ~MediaTranscodingServiceTest() {
        ALOGD("MediaTranscodingingServiceTest destroyed");
    }

    void SetUp() override {
        ::ndk::SpAIBinder binder(AServiceManager_getService("media.transcoding"));
        mService = IMediaTranscodingService::fromBinder(binder);
        if (mService == nullptr) {
            ALOGE("Failed to connect to the media.trascoding service.");
            return;
        }
        mClientListener = ::ndk::SharedRefBase::make<TestClient>();
        mClientListener2 = ::ndk::SharedRefBase::make<TestClient>();
        mClientListener3 = ::ndk::SharedRefBase::make<TestClient>();
    }

    std::shared_ptr<IMediaTranscodingService> mService;
    std::shared_ptr<ITranscodingClientListener> mClientListener;
    std::shared_ptr<ITranscodingClientListener> mClientListener2;
    std::shared_ptr<ITranscodingClientListener> mClientListener3;
};


TEST_F(MediaTranscodingServiceTest, TestRegisterNullClient) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with null listener
    Status status = mService->registerClient(
            nullptr, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientPid) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(
            mClientListener, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kInvalidClientPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientUid) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(
            mClientListener, kClientName, kClientOpPackageName,
            kInvalidClientUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(
            mClientListener, kInvalidClientName, kInvalidClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientPackageName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(
            mClientListener, kClientName, kInvalidClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterOneClient) {
    std::shared_ptr<ITranscodingClient> client;

    Status status = mService->registerClient(
            mClientListener, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_TRUE(status.isOk());

    // Validate the client.
    EXPECT_TRUE(client != nullptr);

    // Check the number of Clients.
    int32_t numOfClients;
    status = mService->getNumOfClients(&numOfClients);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(1, numOfClients);

    // Unregister the client.
    status = client->unregister();
    EXPECT_TRUE(status.isOk());

    // Check the number of Clients.
    status = mService->getNumOfClients(&numOfClients);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(0, numOfClients);
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientTwice) {
    std::shared_ptr<ITranscodingClient> client;

    Status status = mService->registerClient(
            mClientListener, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_TRUE(status.isOk());

    // Validate the client.
    EXPECT_TRUE(client != nullptr);

    // Register the client again and expects failure.
    std::shared_ptr<ITranscodingClient> client1;
    status = mService->registerClient(
            mClientListener, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client1);
    EXPECT_FALSE(status.isOk());

    // Unregister the client.
    status = client->unregister();
    EXPECT_TRUE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterMultipleClients) {
    std::shared_ptr<ITranscodingClient> client1;
    std::shared_ptr<ITranscodingClient> client2;
    std::shared_ptr<ITranscodingClient> client3;

    // Register 3 clients.
    Status status = mService->registerClient(
            mClientListener, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client1);
    EXPECT_TRUE(status.isOk());
    EXPECT_TRUE(client1 != nullptr);

    status = mService->registerClient(
            mClientListener2, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client2);
    EXPECT_TRUE(status.isOk());
    EXPECT_TRUE(client2 != nullptr);

    status = mService->registerClient(
            mClientListener3, kClientName, kClientOpPackageName,
            kClientUseCallingUid, kClientUseCallingPid, &client3);
    EXPECT_TRUE(status.isOk());
    EXPECT_TRUE(client3 != nullptr);

    // Check the number of clients.
    int32_t numOfClients;
    status = mService->getNumOfClients(&numOfClients);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(3, numOfClients);

    // Unregister the clients.
    status = client1->unregister();
    EXPECT_TRUE(status.isOk());

    status = client2->unregister();
    EXPECT_TRUE(status.isOk());

    status = client3->unregister();
    EXPECT_TRUE(status.isOk());

    // Check the number of clients.
    status = mService->getNumOfClients(&numOfClients);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(0, numOfClients);
}
}  // namespace media
}  // namespace android
