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

#include <aidl/android/media/BnTranscodingServiceClient.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <aidl/android/media/ITranscodingServiceClient.h>
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
using aidl::android::media::BnTranscodingServiceClient;
using aidl::android::media::IMediaTranscodingService;
using aidl::android::media::ITranscodingServiceClient;

constexpr int32_t kInvalidClientId = -5;

// Note that -1 is valid and means using calling pid/uid for the service. But only privilege caller could
// use them. This test is not a privilege caller.
constexpr int32_t kInvalidClientPid = -5;
constexpr int32_t kInvalidClientUid = -5;
constexpr const char* kInvalidClientOpPackageName = "";

constexpr int32_t kClientUseCallingPid = -1;
constexpr int32_t kClientUseCallingUid = -1;
constexpr const char* kClientOpPackageName = "TestClient";

class MediaTranscodingServiceTest : public ::testing::Test {
public:
    MediaTranscodingServiceTest() { ALOGD("MediaTranscodingServiceTest created"); }

    void SetUp() override {
        ::ndk::SpAIBinder binder(AServiceManager_getService("media.transcoding"));
        mService = IMediaTranscodingService::fromBinder(binder);
        if (mService == nullptr) {
            ALOGE("Failed to connect to the media.trascoding service.");
            return;
        }
    }

    ~MediaTranscodingServiceTest() { ALOGD("MediaTranscodingingServiceTest destroyed"); }

    std::shared_ptr<IMediaTranscodingService> mService = nullptr;
};

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
};

TEST_F(MediaTranscodingServiceTest, TestRegisterNullClient) {
    std::shared_ptr<ITranscodingServiceClient> client = nullptr;
    int32_t clientId = 0;
    Status status = mService->registerClient(client, kClientOpPackageName, kClientUseCallingUid,
                                             kClientUseCallingPid, &clientId);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientPid) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);
    EXPECT_TRUE(client != nullptr);

    // Register the client with the service.
    int32_t clientId = 0;
    Status status = mService->registerClient(client, kClientOpPackageName, kClientUseCallingUid,
                                             kInvalidClientPid, &clientId);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientUid) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);
    EXPECT_TRUE(client != nullptr);

    // Register the client with the service.
    int32_t clientId = 0;
    Status status = mService->registerClient(client, kClientOpPackageName, kInvalidClientUid,
                                             kClientUseCallingPid, &clientId);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientPackageName) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);
    EXPECT_TRUE(client != nullptr);

    // Register the client with the service.
    int32_t clientId = 0;
    Status status = mService->registerClient(client, kInvalidClientOpPackageName,
                                             kClientUseCallingUid, kClientUseCallingPid, &clientId);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterOneClient) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);
    EXPECT_TRUE(client != nullptr);

    // Register the client with the service.
    int32_t clientId = 0;
    Status status = mService->registerClient(client, kClientOpPackageName, kClientUseCallingPid,
                                             kClientUseCallingUid, &clientId);
    ALOGD("client id is %d", clientId);
    EXPECT_TRUE(status.isOk());

    // Validate the clientId.
    EXPECT_TRUE(clientId > 0);

    // Check the number of Clients.
    int32_t numOfClients;
    status = mService->getNumOfClients(&numOfClients);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(1, numOfClients);

    // Unregister the client.
    bool res;
    status = mService->unregisterClient(clientId, &res);
    EXPECT_TRUE(status.isOk());
    EXPECT_TRUE(res);
}

TEST_F(MediaTranscodingServiceTest, TestUnRegisterClientWithInvalidClientId) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);
    EXPECT_TRUE(client != nullptr);

    // Register the client with the service.
    int32_t clientId = 0;
    Status status = mService->registerClient(client, kClientOpPackageName, kClientUseCallingUid,
                                             kClientUseCallingPid, &clientId);
    ALOGD("client id is %d", clientId);
    EXPECT_TRUE(status.isOk());

    // Validate the clientId.
    EXPECT_TRUE(clientId > 0);

    // Check the number of Clients.
    int32_t numOfClients;
    status = mService->getNumOfClients(&numOfClients);
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(1, numOfClients);

    // Unregister the client with invalid ID
    bool res;
    mService->unregisterClient(kInvalidClientId, &res);
    EXPECT_FALSE(res);

    // Unregister the valid client.
    mService->unregisterClient(clientId, &res);
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientTwice) {
    std::shared_ptr<ITranscodingServiceClient> client =
            ::ndk::SharedRefBase::make<TestClient>(mService);
    EXPECT_TRUE(client != nullptr);

    // Register the client with the service.
    int32_t clientId = 0;
    Status status = mService->registerClient(client, kClientOpPackageName, kClientUseCallingUid,
                                             kClientUseCallingPid, &clientId);
    EXPECT_TRUE(status.isOk());

    // Validate the clientId.
    EXPECT_TRUE(clientId > 0);

    // Register the client again and expects failure.
    status = mService->registerClient(client, kClientOpPackageName, kClientUseCallingUid,
                                      kClientUseCallingPid, &clientId);
    EXPECT_FALSE(status.isOk());

    // Unregister the valid client.
    bool res;
    mService->unregisterClient(clientId, &res);
}

}  // namespace media
}  // namespace android
