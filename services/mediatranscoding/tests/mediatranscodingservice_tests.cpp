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
#define LOG_TAG "MediaTranscodingServiceTest"

#include <aidl/android/media/BnTranscodingClientCallback.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <aidl/android/media/ITranscodingClient.h>
#include <aidl/android/media/ITranscodingClientCallback.h>
#include <aidl/android/media/TranscodingJobParcel.h>
#include <aidl/android/media/TranscodingRequestParcel.h>
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
using aidl::android::media::BnTranscodingClientCallback;
using aidl::android::media::IMediaTranscodingService;
using aidl::android::media::ITranscodingClient;
using aidl::android::media::ITranscodingClientCallback;
using aidl::android::media::TranscodingJobParcel;
using aidl::android::media::TranscodingRequestParcel;

// Note that -1 is valid and means using calling pid/uid for the service. But only privilege caller could
// use them. This test is not a privilege caller.
constexpr int32_t kInvalidClientPid = -5;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientOpPackageName = "";

constexpr int32_t kClientUseCallingPid = IMediaTranscodingService::USE_CALLING_PID;
constexpr int32_t kClientUseCallingUid = IMediaTranscodingService::USE_CALLING_UID;
constexpr const char* kClientName = "TestClient";
constexpr const char* kClientOpPackageName = "TestClientPackage";

struct TestClient : public BnTranscodingClientCallback {
    TestClient() { ALOGD("TestClient Created"); }

    virtual ~TestClient() { ALOGI("TestClient destroyed"); }

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
    MediaTranscodingServiceTest() { ALOGD("MediaTranscodingServiceTest created"); }

    ~MediaTranscodingServiceTest() { ALOGD("MediaTranscodingingServiceTest destroyed"); }

    void SetUp() override {
        ::ndk::SpAIBinder binder(AServiceManager_getService("media.transcoding"));
        mService = IMediaTranscodingService::fromBinder(binder);
        if (mService == nullptr) {
            ALOGE("Failed to connect to the media.trascoding service.");
            return;
        }
        mClientCallback = ::ndk::SharedRefBase::make<TestClient>();
        mClientCallback2 = ::ndk::SharedRefBase::make<TestClient>();
        mClientCallback3 = ::ndk::SharedRefBase::make<TestClient>();
    }

    void registerMultipleClients() {
        // Register 3 clients.
        Status status =
                mService->registerClient(mClientCallback, kClientName, kClientOpPackageName,
                                         kClientUseCallingUid, kClientUseCallingPid, &mClient1);
        EXPECT_TRUE(status.isOk());
        EXPECT_TRUE(mClient1 != nullptr);

        status = mService->registerClient(mClientCallback2, kClientName, kClientOpPackageName,
                                          kClientUseCallingUid, kClientUseCallingPid, &mClient2);
        EXPECT_TRUE(status.isOk());
        EXPECT_TRUE(mClient2 != nullptr);

        status = mService->registerClient(mClientCallback3, kClientName, kClientOpPackageName,
                                          kClientUseCallingUid, kClientUseCallingPid, &mClient3);
        EXPECT_TRUE(status.isOk());
        EXPECT_TRUE(mClient3 != nullptr);

        // Check the number of clients.
        int32_t numOfClients;
        status = mService->getNumOfClients(&numOfClients);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(3, numOfClients);
    }

    void unregisterMultipleClients() {
        // Unregister the clients.
        Status status = mClient1->unregister();
        EXPECT_TRUE(status.isOk());

        status = mClient2->unregister();
        EXPECT_TRUE(status.isOk());

        status = mClient3->unregister();
        EXPECT_TRUE(status.isOk());

        // Check the number of clients.
        int32_t numOfClients;
        status = mService->getNumOfClients(&numOfClients);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(0, numOfClients);
    }

    std::shared_ptr<IMediaTranscodingService> mService;
    std::shared_ptr<ITranscodingClientCallback> mClientCallback;
    std::shared_ptr<ITranscodingClientCallback> mClientCallback2;
    std::shared_ptr<ITranscodingClientCallback> mClientCallback3;
    std::shared_ptr<ITranscodingClient> mClient1;
    std::shared_ptr<ITranscodingClient> mClient2;
    std::shared_ptr<ITranscodingClient> mClient3;
};

TEST_F(MediaTranscodingServiceTest, TestRegisterNullClient) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with null callback.
    Status status = mService->registerClient(nullptr, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientPid) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(mClientCallback, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kInvalidClientPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(mClientCallback, kInvalidClientName,
                                             kInvalidClientOpPackageName, kClientUseCallingUid,
                                             kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientPackageName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status =
            mService->registerClient(mClientCallback, kClientName, kInvalidClientOpPackageName,
                                     kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterOneClient) {
    std::shared_ptr<ITranscodingClient> client;

    Status status = mService->registerClient(mClientCallback, kClientName, kClientOpPackageName,
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

    Status status = mService->registerClient(mClientCallback, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_TRUE(status.isOk());

    // Validate the client.
    EXPECT_TRUE(client != nullptr);

    // Register the client again and expects failure.
    std::shared_ptr<ITranscodingClient> client1;
    status = mService->registerClient(mClientCallback, kClientName, kClientOpPackageName,
                                      kClientUseCallingUid, kClientUseCallingPid, &client1);
    EXPECT_FALSE(status.isOk());

    // Unregister the client.
    status = client->unregister();
    EXPECT_TRUE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterMultipleClients) {
    registerMultipleClients();
    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceTest, TestSubmitCancelGetJobs) {
    registerMultipleClients();

    // Test jobId assignment.
    TranscodingRequestParcel request;
    request.fileName = "test_file_0";
    TranscodingJobParcel job;
    bool result;
    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, 0);

    request.fileName = "test_file_1";
    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, 1);

    request.fileName = "test_file_2";
    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, 2);

    // Test submit bad request (no valid fileName) fails.
    TranscodingRequestParcel badRequest;
    EXPECT_TRUE(mClient1->submitRequest(badRequest, &job, &result).isOk());
    EXPECT_FALSE(result);

    // Test get jobs by id.
    EXPECT_TRUE(mClient1->getJobWithId(2, &job, &result).isOk());
    EXPECT_EQ(job.jobId, 2);
    EXPECT_EQ(job.request.fileName, "test_file_2");
    EXPECT_TRUE(result);

    // Test get jobs by invalid id fails.
    EXPECT_TRUE(mClient1->getJobWithId(100, &job, &result).isOk());
    EXPECT_FALSE(result);

    // Test cancel non-existent job fail.
    EXPECT_TRUE(mClient2->cancelJob(100, &result).isOk());
    EXPECT_FALSE(result);

    // Test cancel valid jobId in arbitrary order.
    EXPECT_TRUE(mClient1->cancelJob(2, &result).isOk());
    EXPECT_TRUE(result);

    EXPECT_TRUE(mClient1->cancelJob(0, &result).isOk());
    EXPECT_TRUE(result);

    EXPECT_TRUE(mClient1->cancelJob(1, &result).isOk());
    EXPECT_TRUE(result);

    // Test cancel job again fails.
    EXPECT_TRUE(mClient1->cancelJob(1, &result).isOk());
    EXPECT_FALSE(result);

    // Test get job after cancel fails.
    EXPECT_TRUE(mClient1->getJobWithId(2, &job, &result).isOk());
    EXPECT_FALSE(result);

    // Test jobId independence for each client.
    EXPECT_TRUE(mClient2->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, 0);

    EXPECT_TRUE(mClient2->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, 1);

    unregisterMultipleClients();
}

}  // namespace media
}  // namespace android
