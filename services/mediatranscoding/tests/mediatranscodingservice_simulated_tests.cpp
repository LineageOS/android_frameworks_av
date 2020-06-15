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
#define LOG_TAG "MediaTranscodingServiceSimulatedTest"

#include <aidl/android/media/BnTranscodingClientCallback.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <aidl/android/media/ITranscodingClient.h>
#include <aidl/android/media/ITranscodingClientCallback.h>
#include <aidl/android/media/TranscodingJobParcel.h>
#include <aidl/android/media/TranscodingJobPriority.h>
#include <aidl/android/media/TranscodingRequestParcel.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/PermissionController.h>
#include <cutils/multiuser.h>
#include <gtest/gtest.h>
#include <utils/Log.h>

#include <iostream>
#include <list>

#include "MediaTranscodingServiceTestHelper.h"
#include "SimulatedTranscoder.h"

namespace android {

namespace media {

// Note that -1 is valid and means using calling pid/uid for the service. But only privilege caller could
// use them. This test is not a privilege caller.
constexpr int32_t kInvalidClientPid = -5;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientOpPackageName = "";

constexpr int32_t kClientUseCallingUid = IMediaTranscodingService::USE_CALLING_UID;

constexpr int64_t kPaddingUs = 1000000;
constexpr int64_t kJobWithPaddingUs = SimulatedTranscoder::kJobDurationUs + kPaddingUs;

constexpr const char* kClientOpPackageName = "TestClientPackage";
constexpr const char* kTestActivityName = "/com.android.tests.transcoding.MainActivity";

class MediaTranscodingServiceSimulatedTest : public MediaTranscodingServiceTestBase {
public:
    MediaTranscodingServiceSimulatedTest() {}
};

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterNullClient) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with null callback.
    Status status = mService->registerClient(nullptr, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterClientWithInvalidClientPid) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(mClientCallback1, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kInvalidClientPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterClientWithInvalidClientName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(mClientCallback1, kInvalidClientName,
                                             kInvalidClientOpPackageName, kClientUseCallingUid,
                                             kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterClientWithInvalidClientPackageName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status =
            mService->registerClient(mClientCallback1, kClientName, kInvalidClientOpPackageName,
                                     kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterOneClient) {
    std::shared_ptr<ITranscodingClient> client;

    Status status = mService->registerClient(mClientCallback1, kClientName, kClientOpPackageName,
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

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterClientTwice) {
    std::shared_ptr<ITranscodingClient> client;

    Status status = mService->registerClient(mClientCallback1, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_TRUE(status.isOk());

    // Validate the client.
    EXPECT_TRUE(client != nullptr);

    // Register the client again and expects failure.
    std::shared_ptr<ITranscodingClient> client1;
    status = mService->registerClient(mClientCallback1, kClientName, kClientOpPackageName,
                                      kClientUseCallingUid, kClientUseCallingPid, &client1);
    EXPECT_FALSE(status.isOk());

    // Unregister the client.
    status = client->unregister();
    EXPECT_TRUE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterMultipleClients) {
    registerMultipleClients();
    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestJobIdIndependence) {
    registerMultipleClients();

    // Submit 2 requests on client1 first.
    EXPECT_TRUE(submit(mClient1, 0, "test_source_file", "test_destination_file"));
    EXPECT_TRUE(submit(mClient1, 1, "test_source_file", "test_destination_file"));

    // Submit 2 requests on client2, jobId should be independent for each client.
    EXPECT_TRUE(submit(mClient2, 0, "test_source_file", "test_destination_file"));
    EXPECT_TRUE(submit(mClient2, 1, "test_source_file", "test_destination_file"));

    // Cancel all jobs.
    EXPECT_TRUE(cancel(mClient1, 0));
    EXPECT_TRUE(cancel(mClient1, 1));
    EXPECT_TRUE(cancel(mClient2, 0));
    EXPECT_TRUE(cancel(mClient2, 1));

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestSubmitCancelJobs) {
    registerMultipleClients();

    // Test jobId assignment.
    EXPECT_TRUE(submit(mClient1, 0, "test_source_file_0", "test_destination_file"));
    EXPECT_TRUE(submit(mClient1, 1, "test_source_file_1", "test_destination_file"));
    EXPECT_TRUE(submit(mClient1, 2, "test_source_file_2", "test_destination_file"));

    // Test submit bad request (no valid sourceFilePath) fails.
    EXPECT_TRUE(submit<fail>(mClient1, 0, "", ""));

    // Test cancel non-existent job fails.
    EXPECT_TRUE(cancel<fail>(mClient1, 100));

    // Job 0 should start immediately and finish in 2 seconds, followed by Job 1 start.
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    // Test cancel valid jobId in random order.
    // Test cancel finished job fails.
    EXPECT_TRUE(cancel(mClient1, 2));
    EXPECT_TRUE(cancel<fail>(mClient1, 0));
    EXPECT_TRUE(cancel(mClient1, 1));

    // Test cancel job again fails.
    EXPECT_TRUE(cancel<fail>(mClient1, 1));

    // Test no more events arriving after cancel.
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::NoEvent);

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestGetJobs) {
    registerMultipleClients();

    // Submit 3 requests.
    EXPECT_TRUE(submit(mClient1, 0, "test_source_file_0", "test_destination_file_0"));
    EXPECT_TRUE(submit(mClient1, 1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_TRUE(submit(mClient1, 2, "test_source_file_2", "test_destination_file_2"));

    // Test get jobs by id.
    EXPECT_TRUE(getJob(mClient1, 2, "test_source_file_2", "test_destination_file_2"));
    EXPECT_TRUE(getJob(mClient1, 1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_TRUE(getJob(mClient1, 0, "test_source_file_0", "test_destination_file_0"));

    // Test get job by invalid id fails.
    EXPECT_TRUE(getJob<fail>(mClient1, 100, "", ""));
    EXPECT_TRUE(getJob<fail>(mClient1, -1, "", ""));

    // Test get job after cancel fails.
    EXPECT_TRUE(cancel(mClient1, 2));
    EXPECT_TRUE(getJob<fail>(mClient1, 2, "", ""));

    // Job 0 should start immediately and finish in 2 seconds, followed by Job 1 start.
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    // Test get job after finish fails.
    EXPECT_TRUE(getJob<fail>(mClient1, 0, "", ""));

    // Test get the remaining job 1.
    EXPECT_TRUE(getJob(mClient1, 1, "test_source_file_1", "test_destination_file_1"));

    // Cancel remaining job 1.
    EXPECT_TRUE(cancel(mClient1, 1));

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestSubmitCancelWithOfflineJobs) {
    registerMultipleClients();

    // Submit some offline jobs first.
    EXPECT_TRUE(submit(mClient1, 0, "test_source_file_0", "test_destination_file_0",
                       TranscodingJobPriority::kUnspecified));
    EXPECT_TRUE(submit(mClient1, 1, "test_source_file_1", "test_destination_file_1",
                       TranscodingJobPriority::kUnspecified));

    // Job 0 should start immediately.
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    // Submit more real-time jobs.
    EXPECT_TRUE(submit(mClient1, 2, "test_source_file_2", "test_destination_file_2"));
    EXPECT_TRUE(submit(mClient1, 3, "test_source_file_3", "test_destination_file_3"));

    // Job 0 should pause immediately and job 2 should start.
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Pause(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 2));

    // Job 2 should finish in 2 seconds and job 3 should start.
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 2));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 3));

    // Cancel job 3 now
    EXPECT_TRUE(cancel(mClient1, 3));

    // Job 0 should resume and finish in 2 seconds, followed by job 1 start.
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Resume(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    // Cancel remaining job 1.
    EXPECT_TRUE(cancel(mClient1, 1));

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestClientUseAfterUnregister) {
    std::shared_ptr<ITranscodingClient> client;

    // Register a client, then unregister.
    Status status = mService->registerClient(mClientCallback1, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_TRUE(status.isOk());

    status = client->unregister();
    EXPECT_TRUE(status.isOk());

    // Test various operations on the client, should fail with ERROR_DISCONNECTED.
    TranscodingJobParcel job;
    bool result;
    status = client->getJobWithId(0, &job, &result);
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->cancelJob(0, &result);
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    TranscodingRequestParcel request;
    status = client->submitRequest(request, &job, &result);
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestTranscodingUidPolicy) {
    ALOGD("TestTranscodingUidPolicy starting...");

    EXPECT_TRUE(ShellHelper::RunCmd("input keyevent KEYCODE_WAKEUP"));
    EXPECT_TRUE(ShellHelper::RunCmd("wm dismiss-keyguard"));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageB));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageC));

    registerMultipleClients();

    ALOGD("Moving app A to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kTestActivityName));

    // Submit 3 requests.
    ALOGD("Submitting job to client1 (app A) ...");
    EXPECT_TRUE(submit(mClient1, 0, "test_source_file_0", "test_destination_file_0"));
    EXPECT_TRUE(submit(mClient1, 1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_TRUE(submit(mClient1, 2, "test_source_file_2", "test_destination_file_2"));

    // Job 0 should start immediately.
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    ALOGD("Moving app B to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageB, kTestActivityName));

    // Job 0 should continue and finish in 2 seconds, then job 1 should start.
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    ALOGD("Submitting job to client2 (app B) ...");
    EXPECT_TRUE(submit(mClient2, 0, "test_source_file_0", "test_destination_file_0"));

    // Client1's job should pause, client2's job should start.
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Pause(CLIENT(1), 1));
    EXPECT_EQ(mClientCallback2->pop(kPaddingUs), EventTracker::Start(CLIENT(2), 0));

    ALOGD("Moving app A back to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kTestActivityName));

    // Client2's job should pause, client1's job 1 should resume.
    EXPECT_EQ(mClientCallback2->pop(kPaddingUs), EventTracker::Pause(CLIENT(2), 0));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Resume(CLIENT(1), 1));

    // Client2's job 1 should finish in 2 seconds, then its job 2 should start.
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 1));
    EXPECT_EQ(mClientCallback1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 2));

    // After client2's jobs finish, client1's job should resume.
    EXPECT_EQ(mClientCallback1->pop(kJobWithPaddingUs), EventTracker::Finished(CLIENT(1), 2));
    EXPECT_EQ(mClientCallback2->pop(kPaddingUs), EventTracker::Resume(CLIENT(2), 0));

    unregisterMultipleClients();

    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageB));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageC));

    ALOGD("TestTranscodingUidPolicy finished.");
}

}  // namespace media
}  // namespace android
