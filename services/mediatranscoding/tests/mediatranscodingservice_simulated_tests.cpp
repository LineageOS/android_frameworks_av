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
#include <aidl/android/media/TranscodingRequestParcel.h>
#include <aidl/android/media/TranscodingSessionParcel.h>
#include <aidl/android/media/TranscodingSessionPriority.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/PermissionController.h>
#include <cutils/multiuser.h>
#include <gtest/gtest.h>
#include <utils/Log.h>

#include <iostream>
#include <list>
#include <unordered_set>

#include "MediaTranscodingServiceTestHelper.h"
#include "SimulatedTranscoder.h"

namespace android {

namespace media {

// Note that -1 is valid and means using calling pid/uid for the service. But only privilege caller
// could use them. This test is not a privilege caller.
constexpr int32_t kInvalidClientPid = -5;
constexpr int32_t kInvalidClientUid = -10;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientOpPackageName = "";

constexpr int64_t kPaddingUs = 1000000;
constexpr int64_t kSessionWithPaddingUs = SimulatedTranscoder::kSessionDurationUs + kPaddingUs;
constexpr int64_t kWatchdogTimeoutUs = 3000000;
// Pacer settings used for simulated tests. Listed here for reference.
constexpr int32_t kSimulatedPacerBurstThresholdMs = 500;
//constexpr int32_t kSimulatedPacerBurstCountQuota = 10;
//constexpr int32_t kSimulatedPacerBurstTimeQuotaSec = 3;

constexpr const char* kClientOpPackageName = "TestClientPackage";

class MediaTranscodingServiceSimulatedTest : public MediaTranscodingServiceTestBase {
public:
    MediaTranscodingServiceSimulatedTest() { ALOGI("MediaTranscodingServiceResourceTest created"); }

    virtual ~MediaTranscodingServiceSimulatedTest() {
        ALOGI("MediaTranscodingServiceResourceTest destroyed");
    }

    void testPacerHelper(int numSubmits, int sessionDurationMs, int expectedSuccess) {
        // Idle to clear out burst history.
        usleep(kSimulatedPacerBurstThresholdMs * 2 * 1000);
        for (int i = 0; i < numSubmits; i++) {
            EXPECT_TRUE(mClient3->submit(i, "test_source_file_0", "test_destination_file_0",
                                         TranscodingSessionPriority::kNormal, -1 /*bitrateBps*/,
                                         -1 /*overridePid*/, -1 /*overrideUid*/,
                                         sessionDurationMs));
        }
        for (int i = 0; i < expectedSuccess; i++) {
            EXPECT_EQ(mClient3->pop(kPaddingUs), EventTracker::Start(CLIENT(3), i));
            EXPECT_EQ(mClient3->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(3), i));
        }
        for (int i = expectedSuccess; i < numSubmits; i++) {
            EXPECT_EQ(mClient3->pop(kPaddingUs), EventTracker::Failed(CLIENT(3), i));
            EXPECT_EQ(mClient3->getLastError(), TranscodingErrorCode::kDroppedByService);
        }
    }
};

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterNullClient) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with null callback.
    Status status = mService->registerClient(nullptr, kClientName, kClientOpPackageName, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterClientWithInvalidClientName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(mClient1, kInvalidClientName,
                                             kInvalidClientOpPackageName, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterClientWithInvalidClientPackageName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status =
            mService->registerClient(mClient1, kClientName, kInvalidClientOpPackageName, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterOneClient) {
    std::shared_ptr<ITranscodingClient> client;

    Status status = mService->registerClient(mClient1, kClientName, kClientOpPackageName, &client);
    EXPECT_TRUE(status.isOk());

    // Validate the client.
    EXPECT_TRUE(client != nullptr);

    // Check the number of Clients.
    int32_t numOfClients;
    status = mService->getNumOfClients(&numOfClients);
    EXPECT_TRUE(status.isOk());
    EXPECT_GE(numOfClients, 1);

    // Unregister the client.
    status = client->unregister();
    EXPECT_TRUE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterClientTwice) {
    std::shared_ptr<ITranscodingClient> client;

    Status status = mService->registerClient(mClient1, kClientName, kClientOpPackageName, &client);
    EXPECT_TRUE(status.isOk());

    // Validate the client.
    EXPECT_TRUE(client != nullptr);

    // Register the client again and expects failure.
    std::shared_ptr<ITranscodingClient> client1;
    status = mService->registerClient(mClient1, kClientName, kClientOpPackageName, &client1);
    EXPECT_FALSE(status.isOk());

    // Unregister the client.
    status = client->unregister();
    EXPECT_TRUE(status.isOk());
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestRegisterMultipleClients) {
    registerMultipleClients();
    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestSessionIdIndependence) {
    registerMultipleClients();

    // Submit 2 requests on client1 first.
    EXPECT_TRUE(mClient1->submit(0, "test_source_file", "test_destination_file"));
    EXPECT_TRUE(mClient1->submit(1, "test_source_file", "test_destination_file"));

    // Submit 2 requests on client2, sessionId should be independent for each client.
    EXPECT_TRUE(mClient2->submit(0, "test_source_file", "test_destination_file"));
    EXPECT_TRUE(mClient2->submit(1, "test_source_file", "test_destination_file"));

    // Cancel all sessions.
    EXPECT_TRUE(mClient1->cancel(0));
    EXPECT_TRUE(mClient1->cancel(1));
    EXPECT_TRUE(mClient2->cancel(0));
    EXPECT_TRUE(mClient2->cancel(1));

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestSubmitCancelSessions) {
    registerMultipleClients();

    // Test sessionId assignment.
    EXPECT_TRUE(mClient1->submit(0, "test_source_file_0", "test_destination_file"));
    EXPECT_TRUE(mClient1->submit(1, "test_source_file_1", "test_destination_file"));
    EXPECT_TRUE(mClient1->submit(2, "test_source_file_2", "test_destination_file"));

    // Test submit bad request (no valid sourceFilePath) fails.
    EXPECT_TRUE(mClient1->submit<fail>(0, "", ""));

    // Test submit bad request (no valid sourceFilePath) fails.
    EXPECT_TRUE(mClient1->submit<fail>(0, "src", "dst", TranscodingSessionPriority::kNormal,
                                       1000000, kInvalidClientPid, kInvalidClientUid));

    // Test cancel non-existent session fails.
    EXPECT_TRUE(mClient1->cancel<fail>(100));

    // Session 0 should start immediately and finish in 2 seconds, followed by Session 1 start.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    // Test cancel valid sessionId in random order.
    // Test cancel finished session fails.
    EXPECT_TRUE(mClient1->cancel(2));
    EXPECT_TRUE(mClient1->cancel<fail>(0));
    EXPECT_TRUE(mClient1->cancel(1));

    // Test cancel session again fails.
    EXPECT_TRUE(mClient1->cancel<fail>(1));

    // Test no more events arriving after cancel.
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::NoEvent);

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestGetSessions) {
    registerMultipleClients();

    // Submit 3 requests.
    EXPECT_TRUE(mClient1->submit(0, "test_source_file_0", "test_destination_file_0"));
    EXPECT_TRUE(mClient1->submit(1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_TRUE(mClient1->submit(2, "test_source_file_2", "test_destination_file_2"));

    // Test get sessions by id.
    EXPECT_TRUE(mClient1->getSession(2, "test_source_file_2", "test_destination_file_2"));
    EXPECT_TRUE(mClient1->getSession(1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_TRUE(mClient1->getSession(0, "test_source_file_0", "test_destination_file_0"));

    // Test get session by invalid id fails.
    EXPECT_TRUE(mClient1->getSession<fail>(100, "", ""));
    EXPECT_TRUE(mClient1->getSession<fail>(-1, "", ""));

    // Test get session after cancel fails.
    EXPECT_TRUE(mClient1->cancel(2));
    EXPECT_TRUE(mClient1->getSession<fail>(2, "", ""));

    // Session 0 should start immediately and finish in 2 seconds, followed by Session 1 start.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    // Test get session after finish fails.
    EXPECT_TRUE(mClient1->getSession<fail>(0, "", ""));

    // Test get the remaining session 1.
    EXPECT_TRUE(mClient1->getSession(1, "test_source_file_1", "test_destination_file_1"));

    // Cancel remaining session 1.
    EXPECT_TRUE(mClient1->cancel(1));

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestAddGetClientUids) {
    registerMultipleClients();

    std::vector<int32_t> clientUids;
    TranscodingRequestParcel request;
    TranscodingSessionParcel session;
    uid_t ownUid = ::getuid();

    // Submit one real-time session.
    EXPECT_TRUE(mClient1->submit(0, "test_source_file_0", "test_destination_file"));

    // Should have mClientUid in client uid list.
    EXPECT_TRUE(mClient1->getClientUids(0, &clientUids));
    EXPECT_EQ(clientUids.size(), 1u);
    EXPECT_EQ(clientUids[0], (int32_t)mClient1->mClientUid);

    // Adding invalid client uid should fail.
    EXPECT_TRUE(mClient1->addClientUid<fail>(0, kInvalidClientUid));

    // Adding mClientUid again should fail.
    EXPECT_TRUE(mClient1->addClientUid<fail>(0, mClient1->mClientUid));

    // Submit one offline session.
    EXPECT_TRUE(mClient1->submit(1, "test_source_file_1", "test_destination_file_1",
                                 TranscodingSessionPriority::kUnspecified));

    // Should not have any uids in client uid list.
    EXPECT_TRUE(mClient1->getClientUids(1, &clientUids));
    EXPECT_EQ(clientUids.size(), 0u);

    // Add own uid (with IMediaTranscodingService::USE_CALLING_UID), should succeed.
    EXPECT_TRUE(mClient1->addClientUid(1, IMediaTranscodingService::USE_CALLING_UID));
    EXPECT_TRUE(mClient1->getClientUids(1, &clientUids));
    EXPECT_EQ(clientUids.size(), 1u);
    EXPECT_EQ(clientUids[0], (int32_t)ownUid);

    // Adding mClientUid should succeed.
    EXPECT_TRUE(mClient1->addClientUid(1, mClient1->mClientUid));
    EXPECT_TRUE(mClient1->getClientUids(1, &clientUids));
    std::unordered_set<uid_t> uidSet;
    uidSet.insert(clientUids.begin(), clientUids.end());
    EXPECT_EQ(uidSet.size(), 2u);
    EXPECT_EQ(uidSet.count(ownUid), 1u);
    EXPECT_EQ(uidSet.count(mClient1->mClientUid), 1u);

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestSubmitCancelWithOfflineSessions) {
    registerMultipleClients();

    // Submit some offline sessions first.
    EXPECT_TRUE(mClient1->submit(0, "test_source_file_0", "test_destination_file_0",
                                 TranscodingSessionPriority::kUnspecified));
    EXPECT_TRUE(mClient1->submit(1, "test_source_file_1", "test_destination_file_1",
                                 TranscodingSessionPriority::kUnspecified));

    // Session 0 should start immediately.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    // Submit more real-time sessions.
    EXPECT_TRUE(mClient1->submit(2, "test_source_file_2", "test_destination_file_2"));
    EXPECT_TRUE(mClient1->submit(3, "test_source_file_3", "test_destination_file_3"));

    // Session 0 should pause immediately and session 2 should start.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Pause(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 2));

    // Session 2 should finish in 2 seconds and session 3 should start.
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 2));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 3));

    // Cancel session 3 now
    EXPECT_TRUE(mClient1->cancel(3));

    // Session 0 should resume and finish in 2 seconds, followed by session 1 start.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Resume(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    // Cancel remaining session 1.
    EXPECT_TRUE(mClient1->cancel(1));

    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestClientUseAfterUnregister) {
    std::shared_ptr<ITranscodingClient> client;

    // Register a client, then unregister.
    Status status = mService->registerClient(mClient1, kClientName, kClientOpPackageName, &client);
    EXPECT_TRUE(status.isOk());

    status = client->unregister();
    EXPECT_TRUE(status.isOk());

    // Test various operations on the client, should fail with ERROR_DISCONNECTED.
    TranscodingSessionParcel session;
    bool result;
    status = client->getSessionWithId(0, &session, &result);
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->cancelSession(0, &result);
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    TranscodingRequestParcel request;
    status = client->submitRequest(request, &session, &result);
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
    ALOGD("Submitting session to client1 (app A) ...");
    EXPECT_TRUE(mClient1->submit(0, "test_source_file_0", "test_destination_file_0"));
    EXPECT_TRUE(mClient1->submit(1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_TRUE(mClient1->submit(2, "test_source_file_2", "test_destination_file_2"));

    // Session 0 should start immediately.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    ALOGD("Moving app B to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageB, kTestActivityName));

    // Session 0 should continue and finish in 2 seconds, then session 1 should start.
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    ALOGD("Submitting session to client2 (app B) ...");
    EXPECT_TRUE(mClient2->submit(0, "test_source_file_0", "test_destination_file_0"));

    // Client1's session should pause, client2's session should start.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Pause(CLIENT(1), 1));
    EXPECT_EQ(mClient2->pop(kPaddingUs), EventTracker::Start(CLIENT(2), 0));

    ALOGD("Moving app A back to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kTestActivityName));

    // Client2's session should pause, client1's session 1 should resume.
    EXPECT_EQ(mClient2->pop(kPaddingUs), EventTracker::Pause(CLIENT(2), 0));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Resume(CLIENT(1), 1));

    // Client2's session 1 should finish in 2 seconds, then its session 2 should start.
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 1));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 2));

    // After client2's sessions finish, client1's session should resume.
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 2));
    EXPECT_EQ(mClient2->pop(kPaddingUs), EventTracker::Resume(CLIENT(2), 0));

    unregisterMultipleClients();

    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageB));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageC));

    ALOGD("TestTranscodingUidPolicy finished.");
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestTranscodingUidPolicyWithMultipleClientUids) {
    ALOGD("TestTranscodingUidPolicyWithMultipleClientUids starting...");

    EXPECT_TRUE(ShellHelper::RunCmd("input keyevent KEYCODE_WAKEUP"));
    EXPECT_TRUE(ShellHelper::RunCmd("wm dismiss-keyguard"));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageB));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageC));

    registerMultipleClients();

    ALOGD("Moving app A to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kTestActivityName));

    // Submit 3 requests.
    ALOGD("Submitting session to client1 (app A)...");
    EXPECT_TRUE(mClient1->submit(0, "test_source_file_0", "test_destination_file_0"));
    EXPECT_TRUE(mClient1->submit(1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_TRUE(mClient1->submit(2, "test_source_file_2", "test_destination_file_2"));

    // mClient1's Session 0 should start immediately.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    // Add client2 (app B)'s uid to mClient1's session 1.
    EXPECT_TRUE(mClient1->addClientUid(1, mClient2->mClientUid));

    ALOGD("Moving app B to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageB, kTestActivityName));

    // mClient1's session 0 should pause, session 1 should start.
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Pause(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));

    ALOGD("Moving app A back to top...");
    EXPECT_TRUE(ShellHelper::Start(kClientPackageA, kTestActivityName));
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 1));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Resume(CLIENT(1), 0));

    unregisterMultipleClients();

    EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageB));
    EXPECT_TRUE(ShellHelper::Stop(kClientPackageC));

    ALOGD("TestTranscodingUidPolicyWithMultipleClientUids finished.");
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestTranscodingThermalPolicy) {
    ALOGD("TestTranscodingThermalPolicy starting...");

    registerMultipleClients();

    // Submit request, should start immediately.
    EXPECT_TRUE(mClient1->submit(0, "test_source_file_0", "test_destination_file_0"));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 0));

    // Now, simulate thermal status change by adb cmd. The status code is as defined in
    // frameworks/native/include/android/thermal.h.
    // ATHERMAL_STATUS_SEVERE(3): should start throttling.
    EXPECT_TRUE(ShellHelper::RunCmd("cmd thermalservice override-status 3"));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Pause(CLIENT(1), 0));

    // ATHERMAL_STATUS_CRITICAL(4): shouldn't start throttling again (already started).
    EXPECT_TRUE(ShellHelper::RunCmd("cmd thermalservice override-status 4"));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::NoEvent);

    // ATHERMAL_STATUS_MODERATE(2): should stop throttling.
    EXPECT_TRUE(ShellHelper::RunCmd("cmd thermalservice override-status 2"));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Resume(CLIENT(1), 0));

    // ATHERMAL_STATUS_LIGHT(1): shouldn't stop throttling again (already stopped).
    EXPECT_TRUE(ShellHelper::RunCmd("cmd thermalservice override-status 1"));
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 0));

    unregisterMultipleClients();

    ALOGD("TestTranscodingThermalPolicy finished.");
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestTranscodingWatchdog) {
    ALOGD("TestTranscodingWatchdog starting...");

    registerMultipleClients();

    // SimulatedTranscoder itself does not send heartbeat. Its sessions last 1sec
    // by default, so timeout will not happen normally.
    // Here we run a session of 4000ms with TranscodingTestConfig. This will trigger
    // a watchdog timeout on server side. We use it to check that error code is correct.
    EXPECT_TRUE(mClient1->submit(
            0, "test_source_file_0", "test_destination_file_0", TranscodingSessionPriority::kNormal,
            -1 /*bitrateBps*/, -1 /*overridePid*/, -1 /*overrideUid*/, 4000 /*sessionDurationMs*/));
    EXPECT_EQ(mClient1->pop(100000), EventTracker::Start(CLIENT(1), 0));
    EXPECT_EQ(mClient1->pop(kWatchdogTimeoutUs - 100000), EventTracker::NoEvent);
    EXPECT_EQ(mClient1->pop(200000), EventTracker::Failed(CLIENT(1), 0));
    EXPECT_EQ(mClient1->getLastError(), TranscodingErrorCode::kWatchdogTimeout);

    // After the timeout, submit another request and check it's finished.
    EXPECT_TRUE(mClient1->submit(1, "test_source_file_1", "test_destination_file_1"));
    EXPECT_EQ(mClient1->pop(kPaddingUs), EventTracker::Start(CLIENT(1), 1));
    EXPECT_EQ(mClient1->pop(kSessionWithPaddingUs), EventTracker::Finished(CLIENT(1), 1));

    unregisterMultipleClients();

    ALOGD("TestTranscodingWatchdog finished.");
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestTranscodingPacerOverCountQuotaOnly) {
    ALOGD("TestTranscodingPacerOverCountQuotaOnly starting...");

    registerMultipleClients();
    testPacerHelper(12 /*numSubmits*/, 100 /*sessionDurationMs*/, 12 /*expectedSuccess*/);
    unregisterMultipleClients();

    ALOGD("TestTranscodingPacerOverCountQuotaOnly finished.");
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestTranscodingPacerOverTimeQuotaOnly) {
    ALOGD("TestTranscodingPacerOverTimeQuotaOnly starting...");

    registerMultipleClients();
    testPacerHelper(5 /*numSubmits*/, 1000 /*sessionDurationMs*/, 5 /*expectedSuccess*/);
    unregisterMultipleClients();

    ALOGD("TestTranscodingPacerOverTimeQuotaOnly finished.");
}

TEST_F(MediaTranscodingServiceSimulatedTest, TestTranscodingPacerOverQuota) {
    ALOGD("TestTranscodingPacerOverQuota starting...");

    registerMultipleClients();
    testPacerHelper(12 /*numSubmits*/, 400 /*sessionDurationMs*/, 10 /*expectedSuccess*/);
    unregisterMultipleClients();

    // Idle to clear out burst history. Since we expect it to actually fail, wait for cooldown.
    ALOGD("TestTranscodingPacerOverQuota finished.");
}

}  // namespace media
}  // namespace android
