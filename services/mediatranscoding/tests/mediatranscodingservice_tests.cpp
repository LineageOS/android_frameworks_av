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

#include "SimulatedTranscoder.h"

namespace android {

namespace media {

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnTranscodingClientCallback;
using aidl::android::media::IMediaTranscodingService;
using aidl::android::media::ITranscodingClient;
using aidl::android::media::ITranscodingClientCallback;
using aidl::android::media::TranscodingJobParcel;
using aidl::android::media::TranscodingJobPriority;
using aidl::android::media::TranscodingRequestParcel;

// Note that -1 is valid and means using calling pid/uid for the service. But only privilege caller could
// use them. This test is not a privilege caller.
constexpr int32_t kInvalidClientPid = -5;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientOpPackageName = "";

constexpr int32_t kClientUseCallingPid = IMediaTranscodingService::USE_CALLING_PID;
constexpr int32_t kClientUseCallingUid = IMediaTranscodingService::USE_CALLING_UID;

constexpr uid_t kClientUid = 5000;
#define UID(n) (kClientUid + (n))

constexpr int32_t kClientId = 0;
#define CLIENT(n) (kClientId + (n))

constexpr int64_t kPaddingUs = 1000000;
constexpr int64_t kJobWithPaddingUs = SimulatedTranscoder::kJobDurationUs + kPaddingUs;

constexpr const char* kClientName = "TestClient";
constexpr const char* kClientOpPackageName = "TestClientPackage";
constexpr const char* kClientPackageA = "com.android.tests.transcoding.testapp.A";
constexpr const char* kClientPackageB = "com.android.tests.transcoding.testapp.B";
constexpr const char* kClientPackageC = "com.android.tests.transcoding.testapp.C";
constexpr const char* kTestActivityName = "/com.android.tests.transcoding.MainActivity";

static status_t getUidForPackage(String16 packageName, userid_t userId, /*inout*/ uid_t& uid) {
    PermissionController pc;
    uid = pc.getPackageUid(packageName, 0);
    if (uid <= 0) {
        ALOGE("Unknown package: '%s'", String8(packageName).string());
        return BAD_VALUE;
    }

    if (userId < 0) {
        ALOGE("Invalid user: %d", userId);
        return BAD_VALUE;
    }

    uid = multiuser_get_uid(userId, uid);
    return NO_ERROR;
}

struct ShellHelper {
    static bool RunCmd(const std::string& cmdStr) {
        int ret = system(cmdStr.c_str());
        if (ret != 0) {
            ALOGE("Failed to run cmd: %s, exitcode %d", cmdStr.c_str(), ret);
            return false;
        }
        return true;
    }

    static bool Start(const char* packageName, const char* activityName) {
        return RunCmd("am start -W " + std::string(packageName) + std::string(activityName) +
                      " &> /dev/null");
    }

    static bool Stop(const char* packageName) {
        return RunCmd("am force-stop " + std::string(packageName));
    }
};

struct EventTracker {
    struct Event {
        enum { NoEvent, Start, Pause, Resume, Finished, Failed } type;
        int64_t clientId;
        int32_t jobId;
    };

#define DECLARE_EVENT(action)                              \
    static Event action(int32_t clientId, int32_t jobId) { \
        return {Event::action, clientId, jobId};           \
    }

    DECLARE_EVENT(Start);
    DECLARE_EVENT(Pause);
    DECLARE_EVENT(Resume);
    DECLARE_EVENT(Finished);
    DECLARE_EVENT(Failed);

    static constexpr Event NoEvent = {Event::NoEvent, 0, 0};

    static std::string toString(const Event& event) {
        std::string eventStr;
        switch (event.type) {
        case Event::Start:
            eventStr = "Start";
            break;
        case Event::Pause:
            eventStr = "Pause";
            break;
        case Event::Resume:
            eventStr = "Resume";
            break;
        case Event::Finished:
            eventStr = "Finished";
            break;
        case Event::Failed:
            eventStr = "Failed";
            break;
        default:
            return "NoEvent";
        }
        return "job {" + std::to_string(event.clientId) + ", " + std::to_string(event.jobId) +
               "}: " + eventStr;
    }

    // Pop 1 event from front, wait for up to timeoutUs if empty.
    const Event& pop(int64_t timeoutUs = 0) {
        std::unique_lock lock(mLock);

        if (mEventQueue.empty() && timeoutUs > 0) {
            mCondition.wait_for(lock, std::chrono::microseconds(timeoutUs));
        }

        if (mEventQueue.empty()) {
            mPoppedEvent = NoEvent;
        } else {
            mPoppedEvent = *mEventQueue.begin();
            mEventQueue.pop_front();
        }

        return mPoppedEvent;
    }

    // Push 1 event to back.
    void append(const Event& event) {
        ALOGD("%s", toString(event).c_str());

        std::unique_lock lock(mLock);

        mEventQueue.push_back(event);
        mCondition.notify_one();
    }

private:
    std::mutex mLock;
    std::condition_variable mCondition;
    Event mPoppedEvent;
    std::list<Event> mEventQueue;
};

// Operators for GTest macros.
bool operator==(const EventTracker::Event& lhs, const EventTracker::Event& rhs) {
    return lhs.type == rhs.type && lhs.clientId == rhs.clientId && lhs.jobId == rhs.jobId;
}

std::ostream& operator<<(std::ostream& str, const EventTracker::Event& v) {
    str << EventTracker::toString(v);
    return str;
}

struct TestClientCallback : public BnTranscodingClientCallback, public EventTracker {
    TestClientCallback(int32_t id) : mClientId(id) {
        ALOGI("TestClientCallback %d Created", mClientId);
    }

    virtual ~TestClientCallback() { ALOGI("TestClientCallback %d destroyed", mClientId); }

    Status openFileDescriptor(const std::string& /*in_fileUri*/, const std::string& /*in_mode*/,
                              ::ndk::ScopedFileDescriptor* /*_aidl_return*/) override {
        return Status::ok();
    }

    Status onTranscodingStarted(int32_t in_jobId) override {
        append(Start(mClientId, in_jobId));
        return Status::ok();
    }

    Status onTranscodingPaused(int32_t in_jobId) override {
        append(Pause(mClientId, in_jobId));
        return Status::ok();
    }

    Status onTranscodingResumed(int32_t in_jobId) override {
        append(Resume(mClientId, in_jobId));
        return Status::ok();
    }

    Status onTranscodingFinished(
            int32_t in_jobId,
            const ::aidl::android::media::TranscodingResultParcel& /* in_result */) override {
        append(Finished(mClientId, in_jobId));
        return Status::ok();
    }

    Status onTranscodingFailed(
            int32_t in_jobId,
            ::aidl::android::media::TranscodingErrorCode /* in_errorCode */) override {
        append(Failed(mClientId, in_jobId));
        return Status::ok();
    }

    Status onAwaitNumberOfJobsChanged(int32_t /* in_jobId */, int32_t /* in_oldAwaitNumber */,
                                      int32_t /* in_newAwaitNumber */) override {
        return Status::ok();
    }

    Status onProgressUpdate(int32_t /*in_jobId*/, int32_t /*in_progress*/) override {
        return Status::ok();
    }

    int32_t mClientId;
};

class MediaTranscodingServiceTest : public ::testing::Test {
public:
    MediaTranscodingServiceTest() { ALOGI("MediaTranscodingServiceTest created"); }

    ~MediaTranscodingServiceTest() { ALOGI("MediaTranscodingingServiceTest destroyed"); }

    void SetUp() override {
        // Need thread pool to receive callbacks, otherwise oneway callbacks are
        // silently ignored.
        ABinderProcess_startThreadPool();
        ::ndk::SpAIBinder binder(AServiceManager_getService("media.transcoding"));
        mService = IMediaTranscodingService::fromBinder(binder);
        if (mService == nullptr) {
            ALOGE("Failed to connect to the media.trascoding service.");
            return;
        }
        mClientCallback1 = ::ndk::SharedRefBase::make<TestClientCallback>(CLIENT(1));
        mClientCallback2 = ::ndk::SharedRefBase::make<TestClientCallback>(CLIENT(2));
        mClientCallback3 = ::ndk::SharedRefBase::make<TestClientCallback>(CLIENT(3));
    }

    std::shared_ptr<ITranscodingClient> registerOneClient(
            const char* packageName, const std::shared_ptr<TestClientCallback>& callback,
            uid_t defaultUid) {
        uid_t uid;
        if (getUidForPackage(String16(packageName), 0 /*userId*/, uid) != NO_ERROR) {
            uid = defaultUid;
        }

        ALOGD("registering %s with uid %d", packageName, uid);

        std::shared_ptr<ITranscodingClient> client;
        Status status = mService->registerClient(callback, kClientName, packageName, uid,
                                                 kClientUseCallingPid, &client);
        return status.isOk() ? client : nullptr;
    }

    void registerMultipleClients() {
        // Register 3 clients.
        mClient1 = registerOneClient(kClientPackageA, mClientCallback1, UID(1));
        EXPECT_TRUE(mClient1 != nullptr);

        mClient2 = registerOneClient(kClientPackageB, mClientCallback2, UID(2));
        EXPECT_TRUE(mClient2 != nullptr);

        mClient3 = registerOneClient(kClientPackageC, mClientCallback3, UID(3));
        EXPECT_TRUE(mClient3 != nullptr);

        // Check the number of clients.
        int32_t numOfClients;
        Status status = mService->getNumOfClients(&numOfClients);
        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(3, numOfClients);
    }

    void unregisterMultipleClients() {
        Status status;

        // Unregister the clients.
        status = mClient1->unregister();
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

    static constexpr bool success = true;
    static constexpr bool fail = false;

    template <bool expectation = success>
    bool submit(const std::shared_ptr<ITranscodingClient>& client, int32_t jobId,
                const char* sourceFilePath, const char* destinationFilePath,
                TranscodingJobPriority priority = TranscodingJobPriority::kNormal) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        TranscodingRequestParcel request;
        TranscodingJobParcel job;

        request.sourceFilePath = sourceFilePath;
        request.destinationFilePath = destinationFilePath;
        request.priority = priority;
        Status status = client->submitRequest(request, &job, &result);

        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(result, shouldSucceed);
        if (shouldSucceed) {
            EXPECT_EQ(job.jobId, jobId);
        }

        return status.isOk() && (result == shouldSucceed) && (!shouldSucceed || job.jobId == jobId);
    }

    template <bool expectation = success>
    bool cancel(const std::shared_ptr<ITranscodingClient>& client, int32_t jobId) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        Status status = client->cancelJob(jobId, &result);

        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(result, shouldSucceed);

        return status.isOk() && (result == shouldSucceed);
    }

    template <bool expectation = success>
    bool getJob(const std::shared_ptr<ITranscodingClient>& client, int32_t jobId,
                const char* sourceFilePath, const char* destinationFilePath) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        TranscodingJobParcel job;
        Status status = client->getJobWithId(jobId, &job, &result);

        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(result, shouldSucceed);
        if (shouldSucceed) {
            EXPECT_EQ(job.jobId, jobId);
            EXPECT_EQ(job.request.sourceFilePath, sourceFilePath);
        }

        return status.isOk() && (result == shouldSucceed) &&
               (!shouldSucceed ||
                (job.jobId == jobId && job.request.sourceFilePath == sourceFilePath &&
                 job.request.destinationFilePath == destinationFilePath));
    }

    std::shared_ptr<IMediaTranscodingService> mService;
    std::shared_ptr<TestClientCallback> mClientCallback1;
    std::shared_ptr<TestClientCallback> mClientCallback2;
    std::shared_ptr<TestClientCallback> mClientCallback3;
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
    Status status = mService->registerClient(mClientCallback1, kClientName, kClientOpPackageName,
                                             kClientUseCallingUid, kInvalidClientPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status = mService->registerClient(mClientCallback1, kInvalidClientName,
                                             kInvalidClientOpPackageName, kClientUseCallingUid,
                                             kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterClientWithInvalidClientPackageName) {
    std::shared_ptr<ITranscodingClient> client;

    // Register the client with the service.
    Status status =
            mService->registerClient(mClientCallback1, kClientName, kInvalidClientOpPackageName,
                                     kClientUseCallingUid, kClientUseCallingPid, &client);
    EXPECT_FALSE(status.isOk());
}

TEST_F(MediaTranscodingServiceTest, TestRegisterOneClient) {
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

TEST_F(MediaTranscodingServiceTest, TestRegisterClientTwice) {
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

TEST_F(MediaTranscodingServiceTest, TestRegisterMultipleClients) {
    registerMultipleClients();
    unregisterMultipleClients();
}

TEST_F(MediaTranscodingServiceTest, TestJobIdIndependence) {
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

TEST_F(MediaTranscodingServiceTest, TestSubmitCancelJobs) {
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

TEST_F(MediaTranscodingServiceTest, TestGetJobs) {
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

TEST_F(MediaTranscodingServiceTest, TestSubmitCancelWithOfflineJobs) {
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

TEST_F(MediaTranscodingServiceTest, TestClientUseAfterUnregister) {
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

TEST_F(MediaTranscodingServiceTest, TestTranscodingUidPolicy) {
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
