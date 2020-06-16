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
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
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
using aidl::android::media::TranscodingVideoTrackFormat;

constexpr int32_t kClientUseCallingPid = IMediaTranscodingService::USE_CALLING_PID;

constexpr uid_t kClientUid = 5000;
#define UID(n) (kClientUid + (n))

constexpr int32_t kClientId = 0;
#define CLIENT(n) (kClientId + (n))

constexpr const char* kClientName = "TestClient";
constexpr const char* kClientPackageA = "com.android.tests.transcoding.testapp.A";
constexpr const char* kClientPackageB = "com.android.tests.transcoding.testapp.B";
constexpr const char* kClientPackageC = "com.android.tests.transcoding.testapp.C";

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

    Status openFileDescriptor(const std::string& in_fileUri, const std::string& in_mode,
                              ::ndk::ScopedFileDescriptor* _aidl_return) override {
        ALOGD("@@@ openFileDescriptor: %s", in_fileUri.c_str());
        int fd;
        if (in_mode == "w" || in_mode == "rw") {
            // Write-only, create file if non-existent, don't overwrite existing file.
            constexpr int kOpenFlags = O_WRONLY | O_CREAT | O_EXCL;
            // User R+W permission.
            constexpr int kFileMode = S_IRUSR | S_IWUSR;
            fd = open(in_fileUri.c_str(), kOpenFlags, kFileMode);
        } else {
            fd = open(in_fileUri.c_str(), O_RDONLY);
        }
        _aidl_return->set(fd);
        return Status::ok();
    }

    Status onTranscodingStarted(int32_t in_jobId) override {
        append(EventTracker::Start(mClientId, in_jobId));
        return Status::ok();
    }

    Status onTranscodingPaused(int32_t in_jobId) override {
        append(EventTracker::Pause(mClientId, in_jobId));
        return Status::ok();
    }

    Status onTranscodingResumed(int32_t in_jobId) override {
        append(EventTracker::Resume(mClientId, in_jobId));
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

    Status onProgressUpdate(int32_t /* in_jobId */, int32_t /* in_progress */) override {
        return Status::ok();
    }

    int32_t mClientId;
};

class MediaTranscodingServiceTestBase : public ::testing::Test {
public:
    MediaTranscodingServiceTestBase() { ALOGI("MediaTranscodingServiceTestBase created"); }

    virtual ~MediaTranscodingServiceTestBase() {
        ALOGI("MediaTranscodingServiceTestBase destroyed");
    }

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
                TranscodingJobPriority priority = TranscodingJobPriority::kNormal,
                int bitrateBps = -1) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        TranscodingRequestParcel request;
        TranscodingJobParcel job;

        request.sourceFilePath = sourceFilePath;
        request.destinationFilePath = destinationFilePath;
        request.priority = priority;
        if (bitrateBps > 0) {
            request.requestedVideoTrackFormat.emplace(TranscodingVideoTrackFormat());
            request.requestedVideoTrackFormat->bitrateBps = bitrateBps;
        }
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

    void deleteFile(const char* path) { unlink(path); }

    std::shared_ptr<IMediaTranscodingService> mService;
    std::shared_ptr<TestClientCallback> mClientCallback1;
    std::shared_ptr<TestClientCallback> mClientCallback2;
    std::shared_ptr<TestClientCallback> mClientCallback3;
    std::shared_ptr<ITranscodingClient> mClient1;
    std::shared_ptr<ITranscodingClient> mClient2;
    std::shared_ptr<ITranscodingClient> mClient3;
    const char* mTestName;
};

}  // namespace media
}  // namespace android
