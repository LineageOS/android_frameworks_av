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
#include <aidl/android/media/TranscodingRequestParcel.h>
#include <aidl/android/media/TranscodingSessionParcel.h>
#include <aidl/android/media/TranscodingSessionPriority.h>
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
using aidl::android::media::TranscodingRequestParcel;
using aidl::android::media::TranscodingSessionParcel;
using aidl::android::media::TranscodingSessionPriority;
using aidl::android::media::TranscodingTestConfig;
using aidl::android::media::TranscodingVideoTrackFormat;

constexpr int32_t kClientUseCallingPid = IMediaTranscodingService::USE_CALLING_PID;

constexpr uid_t kClientUid = 5000;
#define UID(n) (kClientUid + (n))

constexpr pid_t kClientPid = 10000;
#define PID(n) (kClientPid + (n))

constexpr int32_t kClientId = 0;
#define CLIENT(n) (kClientId + (n))

constexpr const char* kClientName = "TestClient";
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
        int32_t sessionId;
    };

#define DECLARE_EVENT(action)                                  \
    static Event action(int32_t clientId, int32_t sessionId) { \
        return {Event::action, clientId, sessionId};           \
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
        return "session {" + std::to_string(event.clientId) + ", " +
               std::to_string(event.sessionId) + "}: " + eventStr;
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

    bool waitForSpecificEventAndPop(const Event& target, std::list<Event>* outEvents,
                                    int64_t timeoutUs = 0) {
        std::unique_lock lock(mLock);

        auto startTime = std::chrono::system_clock::now();
        int64_t remainingUs = timeoutUs;

        std::list<Event>::iterator it;
        while (((it = std::find(mEventQueue.begin(), mEventQueue.end(), target)) ==
                mEventQueue.end()) &&
               remainingUs > 0) {
            std::cv_status status =
                    mCondition.wait_for(lock, std::chrono::microseconds(remainingUs));
            if (status == std::cv_status::timeout) {
                break;
            }
            std::chrono::microseconds elapsedTime = std::chrono::system_clock::now() - startTime;
            remainingUs = timeoutUs - elapsedTime.count();
        }

        if (it == mEventQueue.end()) {
            return false;
        }
        *outEvents = std::list<Event>(mEventQueue.begin(), std::next(it));
        mEventQueue.erase(mEventQueue.begin(), std::next(it));
        return true;
    }

    // Push 1 event to back.
    void append(const Event& event,
                const TranscodingErrorCode err = TranscodingErrorCode::kNoError) {
        ALOGD("%s", toString(event).c_str());

        std::unique_lock lock(mLock);

        mEventQueue.push_back(event);
        if (err != TranscodingErrorCode::kNoError) {
            mLastErrQueue.push_back(err);
        }
        mCondition.notify_one();
    }

    void updateProgress(int progress) {
        std::unique_lock lock(mLock);
        mLastProgress = progress;
        mUpdateCount++;
    }

    int getUpdateCount(int* lastProgress) {
        std::unique_lock lock(mLock);
        *lastProgress = mLastProgress;
        return mUpdateCount;
    }

    TranscodingErrorCode getLastError() {
        std::unique_lock lock(mLock);
        if (mLastErrQueue.empty()) {
            return TranscodingErrorCode::kNoError;
        }
        TranscodingErrorCode err = mLastErrQueue.front();
        mLastErrQueue.pop_front();
        return err;
    }

private:
    std::mutex mLock;
    std::condition_variable mCondition;
    Event mPoppedEvent;
    std::list<Event> mEventQueue;
    std::list<TranscodingErrorCode> mLastErrQueue;
    int mUpdateCount = 0;
    int mLastProgress = -1;
};

// Operators for GTest macros.
bool operator==(const EventTracker::Event& lhs, const EventTracker::Event& rhs) {
    return lhs.type == rhs.type && lhs.clientId == rhs.clientId && lhs.sessionId == rhs.sessionId;
}

std::ostream& operator<<(std::ostream& str, const EventTracker::Event& v) {
    str << EventTracker::toString(v);
    return str;
}

static constexpr bool success = true;
static constexpr bool fail = false;

struct TestClientCallback : public BnTranscodingClientCallback,
                            public EventTracker,
                            public std::enable_shared_from_this<TestClientCallback> {
    TestClientCallback(const char* packageName, int32_t id)
          : mClientId(id), mClientPid(PID(id)), mClientUid(UID(id)), mPackageName(packageName) {
        ALOGI("TestClientCallback %d created: pid %d, uid %d", id, PID(id), UID(id));

        // Use package uid if that's available.
        uid_t packageUid;
        if (getUidForPackage(String16(packageName), 0 /*userId*/, packageUid) == NO_ERROR) {
            mClientUid = packageUid;
        }
    }

    virtual ~TestClientCallback() { ALOGI("TestClientCallback %d destroyed", mClientId); }

    Status openFileDescriptor(const std::string& in_fileUri, const std::string& in_mode,
                              ::ndk::ScopedFileDescriptor* _aidl_return) override {
        ALOGD("@@@ openFileDescriptor: %s", in_fileUri.c_str());
        int fd;
        if (in_mode == "w" || in_mode == "rw") {
            int kOpenFlags;
            if (in_mode == "w") {
                // Write-only, create file if non-existent, truncate existing file.
                kOpenFlags = O_WRONLY | O_CREAT | O_TRUNC;
            } else {
                // Read-Write, create if non-existent, no truncate (service will truncate if needed)
                kOpenFlags = O_RDWR | O_CREAT;
            }
            // User R+W permission.
            constexpr int kFileMode = S_IRUSR | S_IWUSR;
            fd = open(in_fileUri.c_str(), kOpenFlags, kFileMode);
        } else {
            fd = open(in_fileUri.c_str(), O_RDONLY);
        }
        _aidl_return->set(fd);
        return Status::ok();
    }

    Status onTranscodingStarted(int32_t in_sessionId) override {
        append(EventTracker::Start(mClientId, in_sessionId));
        return Status::ok();
    }

    Status onTranscodingPaused(int32_t in_sessionId) override {
        append(EventTracker::Pause(mClientId, in_sessionId));
        return Status::ok();
    }

    Status onTranscodingResumed(int32_t in_sessionId) override {
        append(EventTracker::Resume(mClientId, in_sessionId));
        return Status::ok();
    }

    Status onTranscodingFinished(
            int32_t in_sessionId,
            const ::aidl::android::media::TranscodingResultParcel& /* in_result */) override {
        append(Finished(mClientId, in_sessionId));
        return Status::ok();
    }

    Status onTranscodingFailed(int32_t in_sessionId,
                               ::aidl::android::media::TranscodingErrorCode in_errorCode) override {
        append(Failed(mClientId, in_sessionId), in_errorCode);
        return Status::ok();
    }

    Status onAwaitNumberOfSessionsChanged(int32_t /* in_sessionId */,
                                          int32_t /* in_oldAwaitNumber */,
                                          int32_t /* in_newAwaitNumber */) override {
        return Status::ok();
    }

    Status onProgressUpdate(int32_t /* in_sessionId */, int32_t in_progress) override {
        updateProgress(in_progress);
        return Status::ok();
    }

    Status registerClient(const char* packageName,
                          const std::shared_ptr<IMediaTranscodingService>& service) {
        // Override the default uid if the package uid is found.
        uid_t uid;
        if (getUidForPackage(String16(packageName), 0 /*userId*/, uid) == NO_ERROR) {
            mClientUid = uid;
        }

        ALOGD("registering %s with uid %d", packageName, mClientUid);

        std::shared_ptr<ITranscodingClient> client;
        Status status =
                service->registerClient(shared_from_this(), kClientName, packageName, &client);

        mClient = status.isOk() ? client : nullptr;
        return status;
    }

    Status unregisterClient() {
        Status status;
        if (mClient != nullptr) {
            status = mClient->unregister();
            mClient = nullptr;
        }
        return status;
    }

    template <bool expectation = success>
    bool submit(int32_t sessionId, const char* sourceFilePath, const char* destinationFilePath,
                TranscodingSessionPriority priority = TranscodingSessionPriority::kNormal,
                int bitrateBps = -1, int overridePid = -1, int overrideUid = -1,
                int sessionDurationMs = -1) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        TranscodingRequestParcel request;
        TranscodingSessionParcel session;

        request.sourceFilePath = sourceFilePath;
        request.destinationFilePath = destinationFilePath;
        request.priority = priority;
        request.clientPid = (overridePid == -1) ? mClientPid : overridePid;
        request.clientUid = (overrideUid == -1) ? mClientUid : overrideUid;
        request.clientPackageName = (overrideUid == -1) ? mPackageName : "";
        if (bitrateBps > 0) {
            request.requestedVideoTrackFormat.emplace(TranscodingVideoTrackFormat());
            request.requestedVideoTrackFormat->bitrateBps = bitrateBps;
        }
        if (sessionDurationMs > 0) {
            request.isForTesting = true;
            request.testConfig.emplace(TranscodingTestConfig());
            request.testConfig->processingTotalTimeMs = sessionDurationMs;
        }
        Status status = mClient->submitRequest(request, &session, &result);

        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(result, shouldSucceed);
        if (shouldSucceed) {
            EXPECT_EQ(session.sessionId, sessionId);
        }

        return status.isOk() && (result == shouldSucceed) &&
               (!shouldSucceed || session.sessionId == sessionId);
    }

    template <bool expectation = success>
    bool cancel(int32_t sessionId) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        Status status = mClient->cancelSession(sessionId, &result);

        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(result, shouldSucceed);

        return status.isOk() && (result == shouldSucceed);
    }

    template <bool expectation = success>
    bool getSession(int32_t sessionId, const char* sourceFilePath,
                    const char* destinationFilePath) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        TranscodingSessionParcel session;
        Status status = mClient->getSessionWithId(sessionId, &session, &result);

        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(result, shouldSucceed);
        if (shouldSucceed) {
            EXPECT_EQ(session.sessionId, sessionId);
            EXPECT_EQ(session.request.sourceFilePath, sourceFilePath);
        }

        return status.isOk() && (result == shouldSucceed) &&
               (!shouldSucceed || (session.sessionId == sessionId &&
                                   session.request.sourceFilePath == sourceFilePath &&
                                   session.request.destinationFilePath == destinationFilePath));
    }

    template <bool expectation = success>
    bool addClientUid(int32_t sessionId, uid_t clientUid) {
        constexpr bool shouldSucceed = (expectation == success);
        bool result;
        Status status = mClient->addClientUid(sessionId, clientUid, &result);

        EXPECT_TRUE(status.isOk());
        EXPECT_EQ(result, shouldSucceed);

        return status.isOk() && (result == shouldSucceed);
    }

    template <bool expectation = success>
    bool getClientUids(int32_t sessionId, std::vector<int32_t>* clientUids) {
        constexpr bool shouldSucceed = (expectation == success);
        std::optional<std::vector<int32_t>> aidl_return;
        Status status = mClient->getClientUids(sessionId, &aidl_return);

        EXPECT_TRUE(status.isOk());
        bool success = (aidl_return != std::nullopt);
        if (success) {
            *clientUids = *aidl_return;
        }
        EXPECT_EQ(success, shouldSucceed);

        return status.isOk() && (success == shouldSucceed);
    }

    int32_t mClientId;
    pid_t mClientPid;
    uid_t mClientUid;
    std::string mPackageName;
    std::shared_ptr<ITranscodingClient> mClient;
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
        ::ndk::SpAIBinder binder(AServiceManager_waitForService("media.transcoding"));
        mService = IMediaTranscodingService::fromBinder(binder);
        if (mService == nullptr) {
            ALOGE("Failed to connect to the media.trascoding service.");
            return;
        }

        mClient1 = ::ndk::SharedRefBase::make<TestClientCallback>(kClientPackageA, 1);
        mClient2 = ::ndk::SharedRefBase::make<TestClientCallback>(kClientPackageB, 2);
        mClient3 = ::ndk::SharedRefBase::make<TestClientCallback>(kClientPackageC, 3);
    }

    Status registerOneClient(const std::shared_ptr<TestClientCallback>& callback) {
        ALOGD("registering %s with uid %d", callback->mPackageName.c_str(), callback->mClientUid);

        std::shared_ptr<ITranscodingClient> client;
        Status status =
                mService->registerClient(callback, kClientName, callback->mPackageName, &client);

        if (status.isOk()) {
            callback->mClient = client;
        } else {
            callback->mClient = nullptr;
        }
        return status;
    }

    void registerMultipleClients() {
        // Register 3 clients.
        EXPECT_TRUE(registerOneClient(mClient1).isOk());
        EXPECT_TRUE(registerOneClient(mClient2).isOk());
        EXPECT_TRUE(registerOneClient(mClient3).isOk());

        // Check the number of clients.
        int32_t numOfClients;
        Status status = mService->getNumOfClients(&numOfClients);
        EXPECT_TRUE(status.isOk());
        EXPECT_GE(numOfClients, 3);
    }

    void unregisterMultipleClients() {
        // Unregister the clients.
        EXPECT_TRUE(mClient1->unregisterClient().isOk());
        EXPECT_TRUE(mClient2->unregisterClient().isOk());
        EXPECT_TRUE(mClient3->unregisterClient().isOk());
    }

    const char* prepareOutputFile(const char* path) {
        deleteFile(path);
        return path;
    }

    void deleteFile(const char* path) { unlink(path); }

    void dismissKeyguard() {
        EXPECT_TRUE(ShellHelper::RunCmd("input keyevent KEYCODE_WAKEUP"));
        EXPECT_TRUE(ShellHelper::RunCmd("wm dismiss-keyguard"));
    }

    void stopAppPackages() {
        EXPECT_TRUE(ShellHelper::Stop(kClientPackageA));
        EXPECT_TRUE(ShellHelper::Stop(kClientPackageB));
        EXPECT_TRUE(ShellHelper::Stop(kClientPackageC));
    }

    std::shared_ptr<IMediaTranscodingService> mService;
    std::shared_ptr<TestClientCallback> mClient1;
    std::shared_ptr<TestClientCallback> mClient2;
    std::shared_ptr<TestClientCallback> mClient3;
};

}  // namespace media
}  // namespace android
