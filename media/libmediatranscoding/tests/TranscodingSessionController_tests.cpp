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

// Unit Test for TranscodingSessionController

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingSessionControllerTest"

#include <aidl/android/media/BnTranscodingClientCallback.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <aidl/android/media/ITranscodingClient.h>
#include <aidl/android/media/ITranscodingClientCallback.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingSessionController.h>
#include <utils/Log.h>

#include <unordered_set>

namespace android {

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnTranscodingClientCallback;
using aidl::android::media::IMediaTranscodingService;
using aidl::android::media::ITranscodingClient;
using aidl::android::media::TranscodingRequestParcel;

constexpr ClientIdType kClientId = 1000;
constexpr SessionIdType kClientSessionId = 0;
constexpr uid_t kClientUid = 5000;
constexpr pid_t kClientPid = 10000;
constexpr uid_t kInvalidUid = (uid_t)-1;
constexpr pid_t kInvalidPid = (pid_t)-1;

#define CLIENT(n) (kClientId + (n))
#define SESSION(n) (kClientSessionId + (n))
#define UID(n) (kClientUid + (n))
#define PID(n) (kClientPid + (n))

class TestUidPolicy : public UidPolicyInterface {
public:
    TestUidPolicy() = default;
    virtual ~TestUidPolicy() = default;

    // UidPolicyInterface
    void registerMonitorUid(uid_t /*uid*/) override {}
    void unregisterMonitorUid(uid_t /*uid*/) override {}
    bool isUidOnTop(uid_t uid) override { return mTopUids.count(uid) > 0; }
    std::unordered_set<uid_t> getTopUids() const override { return mTopUids; }
    void setCallback(const std::shared_ptr<UidPolicyCallbackInterface>& cb) override {
        mUidPolicyCallback = cb;
    }
    void setTop(uid_t uid) {
        std::unordered_set<uid_t> uids = {uid};
        setTop(uids);
    }
    void setTop(const std::unordered_set<uid_t>& uids) {
        mTopUids = uids;
        auto uidPolicyCb = mUidPolicyCallback.lock();
        if (uidPolicyCb != nullptr) {
            uidPolicyCb->onTopUidsChanged(mTopUids);
        }
    }

    std::unordered_set<uid_t> mTopUids;
    std::weak_ptr<UidPolicyCallbackInterface> mUidPolicyCallback;
};

class TestResourcePolicy : public ResourcePolicyInterface {
public:
    TestResourcePolicy() { reset(); }
    virtual ~TestResourcePolicy() = default;

    // ResourcePolicyInterface
    void setCallback(const std::shared_ptr<ResourcePolicyCallbackInterface>& /*cb*/) override {}
    void setPidResourceLost(pid_t pid) override { mResourceLostPid = pid; }
    // ~ResourcePolicyInterface

    pid_t getPid() {
        pid_t result = mResourceLostPid;
        reset();
        return result;
    }

private:
    void reset() { mResourceLostPid = kInvalidPid; }
    pid_t mResourceLostPid;
};

class TestThermalPolicy : public ThermalPolicyInterface {
public:
    TestThermalPolicy() = default;
    virtual ~TestThermalPolicy() = default;

    // ThermalPolicyInterface
    void setCallback(const std::shared_ptr<ThermalPolicyCallbackInterface>& /*cb*/) override {}
    bool getThrottlingStatus() { return false; }
    // ~ThermalPolicyInterface

private:
};

class TestTranscoder : public TranscoderInterface {
public:
    TestTranscoder() : mLastError(TranscodingErrorCode::kUnknown) {}
    virtual ~TestTranscoder() {}

    // TranscoderInterface
    void setCallback(const std::shared_ptr<TranscoderCallbackInterface>& /*cb*/) override {}

    void start(ClientIdType clientId, SessionIdType sessionId,
               const TranscodingRequestParcel& /*request*/,
               const std::shared_ptr<ITranscodingClientCallback>& /*clientCallback*/) override {
        mEventQueue.push_back(Start(clientId, sessionId));
    }
    void pause(ClientIdType clientId, SessionIdType sessionId) override {
        mEventQueue.push_back(Pause(clientId, sessionId));
    }
    void resume(ClientIdType clientId, SessionIdType sessionId,
                const TranscodingRequestParcel& /*request*/,
                const std::shared_ptr<ITranscodingClientCallback>& /*clientCallback*/) override {
        mEventQueue.push_back(Resume(clientId, sessionId));
    }
    void stop(ClientIdType clientId, SessionIdType sessionId) override {
        mEventQueue.push_back(Stop(clientId, sessionId));
    }

    void onFinished(ClientIdType clientId, SessionIdType sessionId) {
        mEventQueue.push_back(Finished(clientId, sessionId));
    }

    void onFailed(ClientIdType clientId, SessionIdType sessionId, TranscodingErrorCode err) {
        mLastError = err;
        mEventQueue.push_back(Failed(clientId, sessionId));
    }

    TranscodingErrorCode getLastError() {
        TranscodingErrorCode result = mLastError;
        mLastError = TranscodingErrorCode::kUnknown;
        return result;
    }

    struct Event {
        enum { NoEvent, Start, Pause, Resume, Stop, Finished, Failed } type;
        ClientIdType clientId;
        SessionIdType sessionId;
    };

    static constexpr Event NoEvent = {Event::NoEvent, 0, 0};

#define DECLARE_EVENT(action)                                             \
    static Event action(ClientIdType clientId, SessionIdType sessionId) { \
        return {Event::action, clientId, sessionId};                      \
    }

    DECLARE_EVENT(Start);
    DECLARE_EVENT(Pause);
    DECLARE_EVENT(Resume);
    DECLARE_EVENT(Stop);
    DECLARE_EVENT(Finished);
    DECLARE_EVENT(Failed);

    const Event& popEvent() {
        if (mEventQueue.empty()) {
            mPoppedEvent = NoEvent;
        } else {
            mPoppedEvent = *mEventQueue.begin();
            mEventQueue.pop_front();
        }
        return mPoppedEvent;
    }

private:
    Event mPoppedEvent;
    std::list<Event> mEventQueue;
    TranscodingErrorCode mLastError;
};

bool operator==(const TestTranscoder::Event& lhs, const TestTranscoder::Event& rhs) {
    return lhs.type == rhs.type && lhs.clientId == rhs.clientId && lhs.sessionId == rhs.sessionId;
}

struct TestClientCallback : public BnTranscodingClientCallback {
    TestClientCallback(TestTranscoder* owner, int64_t clientId)
          : mOwner(owner), mClientId(clientId) {
        ALOGD("TestClient Created");
    }

    Status openFileDescriptor(const std::string& /*in_fileUri*/, const std::string& /*in_mode*/,
                              ::ndk::ScopedFileDescriptor* /*_aidl_return*/) override {
        return Status::ok();
    }

    Status onTranscodingStarted(int32_t /*in_sessionId*/) override { return Status::ok(); }

    Status onTranscodingPaused(int32_t /*in_sessionId*/) override { return Status::ok(); }

    Status onTranscodingResumed(int32_t /*in_sessionId*/) override { return Status::ok(); }

    Status onTranscodingFinished(int32_t in_sessionId,
                                 const TranscodingResultParcel& in_result) override {
        EXPECT_EQ(in_sessionId, in_result.sessionId);
        ALOGD("TestClientCallback: received onTranscodingFinished");
        mOwner->onFinished(mClientId, in_sessionId);
        return Status::ok();
    }

    Status onTranscodingFailed(int32_t in_sessionId, TranscodingErrorCode in_errorCode) override {
        mOwner->onFailed(mClientId, in_sessionId, in_errorCode);
        return Status::ok();
    }

    Status onAwaitNumberOfSessionsChanged(int32_t /* in_sessionId */,
                                          int32_t /* in_oldAwaitNumber */,
                                          int32_t /* in_newAwaitNumber */) override {
        return Status::ok();
    }

    Status onProgressUpdate(int32_t /* in_sessionId */, int32_t /* in_progress */) override {
        return Status::ok();
    }

    virtual ~TestClientCallback() { ALOGI("TestClient destroyed"); };

private:
    TestTranscoder* mOwner;
    int64_t mClientId;
    TestClientCallback(const TestClientCallback&) = delete;
    TestClientCallback& operator=(const TestClientCallback&) = delete;
};

class TranscodingSessionControllerTest : public ::testing::Test {
public:
    TranscodingSessionControllerTest() { ALOGI("TranscodingSessionControllerTest created"); }

    void SetUp() override {
        ALOGI("TranscodingSessionControllerTest set up");
        mTranscoder.reset(new TestTranscoder());
        mUidPolicy.reset(new TestUidPolicy());
        mResourcePolicy.reset(new TestResourcePolicy());
        mThermalPolicy.reset(new TestThermalPolicy());
        mController.reset(new TranscodingSessionController(mTranscoder, mUidPolicy, mResourcePolicy,
                                                           mThermalPolicy));
        mUidPolicy->setCallback(mController);

        // Set priority only, ignore other fields for now.
        mOfflineRequest.priority = TranscodingSessionPriority::kUnspecified;
        mRealtimeRequest.priority = TranscodingSessionPriority::kHigh;
        mClientCallback0 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(0));
        mClientCallback1 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(1));
        mClientCallback2 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(2));
        mClientCallback3 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(3));
    }

    void TearDown() override { ALOGI("TranscodingSessionControllerTest tear down"); }

    ~TranscodingSessionControllerTest() { ALOGD("TranscodingSessionControllerTest destroyed"); }

    std::shared_ptr<TestTranscoder> mTranscoder;
    std::shared_ptr<TestUidPolicy> mUidPolicy;
    std::shared_ptr<TestResourcePolicy> mResourcePolicy;
    std::shared_ptr<TestThermalPolicy> mThermalPolicy;
    std::shared_ptr<TranscodingSessionController> mController;
    TranscodingRequestParcel mOfflineRequest;
    TranscodingRequestParcel mRealtimeRequest;
    std::shared_ptr<TestClientCallback> mClientCallback0;
    std::shared_ptr<TestClientCallback> mClientCallback1;
    std::shared_ptr<TestClientCallback> mClientCallback2;
    std::shared_ptr<TestClientCallback> mClientCallback3;
};

TEST_F(TranscodingSessionControllerTest, TestSubmitSession) {
    ALOGD("TestSubmitSession");

    // Start with UID(1) on top.
    mUidPolicy->setTop(UID(1));

    // Submit offline session to CLIENT(0) in UID(0).
    // Should start immediately (because this is the only session).
    mController->submit(CLIENT(0), SESSION(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), 0));

    // Submit real-time session to CLIENT(0).
    // Should pause offline session and start new session,  even if UID(0) is not on top.
    mController->submit(CLIENT(0), SESSION(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Submit real-time session to CLIENT(0), should be queued after the previous session.
    mController->submit(CLIENT(0), SESSION(2), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(1) in same uid, should be queued after the previous
    // session.
    mController->submit(CLIENT(1), SESSION(0), UID(0), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in UID(1).
    // Should pause previous session and start new session, because UID(1) is (has been) top.
    mController->submit(CLIENT(2), SESSION(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), SESSION(0)));

    // Submit offline session, shouldn't generate any event.
    mController->submit(CLIENT(2), SESSION(1), UID(1), mOfflineRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Bring UID(0) to top.
    mUidPolicy->setTop(UID(0));
    // Should pause current session, and resume last session in UID(0).
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(1)));
}

TEST_F(TranscodingSessionControllerTest, TestCancelSession) {
    ALOGD("TestCancelSession");

    // Submit real-time session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should not start.
    mController->submit(CLIENT(0), SESSION(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Cancel queued real-time session.
    // Cancel real-time session SESSION(1), should be cancelled.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(1)));

    // Cancel queued offline session.
    // Cancel offline session SESSION(2), should be cancelled.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(2)));

    // Submit offline session SESSION(3), shouldn't cause any event.
    mController->submit(CLIENT(0), SESSION(3), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Cancel running real-time session SESSION(0).
    // - Should be stopped first then cancelled.
    // - Should also start offline session SESSION(2) because real-time queue is empty.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(3)));

    // Submit real-time session SESSION(4), offline SESSION(3) should pause and SESSION(4)
    // should start.
    mController->submit(CLIENT(0), SESSION(4), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(4)));

    // Cancel paused SESSION(3). SESSION(3) should be stopped.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(3)));
}

TEST_F(TranscodingSessionControllerTest, TestFinishSession) {
    ALOGD("TestFinishSession");

    // Start with unspecified top UID.
    // Finish without any sessions submitted, should be ignored.
    mController->onFinish(CLIENT(0), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should pause offline session and start immediately.
    mController->submit(CLIENT(0), SESSION(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Submit real-time session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Finish when the session never started, should be ignored.
    mController->onFinish(CLIENT(0), SESSION(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // Submit real-time session to CLIENT(1) in UID(1), should pause previous session and start
    // new session.
    mController->submit(CLIENT(1), SESSION(0), UID(1), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), SESSION(0)));

    // Simulate Finish that arrived late, after pause issued by controller.
    // Should still be propagated to client, but shouldn't trigger any new start.
    mController->onFinish(CLIENT(0), SESSION(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(1)));

    // Finish running real-time session, should start next real-time session in queue.
    mController->onFinish(CLIENT(1), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(1), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));

    // Finish running real-time session, should resume next session (offline session) in queue.
    mController->onFinish(CLIENT(0), SESSION(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(2)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Finish running offline session.
    mController->onFinish(CLIENT(0), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(0)));

    // Duplicate finish for last session, should be ignored.
    mController->onFinish(CLIENT(0), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
}

TEST_F(TranscodingSessionControllerTest, TestFailSession) {
    ALOGD("TestFailSession");

    // Start with unspecified top UID.
    // Fail without any sessions submitted, should be ignored.
    mController->onError(CLIENT(0), SESSION(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should pause offline session and start immediately.
    mController->submit(CLIENT(0), SESSION(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Submit real-time session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Fail when the session never started, should be ignored.
    mController->onError(CLIENT(0), SESSION(2), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // Submit real-time session to CLIENT(1) in UID(1), should pause previous session and start
    // new session.
    mController->submit(CLIENT(1), SESSION(0), UID(1), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), SESSION(0)));

    // Simulate Fail that arrived late, after pause issued by controller.
    // Should still be propagated to client, but shouldn't trigger any new start.
    mController->onError(CLIENT(0), SESSION(1), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(1)));

    // Fail running real-time session, should start next real-time session in queue.
    mController->onError(CLIENT(1), SESSION(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(1), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));

    // Fail running real-time session, should resume next session (offline session) in queue.
    mController->onError(CLIENT(0), SESSION(2), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(2)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Fail running offline session, and test error code propagation.
    mController->onError(CLIENT(0), SESSION(0), TranscodingErrorCode::kInvalidOperation);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kInvalidOperation);

    // Duplicate fail for last session, should be ignored.
    mController->onError(CLIENT(0), SESSION(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
}

TEST_F(TranscodingSessionControllerTest, TestTopUidChanged) {
    ALOGD("TestTopUidChanged");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mController->submit(CLIENT(1), SESSION(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mController->submit(CLIENT(2), SESSION(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), SESSION(0)));

    // Bring UID(0) back to top.
    mUidPolicy->setTop(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Bring invalid uid to top.
    mUidPolicy->setTop(kInvalidUid);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Finish session, next real-time session should resume.
    mController->onFinish(CLIENT(0), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Finish session, offline session should start.
    mController->onFinish(CLIENT(2), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(2), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), SESSION(0)));
}

TEST_F(TranscodingSessionControllerTest, TestTopUidSetChanged) {
    ALOGD("TestTopUidChanged_MultipleUids");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mController->submit(CLIENT(1), SESSION(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Set UID(0), UID(1) to top set.
    // UID(0) should continue to run.
    mUidPolicy->setTop({UID(0), UID(1)});
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // UID(0) should pause and UID(1) should start.
    mController->submit(CLIENT(2), SESSION(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), SESSION(0)));

    // Remove UID(0) from top set, and only leave UID(1) in the set.
    // UID(1) should continue to run.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Set UID(0), UID(2) to top set.
    // UID(1) should continue to run.
    mUidPolicy->setTop({UID(1), UID(2)});
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Bring UID(0) back to top.
    mUidPolicy->setTop(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Bring invalid uid to top.
    mUidPolicy->setTop(kInvalidUid);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Finish session, next real-time session from UID(1) should resume, even if UID(1)
    // no longer top.
    mController->onFinish(CLIENT(0), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Finish session, offline session should start.
    mController->onFinish(CLIENT(2), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(2), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), SESSION(0)));
}

/* Test resource lost without thermal throttling */
TEST_F(TranscodingSessionControllerTest, TestResourceLost) {
    ALOGD("TestResourceLost");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mRealtimeRequest.clientPid = PID(0);
    mController->submit(CLIENT(0), SESSION(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mOfflineRequest.clientPid = PID(0);
    mController->submit(CLIENT(1), SESSION(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mRealtimeRequest.clientPid = PID(1);
    mController->submit(CLIENT(2), SESSION(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), SESSION(0)));

    // Test 0: No call into ResourcePolicy if resource lost is from a non-running
    // or non-existent session.
    mController->onResourceLost(CLIENT(0), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), kInvalidPid);
    mController->onResourceLost(CLIENT(3), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), kInvalidPid);

    // Test 1: No queue change during resource loss.
    // Signal resource lost.
    mController->onResourceLost(CLIENT(2), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), PID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Signal resource available, CLIENT(2) should resume.
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Test 2: Change of queue order during resource loss.
    // Signal resource lost.
    mController->onResourceLost(CLIENT(2), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), PID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(0) back to top, should have no resume due to no resource.
    mUidPolicy->setTop(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Signal resource available, CLIENT(0) should resume.
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Test 3:
    mController->onResourceLost(CLIENT(0), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), PID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    // Cancel the paused top session during resource lost.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(0)));
    // Signal resource available, CLIENT(2)'s session should start.
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Test 4: Adding new queue during resource loss.
    // Signal resource lost.
    mController->onResourceLost(CLIENT(2), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), PID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(2) to top.
    mUidPolicy->setTop(UID(2));

    // Submit real-time session to CLIENT(3) in UID(2), session shouldn't start due to no resource.
    mRealtimeRequest.clientPid = PID(2);
    mController->submit(CLIENT(3), SESSION(0), UID(2), mRealtimeRequest, mClientCallback3);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Signal resource available, CLIENT(3)'s session should start.
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(3), SESSION(0)));
}

/* Test thermal throttling without resource lost */
TEST_F(TranscodingSessionControllerTest, TestThermalCallback) {
    ALOGD("TestThermalCallback");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mRealtimeRequest.clientPid = PID(0);
    mController->submit(CLIENT(0), SESSION(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mOfflineRequest.clientPid = PID(0);
    mController->submit(CLIENT(1), SESSION(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mRealtimeRequest.clientPid = PID(1);
    mController->submit(CLIENT(2), SESSION(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), SESSION(0)));

    // Test 0: Basic case, no queue change during throttling, top session should pause/resume
    // with throttling.
    mController->onThrottlingStarted();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), SESSION(0)));
    mController->onThrottlingStopped();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Test 1: Change of queue order during thermal throttling, when throttling stops,
    // new top session should resume.
    mController->onThrottlingStarted();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), SESSION(0)));
    mUidPolicy->setTop(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    mController->onThrottlingStopped();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Test 2: Cancel session during throttling, when throttling stops, new top
    // session should resume.
    mController->onThrottlingStarted();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    // Cancel the paused top session during throttling.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(0)));
    // Throttling stops, CLIENT(2)'s session should start.
    mController->onThrottlingStopped();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Test 3: Add new queue during throttling, when throttling stops, new top
    // session should resume.
    mController->onThrottlingStarted();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), SESSION(0)));
    // Move UID(2) to top.
    mUidPolicy->setTop(UID(2));
    // Submit real-time session to CLIENT(3) in UID(2), session shouldn't start during throttling.
    mRealtimeRequest.clientPid = PID(2);
    mController->submit(CLIENT(3), SESSION(0), UID(2), mRealtimeRequest, mClientCallback3);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    // Throttling stops, CLIENT(3)'s session should start.
    mController->onThrottlingStopped();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(3), SESSION(0)));
}

/* Test resource lost and thermal throttling happening simultaneously */
TEST_F(TranscodingSessionControllerTest, TestResourceLostAndThermalCallback) {
    ALOGD("TestResourceLostAndThermalCallback");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mRealtimeRequest.clientPid = PID(0);
    mController->submit(CLIENT(0), SESSION(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mOfflineRequest.clientPid = PID(0);
    mController->submit(CLIENT(1), SESSION(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mRealtimeRequest.clientPid = PID(1);
    mController->submit(CLIENT(2), SESSION(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), SESSION(0)));

    // Test 0: Resource lost during throttling.
    // Throttling starts, top session should pause.
    mController->onThrottlingStarted();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), SESSION(0)));
    // Signal resource lost, this should get ignored because the session is now paused.
    mController->onResourceLost(CLIENT(2), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), kInvalidPid);
    // Signal resource available, CLIENT(2) shouldn't resume.
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    // Throttling ends, top session should resume.
    mController->onThrottlingStopped();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Test 1: Throttling during resource lost.
    mController->onResourceLost(CLIENT(2), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), PID(1));
    mController->onThrottlingStarted();
    mController->onThrottlingStopped();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));

    // Test 2: Interleaving resource lost and throttling.
    mController->onResourceLost(CLIENT(2), SESSION(0));
    EXPECT_EQ(mResourcePolicy->getPid(), PID(1));
    mController->onThrottlingStarted();
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    mController->onThrottlingStopped();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), SESSION(0)));
}

}  // namespace android
