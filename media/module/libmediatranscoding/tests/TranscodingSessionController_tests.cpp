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
    TestTranscoder() : mGeneration(0) {}
    virtual ~TestTranscoder() {}

    // TranscoderInterface
    void start(ClientIdType clientId, SessionIdType sessionId,
               const TranscodingRequestParcel& /*request*/, uid_t /*callingUid*/,
               const std::shared_ptr<ITranscodingClientCallback>& /*clientCallback*/) override {
        append(Start(clientId, sessionId));
    }
    void pause(ClientIdType clientId, SessionIdType sessionId) override {
        append(Pause(clientId, sessionId));
    }
    void resume(ClientIdType clientId, SessionIdType sessionId,
                const TranscodingRequestParcel& /*request*/, uid_t /*callingUid*/,
                const std::shared_ptr<ITranscodingClientCallback>& /*clientCallback*/) override {
        append(Resume(clientId, sessionId));
    }
    void stop(ClientIdType clientId, SessionIdType sessionId, bool abandon) override {
        append(abandon ? Abandon(clientId, sessionId) : Stop(clientId, sessionId));
    }

    void onFinished(ClientIdType clientId, SessionIdType sessionId) {
        append(Finished(clientId, sessionId));
    }

    void onFailed(ClientIdType clientId, SessionIdType sessionId, TranscodingErrorCode err) {
        append(Failed(clientId, sessionId), err);
    }

    void onCreated() {
        std::scoped_lock lock{mLock};
        mGeneration++;
    }

    struct Event {
        enum { NoEvent, Start, Pause, Resume, Stop, Finished, Failed, Abandon } type;
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
    DECLARE_EVENT(Abandon);

    // Push 1 event to back.
    void append(const Event& event,
                const TranscodingErrorCode err = TranscodingErrorCode::kNoError) {
        std::unique_lock lock(mLock);

        mEventQueue.push_back(event);
        // Error is sticky, non-error event will not erase it, only getLastError()
        // clears last error.
        if (err != TranscodingErrorCode::kNoError) {
            mLastErrorQueue.push_back(err);
        }
        mCondition.notify_one();
    }

    // Pop 1 event from front, wait for up to timeoutUs if empty.
    const Event& popEvent(int64_t timeoutUs = 0) {
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

    TranscodingErrorCode getLastError() {
        std::scoped_lock lock{mLock};
        if (mLastErrorQueue.empty()) {
            return TranscodingErrorCode::kNoError;
        }
        TranscodingErrorCode err = mLastErrorQueue.front();
        mLastErrorQueue.pop_front();
        return err;
    }

    int32_t getGeneration() {
        std::scoped_lock lock{mLock};
        return mGeneration;
    }

private:
    std::mutex mLock;
    std::condition_variable mCondition;
    Event mPoppedEvent;
    std::list<Event> mEventQueue;
    std::list<TranscodingErrorCode> mLastErrorQueue;
    int32_t mGeneration;
};

bool operator==(const TestTranscoder::Event& lhs, const TestTranscoder::Event& rhs) {
    return lhs.type == rhs.type && lhs.clientId == rhs.clientId && lhs.sessionId == rhs.sessionId;
}

struct TestClientCallback : public BnTranscodingClientCallback {
    TestClientCallback(TestTranscoder* owner, ClientIdType clientId, uid_t clientUid)
          : mOwner(owner), mClientId(clientId), mClientUid(clientUid) {
        ALOGD("TestClient Created");
    }

    ClientIdType clientId() const { return mClientId; }
    uid_t clientUid() const { return mClientUid; }

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
    ClientIdType mClientId;
    uid_t mClientUid;
    TestClientCallback(const TestClientCallback&) = delete;
    TestClientCallback& operator=(const TestClientCallback&) = delete;
};

class TranscodingSessionControllerTest : public ::testing::Test {
public:
    TranscodingSessionControllerTest() { ALOGI("TranscodingSessionControllerTest created"); }
    ~TranscodingSessionControllerTest() { ALOGD("TranscodingSessionControllerTest destroyed"); }

    void SetUp() override {
        ALOGI("TranscodingSessionControllerTest set up");
        mTranscoder.reset(new TestTranscoder());
        mUidPolicy.reset(new TestUidPolicy());
        mResourcePolicy.reset(new TestResourcePolicy());
        mThermalPolicy.reset(new TestThermalPolicy());
        // Overrid default burst params with shorter values for testing.
        TranscodingSessionController::ControllerConfig config = {
                .pacerBurstThresholdMs = 500,
                .pacerBurstCountQuota = 10,
                .pacerBurstTimeQuotaSeconds = 3,
        };
        mController.reset(new TranscodingSessionController(
                [this](const std::shared_ptr<TranscoderCallbackInterface>& /*cb*/) {
                    // Here we require that the SessionController clears out all its refcounts of
                    // the transcoder object when it calls create.
                    EXPECT_EQ(mTranscoder.use_count(), 1);
                    mTranscoder->onCreated();
                    return mTranscoder;
                },
                mUidPolicy, mResourcePolicy, mThermalPolicy, &config));
        mUidPolicy->setCallback(mController);

        // Set priority only, ignore other fields for now.
        mOfflineRequest.priority = TranscodingSessionPriority::kUnspecified;
        mRealtimeRequest.priority = TranscodingSessionPriority::kHigh;
        mClientCallback0 = ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(),
                                                                          CLIENT(0), UID(0));
        mClientCallback1 = ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(),
                                                                          CLIENT(1), UID(1));
        mClientCallback2 = ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(),
                                                                          CLIENT(2), UID(2));
        mClientCallback3 = ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(),
                                                                          CLIENT(3), UID(3));
    }

    void TearDown() override { ALOGI("TranscodingSessionControllerTest tear down"); }

    void expectTimeout(int64_t clientId, int32_t sessionId, int32_t generation) {
        EXPECT_EQ(mTranscoder->popEvent(2900000), TestTranscoder::NoEvent);
        EXPECT_EQ(mTranscoder->popEvent(200000), TestTranscoder::Abandon(clientId, sessionId));
        EXPECT_EQ(mTranscoder->popEvent(100000), TestTranscoder::Failed(clientId, sessionId));
        EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kWatchdogTimeout);
        // Should have created new transcoder.
        EXPECT_EQ(mTranscoder->getGeneration(), generation);
        EXPECT_EQ(mTranscoder.use_count(), 2);
        // b/240537336: Allow extra time to finish onError call
        sleep(1);
    }

    void testPacerHelper(int numSubmits, int sessionDurationMs, int expectedSuccess) {
        testPacerHelper(numSubmits, sessionDurationMs, expectedSuccess, mClientCallback0, {},
                        false /*pauseLastSuccessSession*/, true /*useRealCallingUid*/);
    }

    void testPacerHelperWithPause(int numSubmits, int sessionDurationMs, int expectedSuccess) {
        testPacerHelper(numSubmits, sessionDurationMs, expectedSuccess, mClientCallback0, {},
                        true /*pauseLastSuccessSession*/, true /*useRealCallingUid*/);
    }

    void testPacerHelperWithMultipleUids(int numSubmits, int sessionDurationMs, int expectedSuccess,
                                         const std::shared_ptr<TestClientCallback>& client,
                                         const std::vector<int>& additionalClientUids) {
        testPacerHelper(numSubmits, sessionDurationMs, expectedSuccess, client,
                        additionalClientUids, false /*pauseLastSuccessSession*/,
                        true /*useRealCallingUid*/);
    }

    void testPacerHelperWithSelfUid(int numSubmits, int sessionDurationMs, int expectedSuccess) {
        testPacerHelper(numSubmits, sessionDurationMs, expectedSuccess, mClientCallback0, {},
                        false /*pauseLastSuccessSession*/, false /*useRealCallingUid*/);
    }

    void testPacerHelper(int numSubmits, int sessionDurationMs, int expectedSuccess,
                         const std::shared_ptr<TestClientCallback>& client,
                         const std::vector<int>& additionalClientUids, bool pauseLastSuccessSession,
                         bool useRealCallingUid) {
        uid_t callingUid = useRealCallingUid ? ::getuid() : client->clientUid();
        for (int i = 0; i < numSubmits; i++) {
            mController->submit(client->clientId(), SESSION(i), callingUid, client->clientUid(),
                                mRealtimeRequest, client);
            for (int additionalUid : additionalClientUids) {
                mController->addClientUid(client->clientId(), SESSION(i), additionalUid);
            }
        }
        for (int i = 0; i < expectedSuccess; i++) {
            EXPECT_EQ(mTranscoder->popEvent(),
                      TestTranscoder::Start(client->clientId(), SESSION(i)));
            if ((i == expectedSuccess - 1) && pauseLastSuccessSession) {
                // Insert a pause of 3 sec to the last success running session
                mController->onThrottlingStarted();
                EXPECT_EQ(mTranscoder->popEvent(),
                          TestTranscoder::Pause(client->clientId(), SESSION(i)));
                sleep(3);
                mController->onThrottlingStopped();
                EXPECT_EQ(mTranscoder->popEvent(),
                          TestTranscoder::Resume(client->clientId(), SESSION(i)));
            }
            usleep(sessionDurationMs * 1000);
            // Test half of Finish and half of Error, both should be counted as burst runs.
            if (i & 1) {
                mController->onFinish(client->clientId(), SESSION(i));
                EXPECT_EQ(mTranscoder->popEvent(),
                          TestTranscoder::Finished(client->clientId(), SESSION(i)));
            } else {
                mController->onError(client->clientId(), SESSION(i),
                                     TranscodingErrorCode::kUnknown);
                EXPECT_EQ(mTranscoder->popEvent(100000),
                          TestTranscoder::Failed(client->clientId(), SESSION(i)));
                EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kUnknown);
            }
        }
        for (int i = expectedSuccess; i < numSubmits; i++) {
            EXPECT_EQ(mTranscoder->popEvent(),
                      TestTranscoder::Failed(client->clientId(), SESSION(i)));
            EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kDroppedByService);
        }
    }

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
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), 0));

    // Submit real-time session to CLIENT(0).
    // Should pause offline session and start new session,  even if UID(0) is not on top.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Submit real-time session to CLIENT(0), should be queued after the previous session.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(1) in same uid, should be queued after the previous
    // session.
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(0), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in UID(1).
    // Should pause previous session and start new session, because UID(1) is (has been) top.
    mController->submit(CLIENT(2), SESSION(0), UID(2), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), SESSION(0)));

    // Submit offline session, shouldn't generate any event.
    mController->submit(CLIENT(2), SESSION(1), UID(2), UID(1), mOfflineRequest, mClientCallback2);
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
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should not start.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Cancel queued real-time session.
    // Cancel real-time session SESSION(1), should be cancelled.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(1)));

    // Cancel queued offline session.
    // Cancel offline session SESSION(2), should be cancelled.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(2)));

    // Submit offline session SESSION(3), shouldn't cause any event.
    mController->submit(CLIENT(0), SESSION(3), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Cancel running real-time session SESSION(0).
    // - Should be stopped first then cancelled.
    // - Should also start offline session SESSION(2) because real-time queue is empty.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(3)));

    // Submit real-time session SESSION(4), offline SESSION(3) should pause and SESSION(4)
    // should start.
    mController->submit(CLIENT(0), SESSION(4), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(4)));

    // Cancel paused SESSION(3). SESSION(3) should be stopped.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(3)));
}

TEST_F(TranscodingSessionControllerTest, TestCancelSessionWithMultipleUids) {
    ALOGD("TestCancelSessionWithMultipleUids");
    std::vector<int32_t> clientUids;

    // Submit real-time session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should not start.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));

    // Add UID(1) to the offline SESSION(2), SESSION(2) should start and SESSION(0) should pause.
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(2), UID(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));

    // Add UID(1) to SESSION(1) as well.
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(1), UID(1)));

    // Cancel SESSION(2), should be cancelled and SESSION(1) should start.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(2)));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(2), &clientUids));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(2)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Cancel SESSION(1), should be cancelled and SESSION(0) should resume.
    EXPECT_TRUE(mController->cancel(CLIENT(0), SESSION(1)));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(1), &clientUids));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));
}

TEST_F(TranscodingSessionControllerTest, TestCancelAllSessionsForClient) {
    // Submit real-time session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should not start.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    std::vector<int32_t> clientUids;
    // Make some more uids blocked on the sessions.
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(0), UID(1)));
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(1), UID(1)));
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(2), UID(1)));
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(0), &clientUids));
    EXPECT_EQ(clientUids.size(), 2);
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(1), &clientUids));
    EXPECT_EQ(clientUids.size(), 2);
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(2), &clientUids));
    EXPECT_EQ(clientUids.size(), 1);

    // Cancel all sessions for CLIENT(0) with -1.
    // Expect SESSION(0) and SESSION(1) to be gone.
    // Expect SESSION(2) still there with empty client uid list (only kept for offline) and start.
    EXPECT_TRUE(mController->cancel(CLIENT(0), -1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(0)));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(0), &clientUids));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(1), &clientUids));
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(2), &clientUids));
    EXPECT_EQ(clientUids.size(), 0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));
}

TEST_F(TranscodingSessionControllerTest, TestFinishSession) {
    ALOGD("TestFinishSession");

    // Start with unspecified top UID.
    // Finish without any sessions submitted, should be ignored.
    mController->onFinish(CLIENT(0), SESSION(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should pause offline session and start immediately.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Submit real-time session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Finish when the session never started, should be ignored.
    mController->onFinish(CLIENT(0), SESSION(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // Submit real-time session to CLIENT(1) in UID(1), should pause previous session and start
    // new session.
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(1), mRealtimeRequest, mClientCallback1);
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

TEST_F(TranscodingSessionControllerTest, TestFinishSessionWithMultipleUids) {
    ALOGD("TestFinishSessionWithMultipleUids");
    std::vector<int32_t> clientUids;

    // Start with unspecified top uid.
    // Submit real-time session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should not start.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(1), UID(1)));

    // Submit real-time session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(2), UID(1)));
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(2), UID(2)));

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // SESSION(0) should pause, SESSION(1) should start.
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Finish SESSION(1), SESSION(2) (next in line for UID(1)) should start.
    mController->onFinish(CLIENT(0), SESSION(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(1), &clientUids));

    // Finish SESSION(2), SESSION(0) should resume.
    mController->onFinish(CLIENT(0), SESSION(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(2)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(2), &clientUids));
}

TEST_F(TranscodingSessionControllerTest, TestFailSession) {
    ALOGD("TestFailSession");

    // Start with unspecified top UID.
    // Fail without any sessions submitted, should be ignored.
    mController->onError(CLIENT(0), SESSION(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should pause offline session and start immediately.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Submit real-time session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Fail when the session never started, should be ignored.
    mController->onError(CLIENT(0), SESSION(2), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // Submit real-time session to CLIENT(1) in UID(1), should pause previous session and start
    // new session.
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(1), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), SESSION(0)));

    // Simulate Fail that arrived late, after pause issued by controller.
    // Should still be propagated to client, but shouldn't trigger any new start.
    mController->onError(CLIENT(0), SESSION(1), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kUnknown);

    // Fail running real-time session, should start next real-time session in queue.
    mController->onError(CLIENT(1), SESSION(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(1), SESSION(0)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));

    // Fail running real-time session, should resume next session (offline session) in queue.
    mController->onError(CLIENT(0), SESSION(2), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(2)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Fail running offline session, and test error code propagation.
    mController->onError(CLIENT(0), SESSION(0), TranscodingErrorCode::kInvalidOperation);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kInvalidOperation);

    // Duplicate fail for last session, should be ignored.
    mController->onError(CLIENT(0), SESSION(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
}

TEST_F(TranscodingSessionControllerTest, TestFailSessionWithMultipleUids) {
    ALOGD("TestFailSessionWithMultipleUids");
    std::vector<int32_t> clientUids;

    // Start with unspecified top uid.
    // Submit real-time session SESSION(0), should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit real-time session SESSION(1), should not start.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(1), UID(1)));

    // Submit real-time session SESSION(2), should not start.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // SESSION(0) should pause, SESSION(1) should start.
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    // Add UID(1) and UID(2) to SESSION(2).
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(2), UID(1)));
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(2), UID(2)));

    // Fail SESSION(1), SESSION(2) (next in line for UID(1)) should start.
    mController->onError(CLIENT(0), SESSION(1), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(1), &clientUids));

    // Fail SESSION(2), SESSION(0) should resume.
    mController->onError(CLIENT(0), SESSION(2), TranscodingErrorCode::kInvalidOperation);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(2)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kInvalidOperation);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(2), &clientUids));
}

TEST_F(TranscodingSessionControllerTest, TestTopUidChanged) {
    ALOGD("TestTopUidChanged");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mController->submit(CLIENT(2), SESSION(0), UID(2), UID(1), mRealtimeRequest, mClientCallback2);
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

TEST_F(TranscodingSessionControllerTest, TestTopUidChangedMultipleUids) {
    ALOGD("TestTopUidChangedMultipleUids");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Bring UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Add UID(1) to SESSION(0), SESSION(0) should continue to run
    // (no pause&resume of the same session).
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(0), UID(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Bring UID(0) back to top, SESSION(0) should continue to run
    // (no pause&resume of the same session).
    mUidPolicy->setTop(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Bring UID(2) to top.
    mUidPolicy->setTop(UID(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    // Add UID(2) to the offline session, it should be started.
    EXPECT_TRUE(mController->addClientUid(CLIENT(1), SESSION(0), UID(2)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), SESSION(0)));

    // ADD UID(3) to SESSION(0).
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(0), UID(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    // Bring UID(3) to top, SESSION(0) should resume.
    mUidPolicy->setTop(UID(3));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(1), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(0)));

    // Now make UID(2) also blocked on CLIENT(0), SESSION(0).
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(0), UID(2)));

    // Bring UID(2) back to top, CLIENT(0), SESSION(0) should continue to run (even if it's
    // added to UID(2)'s queue later than CLIENT(1)'s SESSION(0)).
    mUidPolicy->setTop(UID(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
}

TEST_F(TranscodingSessionControllerTest, TestTopUidSetChanged) {
    ALOGD("TestTopUidSetChanged");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Set UID(0), UID(1) to top set.
    // UID(0) should continue to run.
    mUidPolicy->setTop({UID(0), UID(1)});
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // UID(0) should pause and UID(1) should start.
    mController->submit(CLIENT(2), SESSION(0), UID(2), UID(1), mRealtimeRequest, mClientCallback2);
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

TEST_F(TranscodingSessionControllerTest, TestUidGone) {
    ALOGD("TestUidGone");

    mUidPolicy->setTop(UID(0));
    // Start with unspecified top UID.
    // Submit real-time sessions to CLIENT(0), session should start immediately.
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(1), UID(1)));

    // Submit real-time session to CLIENT(1), should not start.
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(1), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
    EXPECT_TRUE(mController->addClientUid(CLIENT(1), SESSION(0), UID(1)));

    // Tell the controller that UID(0) is gone.
    mUidPolicy->setTop(UID(1));
    // CLIENT(0)'s SESSION(1) should start, SESSION(0) should be cancelled.
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));
    mController->onUidGone(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kUidGoneCancelled);

    std::vector<int32_t> clientUids;
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(0), &clientUids));
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(1), &clientUids));
    EXPECT_EQ(clientUids.size(), 1);
    EXPECT_EQ(clientUids[0], UID(1));

    // Tell the controller that UID(1) is gone too.
    mController->onUidGone(UID(1));
    // CLIENT(1)'s SESSION(0) should start, CLIENT(0)'s SESSION(1) should be cancelled.
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), SESSION(1)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kUidGoneCancelled);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), SESSION(0)));
    // CLIENT(1) SESSION(0) should not have any client uids as it's only kept for offline.
    EXPECT_TRUE(mController->getClientUids(CLIENT(1), SESSION(0), &clientUids));
    EXPECT_EQ(clientUids.size(), 0);
}

TEST_F(TranscodingSessionControllerTest, TestAddGetClientUids) {
    ALOGD("TestAddGetClientUids");

    // Add/get client uids with non-existent session, should fail.
    std::vector<int32_t> clientUids;
    uid_t ownUid = ::getuid();
    EXPECT_FALSE(mController->addClientUid(CLIENT(0), SESSION(0), ownUid));
    EXPECT_FALSE(mController->getClientUids(CLIENT(0), SESSION(0), &clientUids));

    // Submit a real-time request.
    EXPECT_TRUE(mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest,
                                    mClientCallback0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Should have own uid in client uids.
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(0), &clientUids));
    EXPECT_EQ(clientUids.size(), 1);
    EXPECT_EQ(clientUids[0], UID(0));

    // Add UID(0) again should fail.
    EXPECT_FALSE(mController->addClientUid(CLIENT(0), SESSION(0), UID(0)));

    // Add own uid should succeed.
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(0), ownUid));
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(0), &clientUids));
    std::unordered_set<uid_t> uidSet;
    uidSet.insert(clientUids.begin(), clientUids.end());
    EXPECT_EQ(uidSet.size(), 2);
    EXPECT_EQ(uidSet.count(UID(0)), 1);
    EXPECT_EQ(uidSet.count(ownUid), 1);

    // Submit an offline request.
    EXPECT_TRUE(mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mOfflineRequest,
                                    mClientCallback0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Should not have own uid in client uids.
    EXPECT_TRUE(mController->getClientUids(CLIENT(0), SESSION(1), &clientUids));
    EXPECT_EQ(clientUids.size(), 0);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    // Add UID(1) to offline session, offline session should start and SESSION(0) should pause.
    EXPECT_TRUE(mController->addClientUid(CLIENT(0), SESSION(1), UID(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));
}

/* Test resource lost without thermal throttling */
TEST_F(TranscodingSessionControllerTest, TestResourceLost) {
    ALOGD("TestResourceLost");

    // Start with unspecified top UID.
    // Submit real-time session to CLIENT(0), session should start immediately.
    mRealtimeRequest.clientPid = PID(0);
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mOfflineRequest.clientPid = PID(0);
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mRealtimeRequest.clientPid = PID(1);
    mController->submit(CLIENT(2), SESSION(0), UID(2), UID(1), mRealtimeRequest, mClientCallback2);
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
    mController->submit(CLIENT(3), SESSION(0), UID(3), UID(2), mRealtimeRequest, mClientCallback3);
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
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mOfflineRequest.clientPid = PID(0);
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mRealtimeRequest.clientPid = PID(1);
    mController->submit(CLIENT(2), SESSION(0), UID(2), UID(1), mRealtimeRequest, mClientCallback2);
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
    mController->submit(CLIENT(3), SESSION(0), UID(3), UID(2), mRealtimeRequest, mClientCallback3);
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
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Submit offline session to CLIENT(0), should not start.
    mOfflineRequest.clientPid = PID(0);
    mController->submit(CLIENT(1), SESSION(0), UID(1), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time session to CLIENT(2) in different uid UID(1).
    // Should pause previous session and start new session.
    mRealtimeRequest.clientPid = PID(1);
    mController->submit(CLIENT(2), SESSION(0), UID(2), UID(1), mRealtimeRequest, mClientCallback2);
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

TEST_F(TranscodingSessionControllerTest, TestTranscoderWatchdogNoHeartbeat) {
    ALOGD("TestTranscoderWatchdogTimeout");

    // Submit session to CLIENT(0) in UID(0).
    // Should start immediately (because this is the only session).
    mController->submit(CLIENT(0), SESSION(0), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(0)));

    // Test 1: If not sending keep-alive at all, timeout after 3 seconds.
    expectTimeout(CLIENT(0), SESSION(0), 2);
}

TEST_F(TranscodingSessionControllerTest, TestTranscoderWatchdogHeartbeat) {
    // Test 2: No timeout as long as keep-alive coming; timeout after keep-alive stops.
    mController->submit(CLIENT(0), SESSION(1), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(1)));

    for (int i = 0; i < 5; i++) {
        EXPECT_EQ(mTranscoder->popEvent(1000000), TestTranscoder::NoEvent);
        mController->onHeartBeat(CLIENT(0), SESSION(1));
    }
    expectTimeout(CLIENT(0), SESSION(1), 2);
}

TEST_F(TranscodingSessionControllerTest, TestTranscoderWatchdogDuringPause) {
    int expectedGen = 2;

    // Test 3a: No timeout for paused session even if no keep-alive is sent.
    mController->submit(CLIENT(0), SESSION(2), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(2)));
    // Trigger a pause by sending a resource lost.
    mController->onResourceLost(CLIENT(0), SESSION(2));
    EXPECT_EQ(mTranscoder->popEvent(3100000), TestTranscoder::NoEvent);
    mController->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(100000), TestTranscoder::Resume(CLIENT(0), SESSION(2)));
    expectTimeout(CLIENT(0), SESSION(2), expectedGen++);

    // Test 3b: No timeout for paused session even if no keep-alive is sent.
    mController->submit(CLIENT(0), SESSION(3), UID(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(3)));
    // Let the session run almost to timeout, to test timeout reset after pause.
    EXPECT_EQ(mTranscoder->popEvent(2900000), TestTranscoder::NoEvent);
    // Trigger a pause by submitting a higher-priority request.
    mController->submit(CLIENT(0), SESSION(4), UID(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), SESSION(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), SESSION(4)));
    // Finish the higher-priority session, lower-priority session should resume,
    // and the timeout should reset to full value.
    mController->onFinish(CLIENT(0), SESSION(4));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), SESSION(4)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), SESSION(3)));
    expectTimeout(CLIENT(0), SESSION(3), expectedGen++);
}

TEST_F(TranscodingSessionControllerTest, TestTranscoderPacerOverCountOnly) {
    ALOGD("TestTranscoderPacerOverCountOnly");
    testPacerHelper(12 /*numSubmits*/, 100 /*sessionDurationMs*/, 12 /*expectedSuccess*/);
}

TEST_F(TranscodingSessionControllerTest, TestTranscoderPacerOverTimeOnly) {
    ALOGD("TestTranscoderPacerOverTimeOnly");
    testPacerHelper(5 /*numSubmits*/, 1000 /*sessionDurationMs*/, 5 /*expectedSuccess*/);
}

TEST_F(TranscodingSessionControllerTest, TestTranscoderPacerOverQuota) {
    ALOGD("TestTranscoderPacerOverQuota");
    testPacerHelper(12 /*numSubmits*/, 400 /*sessionDurationMs*/, 10 /*expectedSuccess*/);
}

TEST_F(TranscodingSessionControllerTest, TestTranscoderPacerWithPause) {
    ALOGD("TestTranscoderPacerDuringPause");
    testPacerHelperWithPause(12 /*numSubmits*/, 400 /*sessionDurationMs*/, 10 /*expectedSuccess*/);
}

/*
 * Test the case where multiple client uids request the same session. Session should only
 * be dropped when all clients are over quota.
 */
TEST_F(TranscodingSessionControllerTest, TestTranscoderPacerMultipleUids) {
    ALOGD("TestTranscoderPacerMultipleUids");
    // First, run mClientCallback0 to the point of no quota.
    testPacerHelperWithMultipleUids(12 /*numSubmits*/, 400 /*sessionDurationMs*/,
                                    10 /*expectedSuccess*/, mClientCallback0, {});
    // Make UID(0) block on Client1's sessions too, Client1's quota should not be affected.
    testPacerHelperWithMultipleUids(12 /*numSubmits*/, 400 /*sessionDurationMs*/,
                                    10 /*expectedSuccess*/, mClientCallback1, {UID(0)});
    // Make UID(10) block on Client2's sessions. We expect to see 11 succeeds (instead of 10),
    // because the addClientUid() is called after the submit, and first session is already
    // started by the time UID(10) is added. UID(10) allowed us to run the 11th session,
    // after that both UID(10) and UID(2) are out of quota.
    testPacerHelperWithMultipleUids(12 /*numSubmits*/, 400 /*sessionDurationMs*/,
                                    11 /*expectedSuccess*/, mClientCallback2, {UID(10)});
}

/*
 * Use same uid for clientUid and callingUid, should not be limited by quota.
 */
TEST_F(TranscodingSessionControllerTest, TestTranscoderPacerSelfUid) {
    ALOGD("TestTranscoderPacerSelfUid");
    testPacerHelperWithSelfUid(12 /*numSubmits*/, 400 /*sessionDurationMs*/,
                               12 /*expectedSuccess*/);
}

}  // namespace android
