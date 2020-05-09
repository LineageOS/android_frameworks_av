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

// Unit Test for TranscodingJobScheduler

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingJobSchedulerTest"

#include <aidl/android/media/BnTranscodingClientCallback.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <aidl/android/media/ITranscodingClient.h>
#include <aidl/android/media/ITranscodingClientCallback.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingJobScheduler.h>
#include <utils/Log.h>

#include <unordered_set>

namespace android {

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnTranscodingClientCallback;
using aidl::android::media::IMediaTranscodingService;
using aidl::android::media::ITranscodingClient;
using aidl::android::media::TranscodingRequestParcel;

constexpr ClientIdType kClientId = 1000;
constexpr JobIdType kClientJobId = 0;
constexpr uid_t kClientUid = 5000;
constexpr uid_t kInvalidUid = (uid_t)-1;

#define CLIENT(n) (kClientId + (n))
#define JOB(n) (kClientJobId + (n))
#define UID(n) (kClientUid + (n))

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

class TestTranscoder : public TranscoderInterface {
public:
    TestTranscoder() : mLastError(TranscodingErrorCode::kUnknown) {}
    virtual ~TestTranscoder() {}

    // TranscoderInterface
    void setCallback(const std::shared_ptr<TranscoderCallbackInterface>& /*cb*/) override {}

    void start(ClientIdType clientId, JobIdType jobId,
               const TranscodingRequestParcel& /*request*/) override {
        mEventQueue.push_back(Start(clientId, jobId));
    }
    void pause(ClientIdType clientId, JobIdType jobId) override {
        mEventQueue.push_back(Pause(clientId, jobId));
    }
    void resume(ClientIdType clientId, JobIdType jobId) override {
        mEventQueue.push_back(Resume(clientId, jobId));
    }
    void stop(ClientIdType clientId, JobIdType jobId) override {
        mEventQueue.push_back(Stop(clientId, jobId));
    }

    void onFinished(ClientIdType clientId, JobIdType jobId) {
        mEventQueue.push_back(Finished(clientId, jobId));
    }

    void onFailed(ClientIdType clientId, JobIdType jobId, TranscodingErrorCode err) {
        mLastError = err;
        mEventQueue.push_back(Failed(clientId, jobId));
    }

    TranscodingErrorCode getLastError() {
        TranscodingErrorCode result = mLastError;
        mLastError = TranscodingErrorCode::kUnknown;
        return result;
    }

    struct Event {
        enum { NoEvent, Start, Pause, Resume, Stop, Finished, Failed } type;
        ClientIdType clientId;
        JobIdType jobId;
    };

    static constexpr Event NoEvent = {Event::NoEvent, 0, 0};

#define DECLARE_EVENT(action)                                     \
    static Event action(ClientIdType clientId, JobIdType jobId) { \
        return {Event::action, clientId, jobId};                  \
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
    return lhs.type == rhs.type && lhs.clientId == rhs.clientId && lhs.jobId == rhs.jobId;
}

struct TestClientCallback : public BnTranscodingClientCallback {
    TestClientCallback(TestTranscoder* owner, int64_t clientId)
          : mOwner(owner), mClientId(clientId) {
        ALOGD("TestClient Created");
    }

    Status onTranscodingFinished(int32_t in_jobId,
                                 const TranscodingResultParcel& in_result) override {
        EXPECT_EQ(in_jobId, in_result.jobId);
        ALOGD("TestClientCallback: received onTranscodingFinished");
        mOwner->onFinished(mClientId, in_jobId);
        return Status::ok();
    }

    Status onTranscodingFailed(int32_t in_jobId, TranscodingErrorCode in_errorCode) override {
        mOwner->onFailed(mClientId, in_jobId, in_errorCode);
        return Status::ok();
    }

    Status onAwaitNumberOfJobsChanged(int32_t /* in_jobId */, int32_t /* in_oldAwaitNumber */,
                                      int32_t /* in_newAwaitNumber */) override {
        return Status::ok();
    }

    Status onProgressUpdate(int32_t /* in_jobId */, int32_t /* in_progress */) override {
        return Status::ok();
    }

    virtual ~TestClientCallback() { ALOGI("TestClient destroyed"); };

private:
    TestTranscoder* mOwner;
    int64_t mClientId;
    TestClientCallback(const TestClientCallback&) = delete;
    TestClientCallback& operator=(const TestClientCallback&) = delete;
};

class TranscodingJobSchedulerTest : public ::testing::Test {
public:
    TranscodingJobSchedulerTest() { ALOGI("TranscodingJobSchedulerTest created"); }

    void SetUp() override {
        ALOGI("TranscodingJobSchedulerTest set up");
        mTranscoder.reset(new TestTranscoder());
        mUidPolicy.reset(new TestUidPolicy());
        mScheduler.reset(new TranscodingJobScheduler(mTranscoder, mUidPolicy));
        mUidPolicy->setCallback(mScheduler);

        // Set priority only, ignore other fields for now.
        mOfflineRequest.priority = TranscodingJobPriority::kUnspecified;
        mRealtimeRequest.priority = TranscodingJobPriority::kHigh;
        mClientCallback0 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(0));
        mClientCallback1 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(1));
        mClientCallback2 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(2));
        mClientCallback3 =
                ::ndk::SharedRefBase::make<TestClientCallback>(mTranscoder.get(), CLIENT(3));
    }

    void TearDown() override { ALOGI("TranscodingJobSchedulerTest tear down"); }

    ~TranscodingJobSchedulerTest() { ALOGD("TranscodingJobSchedulerTest destroyed"); }

    std::shared_ptr<TestTranscoder> mTranscoder;
    std::shared_ptr<TestUidPolicy> mUidPolicy;
    std::shared_ptr<TranscodingJobScheduler> mScheduler;
    TranscodingRequestParcel mOfflineRequest;
    TranscodingRequestParcel mRealtimeRequest;
    std::shared_ptr<TestClientCallback> mClientCallback0;
    std::shared_ptr<TestClientCallback> mClientCallback1;
    std::shared_ptr<TestClientCallback> mClientCallback2;
    std::shared_ptr<TestClientCallback> mClientCallback3;
};

TEST_F(TranscodingJobSchedulerTest, TestSubmitJob) {
    ALOGD("TestSubmitJob");

    // Start with UID(1) on top.
    mUidPolicy->setTop(UID(1));

    // Submit offline job to CLIENT(0) in UID(0).
    // Should start immediately (because this is the only job).
    mScheduler->submit(CLIENT(0), JOB(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), 0));

    // Submit real-time job to CLIENT(0).
    // Should pause offline job and start new job,  even if UID(0) is not on top.
    mScheduler->submit(CLIENT(0), JOB(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(1)));

    // Submit real-time job to CLIENT(0), should be queued after the previous job.
    mScheduler->submit(CLIENT(0), JOB(2), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time job to CLIENT(1) in same uid, should be queued after the previous job.
    mScheduler->submit(CLIENT(1), JOB(0), UID(0), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time job to CLIENT(2) in UID(1).
    // Should pause previous job and start new job, because UID(1) is (has been) top.
    mScheduler->submit(CLIENT(2), JOB(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), JOB(0)));

    // Submit offline job, shouldn't generate any event.
    mScheduler->submit(CLIENT(2), JOB(1), UID(1), mOfflineRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Bring UID(0) to top.
    mUidPolicy->setTop(UID(0));
    // Should pause current job, and resume last job in UID(0).
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), JOB(1)));
}

TEST_F(TranscodingJobSchedulerTest, TestCancelJob) {
    ALOGD("TestCancelJob");

    // Submit real-time job JOB(0), should start immediately.
    mScheduler->submit(CLIENT(0), JOB(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(0)));

    // Submit real-time job JOB(1), should not start.
    mScheduler->submit(CLIENT(0), JOB(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline job JOB(2), should not start.
    mScheduler->submit(CLIENT(0), JOB(2), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Cancel queued real-time job.
    // Cancel real-time job JOB(1), should be cancelled.
    EXPECT_TRUE(mScheduler->cancel(CLIENT(0), JOB(1)));

    // Cancel queued offline job.
    // Cancel offline job JOB(2), should be cancelled.
    EXPECT_TRUE(mScheduler->cancel(CLIENT(0), JOB(2)));

    // Submit offline job JOB(3), shouldn't cause any event.
    mScheduler->submit(CLIENT(0), JOB(3), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Cancel running real-time job JOB(0).
    // - Should be stopped first then cancelled.
    // - Should also start offline job JOB(2) because real-time queue is empty.
    EXPECT_TRUE(mScheduler->cancel(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(3)));

    // Submit real-time job JOB(4), offline JOB(3) should pause and JOB(4) should start.
    mScheduler->submit(CLIENT(0), JOB(4), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(4)));

    // Cancel paused JOB(3). JOB(3) should be stopped.
    EXPECT_TRUE(mScheduler->cancel(CLIENT(0), JOB(3)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Stop(CLIENT(0), JOB(3)));
}

TEST_F(TranscodingJobSchedulerTest, TestFinishJob) {
    ALOGD("TestFinishJob");

    // Start with unspecified top UID.
    // Finish without any jobs submitted, should be ignored.
    mScheduler->onFinish(CLIENT(0), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline job JOB(0), should start immediately.
    mScheduler->submit(CLIENT(0), JOB(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(0)));

    // Submit real-time job JOB(1), should pause offline job and start immediately.
    mScheduler->submit(CLIENT(0), JOB(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(1)));

    // Submit real-time job JOB(2), should not start.
    mScheduler->submit(CLIENT(0), JOB(2), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Finish when the job never started, should be ignored.
    mScheduler->onFinish(CLIENT(0), JOB(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // Submit real-time job to CLIENT(1) in UID(1), should pause previous job and start new job.
    mScheduler->submit(CLIENT(1), JOB(0), UID(1), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), JOB(0)));

    // Simulate Finish that arrived late, after pause issued by scheduler.
    // Should still be propagated to client, but shouldn't trigger any new start.
    mScheduler->onFinish(CLIENT(0), JOB(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), JOB(1)));

    // Finish running real-time job, should start next real-time job in queue.
    mScheduler->onFinish(CLIENT(1), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(1), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(2)));

    // Finish running real-time job, should resume next job (offline job) in queue.
    mScheduler->onFinish(CLIENT(0), JOB(2));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), JOB(2)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), JOB(0)));

    // Finish running offline job.
    mScheduler->onFinish(CLIENT(0), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), JOB(0)));

    // Duplicate finish for last job, should be ignored.
    mScheduler->onFinish(CLIENT(0), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
}

TEST_F(TranscodingJobSchedulerTest, TestFailJob) {
    ALOGD("TestFailJob");

    // Start with unspecified top UID.
    // Fail without any jobs submitted, should be ignored.
    mScheduler->onError(CLIENT(0), JOB(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit offline job JOB(0), should start immediately.
    mScheduler->submit(CLIENT(0), JOB(0), UID(0), mOfflineRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(0)));

    // Submit real-time job JOB(1), should pause offline job and start immediately.
    mScheduler->submit(CLIENT(0), JOB(1), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(1)));

    // Submit real-time job JOB(2), should not start.
    mScheduler->submit(CLIENT(0), JOB(2), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Fail when the job never started, should be ignored.
    mScheduler->onError(CLIENT(0), JOB(2), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // UID(1) moves to top.
    mUidPolicy->setTop(UID(1));
    // Submit real-time job to CLIENT(1) in UID(1), should pause previous job and start new job.
    mScheduler->submit(CLIENT(1), JOB(0), UID(1), mRealtimeRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(1)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), JOB(0)));

    // Simulate Fail that arrived late, after pause issued by scheduler.
    // Should still be propagated to client, but shouldn't trigger any new start.
    mScheduler->onError(CLIENT(0), JOB(1), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), JOB(1)));

    // Fail running real-time job, should start next real-time job in queue.
    mScheduler->onError(CLIENT(1), JOB(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(1), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(2)));

    // Fail running real-time job, should resume next job (offline job) in queue.
    mScheduler->onError(CLIENT(0), JOB(2), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), JOB(2)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), JOB(0)));

    // Fail running offline job, and test error code propagation.
    mScheduler->onError(CLIENT(0), JOB(0), TranscodingErrorCode::kInvalidBitstream);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Failed(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->getLastError(), TranscodingErrorCode::kInvalidBitstream);

    // Duplicate fail for last job, should be ignored.
    mScheduler->onError(CLIENT(0), JOB(0), TranscodingErrorCode::kUnknown);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);
}

TEST_F(TranscodingJobSchedulerTest, TestTopUidChanged) {
    ALOGD("TestTopUidChanged");

    // Start with unspecified top UID.
    // Submit real-time job to CLIENT(0), job should start immediately.
    mScheduler->submit(CLIENT(0), JOB(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(0)));

    // Submit offline job to CLIENT(0), should not start.
    mScheduler->submit(CLIENT(1), JOB(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time job to CLIENT(2) in different uid UID(1).
    // Should pause previous job and start new job.
    mScheduler->submit(CLIENT(2), JOB(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), JOB(0)));

    // Bring UID(0) back to top.
    mUidPolicy->setTop(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), JOB(0)));

    // Bring invalid uid to top.
    mUidPolicy->setTop(kInvalidUid);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Finish job, next real-time job should resume.
    mScheduler->onFinish(CLIENT(0), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), JOB(0)));

    // Finish job, offline job should start.
    mScheduler->onFinish(CLIENT(2), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(2), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), JOB(0)));
}

TEST_F(TranscodingJobSchedulerTest, TestTopUidSetChanged) {
    ALOGD("TestTopUidChanged_MultipleUids");

    // Start with unspecified top UID.
    // Submit real-time job to CLIENT(0), job should start immediately.
    mScheduler->submit(CLIENT(0), JOB(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(0)));

    // Submit offline job to CLIENT(0), should not start.
    mScheduler->submit(CLIENT(1), JOB(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Set UID(0), UID(1) to top set.
    // UID(0) should continue to run.
    mUidPolicy->setTop({UID(0), UID(1)});
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time job to CLIENT(2) in different uid UID(1).
    // UID(0) should pause and UID(1) should start.
    mScheduler->submit(CLIENT(2), JOB(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), JOB(0)));

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
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(2), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), JOB(0)));

    // Bring invalid uid to top.
    mUidPolicy->setTop(kInvalidUid);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Finish job, next real-time job from UID(1) should resume, even if UID(1) no longer top.
    mScheduler->onFinish(CLIENT(0), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), JOB(0)));

    // Finish job, offline job should start.
    mScheduler->onFinish(CLIENT(2), JOB(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Finished(CLIENT(2), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(1), JOB(0)));
}

TEST_F(TranscodingJobSchedulerTest, TestResourceLost) {
    ALOGD("TestResourceLost");

    // Start with unspecified top UID.
    // Submit real-time job to CLIENT(0), job should start immediately.
    mScheduler->submit(CLIENT(0), JOB(0), UID(0), mRealtimeRequest, mClientCallback0);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(0), JOB(0)));

    // Submit offline job to CLIENT(0), should not start.
    mScheduler->submit(CLIENT(1), JOB(0), UID(0), mOfflineRequest, mClientCallback1);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(1) to top.
    mUidPolicy->setTop(UID(1));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Submit real-time job to CLIENT(2) in different uid UID(1).
    // Should pause previous job and start new job.
    mScheduler->submit(CLIENT(2), JOB(0), UID(1), mRealtimeRequest, mClientCallback2);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Pause(CLIENT(0), JOB(0)));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(2), JOB(0)));

    // Test 1: No queue change during resource loss.
    // Signal resource lost.
    mScheduler->onResourceLost();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Signal resource available, CLIENT(2) should resume.
    mScheduler->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(2), JOB(0)));

    // Test 2: Change of queue order during resource loss.
    // Signal resource lost.
    mScheduler->onResourceLost();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(0) back to top, should have no resume due to no resource.
    mUidPolicy->setTop(UID(0));
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Signal resource available, CLIENT(0) should resume.
    mScheduler->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Resume(CLIENT(0), JOB(0)));

    // Test 3: Adding new queue during resource loss.
    // Signal resource lost.
    mScheduler->onResourceLost();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Move UID(2) to top.
    mUidPolicy->setTop(UID(2));

    // Submit real-time job to CLIENT(3) in UID(2), job shouldn't start due to no resource.
    mScheduler->submit(CLIENT(3), JOB(0), UID(2), mRealtimeRequest, mClientCallback3);
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::NoEvent);

    // Signal resource available, CLIENT(3)'s job should start.
    mScheduler->onResourceAvailable();
    EXPECT_EQ(mTranscoder->popEvent(), TestTranscoder::Start(CLIENT(3), JOB(0)));
}

}  // namespace android
