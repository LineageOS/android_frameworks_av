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

// Unit Test for TranscodingClientManager

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingClientManagerTest"

#include <aidl/android/media/BnTranscodingClientCallback.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <media/SchedulerClientInterface.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingRequest.h>
#include <utils/Log.h>

#include <list>

namespace android {

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::BnTranscodingClientCallback;
using ::aidl::android::media::IMediaTranscodingService;
using ::aidl::android::media::TranscodingErrorCode;
using ::aidl::android::media::TranscodingJobParcel;
using ::aidl::android::media::TranscodingJobPriority;
using ::aidl::android::media::TranscodingRequestParcel;
using ::aidl::android::media::TranscodingResultParcel;

constexpr pid_t kInvalidClientPid = -1;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientPackage = "";

constexpr pid_t kClientPid = 2;
constexpr uid_t kClientUid = 3;
constexpr const char* kClientName = "TestClientName";
constexpr const char* kClientPackage = "TestClientPackage";

#define JOB(n) (n)

struct TestClientCallback : public BnTranscodingClientCallback {
    TestClientCallback() { ALOGI("TestClientCallback Created"); }

    virtual ~TestClientCallback() { ALOGI("TestClientCallback destroyed"); };

    Status onTranscodingFinished(int32_t in_jobId,
                                 const TranscodingResultParcel& in_result) override {
        EXPECT_EQ(in_jobId, in_result.jobId);
        mEventQueue.push_back(Finished(in_jobId));
        return Status::ok();
    }

    Status onTranscodingFailed(int32_t in_jobId, TranscodingErrorCode /*in_errorCode */) override {
        mEventQueue.push_back(Failed(in_jobId));
        return Status::ok();
    }

    Status onAwaitNumberOfJobsChanged(int32_t /* in_jobId */, int32_t /* in_oldAwaitNumber */,
                                      int32_t /* in_newAwaitNumber */) override {
        return Status::ok();
    }

    Status onProgressUpdate(int32_t /* in_jobId */, int32_t /* in_progress */) override {
        return Status::ok();
    }

    struct Event {
        enum {
            NoEvent,
            Finished,
            Failed,
        } type;
        JobIdType jobId;
    };

    static constexpr Event NoEvent = {Event::NoEvent, 0};
#define DECLARE_EVENT(action) \
    static Event action(JobIdType jobId) { return {Event::action, jobId}; }

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

    TestClientCallback(const TestClientCallback&) = delete;
    TestClientCallback& operator=(const TestClientCallback&) = delete;
};

bool operator==(const TestClientCallback::Event& lhs, const TestClientCallback::Event& rhs) {
    return lhs.type == rhs.type && lhs.jobId == rhs.jobId;
}

struct TestScheduler : public SchedulerClientInterface {
    TestScheduler() { ALOGI("TestScheduler Created"); }

    virtual ~TestScheduler() { ALOGI("TestScheduler Destroyed"); }

    bool submit(ClientIdType clientId, JobIdType jobId, uid_t /*uid*/,
                const TranscodingRequestParcel& request,
                const std::weak_ptr<ITranscodingClientCallback>& clientCallback) override {
        JobKeyType jobKey = std::make_pair(clientId, jobId);
        if (mJobs.count(jobKey) > 0) {
            return false;
        }

        // This is the secret name we'll check, to test error propagation from
        // the scheduler back to client.
        if (request.fileName == "bad_file") {
            return false;
        }

        mJobs[jobKey].request = request;
        mJobs[jobKey].callback = clientCallback;

        mLastJob = jobKey;
        return true;
    }

    bool cancel(ClientIdType clientId, JobIdType jobId) override {
        JobKeyType jobKey = std::make_pair(clientId, jobId);

        if (mJobs.count(jobKey) == 0) {
            return false;
        }
        mJobs.erase(jobKey);
        return true;
    }

    bool getJob(ClientIdType clientId, JobIdType jobId,
                TranscodingRequestParcel* request) override {
        JobKeyType jobKey = std::make_pair(clientId, jobId);
        if (mJobs.count(jobKey) == 0) {
            return false;
        }

        *(TranscodingRequest*)request = mJobs[jobKey].request;
        return true;
    }

    void finishLastJob() {
        auto it = mJobs.find(mLastJob);
        if (it == mJobs.end()) {
            return;
        }
        {
            auto clientCallback = it->second.callback.lock();
            if (clientCallback != nullptr) {
                clientCallback->onTranscodingFinished(
                        mLastJob.second, TranscodingResultParcel({mLastJob.second, 0}));
            }
        }
        mJobs.erase(it);
    }

    void abortLastJob() {
        auto it = mJobs.find(mLastJob);
        if (it == mJobs.end()) {
            return;
        }
        {
            auto clientCallback = it->second.callback.lock();
            if (clientCallback != nullptr) {
                clientCallback->onTranscodingFailed(mLastJob.second,
                                                    TranscodingErrorCode::kUnknown);
            }
        }
        mJobs.erase(it);
    }

    struct Job {
        TranscodingRequest request;
        std::weak_ptr<ITranscodingClientCallback> callback;
    };

    typedef std::pair<ClientIdType, JobIdType> JobKeyType;
    std::map<JobKeyType, Job> mJobs;
    JobKeyType mLastJob;
};

class TranscodingClientManagerTest : public ::testing::Test {
public:
    TranscodingClientManagerTest()
          : mScheduler(new TestScheduler()),
            mClientManager(new TranscodingClientManager(mScheduler)) {
        ALOGD("TranscodingClientManagerTest created");
    }

    void SetUp() override {
        mClientCallback1 = ::ndk::SharedRefBase::make<TestClientCallback>();
        mClientCallback2 = ::ndk::SharedRefBase::make<TestClientCallback>();
        mClientCallback3 = ::ndk::SharedRefBase::make<TestClientCallback>();
    }

    void TearDown() override { ALOGI("TranscodingClientManagerTest tear down"); }

    ~TranscodingClientManagerTest() { ALOGD("TranscodingClientManagerTest destroyed"); }

    void addMultipleClients() {
        EXPECT_EQ(mClientManager->addClient(mClientCallback1, kClientPid, kClientUid, kClientName,
                                            kClientPackage, &mClient1),
                  OK);
        EXPECT_NE(mClient1, nullptr);

        EXPECT_EQ(mClientManager->addClient(mClientCallback2, kClientPid, kClientUid, kClientName,
                                            kClientPackage, &mClient2),
                  OK);
        EXPECT_NE(mClient2, nullptr);

        EXPECT_EQ(mClientManager->addClient(mClientCallback3, kClientPid, kClientUid, kClientName,
                                            kClientPackage, &mClient3),
                  OK);
        EXPECT_NE(mClient3, nullptr);

        EXPECT_EQ(mClientManager->getNumOfClients(), 3);
    }

    void unregisterMultipleClients() {
        EXPECT_TRUE(mClient1->unregister().isOk());
        EXPECT_TRUE(mClient2->unregister().isOk());
        EXPECT_TRUE(mClient3->unregister().isOk());
        EXPECT_EQ(mClientManager->getNumOfClients(), 0);
    }

    std::shared_ptr<TestScheduler> mScheduler;
    std::shared_ptr<TranscodingClientManager> mClientManager;
    std::shared_ptr<ITranscodingClient> mClient1;
    std::shared_ptr<ITranscodingClient> mClient2;
    std::shared_ptr<ITranscodingClient> mClient3;
    std::shared_ptr<TestClientCallback> mClientCallback1;
    std::shared_ptr<TestClientCallback> mClientCallback2;
    std::shared_ptr<TestClientCallback> mClientCallback3;
};

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientCallback) {
    // Add a client with null callback and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(nullptr, kClientPid, kClientUid, kClientName,
                                             kClientPackage, &client);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPid) {
    // Add a client with invalid Pid and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kInvalidClientPid, kClientUid,
                                             kClientName, kClientPackage, &client);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientName) {
    // Add a client with invalid name and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kClientPid, kClientUid,
                                             kInvalidClientName, kClientPackage, &client);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPackageName) {
    // Add a client with invalid packagename and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kClientPid, kClientUid, kClientName,
                                             kInvalidClientPackage, &client);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
}

TEST_F(TranscodingClientManagerTest, TestAddingValidClient) {
    // Add a valid client, should succeed.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kClientPid, kClientUid, kClientName,
                                             kClientPackage, &client);
    EXPECT_EQ(err, OK);
    EXPECT_NE(client.get(), nullptr);
    EXPECT_EQ(mClientManager->getNumOfClients(), 1);

    // Unregister client, should succeed.
    Status status = client->unregister();
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(mClientManager->getNumOfClients(), 0);
}

TEST_F(TranscodingClientManagerTest, TestAddingDupliacteClient) {
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kClientPid, kClientUid, kClientName,
                                             kClientPackage, &client);
    EXPECT_EQ(err, OK);
    EXPECT_NE(client.get(), nullptr);
    EXPECT_EQ(mClientManager->getNumOfClients(), 1);

    std::shared_ptr<ITranscodingClient> dupClient;
    err = mClientManager->addClient(mClientCallback1, kClientPid, kClientUid, "dupClient",
                                    "dupPackage", &dupClient);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ALREADY_EXISTS);
    EXPECT_EQ(dupClient.get(), nullptr);
    EXPECT_EQ(mClientManager->getNumOfClients(), 1);

    Status status = client->unregister();
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(mClientManager->getNumOfClients(), 0);

    err = mClientManager->addClient(mClientCallback1, kClientPid, kClientUid, "dupClient",
                                    "dupPackage", &dupClient);
    EXPECT_EQ(err, OK);
    EXPECT_NE(dupClient.get(), nullptr);
    EXPECT_EQ(mClientManager->getNumOfClients(), 1);

    status = dupClient->unregister();
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(mClientManager->getNumOfClients(), 0);
}

TEST_F(TranscodingClientManagerTest, TestAddingMultipleClient) {
    addMultipleClients();
    unregisterMultipleClients();
}

TEST_F(TranscodingClientManagerTest, TestSubmitCancelGetJobs) {
    addMultipleClients();

    // Test jobId assignment.
    TranscodingRequestParcel request;
    request.fileName = "test_file_0";
    TranscodingJobParcel job;
    bool result;
    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(0));

    request.fileName = "test_file_1";
    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(1));

    request.fileName = "test_file_2";
    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(2));

    // Test submit bad request (no valid fileName) fails.
    TranscodingRequestParcel badRequest;
    badRequest.fileName = "bad_file";
    EXPECT_TRUE(mClient1->submitRequest(badRequest, &job, &result).isOk());
    EXPECT_FALSE(result);

    // Test get jobs by id.
    EXPECT_TRUE(mClient1->getJobWithId(JOB(2), &job, &result).isOk());
    EXPECT_EQ(job.jobId, JOB(2));
    EXPECT_EQ(job.request.fileName, "test_file_2");
    EXPECT_TRUE(result);

    // Test get jobs by invalid id fails.
    EXPECT_TRUE(mClient1->getJobWithId(JOB(100), &job, &result).isOk());
    EXPECT_FALSE(result);

    // Test cancel non-existent job fail.
    EXPECT_TRUE(mClient2->cancelJob(JOB(100), &result).isOk());
    EXPECT_FALSE(result);

    // Test cancel valid jobId in arbitrary order.
    EXPECT_TRUE(mClient1->cancelJob(JOB(2), &result).isOk());
    EXPECT_TRUE(result);

    EXPECT_TRUE(mClient1->cancelJob(JOB(0), &result).isOk());
    EXPECT_TRUE(result);

    EXPECT_TRUE(mClient1->cancelJob(JOB(1), &result).isOk());
    EXPECT_TRUE(result);

    // Test cancel job again fails.
    EXPECT_TRUE(mClient1->cancelJob(JOB(1), &result).isOk());
    EXPECT_FALSE(result);

    // Test get job after cancel fails.
    EXPECT_TRUE(mClient1->getJobWithId(JOB(2), &job, &result).isOk());
    EXPECT_FALSE(result);

    // Test jobId independence for each client.
    EXPECT_TRUE(mClient2->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(0));

    EXPECT_TRUE(mClient2->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(1));

    unregisterMultipleClients();
}

TEST_F(TranscodingClientManagerTest, TestClientCallback) {
    addMultipleClients();

    TranscodingRequestParcel request;
    request.fileName = "test_file_name";
    TranscodingJobParcel job;
    bool result;
    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(0));

    mScheduler->finishLastJob();
    EXPECT_EQ(mClientCallback1->popEvent(), TestClientCallback::Finished(job.jobId));

    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(1));

    mScheduler->abortLastJob();
    EXPECT_EQ(mClientCallback1->popEvent(), TestClientCallback::Failed(job.jobId));

    EXPECT_TRUE(mClient1->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(2));

    EXPECT_TRUE(mClient2->submitRequest(request, &job, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(job.jobId, JOB(0));

    mScheduler->finishLastJob();
    EXPECT_EQ(mClientCallback2->popEvent(), TestClientCallback::Finished(job.jobId));

    unregisterMultipleClients();
}

TEST_F(TranscodingClientManagerTest, TestUseAfterUnregister) {
    // Add a client.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kClientPid, kClientUid, kClientName,
                                             kClientPackage, &client);
    EXPECT_EQ(err, OK);
    EXPECT_NE(client.get(), nullptr);

    // Submit 2 requests, 1 offline and 1 realtime.
    TranscodingRequestParcel request;
    TranscodingJobParcel job;
    bool result;

    request.fileName = "test_file_0";
    request.priority = TranscodingJobPriority::kUnspecified;
    EXPECT_TRUE(client->submitRequest(request, &job, &result).isOk() && result);
    EXPECT_EQ(job.jobId, JOB(0));

    request.fileName = "test_file_1";
    request.priority = TranscodingJobPriority::kNormal;
    EXPECT_TRUE(client->submitRequest(request, &job, &result).isOk() && result);
    EXPECT_EQ(job.jobId, JOB(1));

    // Unregister client, should succeed.
    Status status = client->unregister();
    EXPECT_TRUE(status.isOk());

    // Test submit new request after unregister, should fail with ERROR_DISCONNECTED.
    request.fileName = "test_file_2";
    request.priority = TranscodingJobPriority::kNormal;
    status = client->submitRequest(request, &job, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    // Test cancel jobs after unregister, should fail with ERROR_DISCONNECTED
    // regardless of realtime or offline job, or whether the jobId is valid.
    status = client->cancelJob(JOB(0), &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->cancelJob(JOB(1), &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->cancelJob(JOB(2), &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    // Test get jobs, should fail with ERROR_DISCONNECTED regardless of realtime
    // or offline job, or whether the jobId is valid.
    status = client->getJobWithId(JOB(0), &job, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->getJobWithId(JOB(1), &job, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->getJobWithId(JOB(2), &job, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);
}

}  // namespace android
