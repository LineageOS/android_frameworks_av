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
#include <media/ControllerClientInterface.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingRequest.h>
#include <utils/Log.h>

#include <list>

namespace android {

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::BnTranscodingClientCallback;
using ::aidl::android::media::IMediaTranscodingService;
using ::aidl::android::media::TranscodingErrorCode;
using ::aidl::android::media::TranscodingRequestParcel;
using ::aidl::android::media::TranscodingResultParcel;
using ::aidl::android::media::TranscodingSessionParcel;
using ::aidl::android::media::TranscodingSessionPriority;

constexpr pid_t kInvalidClientPid = -5;
constexpr pid_t kInvalidClientUid = -10;
constexpr const char* kInvalidClientName = "";
constexpr const char* kInvalidClientPackage = "";

constexpr const char* kClientName = "TestClientName";
constexpr const char* kClientPackage = "TestClientPackage";
constexpr uid_t OFFLINE_UID = -1;

#define SESSION(n) (n)

struct TestClientCallback : public BnTranscodingClientCallback {
    TestClientCallback() { ALOGI("TestClientCallback Created"); }

    virtual ~TestClientCallback() { ALOGI("TestClientCallback destroyed"); };

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
        mEventQueue.push_back(Finished(in_sessionId));
        return Status::ok();
    }

    Status onTranscodingFailed(int32_t in_sessionId,
                               TranscodingErrorCode /*in_errorCode */) override {
        mEventQueue.push_back(Failed(in_sessionId));
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

    struct Event {
        enum {
            NoEvent,
            Finished,
            Failed,
        } type;
        SessionIdType sessionId;
    };

    static constexpr Event NoEvent = {Event::NoEvent, 0};
#define DECLARE_EVENT(action) \
    static Event action(SessionIdType sessionId) { return {Event::action, sessionId}; }

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
    return lhs.type == rhs.type && lhs.sessionId == rhs.sessionId;
}

struct TestController : public ControllerClientInterface {
    TestController() { ALOGI("TestController Created"); }

    virtual ~TestController() { ALOGI("TestController Destroyed"); }

    bool submit(ClientIdType clientId, SessionIdType sessionId, uid_t /*callingUid*/,
                uid_t clientUid, const TranscodingRequestParcel& request,
                const std::weak_ptr<ITranscodingClientCallback>& clientCallback) override {
        SessionKeyType sessionKey = std::make_pair(clientId, sessionId);
        if (mSessions.count(sessionKey) > 0) {
            return false;
        }

        // This is the secret name we'll check, to test error propagation from
        // the controller back to client.
        if (request.sourceFilePath == "bad_source_file") {
            return false;
        }

        if (request.priority == TranscodingSessionPriority::kUnspecified) {
            clientUid = OFFLINE_UID;
        }

        mSessions[sessionKey].request = request;
        mSessions[sessionKey].callback = clientCallback;
        mSessions[sessionKey].allClientUids.insert(clientUid);

        mLastSession = sessionKey;
        return true;
    }

    bool addClientUid(ClientIdType clientId, SessionIdType sessionId, uid_t clientUid) override {
        SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

        if (mSessions.count(sessionKey) == 0) {
            return false;
        }
        if (mSessions[sessionKey].allClientUids.count(clientUid) > 0) {
            return false;
        }
        mSessions[sessionKey].allClientUids.insert(clientUid);
        return true;
    }

    bool getClientUids(ClientIdType clientId, SessionIdType sessionId,
                       std::vector<int32_t>* out_clientUids) override {
        SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

        if (mSessions.count(sessionKey) == 0) {
            return false;
        }
        out_clientUids->clear();
        for (uid_t uid : mSessions[sessionKey].allClientUids) {
            if (uid != OFFLINE_UID) {
                out_clientUids->push_back(uid);
            }
        }
        return true;
    }

    bool cancel(ClientIdType clientId, SessionIdType sessionId) override {
        SessionKeyType sessionKey = std::make_pair(clientId, sessionId);

        if (mSessions.count(sessionKey) == 0) {
            return false;
        }
        mSessions.erase(sessionKey);
        return true;
    }

    bool getSession(ClientIdType clientId, SessionIdType sessionId,
                    TranscodingRequestParcel* request) override {
        SessionKeyType sessionKey = std::make_pair(clientId, sessionId);
        if (mSessions.count(sessionKey) == 0) {
            return false;
        }

        *(TranscodingRequest*)request = mSessions[sessionKey].request;
        return true;
    }

    void finishLastSession() {
        auto it = mSessions.find(mLastSession);
        if (it == mSessions.end()) {
            return;
        }
        {
            auto clientCallback = it->second.callback.lock();
            if (clientCallback != nullptr) {
                clientCallback->onTranscodingFinished(
                        mLastSession.second,
                        TranscodingResultParcel({mLastSession.second, 0, std::nullopt}));
            }
        }
        mSessions.erase(it);
    }

    void abortLastSession() {
        auto it = mSessions.find(mLastSession);
        if (it == mSessions.end()) {
            return;
        }
        {
            auto clientCallback = it->second.callback.lock();
            if (clientCallback != nullptr) {
                clientCallback->onTranscodingFailed(mLastSession.second,
                                                    TranscodingErrorCode::kUnknown);
            }
        }
        mSessions.erase(it);
    }

    struct Session {
        TranscodingRequest request;
        std::weak_ptr<ITranscodingClientCallback> callback;
        std::unordered_set<uid_t> allClientUids;
    };

    typedef std::pair<ClientIdType, SessionIdType> SessionKeyType;
    std::map<SessionKeyType, Session> mSessions;
    SessionKeyType mLastSession;
};

class TranscodingClientManagerTest : public ::testing::Test {
public:
    TranscodingClientManagerTest()
          : mController(new TestController()),
            mClientManager(new TranscodingClientManager(mController)) {
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
        EXPECT_EQ(
                mClientManager->addClient(mClientCallback1, kClientName, kClientPackage, &mClient1),
                OK);
        EXPECT_NE(mClient1, nullptr);

        EXPECT_EQ(
                mClientManager->addClient(mClientCallback2, kClientName, kClientPackage, &mClient2),
                OK);
        EXPECT_NE(mClient2, nullptr);

        EXPECT_EQ(
                mClientManager->addClient(mClientCallback3, kClientName, kClientPackage, &mClient3),
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

    std::shared_ptr<TestController> mController;
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
    status_t err = mClientManager->addClient(nullptr, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
}
//
//TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPid) {
//    // Add a client with invalid Pid and expect failure.
//    std::shared_ptr<ITranscodingClient> client;
//    status_t err = mClientManager->addClient(mClientCallback1,
//                                             kClientName, kClientPackage, &client);
//    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
//}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientName) {
    // Add a client with invalid name and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kInvalidClientName, kClientPackage,
                                             &client);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
}

TEST_F(TranscodingClientManagerTest, TestAddingWithInvalidClientPackageName) {
    // Add a client with invalid packagename and expect failure.
    std::shared_ptr<ITranscodingClient> client;
    status_t err = mClientManager->addClient(mClientCallback1, kClientName, kInvalidClientPackage,
                                             &client);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT);
}

TEST_F(TranscodingClientManagerTest, TestAddingValidClient) {
    // Add a valid client, should succeed.
    std::shared_ptr<ITranscodingClient> client;
    status_t err =
            mClientManager->addClient(mClientCallback1, kClientName, kClientPackage, &client);
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
    status_t err =
            mClientManager->addClient(mClientCallback1, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, OK);
    EXPECT_NE(client.get(), nullptr);
    EXPECT_EQ(mClientManager->getNumOfClients(), 1);

    std::shared_ptr<ITranscodingClient> dupClient;
    err = mClientManager->addClient(mClientCallback1, "dupClient", "dupPackage", &dupClient);
    EXPECT_EQ(err, IMediaTranscodingService::ERROR_ALREADY_EXISTS);
    EXPECT_EQ(dupClient.get(), nullptr);
    EXPECT_EQ(mClientManager->getNumOfClients(), 1);

    Status status = client->unregister();
    EXPECT_TRUE(status.isOk());
    EXPECT_EQ(mClientManager->getNumOfClients(), 0);

    err = mClientManager->addClient(mClientCallback1, "dupClient", "dupPackage", &dupClient);
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

TEST_F(TranscodingClientManagerTest, TestSubmitCancelGetSessions) {
    addMultipleClients();

    // Test sessionId assignment.
    TranscodingRequestParcel request;
    request.sourceFilePath = "test_source_file_0";
    request.destinationFilePath = "test_desintaion_file_0";
    TranscodingSessionParcel session;
    bool result;
    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(0));

    request.sourceFilePath = "test_source_file_1";
    request.destinationFilePath = "test_desintaion_file_1";
    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(1));

    request.sourceFilePath = "test_source_file_2";
    request.destinationFilePath = "test_desintaion_file_2";
    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(2));

    // Test submit bad request (no valid sourceFilePath) fails.
    TranscodingRequestParcel badRequest;
    badRequest.sourceFilePath = "bad_source_file";
    badRequest.destinationFilePath = "bad_destination_file";
    EXPECT_TRUE(mClient1->submitRequest(badRequest, &session, &result).isOk());
    EXPECT_FALSE(result);

    // Test submit with bad pid/uid.
    badRequest.sourceFilePath = "test_source_file_3";
    badRequest.destinationFilePath = "test_desintaion_file_3";
    badRequest.clientPid = kInvalidClientPid;
    badRequest.clientUid = kInvalidClientUid;
    EXPECT_TRUE(mClient1->submitRequest(badRequest, &session, &result).isOk());
    EXPECT_FALSE(result);

    // Test get sessions by id.
    EXPECT_TRUE(mClient1->getSessionWithId(SESSION(2), &session, &result).isOk());
    EXPECT_EQ(session.sessionId, SESSION(2));
    EXPECT_EQ(session.request.sourceFilePath, "test_source_file_2");
    EXPECT_TRUE(result);

    // Test get sessions by invalid id fails.
    EXPECT_TRUE(mClient1->getSessionWithId(SESSION(100), &session, &result).isOk());
    EXPECT_FALSE(result);

    // Test cancel non-existent session fail.
    EXPECT_TRUE(mClient2->cancelSession(SESSION(100), &result).isOk());
    EXPECT_FALSE(result);

    // Test cancel valid sessionId in arbitrary order.
    EXPECT_TRUE(mClient1->cancelSession(SESSION(2), &result).isOk());
    EXPECT_TRUE(result);

    EXPECT_TRUE(mClient1->cancelSession(SESSION(0), &result).isOk());
    EXPECT_TRUE(result);

    EXPECT_TRUE(mClient1->cancelSession(SESSION(1), &result).isOk());
    EXPECT_TRUE(result);

    // Test cancel session again fails.
    EXPECT_TRUE(mClient1->cancelSession(SESSION(1), &result).isOk());
    EXPECT_FALSE(result);

    // Test get session after cancel fails.
    EXPECT_TRUE(mClient1->getSessionWithId(SESSION(2), &session, &result).isOk());
    EXPECT_FALSE(result);

    // Test sessionId independence for each client.
    EXPECT_TRUE(mClient2->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(0));

    EXPECT_TRUE(mClient2->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(1));

    unregisterMultipleClients();
}

TEST_F(TranscodingClientManagerTest, TestClientCallback) {
    addMultipleClients();

    TranscodingRequestParcel request;
    request.sourceFilePath = "test_source_file_name";
    request.destinationFilePath = "test_destination_file_name";
    TranscodingSessionParcel session;
    bool result;
    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(0));

    mController->finishLastSession();
    EXPECT_EQ(mClientCallback1->popEvent(), TestClientCallback::Finished(session.sessionId));

    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(1));

    mController->abortLastSession();
    EXPECT_EQ(mClientCallback1->popEvent(), TestClientCallback::Failed(session.sessionId));

    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(2));

    EXPECT_TRUE(mClient2->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_EQ(session.sessionId, SESSION(0));

    mController->finishLastSession();
    EXPECT_EQ(mClientCallback2->popEvent(), TestClientCallback::Finished(session.sessionId));

    unregisterMultipleClients();
}

TEST_F(TranscodingClientManagerTest, TestUseAfterUnregister) {
    // Add a client.
    std::shared_ptr<ITranscodingClient> client;
    status_t err =
            mClientManager->addClient(mClientCallback1, kClientName, kClientPackage, &client);
    EXPECT_EQ(err, OK);
    EXPECT_NE(client.get(), nullptr);

    // Submit 2 requests, 1 offline and 1 realtime.
    TranscodingRequestParcel request;
    TranscodingSessionParcel session;
    bool result;

    request.sourceFilePath = "test_source_file_0";
    request.destinationFilePath = "test_destination_file_0";
    request.priority = TranscodingSessionPriority::kUnspecified;
    EXPECT_TRUE(client->submitRequest(request, &session, &result).isOk() && result);
    EXPECT_EQ(session.sessionId, SESSION(0));

    request.sourceFilePath = "test_source_file_1";
    request.destinationFilePath = "test_destination_file_1";
    request.priority = TranscodingSessionPriority::kNormal;
    EXPECT_TRUE(client->submitRequest(request, &session, &result).isOk() && result);
    EXPECT_EQ(session.sessionId, SESSION(1));

    // Unregister client, should succeed.
    Status status = client->unregister();
    EXPECT_TRUE(status.isOk());

    // Test submit new request after unregister, should fail with ERROR_DISCONNECTED.
    request.sourceFilePath = "test_source_file_2";
    request.destinationFilePath = "test_destination_file_2";
    request.priority = TranscodingSessionPriority::kNormal;
    status = client->submitRequest(request, &session, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    // Test cancel sessions after unregister, should fail with ERROR_DISCONNECTED
    // regardless of realtime or offline session, or whether the sessionId is valid.
    status = client->cancelSession(SESSION(0), &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->cancelSession(SESSION(1), &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->cancelSession(SESSION(2), &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    // Test get sessions, should fail with ERROR_DISCONNECTED regardless of realtime
    // or offline session, or whether the sessionId is valid.
    status = client->getSessionWithId(SESSION(0), &session, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->getSessionWithId(SESSION(1), &session, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);

    status = client->getSessionWithId(SESSION(2), &session, &result);
    EXPECT_FALSE(status.isOk());
    EXPECT_EQ(status.getServiceSpecificError(), IMediaTranscodingService::ERROR_DISCONNECTED);
}

TEST_F(TranscodingClientManagerTest, TestAddGetClientUidsInvalidArgs) {
    addMultipleClients();

    bool result;
    std::optional<std::vector<int32_t>> clientUids;
    TranscodingRequestParcel request;
    TranscodingSessionParcel session;
    uid_t ownUid = ::getuid();

    // Add/Get clients with invalid session id fails.
    EXPECT_TRUE(mClient1->addClientUid(-1, ownUid, &result).isOk());
    EXPECT_FALSE(result);
    EXPECT_TRUE(mClient1->addClientUid(SESSION(0), ownUid, &result).isOk());
    EXPECT_FALSE(result);
    EXPECT_TRUE(mClient1->getClientUids(-1, &clientUids).isOk());
    EXPECT_EQ(clientUids, std::nullopt);
    EXPECT_TRUE(mClient1->getClientUids(SESSION(0), &clientUids).isOk());
    EXPECT_EQ(clientUids, std::nullopt);

    unregisterMultipleClients();
}

TEST_F(TranscodingClientManagerTest, TestAddGetClientUids) {
    addMultipleClients();

    bool result;
    std::optional<std::vector<int32_t>> clientUids;
    TranscodingRequestParcel request;
    TranscodingSessionParcel session;
    uid_t ownUid = ::getuid();

    // Submit one real-time session.
    request.sourceFilePath = "test_source_file_0";
    request.destinationFilePath = "test_desintaion_file_0";
    request.priority = TranscodingSessionPriority::kNormal;
    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);

    // Should have own uid in client uid list.
    EXPECT_TRUE(mClient1->getClientUids(SESSION(0), &clientUids).isOk());
    EXPECT_NE(clientUids, std::nullopt);
    EXPECT_EQ(clientUids->size(), 1);
    EXPECT_EQ((*clientUids)[0], ownUid);

    // Adding invalid client uid should fail.
    EXPECT_TRUE(mClient1->addClientUid(SESSION(0), kInvalidClientUid, &result).isOk());
    EXPECT_FALSE(result);

    // Adding own uid again should fail.
    EXPECT_TRUE(mClient1->addClientUid(SESSION(0), ownUid, &result).isOk());
    EXPECT_FALSE(result);

    // Submit one offline session.
    request.sourceFilePath = "test_source_file_1";
    request.destinationFilePath = "test_desintaion_file_1";
    request.priority = TranscodingSessionPriority::kUnspecified;
    EXPECT_TRUE(mClient1->submitRequest(request, &session, &result).isOk());
    EXPECT_TRUE(result);

    // Should not have own uid in client uid list.
    EXPECT_TRUE(mClient1->getClientUids(SESSION(1), &clientUids).isOk());
    EXPECT_NE(clientUids, std::nullopt);
    EXPECT_EQ(clientUids->size(), 0);

    // Add own uid (with IMediaTranscodingService::USE_CALLING_UID) again, should succeed.
    EXPECT_TRUE(
            mClient1->addClientUid(SESSION(1), IMediaTranscodingService::USE_CALLING_UID, &result)
                    .isOk());
    EXPECT_TRUE(result);
    EXPECT_TRUE(mClient1->getClientUids(SESSION(1), &clientUids).isOk());
    EXPECT_NE(clientUids, std::nullopt);
    EXPECT_EQ(clientUids->size(), 1);
    EXPECT_EQ((*clientUids)[0], ownUid);

    // Add more uids, should succeed.
    int32_t kFakeUid = ::getuid() ^ 0x1;
    EXPECT_TRUE(mClient1->addClientUid(SESSION(1), kFakeUid, &result).isOk());
    EXPECT_TRUE(result);
    EXPECT_TRUE(mClient1->getClientUids(SESSION(1), &clientUids).isOk());
    EXPECT_NE(clientUids, std::nullopt);
    std::unordered_set<uid_t> uidSet;
    uidSet.insert(clientUids->begin(), clientUids->end());
    EXPECT_EQ(uidSet.size(), 2);
    EXPECT_EQ(uidSet.count(ownUid), 1);
    EXPECT_EQ(uidSet.count(kFakeUid), 1);

    unregisterMultipleClients();
}

}  // namespace android
