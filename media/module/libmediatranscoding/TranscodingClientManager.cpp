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

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingClientManager"

#include <aidl/android/media/BnTranscodingClient.h>
#include <aidl/android/media/IMediaTranscodingService.h>
#include <android/binder_ibinder.h>
#include <android/permission_manager.h>
#include <inttypes.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingRequest.h>
#include <media/TranscodingUidPolicy.h>
#include <private/android_filesystem_config.h>
#include <utils/Log.h>
#include <utils/String16.h>

namespace android {

static_assert(sizeof(ClientIdType) == sizeof(void*), "ClientIdType should be pointer-sized");

using ::aidl::android::media::BnTranscodingClient;
using ::aidl::android::media::IMediaTranscodingService;  // For service error codes
using ::aidl::android::media::TranscodingRequestParcel;
using ::aidl::android::media::TranscodingSessionParcel;
using Status = ::ndk::ScopedAStatus;
using ::ndk::SpAIBinder;

//static
std::atomic<ClientIdType> TranscodingClientManager::sCookieCounter = 0;
//static
std::mutex TranscodingClientManager::sCookie2ClientLock;
//static
std::map<ClientIdType, std::shared_ptr<TranscodingClientManager::ClientImpl>>
        TranscodingClientManager::sCookie2Client;
///////////////////////////////////////////////////////////////////////////////

// Convenience methods for constructing binder::Status objects for error returns
#define STATUS_ERROR_FMT(errorCode, errorString, ...) \
    Status::fromServiceSpecificErrorWithMessage(      \
            errorCode,                                \
            String8::format("%s:%d: " errorString, __FUNCTION__, __LINE__, ##__VA_ARGS__))

/**
 * ClientImpl implements a single client and contains all its information.
 */
struct TranscodingClientManager::ClientImpl : public BnTranscodingClient {
    /* The remote client callback that this ClientInfo is associated with.
     * Once the ClientInfo is created, we hold an SpAIBinder so that the binder
     * object doesn't get created again, otherwise the binder object pointer
     * may not be unique.
     */
    SpAIBinder mClientBinder;
    std::shared_ptr<ITranscodingClientCallback> mClientCallback;
    /* A unique id assigned to the client by the service. This number is used
     * by the service for indexing. Here we use the binder object's pointer
     * (casted to int64t_t) as the client id.
     */
    ClientIdType mClientId;
    std::string mClientName;
    std::string mClientOpPackageName;

    // Next sessionId to assign.
    std::atomic<int32_t> mNextSessionId;
    // Whether this client has been unregistered already.
    std::atomic<bool> mAbandoned;
    // Weak pointer to the client manager for this client.
    std::weak_ptr<TranscodingClientManager> mOwner;

    ClientImpl(const std::shared_ptr<ITranscodingClientCallback>& callback,
               const std::string& clientName, const std::string& opPackageName,
               const std::weak_ptr<TranscodingClientManager>& owner);

    Status submitRequest(const TranscodingRequestParcel& /*in_request*/,
                         TranscodingSessionParcel* /*out_session*/,
                         bool* /*_aidl_return*/) override;

    Status cancelSession(int32_t /*in_sessionId*/, bool* /*_aidl_return*/) override;

    Status getSessionWithId(int32_t /*in_sessionId*/, TranscodingSessionParcel* /*out_session*/,
                            bool* /*_aidl_return*/) override;

    Status addClientUid(int32_t /*in_sessionId*/, int32_t /*in_clientUid*/,
                        bool* /*_aidl_return*/) override;

    Status getClientUids(int32_t /*in_sessionId*/,
                         std::optional<std::vector<int32_t>>* /*_aidl_return*/) override;

    Status unregister() override;
};

TranscodingClientManager::ClientImpl::ClientImpl(
        const std::shared_ptr<ITranscodingClientCallback>& callback, const std::string& clientName,
        const std::string& opPackageName, const std::weak_ptr<TranscodingClientManager>& owner)
      : mClientBinder((callback != nullptr) ? callback->asBinder() : nullptr),
        mClientCallback(callback),
        mClientId(sCookieCounter.fetch_add(1, std::memory_order_relaxed)),
        mClientName(clientName),
        mClientOpPackageName(opPackageName),
        mNextSessionId(0),
        mAbandoned(false),
        mOwner(owner) {}

Status TranscodingClientManager::ClientImpl::submitRequest(
        const TranscodingRequestParcel& in_request, TranscodingSessionParcel* out_session,
        bool* _aidl_return) {
    *_aidl_return = false;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_request.sourceFilePath.empty() || in_request.destinationFilePath.empty()) {
        return Status::ok();
    }

    int32_t callingPid = AIBinder_getCallingPid();
    int32_t callingUid = AIBinder_getCallingUid();
    int32_t in_clientUid = in_request.clientUid;
    int32_t in_clientPid = in_request.clientPid;

    // Check if we can trust clientUid. Only privilege caller could forward the
    // uid on app client's behalf.
    if (in_clientUid == IMediaTranscodingService::USE_CALLING_UID) {
        in_clientUid = callingUid;
    } else if (in_clientUid < 0) {
        return Status::ok();
    } else if (in_clientUid != callingUid && !owner->isTrustedCaller(callingPid, callingUid)) {
        ALOGE("submitRequest rejected (clientPid %d, clientUid %d) "
              "(don't trust callingUid %d)",
              in_clientPid, in_clientUid, callingUid);
        return STATUS_ERROR_FMT(IMediaTranscodingService::ERROR_PERMISSION_DENIED,
                                "submitRequest rejected (clientPid %d, clientUid %d) "
                                "(don't trust callingUid %d)",
                                in_clientPid, in_clientUid, callingUid);
    }

    // Check if we can trust clientPid. Only privilege caller could forward the
    // pid on app client's behalf.
    if (in_clientPid == IMediaTranscodingService::USE_CALLING_PID) {
        in_clientPid = callingPid;
    } else if (in_clientPid < 0) {
        return Status::ok();
    } else if (in_clientPid != callingPid && !owner->isTrustedCaller(callingPid, callingUid)) {
        ALOGE("submitRequest rejected (clientPid %d, clientUid %d) "
              "(don't trust callingUid %d)",
              in_clientPid, in_clientUid, callingUid);
        return STATUS_ERROR_FMT(IMediaTranscodingService::ERROR_PERMISSION_DENIED,
                                "submitRequest rejected (clientPid %d, clientUid %d) "
                                "(don't trust callingUid %d)",
                                in_clientPid, in_clientUid, callingUid);
    }

    int32_t sessionId = mNextSessionId.fetch_add(1);

    *_aidl_return = owner->mSessionController->submit(mClientId, sessionId, callingUid,
                                                      in_clientUid, in_request, mClientCallback);

    if (*_aidl_return) {
        out_session->sessionId = sessionId;

        // TODO(chz): is some of this coming from SessionController?
        *(TranscodingRequest*)&out_session->request = in_request;
        out_session->awaitNumberOfSessions = 0;
    }

    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::cancelSession(int32_t in_sessionId,
                                                           bool* _aidl_return) {
    *_aidl_return = false;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_sessionId < 0) {
        return Status::ok();
    }

    *_aidl_return = owner->mSessionController->cancel(mClientId, in_sessionId);
    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::getSessionWithId(int32_t in_sessionId,
                                                              TranscodingSessionParcel* out_session,
                                                              bool* _aidl_return) {
    *_aidl_return = false;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_sessionId < 0) {
        return Status::ok();
    }

    *_aidl_return =
            owner->mSessionController->getSession(mClientId, in_sessionId, &out_session->request);

    if (*_aidl_return) {
        out_session->sessionId = in_sessionId;
        out_session->awaitNumberOfSessions = 0;
    }
    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::addClientUid(int32_t in_sessionId,
                                                          int32_t in_clientUid,
                                                          bool* _aidl_return) {
    *_aidl_return = false;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_sessionId < 0) {
        return Status::ok();
    }

    int32_t callingPid = AIBinder_getCallingPid();
    int32_t callingUid = AIBinder_getCallingUid();

    // Check if we can trust clientUid. Only privilege caller could add uid to existing sessions.
    if (in_clientUid == IMediaTranscodingService::USE_CALLING_UID) {
        in_clientUid = callingUid;
    } else if (in_clientUid < 0) {
        return Status::ok();
    } else if (in_clientUid != callingUid && !owner->isTrustedCaller(callingPid, callingUid)) {
        ALOGE("addClientUid rejected (clientUid %d) "
              "(don't trust callingUid %d)",
              in_clientUid, callingUid);
        return STATUS_ERROR_FMT(IMediaTranscodingService::ERROR_PERMISSION_DENIED,
                                "addClientUid rejected (clientUid %d) "
                                "(don't trust callingUid %d)",
                                in_clientUid, callingUid);
    }

    *_aidl_return = owner->mSessionController->addClientUid(mClientId, in_sessionId, in_clientUid);
    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::getClientUids(
        int32_t in_sessionId, std::optional<std::vector<int32_t>>* _aidl_return) {
    *_aidl_return = std::nullopt;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_sessionId < 0) {
        return Status::ok();
    }

    std::vector<int32_t> result;

    if (owner->mSessionController->getClientUids(mClientId, in_sessionId, &result)) {
        *_aidl_return = result;
    }
    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::unregister() {
    bool abandoned = mAbandoned.exchange(true);

    std::shared_ptr<TranscodingClientManager> owner;
    if (abandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    // Use sessionId == -1 to cancel all realtime sessions for this client with the controller.
    owner->mSessionController->cancel(mClientId, -1);
    owner->removeClient(mClientId);

    return Status::ok();
}

///////////////////////////////////////////////////////////////////////////////

// static
void TranscodingClientManager::BinderDiedCallback(void* cookie) {
    ClientIdType clientId = reinterpret_cast<ClientIdType>(cookie);

    ALOGD("Client %lld is dead", (long long)clientId);

    std::shared_ptr<ClientImpl> client;

    {
        std::scoped_lock lock{sCookie2ClientLock};

        auto it = sCookie2Client.find(clientId);
        if (it != sCookie2Client.end()) {
            client = it->second;
        }
    }

    if (client != nullptr) {
        client->unregister();
    }
}

TranscodingClientManager::TranscodingClientManager(
        const std::shared_ptr<ControllerClientInterface>& controller)
      : mDeathRecipient(AIBinder_DeathRecipient_new(BinderDiedCallback)),
        mSessionController(controller) {
    ALOGD("TranscodingClientManager started");
    for (uid_t uid : {AID_ROOT, AID_SYSTEM, AID_SHELL, AID_MEDIA}) {
        mTrustedUids.insert(uid);
    }
}

TranscodingClientManager::~TranscodingClientManager() {
    ALOGD("TranscodingClientManager exited");
}

void TranscodingClientManager::dumpAllClients(int fd, const Vector<String16>& args __unused) {
    String8 result;

    const size_t SIZE = 256;
    char buffer[SIZE];
    std::scoped_lock lock{mLock};

    if (mClientIdToClientMap.size() > 0) {
        snprintf(buffer, SIZE, "\n========== Dumping all clients =========\n");
        result.append(buffer);
    }

    snprintf(buffer, SIZE, "  Total num of Clients: %zu\n", mClientIdToClientMap.size());
    result.append(buffer);

    for (const auto& iter : mClientIdToClientMap) {
        snprintf(buffer, SIZE, "    Client %lld:  pkg: %s\n", (long long)iter.first,
                 iter.second->mClientName.c_str());
        result.append(buffer);
    }

    write(fd, result.c_str(), result.size());
}

bool TranscodingClientManager::isTrustedCaller(pid_t pid, uid_t uid) {
    if (uid > 0 && mTrustedUids.count(uid) > 0) {
        return true;
    }

    int32_t result;
    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        if (APermissionManager_checkPermission("android.permission.WRITE_MEDIA_STORAGE", pid, uid,
                                               &result) == PERMISSION_MANAGER_STATUS_OK &&
            result == PERMISSION_MANAGER_PERMISSION_GRANTED) {
            mTrustedUids.insert(uid);
            return true;
        }
    }

    return false;
}

status_t TranscodingClientManager::addClient(
        const std::shared_ptr<ITranscodingClientCallback>& callback, const std::string& clientName,
        const std::string& opPackageName, std::shared_ptr<ITranscodingClient>* outClient) {
    int32_t callingPid = AIBinder_getCallingPid();
    int32_t callingUid = AIBinder_getCallingUid();

    // Check if client has the permission
    if (!isTrustedCaller(callingPid, callingUid)) {
        ALOGE("addClient rejected (clientPid %d, clientUid %d)", callingPid, callingUid);
        return IMediaTranscodingService::ERROR_PERMISSION_DENIED;
    }

    // Validate the client.
    if (callback == nullptr || clientName.empty() || opPackageName.empty()) {
        ALOGE("Invalid client");
        return IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT;
    }

    SpAIBinder binder = callback->asBinder();

    std::scoped_lock lock{mLock};

    // Checks if the client already registers.
    if (mRegisteredCallbacks.count((uintptr_t)binder.get()) > 0) {
        return IMediaTranscodingService::ERROR_ALREADY_EXISTS;
    }

    // Creates the client (with the id assigned by ClientImpl).
    std::shared_ptr<ClientImpl> client = ::ndk::SharedRefBase::make<ClientImpl>(
            callback, clientName, opPackageName, shared_from_this());

    ALOGD("Adding client id %lld, name %s, package %s", (long long)client->mClientId,
          client->mClientName.c_str(), client->mClientOpPackageName.c_str());

    {
        std::scoped_lock lock{sCookie2ClientLock};
        sCookie2Client.emplace(std::make_pair(client->mClientId, client));
    }

    AIBinder_linkToDeath(binder.get(), mDeathRecipient.get(),
                         reinterpret_cast<void*>(client->mClientId));

    // Adds the new client to the map.
    mRegisteredCallbacks.insert((uintptr_t)binder.get());
    mClientIdToClientMap[client->mClientId] = client;

    *outClient = client;

    return OK;
}

status_t TranscodingClientManager::removeClient(ClientIdType clientId) {
    ALOGD("Removing client id %lld", (long long)clientId);
    std::scoped_lock lock{mLock};

    // Checks if the client is valid.
    auto it = mClientIdToClientMap.find(clientId);
    if (it == mClientIdToClientMap.end()) {
        ALOGE("Client id %lld does not exist", (long long)clientId);
        return IMediaTranscodingService::ERROR_INVALID_OPERATION;
    }

    SpAIBinder binder = it->second->mClientBinder;

    // Check if the client still live. If alive, unlink the death.
    if (binder.get() != nullptr) {
        AIBinder_unlinkToDeath(binder.get(), mDeathRecipient.get(),
                               reinterpret_cast<void*>(it->second->mClientId));
    }

    {
        std::scoped_lock lock{sCookie2ClientLock};
        sCookie2Client.erase(it->second->mClientId);
    }

    // Erase the entry.
    mClientIdToClientMap.erase(it);
    mRegisteredCallbacks.erase((uintptr_t)binder.get());

    return OK;
}

size_t TranscodingClientManager::getNumOfClients() const {
    std::scoped_lock lock{mLock};
    return mClientIdToClientMap.size();
}

}  // namespace android
