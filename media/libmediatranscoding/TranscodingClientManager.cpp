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
#include <inttypes.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingRequest.h>
#include <utils/Log.h>
namespace android {

static_assert(sizeof(ClientIdType) == sizeof(void*), "ClientIdType should be pointer-sized");

using ::aidl::android::media::BnTranscodingClient;
using ::aidl::android::media::IMediaTranscodingService;  // For service error codes
using ::aidl::android::media::TranscodingJobParcel;
using ::aidl::android::media::TranscodingRequestParcel;
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
    pid_t mClientPid;
    uid_t mClientUid;
    std::string mClientName;
    std::string mClientOpPackageName;

    // Next jobId to assign.
    std::atomic<int32_t> mNextJobId;
    // Whether this client has been unregistered already.
    std::atomic<bool> mAbandoned;
    // Weak pointer to the client manager for this client.
    std::weak_ptr<TranscodingClientManager> mOwner;

    ClientImpl(const std::shared_ptr<ITranscodingClientCallback>& callback, pid_t pid, uid_t uid,
               const std::string& clientName, const std::string& opPackageName,
               const std::weak_ptr<TranscodingClientManager>& owner);

    Status submitRequest(const TranscodingRequestParcel& /*in_request*/,
                         TranscodingJobParcel* /*out_job*/, bool* /*_aidl_return*/) override;

    Status cancelJob(int32_t /*in_jobId*/, bool* /*_aidl_return*/) override;

    Status getJobWithId(int32_t /*in_jobId*/, TranscodingJobParcel* /*out_job*/,
                        bool* /*_aidl_return*/) override;

    Status unregister() override;
};

TranscodingClientManager::ClientImpl::ClientImpl(
        const std::shared_ptr<ITranscodingClientCallback>& callback, pid_t pid, uid_t uid,
        const std::string& clientName, const std::string& opPackageName,
        const std::weak_ptr<TranscodingClientManager>& owner)
      : mClientBinder((callback != nullptr) ? callback->asBinder() : nullptr),
        mClientCallback(callback),
        mClientId(sCookieCounter.fetch_add(1, std::memory_order_relaxed)),
        mClientPid(pid),
        mClientUid(uid),
        mClientName(clientName),
        mClientOpPackageName(opPackageName),
        mNextJobId(0),
        mAbandoned(false),
        mOwner(owner) {}

Status TranscodingClientManager::ClientImpl::submitRequest(
        const TranscodingRequestParcel& in_request, TranscodingJobParcel* out_job,
        bool* _aidl_return) {
    *_aidl_return = false;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_request.sourceFilePath.empty() || in_request.destinationFilePath.empty()) {
        // This is the only error we check for now.
        return Status::ok();
    }

    int32_t jobId = mNextJobId.fetch_add(1);

    *_aidl_return =
            owner->mJobScheduler->submit(mClientId, jobId, mClientUid, in_request, mClientCallback);

    if (*_aidl_return) {
        out_job->jobId = jobId;

        // TODO(chz): is some of this coming from JobScheduler?
        *(TranscodingRequest*)&out_job->request = in_request;
        out_job->awaitNumberOfJobs = 0;
    }

    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::cancelJob(int32_t in_jobId, bool* _aidl_return) {
    *_aidl_return = false;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_jobId < 0) {
        return Status::ok();
    }

    *_aidl_return = owner->mJobScheduler->cancel(mClientId, in_jobId);
    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::getJobWithId(int32_t in_jobId,
                                                          TranscodingJobParcel* out_job,
                                                          bool* _aidl_return) {
    *_aidl_return = false;

    std::shared_ptr<TranscodingClientManager> owner;
    if (mAbandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    if (in_jobId < 0) {
        return Status::ok();
    }

    *_aidl_return = owner->mJobScheduler->getJob(mClientId, in_jobId, &out_job->request);

    if (*_aidl_return) {
        out_job->jobId = in_jobId;
        out_job->awaitNumberOfJobs = 0;
    }
    return Status::ok();
}

Status TranscodingClientManager::ClientImpl::unregister() {
    bool abandoned = mAbandoned.exchange(true);

    std::shared_ptr<TranscodingClientManager> owner;
    if (abandoned || (owner = mOwner.lock()) == nullptr) {
        return Status::fromServiceSpecificError(IMediaTranscodingService::ERROR_DISCONNECTED);
    }

    // Use jobId == -1 to cancel all realtime jobs for this client with the scheduler.
    owner->mJobScheduler->cancel(mClientId, -1);
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
        const std::shared_ptr<SchedulerClientInterface>& scheduler)
      : mDeathRecipient(AIBinder_DeathRecipient_new(BinderDiedCallback)), mJobScheduler(scheduler) {
    ALOGD("TranscodingClientManager started");
}

TranscodingClientManager::~TranscodingClientManager() {
    ALOGD("TranscodingClientManager exited");
}

void TranscodingClientManager::dumpAllClients(int fd, const Vector<String16>& args __unused) {
    String8 result;

    const size_t SIZE = 256;
    char buffer[SIZE];
    std::scoped_lock lock{mLock};

    snprintf(buffer, SIZE, "    Total num of Clients: %zu\n", mClientIdToClientMap.size());
    result.append(buffer);

    if (mClientIdToClientMap.size() > 0) {
        snprintf(buffer, SIZE, "========== Dumping all clients =========\n");
        result.append(buffer);
    }

    for (const auto& iter : mClientIdToClientMap) {
        snprintf(buffer, SIZE, "    -- Client id: %lld  name: %s\n", (long long)iter.first,
                 iter.second->mClientName.c_str());
        result.append(buffer);
    }

    write(fd, result.string(), result.size());
}

status_t TranscodingClientManager::addClient(
        const std::shared_ptr<ITranscodingClientCallback>& callback, pid_t pid, uid_t uid,
        const std::string& clientName, const std::string& opPackageName,
        std::shared_ptr<ITranscodingClient>* outClient) {
    // Validate the client.
    if (callback == nullptr || pid < 0 || clientName.empty() || opPackageName.empty()) {
        ALOGE("Invalid client");
        return IMediaTranscodingService::ERROR_ILLEGAL_ARGUMENT;
    }

    SpAIBinder binder = callback->asBinder();

    std::scoped_lock lock{mLock};

    // Checks if the client already registers.
    if (mRegisteredCallbacks.count((uintptr_t)binder.get()) > 0) {
        return IMediaTranscodingService::ERROR_ALREADY_EXISTS;
    }

    // Creates the client and uses its process id as client id.
    std::shared_ptr<ClientImpl> client = ::ndk::SharedRefBase::make<ClientImpl>(
            callback, pid, uid, clientName, opPackageName, shared_from_this());

    ALOGD("Adding client id %lld, pid %d, uid %d, name %s, package %s",
          (long long)client->mClientId, client->mClientPid, client->mClientUid,
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
