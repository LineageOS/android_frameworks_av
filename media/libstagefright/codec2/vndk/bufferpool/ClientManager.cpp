/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <ClientManager.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "BufferPoolClient.h"

namespace android {
namespace hardware {
namespace media {
namespace bufferpool {
namespace V1_0 {
namespace implementation {

static constexpr int64_t kRegisterTimeoutUs = 500000; // 0.5 sec

class ClientManager::Impl {
public:
    Impl();

    ResultStatus registerSender(const sp<IAccessor> &accessor,
                                ConnectionId *pConnectionId);

    ResultStatus create(const std::shared_ptr<BufferPoolAllocator> &allocator,
                        ConnectionId *pConnectionId);

    ResultStatus close(ConnectionId connectionId);

    ResultStatus allocate(ConnectionId connectionId,
                          const std::vector<uint8_t> &params,
                          std::shared_ptr<_C2BlockPoolData> *buffer);

    ResultStatus receive(ConnectionId connectionId,
                         TransactionId transactionId,
                         BufferId bufferId,
                         int64_t timestampUs,
                         std::shared_ptr<_C2BlockPoolData> *buffer);

    ResultStatus postSend(ConnectionId connectionId,
                          ConnectionId receiverId,
                          const std::shared_ptr<_C2BlockPoolData> &buffer,
                          TransactionId *transactionId,
                          int64_t *timestampUs);

    ResultStatus getAccessor(ConnectionId connectionId,
                             sp<IAccessor> *accessor);

private:
    // In order to prevent deadlock between multiple locks,
    // Always lock ClientCache.lock before locking ActiveClients.lock.
    struct ClientCache {
        // This lock is held for brief duration.
        // Blocking operation is not performed holding the lock.
        std::mutex mMutex;
        std::map<const wp<IAccessor>, const std::weak_ptr<BufferPoolClient>>
                mClients;
        std::condition_variable mConnectCv;
        bool mConnecting;

        ClientCache() : mConnecting(false) {}
    } mCache;

    // Active clients which can be retrieved via ConnectionId
    struct ActiveClients {
        // This lock is held for brief duration.
        // Blocking operation is not performed holding the lock.
        std::mutex mMutex;
        std::map<ConnectionId, const std::shared_ptr<BufferPoolClient>>
                mClients;
    } mActive;

};

ClientManager::Impl::Impl() {}

ResultStatus ClientManager::Impl::registerSender(
        const sp<IAccessor> &accessor, ConnectionId *pConnectionId) {
    int64_t timeoutUs = getTimestampNow() + kRegisterTimeoutUs;
    do {
        std::unique_lock<std::mutex> lock(mCache.mMutex);
        auto it = mCache.mClients.find(accessor);
        if (it != mCache.mClients.end()) {
            const std::shared_ptr<BufferPoolClient> client = it->second.lock();
            if (client) {
                *pConnectionId = client->getConnectionId();
                return ResultStatus::ALREADY_EXISTS;
            }
            mCache.mClients.erase(it);
        }
        if (!mCache.mConnecting) {
            mCache.mConnecting = true;
            lock.unlock();
            ResultStatus result = ResultStatus::OK;
            const std::shared_ptr<BufferPoolClient> client =
                    std::make_shared<BufferPoolClient>(accessor);
            lock.lock();
            if (!client) {
                result = ResultStatus::NO_MEMORY;
            } else if (!client->isValid()) {
                result = ResultStatus::CRITICAL_ERROR;
            }
            if (result == ResultStatus::OK) {
                // TODO: handle insert fail. (malloc fail)
                const std::weak_ptr<BufferPoolClient> wclient = client;
                mCache.mClients.insert(std::make_pair(accessor, wclient));
                ConnectionId conId = client->getConnectionId();
                {
                    std::lock_guard<std::mutex> lock(mActive.mMutex);
                    mActive.mClients.insert(std::make_pair(conId, client));
                }
                *pConnectionId = conId;
            }
            mCache.mConnecting = false;
            lock.unlock();
            mCache.mConnectCv.notify_all();
            return result;
        }
        mCache.mConnectCv.wait_for(
                lock, std::chrono::microseconds(kRegisterTimeoutUs));
    } while (getTimestampNow() < timeoutUs);
    // TODO: return timeout error
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus ClientManager::Impl::create(
        const std::shared_ptr<BufferPoolAllocator> &allocator,
        ConnectionId *pConnectionId) {
    const sp<Accessor> accessor = new Accessor(allocator);
    if (!accessor || !accessor->isValid()) {
        return ResultStatus::CRITICAL_ERROR;
    }
    std::shared_ptr<BufferPoolClient> client =
            std::make_shared<BufferPoolClient>(accessor);
    if (!client || !client->isValid()) {
        return ResultStatus::CRITICAL_ERROR;
    }
    {
        // TODO: handle insert fail. (malloc fail)
        std::lock_guard<std::mutex> lock(mCache.mMutex);
        const wp<Accessor> waccessor = accessor;
        const std::weak_ptr<BufferPoolClient> wclient = client;
        mCache.mClients.insert(std::make_pair(waccessor, wclient));
        ConnectionId conId = client->getConnectionId();
        {
            std::lock_guard<std::mutex> lock(mActive.mMutex);
            mActive.mClients.insert(std::make_pair(conId, client));
        }
        *pConnectionId = conId;
    }
    return ResultStatus::OK;
}

ResultStatus ClientManager::Impl::close(ConnectionId connectionId) {
    std::lock_guard<std::mutex> lock1(mCache.mMutex);
    std::lock_guard<std::mutex> lock2(mActive.mMutex);
    auto it = mActive.mClients.find(connectionId);
    if (it != mActive.mClients.end()) {
        sp<IAccessor> accessor;
        if (it->second->getAccessor(&accessor) == ResultStatus::OK) {
            mCache.mClients.erase(accessor);
        }
        mActive.mClients.erase(connectionId);
        return ResultStatus::OK;
    }
    return ResultStatus::NOT_FOUND;
}

ResultStatus ClientManager::Impl::allocate(
        ConnectionId connectionId, const std::vector<uint8_t> &params,
        std::shared_ptr<_C2BlockPoolData> *buffer) {
    std::shared_ptr<BufferPoolClient> client;
    {
        std::lock_guard<std::mutex> lock(mActive.mMutex);
        auto it = mActive.mClients.find(connectionId);
        if (it == mActive.mClients.end()) {
            return ResultStatus::NOT_FOUND;
        }
        client = it->second;
    }
    return client->allocate(params, buffer);
}

ResultStatus ClientManager::Impl::receive(
        ConnectionId connectionId, TransactionId transactionId,
        BufferId bufferId, int64_t timestampUs,
        std::shared_ptr<_C2BlockPoolData> *buffer) {
    std::shared_ptr<BufferPoolClient> client;
    {
        std::lock_guard<std::mutex> lock(mActive.mMutex);
        auto it = mActive.mClients.find(connectionId);
        if (it == mActive.mClients.end()) {
            return ResultStatus::NOT_FOUND;
        }
        client = it->second;
    }
    return client->receive(transactionId, bufferId, timestampUs, buffer);
}

ResultStatus ClientManager::Impl::postSend(
        ConnectionId connectionId, ConnectionId receiverId,
        const std::shared_ptr<_C2BlockPoolData> &buffer,
        TransactionId *transactionId, int64_t *timestampUs) {
    std::shared_ptr<BufferPoolClient> client;
    {
        std::lock_guard<std::mutex> lock(mActive.mMutex);
        auto it = mActive.mClients.find(connectionId);
        if (it == mActive.mClients.end()) {
            return ResultStatus::NOT_FOUND;
        }
        client = it->second;
    }
    return client->postSend(receiverId, buffer, transactionId, timestampUs);
}

ResultStatus ClientManager::Impl::getAccessor(
        ConnectionId connectionId, sp<IAccessor> *accessor) {
    std::shared_ptr<BufferPoolClient> client;
    {
        std::lock_guard<std::mutex> lock(mActive.mMutex);
        auto it = mActive.mClients.find(connectionId);
        if (it == mActive.mClients.end()) {
            return ResultStatus::NOT_FOUND;
        }
        client = it->second;
    }
    return client->getAccessor(accessor);
}

// Methods from ::android::hardware::media::bufferpool::V1_0::IClientManager follow.
Return<void> ClientManager::registerSender(const sp<::android::hardware::media::bufferpool::V1_0::IAccessor>& bufferPool, registerSender_cb _hidl_cb) {
    if (mImpl) {
        ConnectionId connectionId = -1;
        ResultStatus status = mImpl->registerSender(bufferPool, &connectionId);
        _hidl_cb(status, connectionId);
    } else {
        _hidl_cb(ResultStatus::CRITICAL_ERROR, -1);
    }
    return Void();
}

// Methods for local use.
sp<ClientManager> ClientManager::sInstance;
std::mutex ClientManager::sInstanceLock;

sp<ClientManager> ClientManager::getInstance() {
    std::lock_guard<std::mutex> lock(sInstanceLock);
    if (!sInstance) {
        sInstance = new ClientManager();
    }
    return sInstance;
}

ClientManager::ClientManager() : mImpl(new Impl()) {}

ClientManager::~ClientManager() {
}

ResultStatus ClientManager::create(
        const std::shared_ptr<BufferPoolAllocator> &allocator,
        ConnectionId *pConnectionId) {
    if (mImpl) {
        return mImpl->create(allocator, pConnectionId);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus ClientManager::close(ConnectionId connectionId) {
    if (mImpl) {
        return mImpl->close(connectionId);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus ClientManager::allocate(
        ConnectionId connectionId, const std::vector<uint8_t> &params,
        std::shared_ptr<_C2BlockPoolData> *buffer) {
    if (mImpl) {
        return mImpl->allocate(connectionId, params, buffer);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus ClientManager::receive(
        ConnectionId connectionId, TransactionId transactionId,
        BufferId bufferId, int64_t timestampUs,
        std::shared_ptr<_C2BlockPoolData> *buffer) {
    if (mImpl) {
        return mImpl->receive(connectionId, transactionId, bufferId,
                              timestampUs, buffer);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus ClientManager::postSend(
        ConnectionId connectionId, ConnectionId receiverId,
        const std::shared_ptr<_C2BlockPoolData> &buffer,
        TransactionId *transactionId, int64_t* timestampUs) {
    if (mImpl) {
        return mImpl->postSend(connectionId, receiverId, buffer,
                               transactionId, timestampUs);
    }
    return ResultStatus::CRITICAL_ERROR;
}

ResultStatus ClientManager::getAccessor(
        ConnectionId connectionId, sp<IAccessor> *accessor) {
    if (mImpl) {
        return mImpl->getAccessor(connectionId, accessor);
    }
    return ResultStatus::CRITICAL_ERROR;
}

//IClientManager* HIDL_FETCH_IClientManager(const char* /* name */) {
//    return new ClientManager();
//}

}  // namespace implementation
}  // namespace V1_0
}  // namespace bufferpool
}  // namespace media
}  // namespace hardware
}  // namespace android
