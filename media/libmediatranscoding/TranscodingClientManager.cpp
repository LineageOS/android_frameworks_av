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

#include <inttypes.h>
#include <media/TranscodingClientManager.h>
#include <utils/Log.h>

namespace android {

using Status = ::ndk::ScopedAStatus;

// static
TranscodingClientManager& TranscodingClientManager::getInstance() {
    static TranscodingClientManager gInstance{};
    return gInstance;
}

// static
void TranscodingClientManager::BinderDiedCallback(void* cookie) {
    int32_t clientId = static_cast<int32_t>(reinterpret_cast<intptr_t>(cookie));
    ALOGD("Client %" PRId32 " is dead", clientId);
    // Don't check for pid validity since we know it's already dead.
    TranscodingClientManager& manager = TranscodingClientManager::getInstance();
    manager.removeClient(clientId);
}

TranscodingClientManager::TranscodingClientManager()
    : mDeathRecipient(AIBinder_DeathRecipient_new(BinderDiedCallback)) {
    ALOGD("TranscodingClientManager started");
}

TranscodingClientManager::~TranscodingClientManager() {
    ALOGD("TranscodingClientManager exited");
}

bool TranscodingClientManager::isClientIdRegistered(int32_t clientId) const {
    std::scoped_lock lock{mLock};
    return mClientIdToClientInfoMap.find(clientId) != mClientIdToClientInfoMap.end();
}

void TranscodingClientManager::dumpAllClients(int fd, const Vector<String16>& args __unused) {
    String8 result;

    const size_t SIZE = 256;
    char buffer[SIZE];

    snprintf(buffer, SIZE, "    Total num of Clients: %zu\n", mClientIdToClientInfoMap.size());
    result.append(buffer);

    if (mClientIdToClientInfoMap.size() > 0) {
        snprintf(buffer, SIZE, "========== Dumping all clients =========\n");
        result.append(buffer);
    }

    for (const auto& iter : mClientIdToClientInfoMap) {
        const std::shared_ptr<ITranscodingServiceClient> client = iter.second->mClient;
        std::string clientName;
        Status status = client->getName(&clientName);
        if (!status.isOk()) {
            ALOGE("Failed to get client: %d information", iter.first);
            continue;
        }
        snprintf(buffer, SIZE, "    -- Clients: %d  name: %s\n", iter.first, clientName.c_str());
        result.append(buffer);
    }

    write(fd, result.string(), result.size());
}

status_t TranscodingClientManager::addClient(std::unique_ptr<ClientInfo> client) {
    // Validate the client.
    if (client == nullptr || client->mClientId < 0 || client->mClientPid < 0 ||
        client->mClientUid < 0 || client->mClientOpPackageName.empty() ||
        client->mClientOpPackageName == "") {
        ALOGE("Invalid client");
        return BAD_VALUE;
    }

    std::scoped_lock lock{mLock};

    // Check if the client already exists.
    if (mClientIdToClientInfoMap.count(client->mClientId) != 0) {
        ALOGW("Client already exists.");
        return ALREADY_EXISTS;
    }

    ALOGD("Adding client id %d pid: %d uid: %d %s", client->mClientId, client->mClientPid,
          client->mClientUid, client->mClientOpPackageName.c_str());

    AIBinder_linkToDeath(client->mClient->asBinder().get(), mDeathRecipient.get(),
                         reinterpret_cast<void*>(client->mClientId));

    // Adds the new client to the map.
    mClientIdToClientInfoMap[client->mClientId] = std::move(client);

    return OK;
}

status_t TranscodingClientManager::removeClient(int32_t clientId) {
    ALOGD("Removing client id %d", clientId);
    std::scoped_lock lock{mLock};

    // Checks if the client is valid.
    auto it = mClientIdToClientInfoMap.find(clientId);
    if (it == mClientIdToClientInfoMap.end()) {
        ALOGE("Client id %d does not exist", clientId);
        return INVALID_OPERATION;
    }

    std::shared_ptr<ITranscodingServiceClient> client = it->second->mClient;

    // Check if the client still live. If alive, unlink the death.
    if (client) {
        AIBinder_unlinkToDeath(client->asBinder().get(), mDeathRecipient.get(),
                               reinterpret_cast<void*>(clientId));
    }

    // Erase the entry.
    mClientIdToClientInfoMap.erase(it);

    return OK;
}

size_t TranscodingClientManager::getNumOfClients() const {
    std::scoped_lock lock{mLock};
    return mClientIdToClientInfoMap.size();
}

}  // namespace android
