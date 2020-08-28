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

#ifndef ANDROID_MEDIA_TRANSCODING_CLIENT_MANAGER_H
#define ANDROID_MEDIA_TRANSCODING_CLIENT_MANAGER_H

#include <aidl/android/media/BnTranscodingServiceClient.h>
#include <android/binder_ibinder.h>
#include <sys/types.h>
#include <utils/Condition.h>
#include <utils/RefBase.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <mutex>
#include <unordered_map>

namespace android {

using ::aidl::android::media::ITranscodingServiceClient;

class MediaTranscodingService;

/*
 * TranscodingClientManager manages all the transcoding clients across different processes.
 *
 * TranscodingClientManager is a global singleton that could only acquired by
 * MediaTranscodingService. It manages all the clients's registration/unregistration and clients'
 * information. It also bookkeeps all the clients' information. It also monitors to the death of the
 * clients. Upon client's death, it will remove the client from it.
 *
 * TODO(hkuang): Hook up with ResourceManager for resource management.
 * TODO(hkuang): Hook up with MediaMetrics to log all the transactions.
 */
class TranscodingClientManager {
   public:
    virtual ~TranscodingClientManager();

    /**
     * ClientInfo contains a single client's information.
     */
    struct ClientInfo {
        /* The remote client that this ClientInfo is associated with. */
        std::shared_ptr<ITranscodingServiceClient> mClient;
        /* A unique positive Id assigned to the client by the service. */
        int32_t mClientId;
        /* Process id of the client */
        int32_t mClientPid;
        /* User id of the client. */
        int32_t mClientUid;
        /* Package name of the client. */
        std::string mClientOpPackageName;

        ClientInfo(const std::shared_ptr<ITranscodingServiceClient>& client, int64_t clientId,
                   int32_t pid, int32_t uid, const std::string& opPackageName)
            : mClient(client),
              mClientId(clientId),
              mClientPid(pid),
              mClientUid(uid),
              mClientOpPackageName(opPackageName) {}
    };

    /**
     * Adds a new client to the manager.
     *
     * The client must have valid clientId, pid, uid and opPackageName, otherwise, this will return
     * a non-zero errorcode. If the client has already been added, it will also return non-zero
     * errorcode.
     *
     * @param client to be added to the manager.
     * @return 0 if client is added successfully, non-zero errorcode otherwise.
     */
    status_t addClient(std::unique_ptr<ClientInfo> client);

    /**
     * Removes an existing client from the manager.
     *
     * If the client does not exist, this will return non-zero errorcode.
     *
     * @param clientId id of the client to be removed..
     * @return 0 if client is removed successfully, non-zero errorcode otherwise.
     */
    status_t removeClient(int32_t clientId);

    /**
     * Gets the number of clients.
     */
    size_t getNumOfClients() const;

    /**
     * Checks if a client with clientId is already registered.
     */
    bool isClientIdRegistered(int32_t clientId) const;

    /**
     * Dump all the client information to the fd.
     */
    void dumpAllClients(int fd, const Vector<String16>& args);

   private:
    friend class MediaTranscodingService;
    friend class TranscodingClientManagerTest;

    /** Get the singleton instance of the TranscodingClientManager. */
    static TranscodingClientManager& getInstance();

    TranscodingClientManager();

    static void BinderDiedCallback(void* cookie);

    mutable std::mutex mLock;
    std::unordered_map<int32_t, std::unique_ptr<ClientInfo>> mClientIdToClientInfoMap
            GUARDED_BY(mLock);

    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_SERVICE_H
