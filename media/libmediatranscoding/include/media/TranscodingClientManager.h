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

#include <aidl/android/media/ITranscodingClient.h>
#include <aidl/android/media/ITranscodingClientCallback.h>
#include <sys/types.h>
#include <utils/Condition.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#include <mutex>
#include <unordered_map>

#include "SchedulerClientInterface.h"

namespace android {

using ::aidl::android::media::ITranscodingClient;
using ::aidl::android::media::ITranscodingClientCallback;

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
     * Adds a new client to the manager.
     *
     * The client must have valid callback, pid, uid, clientName and opPackageName.
     * Otherwise, this will return a non-zero errorcode. If the client callback has
     * already been added, it will also return non-zero errorcode.
     *
     * @param callback client callback for the service to call this client.
     * @param pid client's process id.
     * @param uid client's user id.
     * @param clientName client's name.
     * @param opPackageName client's package name.
     * @param client output holding the ITranscodingClient interface for the client
     *        to use for subsequent communications with the service.
     * @return 0 if client is added successfully, non-zero errorcode otherwise.
     */
    status_t addClient(const std::shared_ptr<ITranscodingClientCallback>& callback, pid_t pid,
                       uid_t uid, const std::string& clientName, const std::string& opPackageName,
                       std::shared_ptr<ITranscodingClient>* client);

    /**
     * Gets the number of clients.
     */
    size_t getNumOfClients() const;

    /**
     * Dump all the client information to the fd.
     */
    void dumpAllClients(int fd, const Vector<String16>& args);

private:
    friend class MediaTranscodingService;
    friend class TranscodingClientManagerTest;
    struct ClientImpl;

    // Only allow MediaTranscodingService and unit tests to instantiate.
    TranscodingClientManager(const std::shared_ptr<SchedulerClientInterface>& scheduler);

    /**
     * Removes an existing client from the manager.
     *
     * If the client does not exist, this will return non-zero errorcode.
     *
     * @param clientId id of the client to be removed..
     * @return 0 if client is removed successfully, non-zero errorcode otherwise.
     */
    status_t removeClient(ClientIdType clientId);

    static void BinderDiedCallback(void* cookie);

    mutable std::mutex mLock;
    std::unordered_map<ClientIdType, std::shared_ptr<ClientImpl>> mClientIdToClientMap
            GUARDED_BY(mLock);

    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;

    std::shared_ptr<SchedulerClientInterface> mJobScheduler;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_SERVICE_H
