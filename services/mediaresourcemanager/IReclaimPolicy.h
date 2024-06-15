/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef ANDROID_MEDIA_IRECLAIMPOLICY_H_
#define ANDROID_MEDIA_IRECLAIMPOLICY_H_

#include <memory>
#include <aidl/android/media/IResourceManagerClient.h>

namespace android {

struct ClientInfo;
struct ReclaimRequestInfo;

/*
 * Interface that defines Reclaim Policy.
 *
 * This provides an interface to select/identify a client based on a specific
 * Reclaim policy.
 */
class IReclaimPolicy {
public:
    IReclaimPolicy() {}

    virtual ~IReclaimPolicy() {}

    /*
     * Based on the Reclaim policy, identify and return a client from the list
     * of given clients that satisfy the resource requested.
     *
     * @param[in]  reclaimRequestInfo Information about the resource request
     * @param[in]  client List of clients to select from.
     * @param[out] targetClients Upon success, this will have the list of identified client(s).
     *
     * @return true on success, false otherwise
     */
    virtual bool getClients(const ReclaimRequestInfo& reclaimRequestInfo,
                            const std::vector<ClientInfo>& clients,
                            std::vector<ClientInfo>& targetClients) = 0;
};

} // namespace android

#endif  // ANDROID_MEDIA_IRECLAIMPOLICY_H_
