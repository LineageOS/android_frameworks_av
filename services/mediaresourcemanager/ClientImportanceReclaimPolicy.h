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

#ifndef ANDROID_MEDIA_CLIENTIMPORTANCERECLAIMPOLICY_H_
#define ANDROID_MEDIA_CLIENTIMPORTANCERECLAIMPOLICY_H_

#include <media/MediaResource.h>
#include "IReclaimPolicy.h"

namespace android {

class ResourceTracker;
struct ClientInfo;

/*
 * Implementation of Reclaim Policy based on the client's importance.
 *
 * Find the least important (other than that of requesting client) client from the
 * same process (that is requesting for the resource).
 * If there are multiple clients with least importance, then pick the biggest
 * client among them.
 *
 */
class ClientImportanceReclaimPolicy : public IReclaimPolicy {
public:
    explicit ClientImportanceReclaimPolicy(const std::shared_ptr<ResourceTracker>& resourceTracker);

    virtual ~ClientImportanceReclaimPolicy();

    /*
     * Based on the client importance, identify and return the least important client of
     * the requesting process from the list of given clients that satisfy the resource requested.
     *
     * @param[in]  reclaimRequestInfo Information about the resource request
     * @param[in]  client List of clients to select from.
     * @param[out] targetClients Upon success, this will have the list of identified client(s).
     *
     * @return true on success, false otherwise
     */
    bool getClients(const ReclaimRequestInfo& reclaimRequestInfo,
                    const std::vector<ClientInfo>& clients,
                    std::vector<ClientInfo>& targetClients) override;

private:
    std::shared_ptr<ResourceTracker> mResourceTracker;
};

} // namespace android

#endif  // ANDROID_MEDIA_CLIENTIMPORTANCERECLAIMPOLICY_H_
