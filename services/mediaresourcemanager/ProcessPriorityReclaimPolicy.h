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

#ifndef ANDROID_MEDIA_PROCESSPRIORITYRECLAIMPOLICY_H_
#define ANDROID_MEDIA_PROCESSPRIORITYRECLAIMPOLICY_H_

#include <media/MediaResource.h>
#include "IReclaimPolicy.h"

namespace android {

class ResourceTracker;
struct ClientInfo;

/*
 * Implementation of the Reclaim Policy based on the process priority.
 *
 * Find the lowest priority process (lower than the calling/requesting process’s priority)
 * that has the required resources.
 * From that process, find the biggest client and return the same for reclaiming.
 * If there is a codec co-existence policy, that is addressed as below:
 *   - if these are any conflicting codecs, reclaim all those conflicting clients.
 * If no conflicting codecs, the reclaim policy will select a client in the order of:
 *   - Find the biggest client from the lowest priority process that
 *     has the other resources and with the given primary type.
 *   - select the biggest client from the lower priority process that
 *     has the primary type.
 *   - If it's a codec reclaim request, then:
 *      - select the biggest client from the lower priority process that
 *        has the othe type (for example secure for a non-secure and vice versa).
 */
class ProcessPriorityReclaimPolicy : public IReclaimPolicy {
public:
    ProcessPriorityReclaimPolicy(const std::shared_ptr<ResourceTracker>& resourceTracker);

    virtual ~ProcessPriorityReclaimPolicy();

    /*
     * Based on the process priority, identify and return a client from the list
     * of given clients that satisfy the resource requested.
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

    // Get the biggest client with the given resources from the given list of clients.
    // The client should belong to lowest possible priority than that of the
    // calling/requesting process.
    // returns true on success, false otherwise
    //
    bool getBiggestClientFromLowestPriority(
        pid_t callingPid,
        int callingPriority,
        MediaResource::Type type,
        MediaResource::SubType subType,
        MediaResource::SubType primarySubType,
        const std::vector<ClientInfo>& clients,
        ClientInfo& targetClient,
        int& lowestPriority);

private:
    std::shared_ptr<ResourceTracker> mResourceTracker;
};

} // namespace android

#endif  // ANDROID_MEDIA_PROCESSPRIORITYRECLAIMPOLICY_H_
