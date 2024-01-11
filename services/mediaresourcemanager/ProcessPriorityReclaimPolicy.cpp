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

//#define LOG_NDEBUG 0
#define LOG_TAG "ProcessPriorityReclaimPolicy"
#include <utils/Log.h>

#include "ResourceTracker.h"
#include "ResourceManagerService.h"
#include "ProcessPriorityReclaimPolicy.h"

namespace android {

using aidl::android::media::IResourceManagerClient;

ProcessPriorityReclaimPolicy::ProcessPriorityReclaimPolicy(
        const std::shared_ptr<ResourceTracker>& resourceTracker)
    : mResourceTracker(resourceTracker) {
}

ProcessPriorityReclaimPolicy::~ProcessPriorityReclaimPolicy() {
}

// Process priority (oom score) based reclaim:
//   - Find a process with lowest priority (than that of calling process).
//   - Find the bigegst client (with required resources) from that process.
bool ProcessPriorityReclaimPolicy::getClients(const ReclaimRequestInfo& reclaimRequestInfo,
                                              const std::vector<ClientInfo>& clients,
                                              std::vector<ClientInfo>& targetClients) {
    // NOTE: This is the behavior of the existing reclaim policy.
    // We can alter it to select more than one client to reclaim from, depending
    // on the reclaim polocy.

    MediaResource::Type type = reclaimRequestInfo.mResources[0].type;
    MediaResource::SubType subType = reclaimRequestInfo.mResources[0].subType;
    // Find one client to reclaim the needed resources from.
    // 1. Get the priority of the (reclaim) requesting process.
    int callingPid = reclaimRequestInfo.mCallingPid;
    int callingPriority = -1;
    if (!mResourceTracker->getPriority(callingPid, &callingPriority)) {
        ALOGE("%s: can't get process priority for pid %d", __func__, callingPid);
        return false;
    }

    ClientInfo clientInfo;
    // 2 Look to find the biggest client from the lowest priority process that
    // has the other resources and with the given primary type.
    bool found = false;
    int lowestPriority = -1;
    MediaResource::SubType primarySubType = subType;
    for (size_t index = 1; !found && (index < reclaimRequestInfo.mResources.size()); index++) {
        MediaResource::Type type = reclaimRequestInfo.mResources[index].type;
        MediaResource::SubType subType = reclaimRequestInfo.mResources[index].subType;
        found = getBiggestClientFromLowestPriority(callingPid, callingPriority,
                                                   type, subType, primarySubType,
                                                   clients, clientInfo, lowestPriority);
    }
    // 3 If we haven't found a client yet, then select the biggest client of primary type.
    if (!found) {
        found = getBiggestClientFromLowestPriority(callingPid, callingPriority,
                                                   type, subType,
                                                   MediaResource::SubType::kUnspecifiedSubType,
                                                   clients, clientInfo, lowestPriority);
    }
    // 4 If we haven't found a client yet, then select the biggest client of different type.
    // This is applicable for code type only.
    if (!found) {
        if (type != MediaResource::Type::kSecureCodec &&
            type != MediaResource::Type::kNonSecureCodec) {
            return false;
        }
        MediaResourceType otherType = (type == MediaResource::Type::kSecureCodec) ?
            MediaResource::Type::kNonSecureCodec : MediaResource::Type::kSecureCodec;
        if (!getBiggestClientFromLowestPriority(callingPid, callingPriority,
                                                otherType, subType,
                                                MediaResource::SubType::kUnspecifiedSubType,
                                                clients, clientInfo, lowestPriority)) {
            return false;
        }
    }

    targetClients.emplace_back(clientInfo);
    ALOGI("%s: CallingProcess(%d:%d) will reclaim from the lowestPriorityProcess(%d:%d)",
          __func__, callingPid, callingPriority, clientInfo.mPid, lowestPriority);

    return true;
}

bool ProcessPriorityReclaimPolicy::getBiggestClientFromLowestPriority(
        pid_t callingPid,
        int callingPriority,
        MediaResource::Type type, MediaResource::SubType subType,
        MediaResource::SubType primarySubType,
        const std::vector<ClientInfo>& clients,
        ClientInfo& targetClient,
        int& lowestPriority) {
    // 1. Find the lowest priority process among all the clients with the
    // requested resource type.
    int lowestPriorityPid = -1;
    lowestPriority = -1;
    if (!mResourceTracker->getLowestPriorityPid(type, subType, primarySubType, clients,
                                                lowestPriorityPid, lowestPriority)) {
        ALOGD("%s: can't find a process with lower priority than that of the process[%d:%d]",
              __func__, callingPid, callingPriority);
        return false;
    }

    // 2. Make sure that the priority of the target process is less than
    // requesting process.
    if (lowestPriority <= callingPriority) {
        ALOGD("%s: lowest priority %d vs caller priority %d",
              __func__, lowestPriority, callingPriority);
        return false;
    }

    // 3. Look to find the biggest client from that process for the given resources
    return mResourceTracker->getBiggestClient(lowestPriorityPid, type, subType,
                                              clients, targetClient, primarySubType);
}

} // namespace android
