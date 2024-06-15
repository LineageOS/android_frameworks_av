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
#define LOG_TAG "ClientImportanceReclaimPolicy"
#include <utils/Log.h>

#include "ResourceTracker.h"
#include "ResourceManagerService.h"
#include "ClientImportanceReclaimPolicy.h"

namespace android {

using aidl::android::media::IResourceManagerClient;

ClientImportanceReclaimPolicy::ClientImportanceReclaimPolicy(
        const std::shared_ptr<ResourceTracker>& resourceTracker)
    : mResourceTracker(resourceTracker) {
}

ClientImportanceReclaimPolicy::~ClientImportanceReclaimPolicy() {
}

// Find the biggest client from the same process with the lowest importance
// than that of the requesting client.
bool ClientImportanceReclaimPolicy::getClients(const ReclaimRequestInfo& reclaimRequestInfo,
                                              const std::vector<ClientInfo>& clients,
                                              std::vector<ClientInfo>& targetClients) {
    pid_t callingPid = reclaimRequestInfo.mCallingPid;
    int32_t callingImportance = reclaimRequestInfo.mCallingClientImportance;
    MediaResource::Type type = reclaimRequestInfo.mResources[0].type;
    MediaResource::SubType subType = reclaimRequestInfo.mResources[0].subType;
    ClientInfo targetClient;
    // Look to find the biggest client with lowest importance from the same process that
    // has the other resources and with the given primary type.
    bool found = false;
    MediaResource::SubType primarySubType = subType;
    for (size_t index = 1; !found && (index < reclaimRequestInfo.mResources.size()); index++) {
        MediaResource::Type type = reclaimRequestInfo.mResources[index].type;
        MediaResource::SubType subType = reclaimRequestInfo.mResources[index].subType;
        found = mResourceTracker->getLeastImportantBiggestClient(
            callingPid, callingImportance,
            type, subType, primarySubType,
            clients, targetClient);
    }
    // If no success, then select the biggest client of primary type with lowest importance
    // from the same process.
    if (!found) {
        found = mResourceTracker->getLeastImportantBiggestClient(
            callingPid, callingImportance,
            type, subType, MediaResource::SubType::kUnspecifiedSubType,
            clients, targetClient);
    }
    // If we haven't found a client yet, then select the biggest client of different type
    // with lowest importance from the same process.
    // This is applicable for codec type only.
    if (!found) {
        if (type != MediaResource::Type::kSecureCodec &&
            type != MediaResource::Type::kNonSecureCodec) {
            return false;
        }
        MediaResourceType otherType = (type == MediaResource::Type::kSecureCodec) ?
            MediaResource::Type::kNonSecureCodec : MediaResource::Type::kSecureCodec;
        if (!mResourceTracker->getLeastImportantBiggestClient(
            callingPid, callingImportance,
            otherType, subType, MediaResource::SubType::kUnspecifiedSubType,
            clients, targetClient)) {
            return false;
        }
    }
    targetClients.emplace_back(targetClient);
    return true;
}
} // namespace android
