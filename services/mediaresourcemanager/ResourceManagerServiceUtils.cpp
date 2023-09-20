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
#define LOG_TAG "ResourceManagerServiceUtils"
#include <utils/Log.h>

#include "ResourceManagerService.h"
#include "ResourceManagerServiceUtils.h"

namespace android {

bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
        const MediaResourceParcel& resource) {
    if (type != resource.type) {
      return false;
    }
    switch (type) {
        // Codec subtypes (e.g. video vs. audio) are each considered separate resources, so
        // compare the subtypes as well.
        case MediaResource::Type::kSecureCodec:
        case MediaResource::Type::kNonSecureCodec:
            if (resource.subType == subType) {
                return true;
            }
            break;
        // Non-codec resources are not segregated by the subtype (e.g. video vs. audio).
        default:
            return true;
    }
    return false;
}

bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
        const ResourceList& resources) {
    for (auto it = resources.begin(); it != resources.end(); it++) {
        if (hasResourceType(type, subType, it->second)) {
            return true;
        }
    }
    return false;
}

bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
        const ResourceInfos& infos) {
    for (const auto& [id, info] : infos) {
        if (hasResourceType(type, subType, info.resources)) {
            return true;
        }
    }
    return false;
}

ResourceInfos& getResourceInfosForEdit(int pid, PidResourceInfosMap& map) {
    PidResourceInfosMap::iterator found = map.find(pid);
    if (found == map.end()) {
        // new pid
        ResourceInfos infosForPid;
        auto [it, inserted] = map.emplace(pid, infosForPid);
        found = it;
    }

    return found->second;
}

ResourceInfo& getResourceInfoForEdit(const ClientInfoParcel& clientInfo,
        const std::shared_ptr<IResourceManagerClient>& client, ResourceInfos& infos) {
    ResourceInfos::iterator found = infos.find(clientInfo.id);

    if (found == infos.end()) {
        ResourceInfo info{.uid = static_cast<uid_t>(clientInfo.uid),
                          .clientId = clientInfo.id,
                          .name = clientInfo.name.empty()? "<unknown client>" : clientInfo.name,
                          .client = client,
                          .deathNotifier = nullptr,
                          .pendingRemoval = false};
        auto [it, inserted] = infos.emplace(clientInfo.id, info);
        found = it;
    }

    return found->second;
}

} // namespace android
