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
#define LOG_TAG "DefaultResourceModel"
#include <utils/Log.h>

#include "ResourceManagerServiceUtils.h"
#include "DefaultResourceModel.h"
#include "ResourceTracker.h"

namespace android {

DefaultResourceModel::DefaultResourceModel(
        const std::shared_ptr<ResourceTracker>& resourceTracker,
        bool supportsMultipleSecureCodecs,
        bool supportsSecureWithNonSecureCodec)
    : mSupportsMultipleSecureCodecs(supportsMultipleSecureCodecs),
      mSupportsSecureWithNonSecureCodec(supportsSecureWithNonSecureCodec),
      mResourceTracker(resourceTracker) {
}

DefaultResourceModel::~DefaultResourceModel() {
}

bool DefaultResourceModel::getAllClients(
        const ReclaimRequestInfo& reclimRequestInfo,
        std::vector<ClientInfo>& clients) {

    clients.clear();
    MediaResourceParcel mediaResource{.type = reclimRequestInfo.mResources[0].type,
                                      .subType = reclimRequestInfo.mResources[0].subType};
    ResourceRequestInfo resourceRequestInfo{reclimRequestInfo.mCallingPid,
                                            reclimRequestInfo.mClientId,
                                            &mediaResource};

    // Resolve the secure-unsecure codec conflicts if there is any.
    switch (reclimRequestInfo.mResources[0].type) {
    case MediaResource::Type::kSecureCodec:
        // Looking to start a secure codec.
        // #1. Make sure if multiple secure codecs can coexist
        if (!mSupportsMultipleSecureCodecs) {
            if (!mResourceTracker->getNonConflictingClients(resourceRequestInfo, clients)) {
                // A higher priority process owns an instance of a secure codec.
                // So this request can't be fulfilled.
                return false;
            }
        }
        // #2. Make sure a secure codec can coexist if there is an instance
        // of non-secure codec running already.
        if (!mSupportsSecureWithNonSecureCodec) {
            mediaResource.type = MediaResource::Type::kNonSecureCodec;
            if (!mResourceTracker->getNonConflictingClients(resourceRequestInfo, clients)) {
                // A higher priority process owns an instance of a non-secure codec.
                // So this request can't be fulfilled.
                return false;
            }
        }
        break;
    case MediaResource::Type::kNonSecureCodec:
        // Looking to start a non-secure codec.
        // Make sure a non-secure codec can coexist if there is an instance
        // of secure codec running already.
        if (!mSupportsSecureWithNonSecureCodec) {
            mediaResource.type = MediaResource::Type::kSecureCodec;
            if (!mResourceTracker->getNonConflictingClients(resourceRequestInfo, clients)) {
                // A higher priority process owns an instance of a secure codec.
                // So this request can't be fulfilled.
                return false;
            }
        }
        break;
    default:
        break;
    }

    if (!clients.empty()) {
        // There is secure/unsecure codec co-existence conflict
        // and we have only found processes with lower priority holding the
        // resources. So, all of these need to be reclaimed.
        return false;
    }

    // No more resource conflicts.
    switch (reclimRequestInfo.mResources[0].type) {
    case MediaResource::Type::kSecureCodec:
    case MediaResource::Type::kNonSecureCodec:
        // Handling Codec resource reclaim
        return getCodecClients(reclimRequestInfo, clients);
    case MediaResource::Type::kGraphicMemory:
    case MediaResource::Type::kDrmSession:
        // Handling DRM and GraphicMemory resource reclaim
        mediaResource.id = reclimRequestInfo.mResources[0].id;
        mediaResource.value = reclimRequestInfo.mResources[0].value;
        return mResourceTracker->getAllClients(resourceRequestInfo, clients);
    default:
        break;
    }

    return !clients.empty();
}

bool DefaultResourceModel::getCodecClients(
        const ReclaimRequestInfo& reclimRequestInfo,
        std::vector<ClientInfo>& clients) {
    MediaResourceParcel mediaResource;
    ResourceRequestInfo resourceRequestInfo{reclimRequestInfo.mCallingPid,
                                            reclimRequestInfo.mClientId,
                                            &mediaResource};

    // 1. Look to find the client(s) with the other resources, for the given
    // primary type.
    MediaResource::SubType primarySubType = reclimRequestInfo.mResources[0].subType;
    for (size_t index = 1; index < reclimRequestInfo.mResources.size(); index++) {
        mediaResource.type = reclimRequestInfo.mResources[index].type;
        mediaResource.subType = reclimRequestInfo.mResources[index].subType;
        mResourceTracker->getAllClients(resourceRequestInfo, clients, primarySubType);
    }

    // 2. Get all clients of the same type.
    mediaResource.type = reclimRequestInfo.mResources[0].type;
    mediaResource.subType = reclimRequestInfo.mResources[0].subType;
    mResourceTracker->getAllClients(resourceRequestInfo, clients);

    // 3. Get all cliends of the different type.
    MediaResourceType otherType =
        (reclimRequestInfo.mResources[0].type == MediaResource::Type::kSecureCodec) ?
        MediaResource::Type::kNonSecureCodec : MediaResource::Type::kSecureCodec;
    mediaResource.type = otherType;
    mResourceTracker->getAllClients(resourceRequestInfo, clients);

    return !clients.empty();
}

} // namespace android
