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
#define LOG_TAG "ResourceTracker"
#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <mediautils/ProcessInfo.h>
#include "ResourceTracker.h"
#include "ResourceManagerServiceNew.h"
#include "ResourceObserverService.h"

namespace android {

inline bool isHwCodec(MediaResource::SubType subType) {
    return subType == MediaResource::SubType::kHwImageCodec ||
           subType == MediaResource::SubType::kHwVideoCodec;
}

// Check whether a given resource (of type and subtype) is found in given resource list
// that also has the given Primary SubType.
static bool hasResourceType(MediaResource::Type type, MediaResource::SubType subType,
                            const ResourceList& resources, MediaResource::SubType primarySubType) {
    bool foundResource = false;
    bool matchedPrimary =
        (primarySubType == MediaResource::SubType::kUnspecifiedSubType) ?  true : false;
    for (const MediaResourceParcel& res : resources.getResources()) {
        if (hasResourceType(type, subType, res)) {
            foundResource = true;
        } else if (res.subType == primarySubType) {
            matchedPrimary = true;
        } else if (isHwCodec(res.subType) == isHwCodec(primarySubType)) {
            matchedPrimary = true;
        }
        if (matchedPrimary && foundResource) {
            return true;
        }
    }
    return false;
}

// See if the given client is already in the list of clients.
inline bool contains(const std::vector<ClientInfo>& clients, const int64_t& clientId) {
    std::vector<ClientInfo>::const_iterator found =
        std::find_if(clients.begin(), clients.end(),
                     [clientId](const ClientInfo& client) -> bool {
                         return client.mClientId == clientId;
                     });

    return found != clients.end();
}


ResourceTracker::ResourceTracker(const std::shared_ptr<ResourceManagerServiceNew>& service,
                                 const sp<ProcessInfoInterface>& processInfo) :
        mService(service),
        mProcessInfo(processInfo) {
}

ResourceTracker::~ResourceTracker() {
}

void ResourceTracker::setResourceObserverService(
        const std::shared_ptr<ResourceObserverService>& observerService) {
    mObserverService = observerService;
}

ResourceInfos& ResourceTracker::getResourceInfosForEdit(int pid) {
    std::map<int, ResourceInfos>::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        // new pid
        ResourceInfos infosForPid;
        auto [it, inserted] = mMap.emplace(pid, infosForPid);
        found = it;
    }

    return found->second;
}

bool ResourceTracker::addResource(const ClientInfoParcel& clientInfo,
                                  const std::shared_ptr<IResourceManagerClient>& client,
                                  const std::vector<MediaResourceParcel>& resources) {
    int32_t pid = clientInfo.pid;
    int32_t uid = clientInfo.uid;

    if (!mProcessInfo->isPidUidTrusted(pid, uid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        ALOGW("%s called with untrusted pid %d or uid %d, using calling pid %d, uid %d",
                __func__, pid, uid, callingPid, callingUid);
        pid = callingPid;
        uid = callingUid;
    }
    ResourceInfos& infos = getResourceInfosForEdit(pid);
    ResourceInfo& info = getResourceInfoForEdit(clientInfo, client, infos);
    ResourceList resourceAdded;

    for (const MediaResourceParcel& res : resources) {
        if (res.value < 0 && res.type != MediaResource::Type::kDrmSession) {
            ALOGV("%s: Ignoring request to remove negative value of non-drm resource", __func__);
            continue;
        }
        bool isNewEntry = false;
        if (!info.resources.add(res, &isNewEntry)) {
            continue;
        }
        if (isNewEntry) {
            onFirstAdded(res, info.uid);
        }

        // Add it to the list of added resources for observers.
        resourceAdded.add(res);
    }
    if (info.deathNotifier == nullptr && client != nullptr) {
        info.deathNotifier = DeathNotifier::Create(client, mService, clientInfo);
    }
    if (mObserverService != nullptr && !resourceAdded.empty()) {
        mObserverService->onResourceAdded(uid, pid, resourceAdded);
    }

    return !resourceAdded.empty();
}

bool ResourceTracker::updateResource(const aidl::android::media::ClientInfoParcel& clientInfo) {
    ResourceInfos& infos = getResourceInfosForEdit(clientInfo.pid);

    ResourceInfos::iterator found = infos.find(clientInfo.id);
    if (found == infos.end()) {
        return false;
    }
    // Update the client importance.
    found->second.importance = std::max(0, clientInfo.importance);
    return true;
}

bool ResourceTracker::removeResource(const ClientInfoParcel& clientInfo,
                                     const std::vector<MediaResourceParcel>& resources) {
    int32_t pid = clientInfo.pid;
    int64_t clientId = clientInfo.id;

    if (!mProcessInfo->isPidTrusted(pid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using calling pid %d", __func__,
                pid, callingPid);
        pid = callingPid;
    }
    std::map<int, ResourceInfos>::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("%s: didn't find pid %d for clientId %lld", __func__, pid, (long long) clientId);
        return false;
    }

    ResourceInfos& infos = found->second;
    ResourceInfos::iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("%s: didn't find clientId %lld", __func__, (long long) clientId);
        return false;
    }

    ResourceInfo& info = foundClient->second;
    ResourceList resourceRemoved;
    for (const MediaResourceParcel& res : resources) {
        if (res.value < 0) {
            ALOGV("%s: Ignoring request to remove negative value of resource", __func__);
            continue;
        }

        long removedEntryValue = -1;
        if (info.resources.remove(res, &removedEntryValue)) {
            MediaResourceParcel actualRemoved = res;
            if (removedEntryValue != -1) {
                onLastRemoved(res, info.uid);
                actualRemoved.value = removedEntryValue;
            }

            // Add it to the list of removed resources for observers.
            resourceRemoved.add(actualRemoved);
        }
    }
    if (mObserverService != nullptr && !resourceRemoved.empty()) {
        mObserverService->onResourceRemoved(info.uid, pid, resourceRemoved);
    }
    return true;
}

bool ResourceTracker::removeResource(const ClientInfoParcel& clientInfo, bool validateCallingPid) {
    int32_t pid = clientInfo.pid;
    int64_t clientId = clientInfo.id;

    if (validateCallingPid && !mProcessInfo->isPidTrusted(pid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using calling pid %d", __func__,
                pid, callingPid);
        pid = callingPid;
    }
    std::map<int, ResourceInfos>::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("%s: didn't find pid %d for clientId %lld", __func__, pid, (long long) clientId);
        return false;
    }

    ResourceInfos& infos = found->second;
    ResourceInfos::iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("%s: didn't find clientId %lld", __func__, (long long) clientId);
        return false;
    }

    const ResourceInfo& info = foundClient->second;
    for (const MediaResourceParcel& res : info.resources.getResources()) {
        onLastRemoved(res, info.uid);
    }

    if (mObserverService != nullptr && !info.resources.empty()) {
        mObserverService->onResourceRemoved(info.uid, pid, info.resources);
    }

    infos.erase(foundClient);
    return true;
}

std::shared_ptr<IResourceManagerClient> ResourceTracker::getClient(
        int pid, const int64_t& clientId) const {
    std::map<int, ResourceInfos>::const_iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("%s: didn't find pid %d for clientId %lld", __func__, pid, (long long) clientId);
        return nullptr;
    }

    const ResourceInfos& infos = found->second;
    ResourceInfos::const_iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("%s: didn't find clientId %lld", __func__, (long long) clientId);
        return nullptr;
    }

    return foundClient->second.client;
}

bool ResourceTracker::removeClient(int pid, const int64_t& clientId) {
    std::map<int, ResourceInfos>::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("%s: didn't find pid %d for clientId %lld", __func__, pid, (long long) clientId);
        return false;
    }

    ResourceInfos& infos = found->second;
    ResourceInfos::iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("%s: didn't find clientId %lld", __func__, (long long) clientId);
        return false;
    }

    infos.erase(foundClient);
    return true;
}

bool ResourceTracker::markClientForPendingRemoval(const ClientInfoParcel& clientInfo) {
    int32_t pid = clientInfo.pid;
    int64_t clientId = clientInfo.id;

    if (!mProcessInfo->isPidTrusted(pid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using calling pid %d", __func__,
                pid, callingPid);
        pid = callingPid;
    }
    std::map<int, ResourceInfos>::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("%s: didn't find pid %d for clientId %lld", __func__, pid, (long long)clientId);
        return false;
    }

    ResourceInfos& infos = found->second;
    ResourceInfos::iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("%s: didn't find clientId %lld", __func__, (long long) clientId);
        return false;
    }

    ResourceInfo& info = foundClient->second;
    info.pendingRemoval = true;
    return true;
}

bool ResourceTracker::getClientsMarkedPendingRemoval(int32_t pid,
                                                     std::vector<ClientInfo>& targetClients) {
    if (!mProcessInfo->isPidTrusted(pid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using calling pid %d", __func__, pid, callingPid);
        pid = callingPid;
    }

    // Go through all the MediaResource types (and corresponding subtypes for
    // each, if applicable) and see if the process (with given pid) holds any
    // such resources that are marked as pending removal.
    // Since the use-case of this function is to get all such resources (pending
    // removal) and reclaim them all - the order in which we look for the
    // resource type doesn't matter.
    for (MediaResource::Type type : {MediaResource::Type::kSecureCodec,
                                     MediaResource::Type::kNonSecureCodec,
                                     MediaResource::Type::kGraphicMemory,
                                     MediaResource::Type::kDrmSession}) {
        switch (type) {
        // Codec resources are segregated by audio, video and image domains.
        case MediaResource::Type::kSecureCodec:
        case MediaResource::Type::kNonSecureCodec:
            for (MediaResource::SubType subType : {MediaResource::SubType::kHwAudioCodec,
                                                   MediaResource::SubType::kSwAudioCodec,
                                                   MediaResource::SubType::kHwVideoCodec,
                                                   MediaResource::SubType::kSwVideoCodec,
                                                   MediaResource::SubType::kHwImageCodec,
                                                   MediaResource::SubType::kSwImageCodec}) {
                ClientInfo clientInfo;
                if (getBiggestClientPendingRemoval(pid, type, subType, clientInfo)) {
                    if (!contains(targetClients, clientInfo.mClientId)) {
                        targetClients.emplace_back(clientInfo);
                    }
                    continue;
                }
            }
            break;
        // Non-codec resources are shared by audio, video and image codecs (no subtype).
        default:
            ClientInfo clientInfo;
            MediaResource::SubType subType = MediaResource::SubType::kUnspecifiedSubType;
            if (getBiggestClientPendingRemoval(pid, type, subType, clientInfo)) {
                if (!contains(targetClients, clientInfo.mClientId)) {
                    targetClients.emplace_back(clientInfo);
                }
            }
            break;
        }
    }

    return true;
}

bool ResourceTracker::overridePid(int originalPid, int newPid) {
    mOverridePidMap.erase(originalPid);
    if (newPid != -1) {
        mOverridePidMap.emplace(originalPid, newPid);
        return true;
    }
    return false;
}

bool ResourceTracker::overrideProcessInfo(const std::shared_ptr<IResourceManagerClient>& client,
                                          int pid, int procState, int oomScore) {
    removeProcessInfoOverride(pid);

    if (!mProcessInfo->overrideProcessInfo(pid, procState, oomScore)) {
        // Override value is rejected by ProcessInfo.
        return false;
    }

    ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(pid),
                                .uid = 0,
                                .id = 0,
                                .name = "<unknown client>"};
    std::shared_ptr<DeathNotifier> deathNotifier =
        DeathNotifier::Create(client, mService, clientInfo, true);

    mProcessInfoOverrideMap.emplace(pid, ProcessInfoOverride{deathNotifier, client});

    return true;
}

void ResourceTracker::removeProcessInfoOverride(int pid) {
    auto it = mProcessInfoOverrideMap.find(pid);
    if (it == mProcessInfoOverrideMap.end()) {
        return;
    }

    mProcessInfo->removeProcessInfoOverride(pid);
    mProcessInfoOverrideMap.erase(pid);
}

bool ResourceTracker::getAllClients(const ResourceRequestInfo& resourceRequestInfo,
                                    std::vector<ClientInfo>& clients,
                                    MediaResource::SubType primarySubType) {
    MediaResource::Type type = resourceRequestInfo.mResource->type;
    MediaResource::SubType subType = resourceRequestInfo.mResource->subType;
    bool foundClient = false;

    for (auto& [pid, /* ResourceInfos */ infos] : mMap) {
        for (auto& [id, /* ResourceInfo */ info] : infos) {
            if (hasResourceType(type, subType, info.resources, primarySubType)) {
                if (!contains(clients, info.clientId)) {
                    clients.emplace_back(info.pid, info.uid, info.clientId);
                    foundClient = true;
                }
            }
        }
    }

    return foundClient;
}

bool ResourceTracker::getLowestPriorityPid(MediaResource::Type type, MediaResource::SubType subType,
                                           int& lowestPriorityPid, int& lowestPriority) {
    int pid = -1;
    int priority = -1;
    for (auto& [tempPid, /* ResourceInfos */ infos] : mMap) {
        if (infos.size() == 0) {
            // no client on this process.
            continue;
        }
        if (!hasResourceType(type, subType, infos)) {
            // doesn't have the requested resource type
            continue;
        }
        int tempPriority = -1;
        if (!getPriority(tempPid, &tempPriority)) {
            ALOGV("%s: can't get priority of pid %d, skipped", __func__, tempPid);
            // TODO: remove this pid from mMap?
            continue;
        }
        if (pid == -1 || tempPriority > priority) {
            // initial the value
            pid = tempPid;
            priority = tempPriority;
        }
    }

    bool success = (pid != -1);

    if (success) {
        lowestPriorityPid = pid;
        lowestPriority = priority;
    }
    return success;
}

bool ResourceTracker::getLowestPriorityPid(MediaResource::Type type, MediaResource::SubType subType,
                                           MediaResource::SubType primarySubType,
                                           const std::vector<ClientInfo>& clients,
                                           int& lowestPriorityPid, int& lowestPriority) {
    int pid = -1;
    int priority = -1;
    for (const ClientInfo& client : clients) {
        const ResourceInfo* info = getResourceInfo(client.mPid, client.mClientId);
        if (info == nullptr) {
            continue;
        }
        if (!hasResourceType(type, subType, info->resources, primarySubType)) {
            // doesn't have the requested resource type
            continue;
        }
        int tempPriority = -1;
        if (!getPriority(client.mPid, &tempPriority)) {
            ALOGV("%s: can't get priority of pid %d, skipped", __func__, client.mPid);
            // TODO: remove this pid from mMap?
            continue;
        }
        if (pid == -1 || tempPriority > priority) {
            // initial the value
            pid = client.mPid;
            priority = tempPriority;
        }
    }

    bool success = (pid != -1);

    if (success) {
        lowestPriorityPid = pid;
        lowestPriority = priority;
    }
    return success;
}

bool ResourceTracker::getBiggestClientPendingRemoval(int pid, MediaResource::Type type,
                                                     MediaResource::SubType subType,
                                                     ClientInfo& clientInfo) {
    std::map<int, ResourceInfos>::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        return false;
    }

    uid_t   uid = -1;
    int64_t clientId = -1;
    uint64_t largestValue = 0;
    const ResourceInfos& infos = found->second;
    for (const auto& [id, /* ResourceInfo */ info] : infos) {
        const ResourceList& resources = info.resources;
        // Skip if the client is not marked pending removal.
        if (!info.pendingRemoval) {
            continue;
        }
        for (const MediaResourceParcel& resource : resources.getResources()) {
            if (hasResourceType(type, subType, resource)) {
                if (resource.value > largestValue) {
                    largestValue = resource.value;
                    clientId = info.clientId;
                    uid = info.uid;
                }
            }
        }
    }

    if (clientId == -1) {
        return false;
    }

    clientInfo.mPid = pid;
    clientInfo.mUid = uid;
    clientInfo.mClientId = clientId;
    return true;
}

bool ResourceTracker::getBiggestClient(int targetPid,
                                       MediaResource::Type type, MediaResource::SubType subType,
                                       const std::vector<ClientInfo>& clients,
                                       ClientInfo& clientInfo,
                                       MediaResource::SubType primarySubType) {
    uid_t   uid = -1;
    int64_t clientId = -1;
    uint64_t largestValue = 0;

    for (const ClientInfo& client : clients) {
        // Skip the clients that doesn't belong go the targetPid
        if (client.mPid != targetPid) {
            continue;
        }
        const ResourceInfo* info = getResourceInfo(client.mPid, client.mClientId);
        if (info == nullptr) {
            continue;
        }

        const ResourceList& resources = info->resources;
        bool matchedPrimary =
            (primarySubType == MediaResource::SubType::kUnspecifiedSubType) ?  true : false;
        for (const MediaResourceParcel& resource : resources.getResources()) {
            if (resource.subType == primarySubType) {
                matchedPrimary = true;
                break;
            } else if (isHwCodec(resource.subType) == isHwCodec(primarySubType)) {
                matchedPrimary = true;
                break;
            }
        }
        // Primary type doesn't match, skip the client
        if (!matchedPrimary) {
            continue;
        }
        for (const MediaResourceParcel& resource : resources.getResources()) {
            if (hasResourceType(type, subType, resource)) {
                if (resource.value > largestValue) {
                    largestValue = resource.value;
                    clientId = info->clientId;
                    uid = info->uid;
                }
            }
        }
    }

    if (clientId == -1) {
        ALOGE("%s: can't find resource type %s and subtype %s for pid %d",
                 __func__, asString(type), asString(subType), targetPid);
        return false;
    }

    clientInfo.mPid = targetPid;
    clientInfo.mUid = uid;
    clientInfo.mClientId = clientId;
    return true;
}

bool ResourceTracker::getLeastImportantBiggestClient(int targetPid, int32_t importance,
                                                     MediaResource::Type type,
                                                     MediaResource::SubType subType,
                                                     MediaResource::SubType primarySubType,
                                                     const std::vector<ClientInfo>& clients,
                                                     ClientInfo& clientInfo) {
    uid_t   uid = -1;
    int64_t clientId = -1;
    uint64_t largestValue = 0;

    for (const ClientInfo& client : clients) {
        // Skip the clients that doesn't belong go the targetPid
        if (client.mPid != targetPid) {
            continue;
        }
        const ResourceInfo* info = getResourceInfo(client.mPid, client.mClientId);
        if (info == nullptr) {
            continue;
        }

        // Make sure the importance is lower.
        if (info->importance <= importance) {
            continue;
        }
        const ResourceList& resources = info->resources;
        bool matchedPrimary =
            (primarySubType == MediaResource::SubType::kUnspecifiedSubType) ?  true : false;
        for (const MediaResourceParcel& resource : resources.getResources()) {
            if (resource.subType == primarySubType) {
                matchedPrimary = true;
            } else if (isHwCodec(resource.subType) == isHwCodec(primarySubType)) {
                matchedPrimary = true;
            }
        }
        // Primary type doesn't match, skip the client
        if (!matchedPrimary) {
            continue;
        }
        for (const MediaResourceParcel& resource : resources.getResources()) {
            if (hasResourceType(type, subType, resource)) {
                if (resource.value > largestValue) {
                    largestValue = resource.value;
                    clientId = info->clientId;
                    uid = info->uid;
                }
            }
        }
    }

    if (clientId == -1) {
        ALOGE("%s: can't find resource type %s and subtype %s for pid %d",
                 __func__, asString(type), asString(subType), targetPid);
        return false;
    }

    clientInfo.mPid = targetPid;
    clientInfo.mUid = uid;
    clientInfo.mClientId = clientId;
    return true;
}

void ResourceTracker::dump(std::string& resourceLogs) {
    const size_t SIZE = 256;
    char buffer[SIZE];
    resourceLogs.append("  Processes:\n");
    for (const auto& [pid, /* ResourceInfos */ infos] : mMap) {
        snprintf(buffer, SIZE, "    Pid: %d\n", pid);
        resourceLogs.append(buffer);
        int priority = 0;
        if (getPriority(pid, &priority)) {
            snprintf(buffer, SIZE, "    Priority: %d\n", priority);
        } else {
            snprintf(buffer, SIZE, "    Priority: <unknown>\n");
        }
        resourceLogs.append(buffer);

        for (const auto& [infoKey, /* ResourceInfo */ info] : infos) {
            resourceLogs.append("      Client:\n");
            snprintf(buffer, SIZE, "        Id: %lld\n", (long long)info.clientId);
            resourceLogs.append(buffer);

            std::string clientName = info.name;
            snprintf(buffer, SIZE, "        Name: %s\n", clientName.c_str());
            resourceLogs.append(buffer);

            const ResourceList& resources = info.resources;
            resourceLogs.append("        Resources:\n");
            resourceLogs.append(resources.toString());
        }
    }
    resourceLogs.append("  Process Pid override:\n");
    for (const auto& [oldPid, newPid] : mOverridePidMap) {
        snprintf(buffer, SIZE, "    Original Pid: %d,  Override Pid: %d\n", oldPid, newPid);
        resourceLogs.append(buffer);
    }
}

void ResourceTracker::onFirstAdded(const MediaResourceParcel& resource, uid_t uid) {
    std::shared_ptr<ResourceManagerServiceNew> service = mService.lock();
    if (service == nullptr) {
        ALOGW("%s: ResourceManagerService is invalid!", __func__);
        return;
    }

    service->onFirstAdded(resource, uid);
}

void ResourceTracker::onLastRemoved(const MediaResourceParcel& resource, uid_t uid) {
    std::shared_ptr<ResourceManagerServiceNew> service = mService.lock();
    if (service == nullptr) {
        ALOGW("%s: ResourceManagerService is invalid!", __func__);
        return;
    }

    service->onLastRemoved(resource, uid);
}

bool ResourceTracker::getPriority(int pid, int* priority) {
    int newPid = pid;

    if (mOverridePidMap.find(pid) != mOverridePidMap.end()) {
        newPid = mOverridePidMap[pid];
        ALOGD("%s: use override pid %d instead original pid %d", __func__, newPid, pid);
    }

    return mProcessInfo->getPriority(newPid, priority);
}

bool ResourceTracker::getNonConflictingClients(const ResourceRequestInfo& resourceRequestInfo,
                                               std::vector<ClientInfo>& clients) {
    MediaResource::Type type = resourceRequestInfo.mResource->type;
    MediaResource::SubType subType = resourceRequestInfo.mResource->subType;
    for (auto& [pid, /* ResourceInfos */ infos] : mMap) {
        for (const auto& [id, /* ResourceInfo */ info] : infos) {
            if (hasResourceType(type, subType, info.resources)) {
                if (!isCallingPriorityHigher(resourceRequestInfo.mCallingPid, pid)) {
                    // some higher/equal priority process owns the resource,
                    // this is a conflict.
                    ALOGE("%s: The resource (%s) request from pid %d is conflicting",
                          __func__, asString(type), pid);
                    clients.clear();
                    return false;
                } else {
                    if (!contains(clients, info.clientId)) {
                        clients.emplace_back(info.pid, info.uid, info.clientId);
                    }
                }
            }
        }
    }

    return true;
}

const ResourceInfo* ResourceTracker::getResourceInfo(int pid, const int64_t& clientId) const {
    std::map<int, ResourceInfos>::const_iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("%s: didn't find pid %d for clientId %lld", __func__, pid, (long long) clientId);
        return nullptr;
    }

    const ResourceInfos& infos = found->second;
    ResourceInfos::const_iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("%s: didn't find clientId %lld", __func__, (long long) clientId);
        return nullptr;
    }

    return &foundClient->second;
}

bool ResourceTracker::isCallingPriorityHigher(int callingPid, int pid) {
    int callingPidPriority;
    if (!getPriority(callingPid, &callingPidPriority)) {
        return false;
    }

    int priority;
    if (!getPriority(pid, &priority)) {
        return false;
    }

    return (callingPidPriority < priority);
}

} // namespace android
