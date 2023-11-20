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
#define LOG_TAG "ResourceManagerServiceNew"
#include <utils/Log.h>

#include "ResourceManagerServiceNew.h"

namespace android {

ResourceManagerServiceNew::ResourceManagerServiceNew(
        const sp<ProcessInfoInterface>& processInfo,
        const sp<SystemCallbackInterface>& systemResource) :
  ResourceManagerService(processInfo, systemResource) {}

ResourceManagerServiceNew::~ResourceManagerServiceNew() {}

Status ResourceManagerServiceNew::config(const std::vector<MediaResourcePolicyParcel>& policies) {
    return ResourceManagerService::config(policies);
}

Status ResourceManagerServiceNew::addResource(
        const ClientInfoParcel& clientInfo,
        const std::shared_ptr<IResourceManagerClient>& client,
        const std::vector<MediaResourceParcel>& resources) {
    return ResourceManagerService::addResource(clientInfo, client, resources);
}

Status ResourceManagerServiceNew::removeResource(
        const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources) {
    return ResourceManagerService::removeResource(clientInfo, resources);
}

Status ResourceManagerServiceNew::removeClient(const ClientInfoParcel& clientInfo) {
    return ResourceManagerService::removeClient(clientInfo);
}

Status ResourceManagerServiceNew::removeResource(const ClientInfoParcel& clientInfo,
                                                 bool checkValid) {
    return ResourceManagerService::removeResource(clientInfo, checkValid);
}

Status ResourceManagerServiceNew::reclaimResource(
        const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources,
        bool* _aidl_return) {
    return ResourceManagerService::reclaimResource(clientInfo, resources, _aidl_return);
}

Status ResourceManagerServiceNew::overridePid(int originalPid, int newPid) {
    return ResourceManagerService::overridePid(originalPid, newPid);
}

Status ResourceManagerServiceNew::overrideProcessInfo(
        const std::shared_ptr<IResourceManagerClient>& client,
        int pid,
        int procState,
        int oomScore) {
    return ResourceManagerService::overrideProcessInfo(client, pid, procState, oomScore);
}

Status ResourceManagerServiceNew::markClientForPendingRemoval(const ClientInfoParcel& clientInfo) {
    return ResourceManagerService::markClientForPendingRemoval(clientInfo);
}

Status ResourceManagerServiceNew::reclaimResourcesFromClientsPendingRemoval(int32_t pid) {
    return ResourceManagerService::reclaimResourcesFromClientsPendingRemoval(pid);
}

Status ResourceManagerServiceNew::notifyClientCreated(const ClientInfoParcel& clientInfo) {
    return ResourceManagerService::notifyClientCreated(clientInfo);
}

Status ResourceManagerServiceNew::notifyClientStarted(const ClientConfigParcel& clientConfig) {
    return ResourceManagerService::notifyClientStarted(clientConfig);
}

Status ResourceManagerServiceNew::notifyClientStopped(const ClientConfigParcel& clientConfig) {
    return ResourceManagerService::notifyClientStopped(clientConfig);
}

Status ResourceManagerServiceNew::notifyClientConfigChanged(
        const ClientConfigParcel& clientConfig) {
    return ResourceManagerService::notifyClientConfigChanged(clientConfig);
}

binder_status_t ResourceManagerServiceNew::dump(int fd, const char** args, uint32_t numArgs) {
    return ResourceManagerService::dump(fd, args, numArgs);
}

} // namespace android
