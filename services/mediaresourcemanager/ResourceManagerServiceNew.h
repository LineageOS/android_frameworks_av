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

#ifndef ANDROID_MEDIA_RESOURCEMANAGERSERVICENEW_H
#define ANDROID_MEDIA_RESOURCEMANAGERSERVICENEW_H

#include "ResourceManagerService.h"

namespace android {

//
// A newer implementation of IResourceManagerService, which
// eventually will replace the older implementation in ResourceManagerService.
//
// To make the transition easier, this implementation overrides the
// private virtual methods from ResourceManagerService.
//
// This implementation is devised to abstract and integrate:
//   - resources into an independent abstraction
//   - resource model as a separate interface (and implementation)
//   - reclaim policy as a separate interface (and implementation)
//
class ResourceManagerServiceNew : public ResourceManagerService {
public:

    explicit ResourceManagerServiceNew(const sp<ProcessInfoInterface>& processInfo,
                                       const sp<SystemCallbackInterface>& systemResource);
    virtual ~ResourceManagerServiceNew();

    // IResourceManagerService interface
    Status config(const std::vector<MediaResourcePolicyParcel>& policies) override;

    Status addResource(const ClientInfoParcel& clientInfo,
                       const std::shared_ptr<IResourceManagerClient>& client,
                       const std::vector<MediaResourceParcel>& resources) override;

    Status removeResource(const ClientInfoParcel& clientInfo,
                          const std::vector<MediaResourceParcel>& resources) override;

    Status removeClient(const ClientInfoParcel& clientInfo) override;

    Status reclaimResource(const ClientInfoParcel& clientInfo,
                           const std::vector<MediaResourceParcel>& resources,
                           bool* _aidl_return) override;

    Status overridePid(int32_t originalPid, int32_t newPid) override;

    Status overrideProcessInfo(const std::shared_ptr<IResourceManagerClient>& client,
                               int32_t pid, int32_t procState, int32_t oomScore) override;

    Status markClientForPendingRemoval(const ClientInfoParcel& clientInfo) override;

    Status reclaimResourcesFromClientsPendingRemoval(int32_t pid) override;

    Status removeResource(const ClientInfoParcel& clientInfo, bool checkValid);

    Status notifyClientCreated(const ClientInfoParcel& clientInfo) override;

    Status notifyClientStarted(const ClientConfigParcel& clientConfig) override;

    Status notifyClientStopped(const ClientConfigParcel& clientConfig) override;

    Status notifyClientConfigChanged(const ClientConfigParcel& clientConfig) override;

    binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;
};

// ----------------------------------------------------------------------------
} // namespace android

#endif // ANDROID_MEDIA_RESOURCEMANAGERSERVICENEW_H
