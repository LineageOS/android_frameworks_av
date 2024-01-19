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

class IReclaimPolicy;
class IResourceModel;
class ResourceTracker;

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

    Status notifyClientCreated(const ClientInfoParcel& clientInfo) override;

    Status notifyClientStarted(const ClientConfigParcel& clientConfig) override;

    Status notifyClientStopped(const ClientConfigParcel& clientConfig) override;

    Status notifyClientConfigChanged(const ClientConfigParcel& clientConfig) override;

    binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;

    friend class ResourceTracker;

private:

    // Set up the Resource models.
    void setUpResourceModels();

    // Set up the Reclaim Policies.
    void setUpReclaimPolicies();

    // From the list of clients, pick/select client(s) based on the reclaim policy.
    void getClientForResource_l(
        const ReclaimRequestInfo& reclaimRequestInfo,
        const std::vector<ClientInfo>& clients,
        std::vector<ClientInfo>& targetClients);

    // Initializes the internal state of the ResourceManagerService
    void init() override;

    void setObserverService(
            const std::shared_ptr<ResourceObserverService>& observerService) override;

    // Gets the list of all the clients who own the specified resource type.
    // Returns false if any client belongs to a process with higher priority than the
    // calling process. The clients will remain unchanged if returns false.
    bool getTargetClients(
        const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources,
        std::vector<ClientInfo>& targetClients) override;

    // Removes the pid from the override map.
    void removeProcessInfoOverride(int pid) override;

    // override the pid of given process
    bool overridePid_l(int32_t originalPid, int32_t newPid) override;

    // override the process info of given process
    bool overrideProcessInfo_l(const std::shared_ptr<IResourceManagerClient>& client,
                               int pid, int procState, int oomScore) override;

    // Get priority from process's pid
    bool getPriority_l(int pid, int* priority) const override;

    // Get the client for given pid and the clientId from the map
    std::shared_ptr<IResourceManagerClient> getClient_l(
        int pid, const int64_t& clientId) const override;

    // Remove the client for given pid and the clientId from the map
    bool removeClient_l(int pid, const int64_t& clientId) override;

    // Get all the resource status for dump
    void getResourceDump(std::string& resourceLog) const override;

    // Returns a unmodifiable reference to the internal resource state as a map
    const std::map<int, ResourceInfos>& getResourceMap() const override;

    Status removeResource(const ClientInfoParcel& clientInfo, bool checkValid) override;

    // The following utility functions are used only for testing by ResourceManagerServiceTest
    // START: TEST only functions
    // Gets the list of all the clients who own the specified resource type.
    // Returns false if any client belongs to a process with higher priority than the
    // calling process. The clients will remain unchanged if returns false.
    bool getAllClients_l(const ResourceRequestInfo& resourceRequestInfo,
                         std::vector<ClientInfo>& clientsInfo) override;

    // Gets the client who owns specified resource type from lowest possible priority process.
    // Returns false if the calling process priority is not higher than the lowest process
    // priority. The client will remain unchanged if returns false.
    bool getLowestPriorityBiggestClient_l(
        const ResourceRequestInfo& resourceRequestInfo,
        ClientInfo& clientInfo) override;

    // Gets lowest priority process that has the specified resource type.
    // Returns false if failed. The output parameters will remain unchanged if failed.
    bool getLowestPriorityPid_l(MediaResource::Type type, MediaResource::SubType subType,
                                int* lowestPriorityPid, int* lowestPriority) override;

    // enable/disable process priority based reclaim and client importance based reclaim
    void setReclaimPolicy(bool processPriority, bool clientImportance) override;
    // END: TEST only functions

private:
    std::shared_ptr<ResourceTracker> mResourceTracker;
    std::unique_ptr<IResourceModel> mDefaultResourceModel;
    std::vector<std::unique_ptr<IReclaimPolicy>> mReclaimPolicies;
};

// ----------------------------------------------------------------------------
} // namespace android

#endif // ANDROID_MEDIA_RESOURCEMANAGERSERVICENEW_H
