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

#ifndef ANDROID_MEDIA_RESOURCETRACKER_H_
#define ANDROID_MEDIA_RESOURCETRACKER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <media/MediaResource.h>
#include <aidl/android/media/ClientInfoParcel.h>
#include <aidl/android/media/IResourceManagerClient.h>
#include <aidl/android/media/MediaResourceParcel.h>

#include "ResourceManagerServiceUtils.h"

namespace android {

class DeathNotifier;
class ResourceManagerServiceNew;
class ResourceObserverService;
struct ProcessInfoInterface;
struct ResourceRequestInfo;
struct ClientInfo;

/*
 * ResourceTracker abstracts the resources managed by the ResourceManager.
 * It keeps track of the resource used by the clients (clientid) and by the process (pid)
 */
class ResourceTracker {
public:
    ResourceTracker(const std::shared_ptr<ResourceManagerServiceNew>& service,
                    const sp<ProcessInfoInterface>& processInfo);
    ~ResourceTracker();

    /**
     * Add or update resources for |clientInfo|.
     *
     * If |clientInfo| is not tracked yet, it records its associated |client| and adds
     * |resources| to the tracked resources. If |clientInfo| is already tracked,
     * it updates the tracked resources by adding |resources| to them (|client| in
     * this case is unused and unchecked).
     *
     * @param clientInfo Info of the calling client.
     * @param client Interface for the client.
     * @param resources An array of resources to be added.
     *
     * @return true upon successfully adding/updating the resources, false
     * otherwise.
     */
    bool addResource(const aidl::android::media::ClientInfoParcel& clientInfo,
                     const std::shared_ptr<::aidl::android::media::IResourceManagerClient>& client,
                     const std::vector<::aidl::android::media::MediaResourceParcel>& resources);

    // Update the resource info, if there is any changes.
    bool updateResource(const aidl::android::media::ClientInfoParcel& clientInfo);

    // Remove a set of resources from the given client.
    // returns true on success, false otherwise.
    bool removeResource(const aidl::android::media::ClientInfoParcel& clientInfo,
                        const std::vector<::aidl::android::media::MediaResourceParcel>& resources);

    /**
     * Remove all resources tracked for |clientInfo|.
     *
     * If |validateCallingPid| is true, the (pid of the) calling process is validated that it
     * is from a trusted process.
     * Returns true on success (|clientInfo| was tracked and optionally the caller
     * was a validated trusted process), false otherwise (|clientInfo| was not tracked,
     * or the caller was not a trusted process)
     */
    bool removeResource(const aidl::android::media::ClientInfoParcel& clientInfo,
                        bool validateCallingPid);

    // Mark the client for pending removal.
    // Such clients are primary candidate for reclaim.
    // returns true on success, false otherwise.
    bool markClientForPendingRemoval(const aidl::android::media::ClientInfoParcel& clientInfo);

    // Get a list of clients that belong to process with given pid and are maked to be
    // pending removal by markClientForPendingRemoval.
    // returns true on success, false otherwise.
    bool getClientsMarkedPendingRemoval(int32_t pid, std::vector<ClientInfo>& targetClients);

    // Override the pid of originalPid with newPid
    // To remove the pid entry from the override list, set newPid as -1
    // returns true on successful override, false otherwise.
    bool overridePid(int originalPid, int newPid);

    // Override the process info {state, oom score} of the process with pid.
    // returns true on success, false otherwise.
    bool overrideProcessInfo(
            const std::shared_ptr<aidl::android::media::IResourceManagerClient>& client,
            int pid, int procState, int oomScore);

    // Remove the overridden process info.
    void removeProcessInfoOverride(int pid);

    // Find all clients that have given resources.
    // If applicable, match the primary type too.
    // The |clients| (list) isn't cleared by this function to allow calling this
    // function multiple times for different resources.
    // returns true upon finding at lease one client with the given resource request info,
    // false otherwise (no clients)
    bool getAllClients(
            const ResourceRequestInfo& resourceRequestInfo,
            std::vector<ClientInfo>& clients,
            MediaResource::SubType primarySubType = MediaResource::SubType::kUnspecifiedSubType);

    // Look for the lowest priority process with the given resources.
    // Upon success lowestPriorityPid and lowestPriority are
    // set accordingly and it returns true.
    // If there isn't a lower priority process with the given resources, it will return false
    // with out updating lowestPriorityPid and lowerPriority.
    bool getLowestPriorityPid(MediaResource::Type type, MediaResource::SubType subType,
                              int& lowestPriorityPid, int& lowestPriority);

    // Look for the lowest priority process with the given resources
    // among the given client list.
    // If applicable, match the primary type too.
    // returns true on success, false otherwise.
    bool getLowestPriorityPid(
            MediaResource::Type type, MediaResource::SubType subType,
            MediaResource::SubType primarySubType,
            const std::vector<ClientInfo>& clients,
            int& lowestPriorityPid, int& lowestPriority);

    // Find the biggest client of the given process with given resources,
    // that is marked as pending to be removed.
    // returns true on success, false otherwise.
    bool getBiggestClientPendingRemoval(
            int pid, MediaResource::Type type,
            MediaResource::SubType subType,
            ClientInfo& clientInfo);

    // Find the biggest client from the process pid, selecting them from the list of clients.
    // If applicable, match the primary type too.
    // Returns true when a client is found and clientInfo is updated accordingly.
    // Upon failure to find a client, it will return false without updating
    // clientInfo.
    // Upon failure to find a client, it will return false.
    bool getBiggestClient(
            int targetPid,
            MediaResource::Type type,
            MediaResource::SubType subType,
            const std::vector<ClientInfo>& clients,
            ClientInfo& clientInfo,
            MediaResource::SubType primarySubType = MediaResource::SubType::kUnspecifiedSubType);

    // Find the biggest client from the process pid, that has the least importance
    // (than given importance) among the given list of clients.
    // If applicable, match the primary type too.
    // returns true on success, false otherwise.
    bool getLeastImportantBiggestClient(int targetPid, int32_t importance,
                                        MediaResource::Type type,
                                        MediaResource::SubType subType,
                                        MediaResource::SubType primarySubType,
                                        const std::vector<ClientInfo>& clients,
                                        ClientInfo& clientInfo);

    // Find the client that belongs to given process(pid) and with the given clientId.
    // A nullptr is returned upon failure to find the client.
    std::shared_ptr<::aidl::android::media::IResourceManagerClient> getClient(
            int pid, const int64_t& clientId) const;

    // Removes the client from the given process(pid) with the given clientId.
    // returns true on success, false otherwise.
    bool removeClient(int pid, const int64_t& clientId);

    // Set the resource observer service, to which to notify when the resources
    // are added and removed.
    void setResourceObserverService(
            const std::shared_ptr<ResourceObserverService>& observerService);

    // Dump all the resource allocations for all the processes into a given string
    void dump(std::string& resourceLogs);

    // get the priority of the process.
    // If we can't get the priority of the process (with given pid), it will
    // return false.
    bool getPriority(int pid, int* priority);

    // Check if the given resource request has conflicting clients.
    // The resource conflict is defined by the ResourceModel (such as
    // co-existence of secure codec with another secure or non-secure codec).
    // But here, the ResourceTracker only looks for resources from lower
    // priority processes.
    // If is/are only higher or same priority process/es with the given resource,
    // it will return false.
    // Otherwise, adds all the clients to the list of clients and return true.
    bool getNonConflictingClients(const ResourceRequestInfo& resourceRequestInfo,
                                  std::vector<ClientInfo>& clients);

    // Returns unmodifiable reference to the resource map.
    const std::map<int, ResourceInfos>& getResourceMap() const {
        return mMap;
    }

private:
    // Get ResourceInfos associated with the given process.
    // If none exists, this method will create and associate an empty object and return it.
    ResourceInfos& getResourceInfosForEdit(int pid);

    // A helper function that returns true if the callingPid has higher priority than pid.
    // Returns false otherwise.
    bool isCallingPriorityHigher(int callingPid, int pid);

    // Locate the resource info corresponding to the process pid and
    // the client clientId.
    const ResourceInfo* getResourceInfo(int pid, const int64_t& clientId) const;

    // Notify when a resource is added for the first time.
    void onFirstAdded(const MediaResourceParcel& resource, uid_t uid);
    // Notify when a resource is removed for the last time.
    void onLastRemoved(const MediaResourceParcel& resource, uid_t uid);

private:
    // Structure that defines process info that needs to be overridden.
    struct ProcessInfoOverride {
        std::shared_ptr<DeathNotifier> deathNotifier = nullptr;
        std::shared_ptr<::aidl::android::media::IResourceManagerClient> client;
    };

    // Map of Resource information indexed through the process id.
    std::map<int, ResourceInfos> mMap;
    // A weak reference (to avoid cyclic dependency) to the ResourceManagerService.
    // ResourceTracker uses this to communicate back with the ResourceManagerService.
    std::weak_ptr<ResourceManagerServiceNew> mService;
    // To notify the ResourceObserverService abour resources are added or removed.
    std::shared_ptr<ResourceObserverService> mObserverService;
    // Map of pid and their overrided id.
    std::map<int, int> mOverridePidMap;
    // Map of pid and their overridden process info.
    std::map<pid_t, ProcessInfoOverride> mProcessInfoOverrideMap;
    // Interface that gets process specific information.
    sp<ProcessInfoInterface> mProcessInfo;
};

} // namespace android

#endif // ANDROID_MEDIA_RESOURCETRACKER_H_
