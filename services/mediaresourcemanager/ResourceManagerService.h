/*
**
** Copyright 2015, The Android Open Source Project
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

#ifndef ANDROID_MEDIA_RESOURCEMANAGERSERVICE_H
#define ANDROID_MEDIA_RESOURCEMANAGERSERVICE_H

#include <map>
#include <set>
#include <mutex>
#include <string>
#include <vector>

#include <aidl/android/media/BnResourceManagerService.h>
#include <media/MediaResource.h>
#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/threads.h>

namespace android {

class DeathNotifier;
class ResourceManagerService;
class ResourceObserverService;
class ServiceLog;
struct ProcessInfoInterface;
class ResourceManagerMetrics;

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::IResourceManagerClient;
using ::aidl::android::media::BnResourceManagerService;
using ::aidl::android::media::MediaResourceParcel;
using ::aidl::android::media::MediaResourcePolicyParcel;
using ::aidl::android::media::ClientInfoParcel;
using ::aidl::android::media::ClientConfigParcel;

typedef std::map<std::tuple<
        MediaResource::Type, MediaResource::SubType, std::vector<uint8_t>>,
        MediaResourceParcel> ResourceList;

struct ResourceInfo {
    uid_t uid;
    int64_t clientId;
    std::string name;
    std::shared_ptr<IResourceManagerClient> client;
    std::shared_ptr<DeathNotifier> deathNotifier = nullptr;
    ResourceList resources;
    bool pendingRemoval{false};
};

// vector of <PID, UID>
typedef std::vector<std::pair<int32_t, uid_t>> PidUidVector;

typedef std::map<int64_t, ResourceInfo> ResourceInfos;
typedef std::map<int, ResourceInfos> PidResourceInfosMap;

class ResourceManagerService : public BnResourceManagerService {
public:
    struct SystemCallbackInterface : public RefBase {
        virtual void noteStartVideo(int uid) = 0;
        virtual void noteStopVideo(int uid) = 0;
        virtual void noteResetVideo() = 0;
        virtual bool requestCpusetBoost(bool enable) = 0;
    };

    static char const *getServiceName() { return "media.resource_manager"; }
    static void instantiate();

    virtual inline binder_status_t dump(
            int /*fd*/, const char** /*args*/, uint32_t /*numArgs*/);

    ResourceManagerService();
    explicit ResourceManagerService(const sp<ProcessInfoInterface> &processInfo,
            const sp<SystemCallbackInterface> &systemResource);
    virtual ~ResourceManagerService();
    void setObserverService(const std::shared_ptr<ResourceObserverService>& observerService);

    // IResourceManagerService interface
    Status config(const std::vector<MediaResourcePolicyParcel>& policies) override;

    Status addResource(const ClientInfoParcel& clientInfo,
                       const std::shared_ptr<IResourceManagerClient>& client,
                       const std::vector<MediaResourceParcel>& resources) override;

    Status removeResource(const ClientInfoParcel& clientInfo,
                          const std::vector<MediaResourceParcel>& resources) override;

    Status removeClient(const ClientInfoParcel& clientInfo) override;

    // Tries to reclaim resource from processes with lower priority than the calling process
    // according to the requested resources.
    // Returns true if any resource has been reclaimed, otherwise returns false.
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

private:
    friend class ResourceManagerServiceTest;
    friend class DeathNotifier;
    friend class OverrideProcessInfoDeathNotifier;

    // Reclaims resources from |clients|. Returns true if reclaim succeeded
    // for all clients.
    bool reclaimUnconditionallyFrom(
        const std::vector<std::shared_ptr<IResourceManagerClient>>& clients);

    // Gets the list of all the clients who own the specified resource type.
    // Returns false if any client belongs to a process with higher priority than the
    // calling process. The clients will remain unchanged if returns false.
    bool getAllClients_l(int callingPid, MediaResource::Type type, MediaResource::SubType subType,
            PidUidVector* idList,
            std::vector<std::shared_ptr<IResourceManagerClient>>* clients);

    // Gets the client who owns specified resource type from lowest possible priority process.
    // Returns false if the calling process priority is not higher than the lowest process
    // priority. The client will remain unchanged if returns false.
    bool getLowestPriorityBiggestClient_l(int callingPid, MediaResource::Type type,
            MediaResource::SubType subType, PidUidVector* idList,
            std::shared_ptr<IResourceManagerClient> *client);

    // Gets lowest priority process that has the specified resource type.
    // Returns false if failed. The output parameters will remain unchanged if failed.
    bool getLowestPriorityPid_l(MediaResource::Type type, MediaResource::SubType subType, int *pid,
                int *priority);

    // Gets the client who owns biggest piece of specified resource type from pid.
    // Returns false with no change to client if there are no clients holdiing resources of thisi
    // type.
    bool getBiggestClient_l(int pid, MediaResource::Type type, MediaResource::SubType subType,
            uid_t& uid, std::shared_ptr<IResourceManagerClient> *client,
            bool pendingRemovalOnly = false);
    // Same method as above, but with pendingRemovalOnly as true.
    bool getBiggestClientPendingRemoval_l(int pid, MediaResource::Type type,
            MediaResource::SubType subType, uid_t& uid,
            std::shared_ptr<IResourceManagerClient> *client);

    bool isCallingPriorityHigher_l(int callingPid, int pid);

    // A helper function basically calls getLowestPriorityBiggestClient_l and add
    // the result client to the given Vector.
    void getClientForResource_l(int callingPid, const MediaResourceParcel *res,
            PidUidVector* idList,
            std::vector<std::shared_ptr<IResourceManagerClient>>* clients);

    void onFirstAdded(const MediaResourceParcel& res, const ResourceInfo& clientInfo);
    void onLastRemoved(const MediaResourceParcel& res, const ResourceInfo& clientInfo);

    // Merge r2 into r1
    void mergeResources(MediaResourceParcel& r1, const MediaResourceParcel& r2);

    // Get priority from process's pid
    bool getPriority_l(int pid, int* priority);

    void removeProcessInfoOverride(int pid);

    void removeProcessInfoOverride_l(int pid);

    void pushReclaimAtom(const ClientInfoParcel& clientInfo,
                         const std::vector<std::shared_ptr<IResourceManagerClient>>& clients,
                         const PidUidVector& idList, bool reclaimed);

    // Get the peak concurrent pixel count (associated with the video codecs) for the process.
    long getPeakConcurrentPixelCount(int pid) const;
    // Get the current concurrent pixel count (associated with the video codecs) for the process.
    long getCurrentConcurrentPixelCount(int pid) const;

    mutable std::mutex mLock;
    sp<ProcessInfoInterface> mProcessInfo;
    sp<SystemCallbackInterface> mSystemCB;
    sp<ServiceLog> mServiceLog;
    PidResourceInfosMap mMap;
    bool mSupportsMultipleSecureCodecs;
    bool mSupportsSecureWithNonSecureCodec;
    int32_t mCpuBoostCount;
    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
    struct ProcessInfoOverride {
        std::shared_ptr<DeathNotifier> deathNotifier = nullptr;
        std::shared_ptr<IResourceManagerClient> client;
    };
    std::map<int, int> mOverridePidMap;
    std::map<pid_t, ProcessInfoOverride> mProcessInfoOverrideMap;
    std::shared_ptr<ResourceObserverService> mObserverService;
    std::unique_ptr<ResourceManagerMetrics> mResourceManagerMetrics;
};

// ----------------------------------------------------------------------------
} // namespace android

#endif // ANDROID_MEDIA_RESOURCEMANAGERSERVICE_H
