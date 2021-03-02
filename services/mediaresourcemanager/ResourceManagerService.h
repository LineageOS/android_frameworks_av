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

#include <aidl/android/media/BnResourceManagerService.h>
#include <arpa/inet.h>
#include <media/MediaResource.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/String8.h>
#include <utils/threads.h>
#include <utils/Vector.h>

namespace android {

class DeathNotifier;
class ResourceManagerService;
class ServiceLog;
struct ProcessInfoInterface;

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::IResourceManagerClient;
using ::aidl::android::media::BnResourceManagerService;
using ::aidl::android::media::MediaResourceParcel;
using ::aidl::android::media::MediaResourcePolicyParcel;

typedef std::map<std::tuple<
        MediaResource::Type, MediaResource::SubType, std::vector<int8_t>>,
        MediaResourceParcel> ResourceList;

struct ResourceInfo {
    int64_t clientId;
    uid_t uid;
    std::shared_ptr<IResourceManagerClient> client;
    sp<DeathNotifier> deathNotifier;
    ResourceList resources;
    bool pendingRemoval{false};
};

// TODO: convert these to std::map
typedef KeyedVector<int64_t, ResourceInfo> ResourceInfos;
typedef KeyedVector<int, ResourceInfos> PidResourceInfosMap;

class DeathNotifier : public RefBase {
public:
    DeathNotifier(const std::shared_ptr<ResourceManagerService> &service,
            int pid, int64_t clientId);

    ~DeathNotifier() {}

    // Implement death recipient
    static void BinderDiedCallback(void* cookie);
    void binderDied();

private:
    std::weak_ptr<ResourceManagerService> mService;
    int mPid;
    int64_t mClientId;
};
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
    explicit ResourceManagerService(
            const sp<ProcessInfoInterface> &processInfo,
            const sp<SystemCallbackInterface> &systemResource);
    virtual ~ResourceManagerService();

    // IResourceManagerService interface
    Status config(const std::vector<MediaResourcePolicyParcel>& policies) override;

    Status addResource(
            int32_t pid,
            int32_t uid,
            int64_t clientId,
            const std::shared_ptr<IResourceManagerClient>& client,
            const std::vector<MediaResourceParcel>& resources) override;

    Status removeResource(
            int32_t pid,
            int64_t clientId,
            const std::vector<MediaResourceParcel>& resources) override;

    Status removeClient(int32_t pid, int64_t clientId) override;

    // Tries to reclaim resource from processes with lower priority than the calling process
    // according to the requested resources.
    // Returns true if any resource has been reclaimed, otherwise returns false.
    Status reclaimResource(
            int32_t callingPid,
            const std::vector<MediaResourceParcel>& resources,
            bool* _aidl_return) override;

    Status overridePid(
            int originalPid,
            int newPid) override;

    Status markClientForPendingRemoval(int32_t pid, int64_t clientId) override;

    Status reclaimResourcesFromClientsPendingRemoval(int32_t pid) override;

    Status removeResource(int pid, int64_t clientId, bool checkValid);

private:
    friend class ResourceManagerServiceTest;

    // Reclaims resources from |clients|. Returns true if reclaim succeeded
    // for all clients.
    bool reclaimInternal(
            const Vector<std::shared_ptr<IResourceManagerClient>> &clients);

    // Gets the list of all the clients who own the specified resource type.
    // Returns false if any client belongs to a process with higher priority than the
    // calling process. The clients will remain unchanged if returns false.
    bool getAllClients_l(int callingPid, MediaResource::Type type,
            Vector<std::shared_ptr<IResourceManagerClient>> *clients);

    // Gets the client who owns specified resource type from lowest possible priority process.
    // Returns false if the calling process priority is not higher than the lowest process
    // priority. The client will remain unchanged if returns false.
    bool getLowestPriorityBiggestClient_l(int callingPid, MediaResource::Type type,
            std::shared_ptr<IResourceManagerClient> *client);

    // Gets lowest priority process that has the specified resource type.
    // Returns false if failed. The output parameters will remain unchanged if failed.
    bool getLowestPriorityPid_l(MediaResource::Type type, int *pid, int *priority);

    // Gets the client who owns biggest piece of specified resource type from pid.
    // Returns false if failed. The client will remain unchanged if failed.
    bool getBiggestClient_l(int pid, MediaResource::Type type,
            std::shared_ptr<IResourceManagerClient> *client,
            bool pendingRemovalOnly = false);

    bool isCallingPriorityHigher_l(int callingPid, int pid);

    // A helper function basically calls getLowestPriorityBiggestClient_l and add
    // the result client to the given Vector.
    void getClientForResource_l(int callingPid, const MediaResourceParcel *res,
            Vector<std::shared_ptr<IResourceManagerClient>> *clients);

    void onFirstAdded(const MediaResourceParcel& res, const ResourceInfo& clientInfo);
    void onLastRemoved(const MediaResourceParcel& res, const ResourceInfo& clientInfo);

    // Merge r2 into r1
    void mergeResources(MediaResourceParcel& r1, const MediaResourceParcel& r2);

    // Get priority from process's pid
    bool getPriority_l(int pid, int* priority);

    mutable Mutex mLock;
    sp<ProcessInfoInterface> mProcessInfo;
    sp<SystemCallbackInterface> mSystemCB;
    sp<ServiceLog> mServiceLog;
    PidResourceInfosMap mMap;
    bool mSupportsMultipleSecureCodecs;
    bool mSupportsSecureWithNonSecureCodec;
    int32_t mCpuBoostCount;
    ::ndk::ScopedAIBinder_DeathRecipient mDeathRecipient;
    std::map<int, int> mOverridePidMap;
};

// ----------------------------------------------------------------------------
} // namespace android

#endif // ANDROID_MEDIA_RESOURCEMANAGERSERVICE_H
