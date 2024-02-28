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

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceManagerService"
#include <utils/Log.h>

#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <cutils/sched_policy.h>
#include <media/MediaResourcePolicy.h>
#include <media/stagefright/foundation/ABase.h>
#include <mediautils/BatteryNotifier.h>
#include <mediautils/ProcessInfo.h>
#include <mediautils/SchedulingPolicyService.h>
#include <com_android_media_codec_flags.h>

#include "ResourceManagerMetrics.h"
#include "ResourceManagerServiceNew.h"
#include "ResourceObserverService.h"
#include "ServiceLog.h"

namespace CodecFeatureFlags = com::android::media::codec::flags;

namespace android {

void ResourceManagerService::getResourceDump(std::string& resourceLog) const {
    PidResourceInfosMap mapCopy;
    std::map<int, int> overridePidMapCopy;
    {
        std::scoped_lock lock{mLock};
        mapCopy = mMap;  // Shadow copy, real copy will happen on write.
        overridePidMapCopy = mOverridePidMap;
    }

    const size_t SIZE = 256;
    char buffer[SIZE];
    resourceLog.append("  Processes:\n");
    for (const auto& [pid, infos] : mapCopy) {
        snprintf(buffer, SIZE, "    Pid: %d\n", pid);
        resourceLog.append(buffer);
        int priority = 0;
        if (getPriority_l(pid, &priority)) {
            snprintf(buffer, SIZE, "    Priority: %d\n", priority);
        } else {
            snprintf(buffer, SIZE, "    Priority: <unknown>\n");
        }
        resourceLog.append(buffer);

        for (const auto& [infoKey, info] : infos) {
            resourceLog.append("      Client:\n");
            snprintf(buffer, SIZE, "        Id: %lld\n", (long long)info.clientId);
            resourceLog.append(buffer);

            std::string clientName = info.name;
            snprintf(buffer, SIZE, "        Name: %s\n", clientName.c_str());
            resourceLog.append(buffer);

            const ResourceList& resources = info.resources;
            resourceLog.append("        Resources:\n");
            resourceLog.append(resources.toString());
        }
    }

    resourceLog.append("  Process Pid override:\n");
    for (auto it = overridePidMapCopy.begin(); it != overridePidMapCopy.end(); ++it) {
        snprintf(buffer, SIZE, "    Original Pid: %d,  Override Pid: %d\n",
            it->first, it->second);
        resourceLog.append(buffer);
    }
}

binder_status_t ResourceManagerService::dump(int fd, const char** /*args*/, uint32_t /*numArgs*/) {
    String8 result;

    if (checkCallingPermission(String16("android.permission.DUMP")) == false) {
        result.format("Permission Denial: "
                "can't dump ResourceManagerService from pid=%d, uid=%d\n",
                AIBinder_getCallingPid(),
                AIBinder_getCallingUid());
        write(fd, result.c_str(), result.size());
        return PERMISSION_DENIED;
    }

    bool supportsMultipleSecureCodecs;
    bool supportsSecureWithNonSecureCodec;
    String8 serviceLog;
    {
        std::scoped_lock lock{mLock};
        supportsMultipleSecureCodecs = mSupportsMultipleSecureCodecs;
        supportsSecureWithNonSecureCodec = mSupportsSecureWithNonSecureCodec;
        serviceLog = mServiceLog->toString("    " /* linePrefix */);
    }

    // Get all the resource (and overload pid) logs
    std::string resourceLog;
    getResourceDump(resourceLog);

    const size_t SIZE = 256;
    char buffer[SIZE];
    snprintf(buffer, SIZE, "ResourceManagerService: %p\n", this);
    result.append(buffer);
    result.append("  Policies:\n");
    snprintf(buffer, SIZE, "    SupportsMultipleSecureCodecs: %d\n", supportsMultipleSecureCodecs);
    result.append(buffer);
    snprintf(buffer, SIZE, "    SupportsSecureWithNonSecureCodec: %d\n",
            supportsSecureWithNonSecureCodec);
    result.append(buffer);

    result.append(resourceLog.c_str());

    result.append("  Events logs (most recent at top):\n");
    result.append(serviceLog);

    write(fd, result.c_str(), result.size());
    return OK;
}

struct SystemCallbackImpl : public ResourceManagerService::SystemCallbackInterface {
    SystemCallbackImpl() : mClientToken(new BBinder()) {}

    virtual void noteStartVideo(int uid) override {
        BatteryNotifier::getInstance().noteStartVideo(uid);
    }
    virtual void noteStopVideo(int uid) override {
        BatteryNotifier::getInstance().noteStopVideo(uid);
    }
    virtual void noteResetVideo() override {
        BatteryNotifier::getInstance().noteResetVideo();
    }
    virtual bool requestCpusetBoost(bool enable) override {
        return android::requestCpusetBoost(enable, mClientToken);
    }

protected:
    virtual ~SystemCallbackImpl() {}

private:
    DISALLOW_EVIL_CONSTRUCTORS(SystemCallbackImpl);
    sp<IBinder> mClientToken;
};

ResourceManagerService::ResourceManagerService()
    : ResourceManagerService(new ProcessInfo(), new SystemCallbackImpl()) {}

ResourceManagerService::ResourceManagerService(const sp<ProcessInfoInterface> &processInfo,
        const sp<SystemCallbackInterface> &systemResource)
    : mProcessInfo(processInfo),
      mSystemCB(systemResource),
      mServiceLog(new ServiceLog()),
      mSupportsMultipleSecureCodecs(true),
      mSupportsSecureWithNonSecureCodec(true),
      mCpuBoostCount(0) {
    mSystemCB->noteResetVideo();
    // Create ResourceManagerMetrics that handles all the metrics.
    mResourceManagerMetrics = std::make_unique<ResourceManagerMetrics>(mProcessInfo);
}

//static
void ResourceManagerService::instantiate() {
    std::shared_ptr<ResourceManagerService> service = Create();
    binder_status_t status =
                        AServiceManager_addServiceWithFlags(
                        service->asBinder().get(), getServiceName(),
                        AServiceManager_AddServiceFlag::ADD_SERVICE_ALLOW_ISOLATED);
    if (status != STATUS_OK) {
        return;
    }

    std::shared_ptr<ResourceObserverService> observerService =
            ResourceObserverService::instantiate();

    if (observerService != nullptr) {
        service->setObserverService(observerService);
    }
    // TODO: mediaserver main() is already starting the thread pool,
    // move this to mediaserver main() when other services in mediaserver
    // are converted to ndk-platform aidl.
    //ABinderProcess_startThreadPool();
}

std::shared_ptr<ResourceManagerService> ResourceManagerService::Create() {
    return Create(new ProcessInfo(), new SystemCallbackImpl());
}

std::shared_ptr<ResourceManagerService> ResourceManagerService::Create(
        const sp<ProcessInfoInterface>& processInfo,
        const sp<SystemCallbackInterface>& systemResource) {
    std::shared_ptr<ResourceManagerService> service = nullptr;
    // If codec importance feature is on, create the refactored implementation.
    if (CodecFeatureFlags::codec_importance()) {
        service = ::ndk::SharedRefBase::make<ResourceManagerServiceNew>(processInfo,
                                                                        systemResource);
    } else {
        service = ::ndk::SharedRefBase::make<ResourceManagerService>(processInfo,
                                                                     systemResource);
    }

    if (service != nullptr) {
        service->init();
    }

    return service;
}

// TEST only function.
std::shared_ptr<ResourceManagerService> ResourceManagerService::CreateNew(
        const sp<ProcessInfoInterface>& processInfo,
        const sp<SystemCallbackInterface>& systemResource) {
    std::shared_ptr<ResourceManagerService> service =
        ::ndk::SharedRefBase::make<ResourceManagerServiceNew>(processInfo, systemResource);
    service->init();
    return service;
}

void ResourceManagerService::init() {}

ResourceManagerService::~ResourceManagerService() {}

void ResourceManagerService::setObserverService(
        const std::shared_ptr<ResourceObserverService>& observerService) {
    mObserverService = observerService;
}

Status ResourceManagerService::config(const std::vector<MediaResourcePolicyParcel>& policies) {
    String8 log = String8::format("config(%s)", getString(policies).c_str());
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    for (size_t i = 0; i < policies.size(); ++i) {
        const std::string &type = policies[i].type;
        const std::string &value = policies[i].value;
        if (type == MediaResourcePolicy::kPolicySupportsMultipleSecureCodecs()) {
            mSupportsMultipleSecureCodecs = (value == "true");
        } else if (type == MediaResourcePolicy::kPolicySupportsSecureWithNonSecureCodec()) {
            mSupportsSecureWithNonSecureCodec = (value == "true");
        }
    }
    return Status::ok();
}

void ResourceManagerService::onFirstAdded(const MediaResourceParcel& resource, uid_t uid) {
    // first time added
    if (resource.type == MediaResource::Type::kCpuBoost
     && resource.subType == MediaResource::SubType::kUnspecifiedSubType) {
        // Request it on every new instance of kCpuBoost, as the media.codec
        // could have died, if we only do it the first time subsequent instances
        // never gets the boost.
        if (mSystemCB->requestCpusetBoost(true) != OK) {
            ALOGW("couldn't request cpuset boost");
        }
        mCpuBoostCount++;
    } else if (resource.type == MediaResource::Type::kBattery
            && (resource.subType == MediaResource::SubType::kHwVideoCodec
                || resource.subType == MediaResource::SubType::kSwVideoCodec)) {
        mSystemCB->noteStartVideo(uid);
    }
}

void ResourceManagerService::onLastRemoved(const MediaResourceParcel& resource, uid_t uid) {
    if (resource.type == MediaResource::Type::kCpuBoost
            && resource.subType == MediaResource::SubType::kUnspecifiedSubType
            && mCpuBoostCount > 0) {
        if (--mCpuBoostCount == 0) {
            mSystemCB->requestCpusetBoost(false);
        }
    } else if (resource.type == MediaResource::Type::kBattery
            && (resource.subType == MediaResource::SubType::kHwVideoCodec
                || resource.subType == MediaResource::SubType::kSwVideoCodec)) {
        mSystemCB->noteStopVideo(uid);
    }
}

Status ResourceManagerService::addResource(const ClientInfoParcel& clientInfo,
        const std::shared_ptr<IResourceManagerClient>& client,
        const std::vector<MediaResourceParcel>& resources) {
    int32_t pid = clientInfo.pid;
    int32_t uid = clientInfo.uid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format("addResource(pid %d, uid %d clientId %lld, resources %s)",
            pid, uid, (long long) clientId, getString(resources).c_str());
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    if (!mProcessInfo->isPidUidTrusted(pid, uid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        uid_t callingUid = IPCThreadState::self()->getCallingUid();
        ALOGW("%s called with untrusted pid %d or uid %d, using calling pid %d, uid %d",
                __FUNCTION__, pid, uid, callingPid, callingUid);
        pid = callingPid;
        uid = callingUid;
    }
    ResourceInfos& infos = getResourceInfosForEdit(pid, mMap);
    ResourceInfo& info = getResourceInfoForEdit(clientInfo, client, infos);
    ResourceList resourceAdded;

    for (size_t i = 0; i < resources.size(); ++i) {
        const auto &res = resources[i];

        if (res.value < 0 && res.type != MediaResource::Type::kDrmSession) {
            ALOGW("Ignoring request to remove negative value of non-drm resource");
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
        info.deathNotifier = DeathNotifier::Create(
            client, ref<ResourceManagerService>(), clientInfo);
    }
    if (mObserverService != nullptr && !resourceAdded.empty()) {
        mObserverService->onResourceAdded(uid, pid, resourceAdded);
    }
    notifyResourceGranted(pid, resources);

    return Status::ok();
}

Status ResourceManagerService::removeResource(const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources) {
    int32_t pid = clientInfo.pid;
    int32_t uid = clientInfo.uid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format("removeResource(pid %d, uid %d clientId %lld, resources %s)",
            pid, uid, (long long) clientId, getString(resources).c_str());
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    if (!mProcessInfo->isPidTrusted(pid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using calling pid %d", __FUNCTION__,
                pid, callingPid);
        pid = callingPid;
    }
    PidResourceInfosMap::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("removeResource: didn't find pid %d for clientId %lld", pid, (long long) clientId);
        return Status::ok();
    }
    ResourceInfos& infos = found->second;

    ResourceInfos::iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("removeResource: didn't find clientId %lld", (long long) clientId);
        return Status::ok();
    }

    ResourceInfo& info = foundClient->second;
    ResourceList resourceRemoved;
    for (size_t i = 0; i < resources.size(); ++i) {
        const auto &res = resources[i];

        if (res.value < 0) {
            ALOGW("Ignoring request to remove negative value of resource");
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
    return Status::ok();
}

Status ResourceManagerService::removeClient(const ClientInfoParcel& clientInfo) {
    removeResource(clientInfo, true /*checkValid*/);
    return Status::ok();
}

Status ResourceManagerService::removeResource(const ClientInfoParcel& clientInfo, bool checkValid) {
    int32_t pid = clientInfo.pid;
    int32_t uid = clientInfo.uid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format("removeResource(pid %d, uid %d clientId %lld)",
            pid, uid, (long long) clientId);
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    if (checkValid && !mProcessInfo->isPidTrusted(pid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using calling pid %d", __FUNCTION__,
                pid, callingPid);
        pid = callingPid;
    }
    PidResourceInfosMap::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("removeResource: didn't find pid %d for clientId %lld", pid, (long long) clientId);
        return Status::ok();
    }
    ResourceInfos& infos = found->second;

    ResourceInfos::iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("removeResource: didn't find clientId %lld", (long long) clientId);
        return Status::ok();
    }

    const ResourceInfo& info = foundClient->second;
    for (const MediaResourceParcel& res : info.resources.getResources()) {
        onLastRemoved(res, info.uid);
    }

    // Since this client has been removed, update the metrics collector.
    mResourceManagerMetrics->notifyClientReleased(clientInfo);

    if (mObserverService != nullptr && !info.resources.empty()) {
        mObserverService->onResourceRemoved(info.uid, pid, info.resources);
    }

    infos.erase(foundClient);
    return Status::ok();
}

void ResourceManagerService::getClientForResource_l(
        const ResourceRequestInfo& resourceRequestInfo,
        std::vector<ClientInfo>& clientsInfo) {
    int callingPid = resourceRequestInfo.mCallingPid;
    const MediaResourceParcel* res = resourceRequestInfo.mResource;
    if (res == NULL) {
        return;
    }

    // Before looking into other processes, check if we have clients marked for
    // pending removal in the same process.
    ClientInfo clientInfo;
    if (getBiggestClientPendingRemoval_l(callingPid, res->type, res->subType, clientInfo)) {
        clientsInfo.emplace_back(clientInfo);
        return;
    }

    // Now find client(s) from a lowest priority process that has needed resources.
    if (getLowestPriorityBiggestClient_l(resourceRequestInfo, clientInfo)) {
        clientsInfo.push_back(clientInfo);
    }
}

bool ResourceManagerService::getTargetClients(
        const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources,
        std::vector<ClientInfo>& targetClients) {
    int32_t callingPid = clientInfo.pid;
    int64_t clientId = clientInfo.id;
    std::scoped_lock lock{mLock};
    if (!mProcessInfo->isPidTrusted(callingPid)) {
        pid_t actualCallingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using actual calling pid %d", __FUNCTION__,
                callingPid, actualCallingPid);
        callingPid = actualCallingPid;
    }
    const MediaResourceParcel *secureCodec = NULL;
    const MediaResourceParcel *nonSecureCodec = NULL;
    const MediaResourceParcel *graphicMemory = NULL;
    const MediaResourceParcel *drmSession = NULL;
    for (size_t i = 0; i < resources.size(); ++i) {
        switch (resources[i].type) {
            case MediaResource::Type::kSecureCodec:
                secureCodec = &resources[i];
                break;
            case MediaResource::Type::kNonSecureCodec:
                nonSecureCodec = &resources[i];
                break;
            case MediaResource::Type::kGraphicMemory:
                graphicMemory = &resources[i];
                break;
            case MediaResource::Type::kDrmSession:
                drmSession = &resources[i];
                break;
            default:
                break;
        }
    }

    // first pass to handle secure/non-secure codec conflict
    if (secureCodec != NULL) {
        MediaResourceParcel mediaResource{.type = MediaResource::Type::kSecureCodec,
                                          .subType = secureCodec->subType};
        ResourceRequestInfo resourceRequestInfo{callingPid, clientId, &mediaResource};
        if (!mSupportsMultipleSecureCodecs) {
            if (!getAllClients_l(resourceRequestInfo, targetClients)) {
                return false;
            }
        }
        if (!mSupportsSecureWithNonSecureCodec) {
            mediaResource.type = MediaResource::Type::kNonSecureCodec;
            if (!getAllClients_l(resourceRequestInfo, targetClients)) {
                return false;
            }
        }
    }
    if (nonSecureCodec != NULL) {
        if (!mSupportsSecureWithNonSecureCodec) {
            MediaResourceParcel mediaResource{.type = MediaResource::Type::kSecureCodec,
                                              .subType = nonSecureCodec->subType};
            ResourceRequestInfo resourceRequestInfo{callingPid, clientId, &mediaResource};
            if (!getAllClients_l(resourceRequestInfo, targetClients)) {
                return false;
            }
        }
    }

    if (drmSession != NULL) {
        ResourceRequestInfo resourceRequestInfo{callingPid, clientId, drmSession};
        getClientForResource_l(resourceRequestInfo, targetClients);
        if (targetClients.size() == 0) {
            return false;
        }
    }

    if (targetClients.size() == 0 && graphicMemory != nullptr) {
        // if no secure/non-secure codec conflict, run second pass to handle other resources.
        ResourceRequestInfo resourceRequestInfo{callingPid, clientId, graphicMemory};
        getClientForResource_l(resourceRequestInfo, targetClients);
    }

    if (targetClients.size() == 0) {
        // if we are here, run the third pass to free one codec with the same type.
        if (secureCodec != nullptr) {
            ResourceRequestInfo resourceRequestInfo{callingPid, clientId, secureCodec};
            getClientForResource_l(resourceRequestInfo, targetClients);
        }
        if (nonSecureCodec != nullptr) {
            ResourceRequestInfo resourceRequestInfo{callingPid, clientId, nonSecureCodec};
            getClientForResource_l(resourceRequestInfo, targetClients);
        }
    }

    if (targetClients.size() == 0) {
        // if we are here, run the fourth pass to free one codec with the different type.
        if (secureCodec != nullptr) {
            MediaResource temp(MediaResource::Type::kNonSecureCodec, secureCodec->subType, 1);
            ResourceRequestInfo resourceRequestInfo{callingPid, clientId, &temp};
            getClientForResource_l(resourceRequestInfo, targetClients);
        }
        if (nonSecureCodec != nullptr) {
            MediaResource temp(MediaResource::Type::kSecureCodec, nonSecureCodec->subType, 1);
            ResourceRequestInfo resourceRequestInfo{callingPid, clientId, &temp};
            getClientForResource_l(resourceRequestInfo, targetClients);
        }
    }

    return !targetClients.empty();
}

Status ResourceManagerService::reclaimResource(const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources, bool* _aidl_return) {
    std::string clientName = clientInfo.name;
    String8 log = String8::format("reclaimResource(callingPid %d, uid %d resources %s)",
            clientInfo.pid, clientInfo.uid, getString(resources).c_str());
    mServiceLog->add(log);
    *_aidl_return = false;

    // Check if there are any resources to be reclaimed before processing.
    if (resources.empty()) {
        // Invalid reclaim request. So no need to log.
        return Status::ok();
    }

    std::vector<ClientInfo> targetClients;
    if (getTargetClients(clientInfo, resources, targetClients)) {
        // Reclaim all the target clients.
        *_aidl_return = reclaimUnconditionallyFrom(targetClients);
    } else {
        // No clients to reclaim from.
        ALOGI("%s: There aren't any clients to reclaim from", __func__);
        // We need to log this failed reclaim as "no clients to reclaim from".
        targetClients.clear();
    }

    // Log Reclaim Pushed Atom to statsd
    pushReclaimAtom(clientInfo, targetClients, *_aidl_return);

    return Status::ok();
}

void ResourceManagerService::pushReclaimAtom(const ClientInfoParcel& clientInfo,
                                             const std::vector<ClientInfo>& targetClients,
                                             bool reclaimed) {
    int32_t callingPid = clientInfo.pid;
    int requesterPriority = -1;
    getPriority_l(callingPid, &requesterPriority);
    std::vector<int> priorities;
    priorities.push_back(requesterPriority);

    for (const ClientInfo& targetClient : targetClients) {
        int targetPriority = -1;
        getPriority_l(targetClient.mPid, &targetPriority);
        priorities.push_back(targetPriority);
    }
    mResourceManagerMetrics->pushReclaimAtom(clientInfo, priorities, targetClients, reclaimed);
}

std::shared_ptr<IResourceManagerClient> ResourceManagerService::getClient_l(
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

bool ResourceManagerService::removeClient_l(int pid, const int64_t& clientId) {
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

bool ResourceManagerService::reclaimUnconditionallyFrom(
        const std::vector<ClientInfo>& targetClients) {
    if (targetClients.size() == 0) {
        return false;
    }

    int64_t failedClientId = -1;
    int32_t failedClientPid = -1;
    for (const ClientInfo& targetClient : targetClients) {
        std::shared_ptr<IResourceManagerClient> client = nullptr;
        {
            std::scoped_lock lock{mLock};
            client = getClient_l(targetClient.mPid, targetClient.mClientId);
        }
        if (client == nullptr) {
            // skip already released clients.
            continue;
        }
        String8 log = String8::format("reclaimResource from client %p", client.get());
        mServiceLog->add(log);
        bool success;
        Status status = client->reclaimResource(&success);
        if (!status.isOk() || !success) {
            failedClientId = targetClient.mClientId;
            failedClientPid = targetClient.mPid;
            break;
        }
    }

    if (failedClientId == -1) {
        return true;
    }

    {
        std::scoped_lock lock{mLock};
        bool found = removeClient_l(failedClientPid, failedClientId);
        if (found) {
            ALOGW("Failed to reclaim resources from client with pid %d", failedClientPid);
        } else {
            ALOGW("Failed to reclaim resources from unlocateable client");
        }
    }

    return false;
}

bool ResourceManagerService::overridePid_l(int32_t originalPid, int32_t newPid) {
    mOverridePidMap.erase(originalPid);
    if (newPid != -1) {
        mOverridePidMap.emplace(originalPid, newPid);
        return true;
    }

    return false;
}

Status ResourceManagerService::overridePid(int originalPid, int newPid) {
    String8 log = String8::format("overridePid(originalPid %d, newPid %d)",
            originalPid, newPid);
    mServiceLog->add(log);

    // allow if this is called from the same process or the process has
    // permission.
    if ((AIBinder_getCallingPid() != getpid()) &&
        (checkCallingPermission(String16(
             "android.permission.MEDIA_RESOURCE_OVERRIDE_PID")) == false)) {
      ALOGE(
          "Permission Denial: can't access overridePid method from pid=%d, "
          "self pid=%d\n",
          AIBinder_getCallingPid(), getpid());
      return Status::fromServiceSpecificError(PERMISSION_DENIED);
    }

    {
        std::scoped_lock lock{mLock};
        if (overridePid_l(originalPid, newPid)) {
            mResourceManagerMetrics->addPid(newPid);
        }
    }

    return Status::ok();
}

bool ResourceManagerService::overrideProcessInfo_l(
        const std::shared_ptr<IResourceManagerClient>& client,
        int pid,
        int procState,
        int oomScore) {
    removeProcessInfoOverride_l(pid);

    if (!mProcessInfo->overrideProcessInfo(pid, procState, oomScore)) {
        // Override value is rejected by ProcessInfo.
        return false;
    }

    ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(pid),
                                .uid = 0,
                                .id = 0,
                                .name = "<unknown client>"};
    auto deathNotifier = DeathNotifier::Create(
        client, ref<ResourceManagerService>(), clientInfo, true);

    mProcessInfoOverrideMap.emplace(pid, ProcessInfoOverride{deathNotifier, client});
    return true;
}

Status ResourceManagerService::overrideProcessInfo(
        const std::shared_ptr<IResourceManagerClient>& client, int pid, int procState,
        int oomScore) {
    String8 log = String8::format("overrideProcessInfo(pid %d, procState %d, oomScore %d)",
            pid, procState, oomScore);
    mServiceLog->add(log);

    // Only allow the override if the caller already can access process state and oom scores.
    int callingPid = AIBinder_getCallingPid();
    if (callingPid != getpid() && (callingPid != pid || !checkCallingPermission(String16(
            "android.permission.GET_PROCESS_STATE_AND_OOM_SCORE")))) {
        ALOGE("Permission Denial: overrideProcessInfo method from pid=%d", callingPid);
        return Status::fromServiceSpecificError(PERMISSION_DENIED);
    }

    if (client == nullptr) {
        return Status::fromServiceSpecificError(BAD_VALUE);
    }

    std::scoped_lock lock{mLock};
    if (!overrideProcessInfo_l(client, pid, procState, oomScore)) {
        // Override value is rejected by ProcessInfo.
        return Status::fromServiceSpecificError(BAD_VALUE);
    }
    return Status::ok();

}

void ResourceManagerService::removeProcessInfoOverride(int pid) {
    std::scoped_lock lock{mLock};

    removeProcessInfoOverride_l(pid);
}

void ResourceManagerService::removeProcessInfoOverride_l(int pid) {
    auto it = mProcessInfoOverrideMap.find(pid);
    if (it == mProcessInfoOverrideMap.end()) {
        return;
    }

    mProcessInfo->removeProcessInfoOverride(pid);
    mProcessInfoOverrideMap.erase(pid);
}

Status ResourceManagerService::markClientForPendingRemoval(const ClientInfoParcel& clientInfo) {
    int32_t pid = clientInfo.pid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format(
            "markClientForPendingRemoval(pid %d, clientId %lld)",
            pid, (long long) clientId);
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    if (!mProcessInfo->isPidTrusted(pid)) {
        pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using calling pid %d", __FUNCTION__,
                pid, callingPid);
        pid = callingPid;
    }
    PidResourceInfosMap::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGV("markClientForPendingRemoval: didn't find pid %d for clientId %lld",
              pid, (long long)clientId);
        return Status::ok();
    }
    ResourceInfos& infos = found->second;

    ResourceInfos::iterator foundClient = infos.find(clientId);
    if (foundClient == infos.end()) {
        ALOGV("markClientForPendingRemoval: didn't find clientId %lld", (long long) clientId);
        return Status::ok();
    }

    ResourceInfo& info = foundClient->second;
    info.pendingRemoval = true;
    return Status::ok();
}

Status ResourceManagerService::reclaimResourcesFromClientsPendingRemoval(int32_t pid) {
    String8 log = String8::format("reclaimResourcesFromClientsPendingRemoval(pid %d)", pid);
    mServiceLog->add(log);

    std::vector<ClientInfo> targetClients;
    {
        std::scoped_lock lock{mLock};
        if (!mProcessInfo->isPidTrusted(pid)) {
            pid_t callingPid = IPCThreadState::self()->getCallingPid();
            ALOGW("%s called with untrusted pid %d, using calling pid %d", __FUNCTION__,
                    pid, callingPid);
            pid = callingPid;
        }

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
                        if (getBiggestClientPendingRemoval_l(pid, type, subType, clientInfo)) {
                            targetClients.emplace_back(clientInfo);
                            continue;
                        }
                    }
                    break;
                // Non-codec resources are shared by audio, video and image codecs (no subtype).
                default:
                    ClientInfo clientInfo;
                    if (getBiggestClientPendingRemoval_l(pid, type,
                            MediaResource::SubType::kUnspecifiedSubType, clientInfo)) {
                        targetClients.emplace_back(clientInfo);
                    }
                    break;
            }
        }
    }

    if (!targetClients.empty()) {
        reclaimUnconditionallyFrom(targetClients);
    }
    return Status::ok();
}

bool ResourceManagerService::getPriority_l(int pid, int* priority) const {
    int newPid = pid;

    std::map<int, int>::const_iterator found = mOverridePidMap.find(pid);
    if (found != mOverridePidMap.end()) {
        newPid = found->second;
        ALOGD("getPriority_l: use override pid %d instead original pid %d",
                newPid, pid);
    }

    return mProcessInfo->getPriority(newPid, priority);
}

bool ResourceManagerService::getAllClients_l(
        const ResourceRequestInfo& resourceRequestInfo,
        std::vector<ClientInfo>& clientsInfo) {
    MediaResource::Type type = resourceRequestInfo.mResource->type;
    MediaResource::SubType subType = resourceRequestInfo.mResource->subType;

    for (auto& [pid, infos] : mMap) {
        for (const auto& [id, info] : infos) {
            if (pid == resourceRequestInfo.mCallingPid && id == resourceRequestInfo.mClientId) {
                ALOGI("%s: Skip the client[%jd] for which the resource request is made",
                      __func__, id);
                continue;
            }
            if (hasResourceType(type, subType, info.resources)) {
                if (!isCallingPriorityHigher_l(resourceRequestInfo.mCallingPid, pid)) {
                    // some higher/equal priority process owns the resource,
                    // this request can't be fulfilled.
                    ALOGE("%s: can't reclaim resource %s from pid %d",
                          __func__, asString(type), pid);
                    clientsInfo.clear();
                    return false;
                }
                clientsInfo.emplace_back(pid, info.uid, info.clientId);
            }
        }
    }
    if (clientsInfo.size() == 0) {
        ALOGV("%s: didn't find any resource %s", __func__, asString(type));
    }
    return true;
}

// Process priority (oom score) based reclaim:
//   - Find a process with lowest priority (than that of calling process).
//   - Find the bigegst client (with required resources) from that process.
bool ResourceManagerService::getLowestPriorityBiggestClient_l(
        const ResourceRequestInfo& resourceRequestInfo,
        ClientInfo& clientInfo) {
    int callingPid = resourceRequestInfo.mCallingPid;
    MediaResource::Type type = resourceRequestInfo.mResource->type;
    MediaResource::SubType subType = resourceRequestInfo.mResource->subType;
    int lowestPriorityPid;
    int lowestPriority;
    int callingPriority;

    if (!getPriority_l(callingPid, &callingPriority)) {
        ALOGE("%s: can't get process priority for pid %d", __func__, callingPid);
        return false;
    }
    if (!getLowestPriorityPid_l(type, subType, &lowestPriorityPid, &lowestPriority)) {
        return false;
    }
    if (lowestPriority <= callingPriority) {
        ALOGE("%s: lowest priority %d vs caller priority %d",
              __func__, lowestPriority, callingPriority);
        return false;
    }

    if (!getBiggestClient_l(lowestPriorityPid, type, subType, clientInfo)) {
        return false;
    }

    ALOGI("%s: CallingProcess(%d:%d) will reclaim from the lowestPriorityProcess(%d:%d)",
          __func__, callingPid, callingPriority, lowestPriorityPid, lowestPriority);
    return true;
}

bool ResourceManagerService::getLowestPriorityPid_l(MediaResource::Type type,
        MediaResource::SubType subType, int *lowestPriorityPid, int *lowestPriority) {
    int pid = -1;
    int priority = -1;
    for (auto& [tempPid, infos] : mMap) {
        if (infos.size() == 0) {
            // no client on this process.
            continue;
        }
        if (!hasResourceType(type, subType, infos)) {
            // doesn't have the requested resource type
            continue;
        }
        int tempPriority = -1;
        if (!getPriority_l(tempPid, &tempPriority)) {
            ALOGV("getLowestPriorityPid_l: can't get priority of pid %d, skipped", tempPid);
            // TODO: remove this pid from mMap?
            continue;
        }
        if (pid == -1 || tempPriority > priority) {
            // initial the value
            pid = tempPid;
            priority = tempPriority;
        }
    }
    if (pid != -1) {
        *lowestPriorityPid = pid;
        *lowestPriority = priority;
    }
    return (pid != -1);
}

bool ResourceManagerService::isCallingPriorityHigher_l(int callingPid, int pid) {
    int callingPidPriority;
    if (!getPriority_l(callingPid, &callingPidPriority)) {
        return false;
    }

    int priority;
    if (!getPriority_l(pid, &priority)) {
        return false;
    }

    return (callingPidPriority < priority);
}

bool ResourceManagerService::getBiggestClientPendingRemoval_l(int pid, MediaResource::Type type,
        MediaResource::SubType subType, ClientInfo& clientInfo) {
    return getBiggestClient_l(pid, type, subType, clientInfo, true /* pendingRemovalOnly */);
}

bool ResourceManagerService::getBiggestClient_l(int pid, MediaResource::Type type,
        MediaResource::SubType subType, ClientInfo& clientInfo, bool pendingRemovalOnly) {
    PidResourceInfosMap::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGE_IF(!pendingRemovalOnly,
                 "getBiggestClient_l: can't find resource info for pid %d", pid);
        return false;
    }

    uid_t   uid = -1;
    int64_t clientId = -1;
    uint64_t largestValue = 0;
    const ResourceInfos& infos = found->second;
    for (const auto& [id, info] : infos) {
        const ResourceList& resources = info.resources;
        if (pendingRemovalOnly && !info.pendingRemoval) {
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
        ALOGE_IF(!pendingRemovalOnly,
                 "getBiggestClient_l: can't find resource type %s and subtype %s for pid %d",
                 asString(type), asString(subType), pid);
        return false;
    }

    clientInfo.mPid = pid;
    clientInfo.mUid = uid;
    clientInfo.mClientId = clientId;
    return true;
}

Status ResourceManagerService::notifyClientCreated(const ClientInfoParcel& clientInfo) {
    mResourceManagerMetrics->notifyClientCreated(clientInfo);
    return Status::ok();
}

Status ResourceManagerService::notifyClientStarted(const ClientConfigParcel& clientConfig) {
    mResourceManagerMetrics->notifyClientStarted(clientConfig);
    return Status::ok();
}

Status ResourceManagerService::notifyClientStopped(const ClientConfigParcel& clientConfig) {
    mResourceManagerMetrics->notifyClientStopped(clientConfig);
    return Status::ok();
}

Status ResourceManagerService::notifyClientConfigChanged(const ClientConfigParcel& clientConfig) {
    mResourceManagerMetrics->notifyClientConfigChanged(clientConfig);
    return Status::ok();
}

long ResourceManagerService::getPeakConcurrentPixelCount(int pid) const {
    return mResourceManagerMetrics->getPeakConcurrentPixelCount(pid);
}

long ResourceManagerService::getCurrentConcurrentPixelCount(int pid) const {
    return mResourceManagerMetrics->getCurrentConcurrentPixelCount(pid);
}

void ResourceManagerService::notifyClientReleased(const ClientInfoParcel& clientInfo) {
    mResourceManagerMetrics->notifyClientReleased(clientInfo);
}

} // namespace android
