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
#include <binder/IMediaResourceMonitor.h>
#include <binder/IServiceManager.h>
#include <cutils/sched_policy.h>
#include <dirent.h>
#include <media/MediaResourcePolicy.h>
#include <media/stagefright/ProcessInfo.h>
#include <mediautils/BatteryNotifier.h>
#include <mediautils/SchedulingPolicyService.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "ResourceManagerService.h"
#include "ServiceLog.h"

namespace android {

DeathNotifier::DeathNotifier(const std::shared_ptr<ResourceManagerService> &service,
        int pid, int64_t clientId)
    : mService(service), mPid(pid), mClientId(clientId) {}

//static
void DeathNotifier::BinderDiedCallback(void* cookie) {
    auto thiz = static_cast<DeathNotifier*>(cookie);
    thiz->binderDied();
}

void DeathNotifier::binderDied() {
    // Don't check for pid validity since we know it's already dead.
    std::shared_ptr<ResourceManagerService> service = mService.lock();
    if (service == nullptr) {
        ALOGW("ResourceManagerService is dead as well.");
        return;
    }

    service->overridePid(mPid, -1);
    // thiz is freed in the call below, so it must be last call referring thiz
    service->removeResource(mPid, mClientId, false);

}

template <typename T>
static String8 getString(const std::vector<T> &items) {
    String8 itemsStr;
    for (size_t i = 0; i < items.size(); ++i) {
        itemsStr.appendFormat("%s ", toString(items[i]).string());
    }
    return itemsStr;
}

static bool hasResourceType(MediaResource::Type type, const ResourceList& resources) {
    for (auto it = resources.begin(); it != resources.end(); it++) {
        if (it->second.type == type) {
            return true;
        }
    }
    return false;
}

static bool hasResourceType(MediaResource::Type type, const ResourceInfos& infos) {
    for (size_t i = 0; i < infos.size(); ++i) {
        if (hasResourceType(type, infos[i].resources)) {
            return true;
        }
    }
    return false;
}

static ResourceInfos& getResourceInfosForEdit(
        int pid,
        PidResourceInfosMap& map) {
    ssize_t index = map.indexOfKey(pid);
    if (index < 0) {
        // new pid
        ResourceInfos infosForPid;
        map.add(pid, infosForPid);
    }

    return map.editValueFor(pid);
}

static ResourceInfo& getResourceInfoForEdit(
        uid_t uid,
        int64_t clientId,
        const std::shared_ptr<IResourceManagerClient>& client,
        ResourceInfos& infos) {
    ssize_t index = infos.indexOfKey(clientId);

    if (index < 0) {
        ResourceInfo info;
        info.uid = uid;
        info.clientId = clientId;
        info.client = client;
        info.pendingRemoval = false;

        index = infos.add(clientId, info);
    }

    return infos.editValueAt(index);
}

static void notifyResourceGranted(int pid, const std::vector<MediaResourceParcel> &resources) {
    static const char* const kServiceName = "media_resource_monitor";
    sp<IBinder> binder = defaultServiceManager()->checkService(String16(kServiceName));
    if (binder != NULL) {
        sp<IMediaResourceMonitor> service = interface_cast<IMediaResourceMonitor>(binder);
        for (size_t i = 0; i < resources.size(); ++i) {
            if (resources[i].subType == MediaResource::SubType::kAudioCodec) {
                service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_AUDIO_CODEC);
            } else if (resources[i].subType == MediaResource::SubType::kVideoCodec) {
                service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_VIDEO_CODEC);
            }
        }
    }
}

binder_status_t ResourceManagerService::dump(
        int fd, const char** /*args*/, uint32_t /*numArgs*/) {
    String8 result;

    if (checkCallingPermission(String16("android.permission.DUMP")) == false) {
        result.format("Permission Denial: "
                "can't dump ResourceManagerService from pid=%d, uid=%d\n",
                AIBinder_getCallingPid(),
                AIBinder_getCallingUid());
        write(fd, result.string(), result.size());
        return PERMISSION_DENIED;
    }

    PidResourceInfosMap mapCopy;
    bool supportsMultipleSecureCodecs;
    bool supportsSecureWithNonSecureCodec;
    std::map<int, int> overridePidMapCopy;
    String8 serviceLog;
    {
        Mutex::Autolock lock(mLock);
        mapCopy = mMap;  // Shadow copy, real copy will happen on write.
        supportsMultipleSecureCodecs = mSupportsMultipleSecureCodecs;
        supportsSecureWithNonSecureCodec = mSupportsSecureWithNonSecureCodec;
        serviceLog = mServiceLog->toString("    " /* linePrefix */);
        overridePidMapCopy = mOverridePidMap;
    }

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

    result.append("  Processes:\n");
    for (size_t i = 0; i < mapCopy.size(); ++i) {
        snprintf(buffer, SIZE, "    Pid: %d\n", mapCopy.keyAt(i));
        result.append(buffer);

        const ResourceInfos &infos = mapCopy.valueAt(i);
        for (size_t j = 0; j < infos.size(); ++j) {
            result.append("      Client:\n");
            snprintf(buffer, SIZE, "        Id: %lld\n", (long long)infos[j].clientId);
            result.append(buffer);

            std::string clientName;
            Status status = infos[j].client->getName(&clientName);
            if (!status.isOk()) {
                clientName = "<unknown client>";
            }
            snprintf(buffer, SIZE, "        Name: %s\n", clientName.c_str());
            result.append(buffer);

            const ResourceList &resources = infos[j].resources;
            result.append("        Resources:\n");
            for (auto it = resources.begin(); it != resources.end(); it++) {
                snprintf(buffer, SIZE, "          %s\n", toString(it->second).string());
                result.append(buffer);
            }
        }
    }
    result.append("  Process Pid override:\n");
    for (auto it = overridePidMapCopy.begin(); it != overridePidMapCopy.end(); ++it) {
        snprintf(buffer, SIZE, "    Original Pid: %d,  Override Pid: %d\n",
            it->first, it->second);
        result.append(buffer);
    }
    result.append("  Events logs (most recent at top):\n");
    result.append(serviceLog);

    write(fd, result.string(), result.size());
    return OK;
}

struct SystemCallbackImpl :
        public ResourceManagerService::SystemCallbackInterface {
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

ResourceManagerService::ResourceManagerService(
        const sp<ProcessInfoInterface> &processInfo,
        const sp<SystemCallbackInterface> &systemResource)
    : mProcessInfo(processInfo),
      mSystemCB(systemResource),
      mServiceLog(new ServiceLog()),
      mSupportsMultipleSecureCodecs(true),
      mSupportsSecureWithNonSecureCodec(true),
      mCpuBoostCount(0),
      mDeathRecipient(AIBinder_DeathRecipient_new(DeathNotifier::BinderDiedCallback)) {
    mSystemCB->noteResetVideo();
}

//static
void ResourceManagerService::instantiate() {
    std::shared_ptr<ResourceManagerService> service =
            ::ndk::SharedRefBase::make<ResourceManagerService>();
    binder_status_t status =
            AServiceManager_addService(service->asBinder().get(), getServiceName());
    if (status != STATUS_OK) {
        return;
    }
    // TODO: mediaserver main() is already starting the thread pool,
    // move this to mediaserver main() when other services in mediaserver
    // are converted to ndk-platform aidl.
    //ABinderProcess_startThreadPool();
}

ResourceManagerService::~ResourceManagerService() {}

Status ResourceManagerService::config(const std::vector<MediaResourcePolicyParcel>& policies) {
    String8 log = String8::format("config(%s)", getString(policies).string());
    mServiceLog->add(log);

    Mutex::Autolock lock(mLock);
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

void ResourceManagerService::onFirstAdded(
        const MediaResourceParcel& resource, const ResourceInfo& clientInfo) {
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
            && resource.subType == MediaResource::SubType::kVideoCodec) {
        mSystemCB->noteStartVideo(clientInfo.uid);
    }
}

void ResourceManagerService::onLastRemoved(
        const MediaResourceParcel& resource, const ResourceInfo& clientInfo) {
    if (resource.type == MediaResource::Type::kCpuBoost
            && resource.subType == MediaResource::SubType::kUnspecifiedSubType
            && mCpuBoostCount > 0) {
        if (--mCpuBoostCount == 0) {
            mSystemCB->requestCpusetBoost(false);
        }
    } else if (resource.type == MediaResource::Type::kBattery
            && resource.subType == MediaResource::SubType::kVideoCodec) {
        mSystemCB->noteStopVideo(clientInfo.uid);
    }
}

void ResourceManagerService::mergeResources(
        MediaResourceParcel& r1, const MediaResourceParcel& r2) {
    // The resource entry on record is maintained to be in [0,INT64_MAX].
    // Clamp if merging in the new resource value causes it to go out of bound.
    // Note that the new resource value could be negative, eg.DrmSession, the
    // value goes lower when the session is used more often. During reclaim
    // the session with the highest value (lowest usage) would be closed.
    if (r2.value < INT64_MAX - r1.value) {
        r1.value += r2.value;
        if (r1.value < 0) {
            r1.value = 0;
        }
    } else {
        r1.value = INT64_MAX;
    }
}

Status ResourceManagerService::addResource(
        int32_t pid,
        int32_t uid,
        int64_t clientId,
        const std::shared_ptr<IResourceManagerClient>& client,
        const std::vector<MediaResourceParcel>& resources) {
    String8 log = String8::format("addResource(pid %d, clientId %lld, resources %s)",
            pid, (long long) clientId, getString(resources).string());
    mServiceLog->add(log);

    Mutex::Autolock lock(mLock);
    if (!mProcessInfo->isValidPid(pid)) {
        ALOGE("Rejected addResource call with invalid pid.");
        return Status::fromServiceSpecificError(BAD_VALUE);
    }
    ResourceInfos& infos = getResourceInfosForEdit(pid, mMap);
    ResourceInfo& info = getResourceInfoForEdit(uid, clientId, client, infos);

    for (size_t i = 0; i < resources.size(); ++i) {
        const auto &res = resources[i];
        const auto resType = std::tuple(res.type, res.subType, res.id);

        if (res.value < 0 && res.type != MediaResource::Type::kDrmSession) {
            ALOGW("Ignoring request to remove negative value of non-drm resource");
            continue;
        }
        if (info.resources.find(resType) == info.resources.end()) {
            if (res.value <= 0) {
                // We can't init a new entry with negative value, although it's allowed
                // to merge in negative values after the initial add.
                ALOGW("Ignoring request to add new resource entry with value <= 0");
                continue;
            }
            onFirstAdded(res, info);
            info.resources[resType] = res;
        } else {
            mergeResources(info.resources[resType], res);
        }
    }
    if (info.deathNotifier == nullptr && client != nullptr) {
        info.deathNotifier = new DeathNotifier(ref<ResourceManagerService>(), pid, clientId);
        AIBinder_linkToDeath(client->asBinder().get(),
                mDeathRecipient.get(), info.deathNotifier.get());
    }
    notifyResourceGranted(pid, resources);
    return Status::ok();
}

Status ResourceManagerService::removeResource(
        int32_t pid, int64_t clientId,
        const std::vector<MediaResourceParcel>& resources) {
    String8 log = String8::format("removeResource(pid %d, clientId %lld, resources %s)",
            pid, (long long) clientId, getString(resources).string());
    mServiceLog->add(log);

    Mutex::Autolock lock(mLock);
    if (!mProcessInfo->isValidPid(pid)) {
        ALOGE("Rejected removeResource call with invalid pid.");
        return Status::fromServiceSpecificError(BAD_VALUE);
    }
    ssize_t index = mMap.indexOfKey(pid);
    if (index < 0) {
        ALOGV("removeResource: didn't find pid %d for clientId %lld", pid, (long long) clientId);
        return Status::ok();
    }
    ResourceInfos &infos = mMap.editValueAt(index);

    index = infos.indexOfKey(clientId);
    if (index < 0) {
        ALOGV("removeResource: didn't find clientId %lld", (long long) clientId);
        return Status::ok();
    }

    ResourceInfo &info = infos.editValueAt(index);

    for (size_t i = 0; i < resources.size(); ++i) {
        const auto &res = resources[i];
        const auto resType = std::tuple(res.type, res.subType, res.id);

        if (res.value < 0) {
            ALOGW("Ignoring request to remove negative value of resource");
            continue;
        }
        // ignore if we don't have it
        if (info.resources.find(resType) != info.resources.end()) {
            MediaResourceParcel &resource = info.resources[resType];
            if (resource.value > res.value) {
                resource.value -= res.value;
            } else {
                onLastRemoved(res, info);
                info.resources.erase(resType);
            }
        }
    }
    return Status::ok();
}

Status ResourceManagerService::removeClient(int32_t pid, int64_t clientId) {
    removeResource(pid, clientId, true);
    return Status::ok();
}

Status ResourceManagerService::removeResource(int pid, int64_t clientId, bool checkValid) {
    String8 log = String8::format(
            "removeResource(pid %d, clientId %lld)",
            pid, (long long) clientId);
    mServiceLog->add(log);

    Mutex::Autolock lock(mLock);
    if (checkValid && !mProcessInfo->isValidPid(pid)) {
        ALOGE("Rejected removeResource call with invalid pid.");
        return Status::fromServiceSpecificError(BAD_VALUE);
    }
    ssize_t index = mMap.indexOfKey(pid);
    if (index < 0) {
        ALOGV("removeResource: didn't find pid %d for clientId %lld", pid, (long long) clientId);
        return Status::ok();
    }
    ResourceInfos &infos = mMap.editValueAt(index);

    index = infos.indexOfKey(clientId);
    if (index < 0) {
        ALOGV("removeResource: didn't find clientId %lld", (long long) clientId);
        return Status::ok();
    }

    const ResourceInfo &info = infos[index];
    for (auto it = info.resources.begin(); it != info.resources.end(); it++) {
        onLastRemoved(it->second, info);
    }

    AIBinder_unlinkToDeath(info.client->asBinder().get(),
            mDeathRecipient.get(), info.deathNotifier.get());

    infos.removeItemsAt(index);
    return Status::ok();
}

void ResourceManagerService::getClientForResource_l(
        int callingPid, const MediaResourceParcel *res,
        Vector<std::shared_ptr<IResourceManagerClient>> *clients) {
    if (res == NULL) {
        return;
    }
    std::shared_ptr<IResourceManagerClient> client;
    if (getLowestPriorityBiggestClient_l(callingPid, res->type, &client)) {
        clients->push_back(client);
    }
}

Status ResourceManagerService::reclaimResource(
        int32_t callingPid,
        const std::vector<MediaResourceParcel>& resources,
        bool* _aidl_return) {
    String8 log = String8::format("reclaimResource(callingPid %d, resources %s)",
            callingPid, getString(resources).string());
    mServiceLog->add(log);
    *_aidl_return = false;

    Vector<std::shared_ptr<IResourceManagerClient>> clients;
    {
        Mutex::Autolock lock(mLock);
        if (!mProcessInfo->isValidPid(callingPid)) {
            ALOGE("Rejected reclaimResource call with invalid callingPid.");
            return Status::fromServiceSpecificError(BAD_VALUE);
        }
        const MediaResourceParcel *secureCodec = NULL;
        const MediaResourceParcel *nonSecureCodec = NULL;
        const MediaResourceParcel *graphicMemory = NULL;
        const MediaResourceParcel *drmSession = NULL;
        for (size_t i = 0; i < resources.size(); ++i) {
            MediaResource::Type type = resources[i].type;
            if (resources[i].type == MediaResource::Type::kSecureCodec) {
                secureCodec = &resources[i];
            } else if (type == MediaResource::Type::kNonSecureCodec) {
                nonSecureCodec = &resources[i];
            } else if (type == MediaResource::Type::kGraphicMemory) {
                graphicMemory = &resources[i];
            } else if (type == MediaResource::Type::kDrmSession) {
                drmSession = &resources[i];
            }
        }

        // first pass to handle secure/non-secure codec conflict
        if (secureCodec != NULL) {
            if (!mSupportsMultipleSecureCodecs) {
                if (!getAllClients_l(callingPid, MediaResource::Type::kSecureCodec, &clients)) {
                    return Status::ok();
                }
            }
            if (!mSupportsSecureWithNonSecureCodec) {
                if (!getAllClients_l(callingPid, MediaResource::Type::kNonSecureCodec, &clients)) {
                    return Status::ok();
                }
            }
        }
        if (nonSecureCodec != NULL) {
            if (!mSupportsSecureWithNonSecureCodec) {
                if (!getAllClients_l(callingPid, MediaResource::Type::kSecureCodec, &clients)) {
                    return Status::ok();
                }
            }
        }
        if (drmSession != NULL) {
            getClientForResource_l(callingPid, drmSession, &clients);
            if (clients.size() == 0) {
                return Status::ok();
            }
        }

        if (clients.size() == 0) {
            // if no secure/non-secure codec conflict, run second pass to handle other resources.
            getClientForResource_l(callingPid, graphicMemory, &clients);
        }

        if (clients.size() == 0) {
            // if we are here, run the third pass to free one codec with the same type.
            getClientForResource_l(callingPid, secureCodec, &clients);
            getClientForResource_l(callingPid, nonSecureCodec, &clients);
        }

        if (clients.size() == 0) {
            // if we are here, run the fourth pass to free one codec with the different type.
            if (secureCodec != NULL) {
                MediaResource temp(MediaResource::Type::kNonSecureCodec, 1);
                getClientForResource_l(callingPid, &temp, &clients);
            }
            if (nonSecureCodec != NULL) {
                MediaResource temp(MediaResource::Type::kSecureCodec, 1);
                getClientForResource_l(callingPid, &temp, &clients);
            }
        }
    }

    *_aidl_return = reclaimInternal(clients);
    return Status::ok();
}

bool ResourceManagerService::reclaimInternal(
        const Vector<std::shared_ptr<IResourceManagerClient>> &clients) {
    if (clients.size() == 0) {
        return false;
    }

    std::shared_ptr<IResourceManagerClient> failedClient;
    for (size_t i = 0; i < clients.size(); ++i) {
        String8 log = String8::format("reclaimResource from client %p", clients[i].get());
        mServiceLog->add(log);
        bool success;
        Status status = clients[i]->reclaimResource(&success);
        if (!status.isOk() || !success) {
            failedClient = clients[i];
            break;
        }
    }

    if (failedClient == NULL) {
        return true;
    }

    {
        Mutex::Autolock lock(mLock);
        bool found = false;
        for (size_t i = 0; i < mMap.size(); ++i) {
            ResourceInfos &infos = mMap.editValueAt(i);
            for (size_t j = 0; j < infos.size();) {
                if (infos[j].client == failedClient) {
                    j = infos.removeItemsAt(j);
                    found = true;
                } else {
                    ++j;
                }
            }
            if (found) {
                break;
            }
        }
        if (!found) {
            ALOGV("didn't find failed client");
        }
    }

    return false;
}

Status ResourceManagerService::overridePid(
        int originalPid,
        int newPid) {
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
        Mutex::Autolock lock(mLock);
        mOverridePidMap.erase(originalPid);
        if (newPid != -1) {
            mOverridePidMap.emplace(originalPid, newPid);
        }
    }

    return Status::ok();
}

Status ResourceManagerService::markClientForPendingRemoval(int32_t pid, int64_t clientId) {
    String8 log = String8::format(
            "markClientForPendingRemoval(pid %d, clientId %lld)",
            pid, (long long) clientId);
    mServiceLog->add(log);

    Mutex::Autolock lock(mLock);
    if (!mProcessInfo->isValidPid(pid)) {
        ALOGE("Rejected markClientForPendingRemoval call with invalid pid.");
        return Status::fromServiceSpecificError(BAD_VALUE);
    }
    ssize_t index = mMap.indexOfKey(pid);
    if (index < 0) {
        ALOGV("markClientForPendingRemoval: didn't find pid %d for clientId %lld",
              pid, (long long)clientId);
        return Status::ok();
    }
    ResourceInfos &infos = mMap.editValueAt(index);

    index = infos.indexOfKey(clientId);
    if (index < 0) {
        ALOGV("markClientForPendingRemoval: didn't find clientId %lld", (long long) clientId);
        return Status::ok();
    }

    ResourceInfo &info = infos.editValueAt(index);
    info.pendingRemoval = true;
    return Status::ok();
}

Status ResourceManagerService::reclaimResourcesFromClientsPendingRemoval(int32_t pid) {
    String8 log = String8::format("reclaimResourcesFromClientsPendingRemoval(pid %d)", pid);
    mServiceLog->add(log);

    Vector<std::shared_ptr<IResourceManagerClient>> clients;
    {
        Mutex::Autolock lock(mLock);
        if (!mProcessInfo->isValidPid(pid)) {
            ALOGE("Rejected reclaimResourcesFromClientsPendingRemoval call with invalid pid.");
            return Status::fromServiceSpecificError(BAD_VALUE);
        }

        for (MediaResource::Type type : {MediaResource::Type::kSecureCodec,
                                         MediaResource::Type::kNonSecureCodec,
                                         MediaResource::Type::kGraphicMemory,
                                         MediaResource::Type::kDrmSession}) {
            std::shared_ptr<IResourceManagerClient> client;
            if (getBiggestClient_l(pid, type, &client, true /* pendingRemovalOnly */)) {
                clients.add(client);
                break;
            }
        }
    }

    if (!clients.empty()) {
        reclaimInternal(clients);
    }
    return Status::ok();
}

bool ResourceManagerService::getPriority_l(int pid, int* priority) {
    int newPid = pid;

    if (mOverridePidMap.find(pid) != mOverridePidMap.end()) {
        newPid = mOverridePidMap[pid];
        ALOGD("getPriority_l: use override pid %d instead original pid %d",
                newPid, pid);
    }

    return mProcessInfo->getPriority(newPid, priority);
}

bool ResourceManagerService::getAllClients_l(
        int callingPid, MediaResource::Type type,
        Vector<std::shared_ptr<IResourceManagerClient>> *clients) {
    Vector<std::shared_ptr<IResourceManagerClient>> temp;
    for (size_t i = 0; i < mMap.size(); ++i) {
        ResourceInfos &infos = mMap.editValueAt(i);
        for (size_t j = 0; j < infos.size(); ++j) {
            if (hasResourceType(type, infos[j].resources)) {
                if (!isCallingPriorityHigher_l(callingPid, mMap.keyAt(i))) {
                    // some higher/equal priority process owns the resource,
                    // this request can't be fulfilled.
                    ALOGE("getAllClients_l: can't reclaim resource %s from pid %d",
                            asString(type), mMap.keyAt(i));
                    return false;
                }
                temp.push_back(infos[j].client);
            }
        }
    }
    if (temp.size() == 0) {
        ALOGV("getAllClients_l: didn't find any resource %s", asString(type));
        return true;
    }
    clients->appendVector(temp);
    return true;
}

bool ResourceManagerService::getLowestPriorityBiggestClient_l(
        int callingPid, MediaResource::Type type,
        std::shared_ptr<IResourceManagerClient> *client) {
    int lowestPriorityPid;
    int lowestPriority;
    int callingPriority;

    // Before looking into other processes, check if we have clients marked for
    // pending removal in the same process.
    if (getBiggestClient_l(callingPid, type, client, true /* pendingRemovalOnly */)) {
        return true;
    }
    if (!getPriority_l(callingPid, &callingPriority)) {
        ALOGE("getLowestPriorityBiggestClient_l: can't get process priority for pid %d",
                callingPid);
        return false;
    }
    if (!getLowestPriorityPid_l(type, &lowestPriorityPid, &lowestPriority)) {
        return false;
    }
    if (lowestPriority <= callingPriority) {
        ALOGE("getLowestPriorityBiggestClient_l: lowest priority %d vs caller priority %d",
                lowestPriority, callingPriority);
        return false;
    }

    if (!getBiggestClient_l(lowestPriorityPid, type, client)) {
        return false;
    }
    return true;
}

bool ResourceManagerService::getLowestPriorityPid_l(
        MediaResource::Type type, int *lowestPriorityPid, int *lowestPriority) {
    int pid = -1;
    int priority = -1;
    for (size_t i = 0; i < mMap.size(); ++i) {
        if (mMap.valueAt(i).size() == 0) {
            // no client on this process.
            continue;
        }
        if (!hasResourceType(type, mMap.valueAt(i))) {
            // doesn't have the requested resource type
            continue;
        }
        int tempPid = mMap.keyAt(i);
        int tempPriority;
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

bool ResourceManagerService::getBiggestClient_l(
        int pid, MediaResource::Type type, std::shared_ptr<IResourceManagerClient> *client,
        bool pendingRemovalOnly) {
    ssize_t index = mMap.indexOfKey(pid);
    if (index < 0) {
        ALOGE_IF(!pendingRemovalOnly,
                 "getBiggestClient_l: can't find resource info for pid %d", pid);
        return false;
    }

    std::shared_ptr<IResourceManagerClient> clientTemp;
    uint64_t largestValue = 0;
    const ResourceInfos &infos = mMap.valueAt(index);
    for (size_t i = 0; i < infos.size(); ++i) {
        const ResourceList &resources = infos[i].resources;
        if (pendingRemovalOnly && !infos[i].pendingRemoval) {
            continue;
        }
        for (auto it = resources.begin(); it != resources.end(); it++) {
            const MediaResourceParcel &resource = it->second;
            if (resource.type == type) {
                if (resource.value > largestValue) {
                    largestValue = resource.value;
                    clientTemp = infos[i].client;
                }
            }
        }
    }

    if (clientTemp == NULL) {
        ALOGE_IF(!pendingRemovalOnly,
                 "getBiggestClient_l: can't find resource type %s for pid %d",
                 asString(type), pid);
        return false;
    }

    *client = clientTemp;
    return true;
}

} // namespace android
