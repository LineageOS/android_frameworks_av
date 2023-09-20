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
#include <dirent.h>
#include <media/MediaResourcePolicy.h>
#include <media/stagefright/foundation/ABase.h>
#include <mediautils/BatteryNotifier.h>
#include <mediautils/ProcessInfo.h>
#include <mediautils/SchedulingPolicyService.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "IMediaResourceMonitor.h"
#include "ResourceManagerMetrics.h"
#include "ResourceManagerService.h"
#include "ResourceManagerServiceUtils.h"
#include "ResourceObserverService.h"
#include "ServiceLog.h"

namespace android {

class DeathNotifier : public std::enable_shared_from_this<DeathNotifier> {

    // BinderDiedContext defines the cookie that is passed as DeathRecipient.
    // Since this can maintain more context than a raw pointer, we can
    // validate the scope of DeathNotifier, before deferencing it upon the binder death.
    struct BinderDiedContext {
        std::weak_ptr<DeathNotifier> mDeathNotifier;
    };
public:
    DeathNotifier(const std::shared_ptr<IResourceManagerClient>& client,
                  const std::shared_ptr<ResourceManagerService>& service,
                  const ClientInfoParcel& clientInfo,
                  AIBinder_DeathRecipient* recipient);

    virtual ~DeathNotifier() {
        unlink();
    }

    void unlink() {
        if (mClient != nullptr) {
            // Register for the callbacks by linking to death notification.
            AIBinder_unlinkToDeath(mClient->asBinder().get(), mRecipient, mCookie);
            mClient = nullptr;
        }
    }

    // Implement death recipient
    static void BinderDiedCallback(void* cookie);
    static void BinderUnlinkedCallback(void* cookie);
    virtual void binderDied();

private:
    void link() {
        // Create the context that is passed as cookie to the binder death notification.
        // The context gets deleted at BinderUnlinkedCallback.
        mCookie = new BinderDiedContext{.mDeathNotifier = weak_from_this()};
        // Register for the callbacks by linking to death notification.
        AIBinder_linkToDeath(mClient->asBinder().get(), mRecipient, mCookie);
    }

protected:
    std::shared_ptr<IResourceManagerClient> mClient;
    std::weak_ptr<ResourceManagerService> mService;
    const ClientInfoParcel mClientInfo;
    AIBinder_DeathRecipient* mRecipient;
    BinderDiedContext* mCookie;
};

DeathNotifier::DeathNotifier(const std::shared_ptr<IResourceManagerClient>& client,
                             const std::shared_ptr<ResourceManagerService>& service,
                             const ClientInfoParcel& clientInfo,
                             AIBinder_DeathRecipient* recipient)
    : mClient(client), mService(service), mClientInfo(clientInfo),
      mRecipient(recipient), mCookie(nullptr) {
    link();
}

//static
void DeathNotifier::BinderUnlinkedCallback(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);
    // Since we don't need the context anymore, we are deleting it now.
    delete context;
}

//static
void DeathNotifier::BinderDiedCallback(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);

    // Validate the context and check if the DeathNotifier object is still in scope.
    if (context != nullptr) {
        std::shared_ptr<DeathNotifier> thiz = context->mDeathNotifier.lock();
        if (thiz != nullptr) {
            thiz->binderDied();
        } else {
            ALOGI("DeathNotifier is out of scope already");
        }
    }
}

void DeathNotifier::binderDied() {
    // Don't check for pid validity since we know it's already dead.
    std::shared_ptr<ResourceManagerService> service = mService.lock();
    if (service == nullptr) {
        ALOGW("ResourceManagerService is dead as well.");
        return;
    }

    service->overridePid(mClientInfo.pid, -1);
    // thiz is freed in the call below, so it must be last call referring thiz
    service->removeResource(mClientInfo, false /*checkValid*/);
}

class OverrideProcessInfoDeathNotifier : public DeathNotifier {
public:
    OverrideProcessInfoDeathNotifier(const std::shared_ptr<IResourceManagerClient>& client,
                                     const std::shared_ptr<ResourceManagerService>& service,
                                     const ClientInfoParcel& clientInfo,
                                     AIBinder_DeathRecipient* recipient)
            : DeathNotifier(client, service, clientInfo, recipient) {}

    virtual ~OverrideProcessInfoDeathNotifier() {}

    virtual void binderDied();
};

void OverrideProcessInfoDeathNotifier::binderDied() {
    // Don't check for pid validity since we know it's already dead.
    std::shared_ptr<ResourceManagerService> service = mService.lock();
    if (service == nullptr) {
        ALOGW("ResourceManagerService is dead as well.");
        return;
    }

    service->removeProcessInfoOverride(mClientInfo.pid);
}

static void notifyResourceGranted(int pid, const std::vector<MediaResourceParcel>& resources) {
    static const char* const kServiceName = "media_resource_monitor";
    sp<IBinder> binder = defaultServiceManager()->checkService(String16(kServiceName));
    if (binder != NULL) {
        sp<IMediaResourceMonitor> service = interface_cast<IMediaResourceMonitor>(binder);
        for (size_t i = 0; i < resources.size(); ++i) {
            switch (resources[i].subType) {
                case MediaResource::SubType::kHwAudioCodec:
                case MediaResource::SubType::kSwAudioCodec:
                    service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_AUDIO_CODEC);
                    break;
                case MediaResource::SubType::kHwVideoCodec:
                case MediaResource::SubType::kSwVideoCodec:
                    service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_VIDEO_CODEC);
                    break;
                case MediaResource::SubType::kHwImageCodec:
                case MediaResource::SubType::kSwImageCodec:
                    service->notifyResourceGranted(pid, IMediaResourceMonitor::TYPE_IMAGE_CODEC);
                    break;
                case MediaResource::SubType::kUnspecifiedSubType:
                    break;
            }
        }
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

    PidResourceInfosMap mapCopy;
    bool supportsMultipleSecureCodecs;
    bool supportsSecureWithNonSecureCodec;
    std::map<int, int> overridePidMapCopy;
    String8 serviceLog;
    {
        std::scoped_lock lock{mLock};
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
    for (const auto& [pid, infos] : mapCopy) {
        snprintf(buffer, SIZE, "    Pid: %d\n", pid);
        result.append(buffer);
        int priority = 0;
        if (getPriority_l(pid, &priority)) {
            snprintf(buffer, SIZE, "    Priority: %d\n", priority);
        } else {
            snprintf(buffer, SIZE, "    Priority: <unknown>\n");
        }
        result.append(buffer);

        for (const auto& [infoKey, info] : infos) {
            result.append("      Client:\n");
            snprintf(buffer, SIZE, "        Id: %lld\n", (long long)info.clientId);
            result.append(buffer);

            std::string clientName = info.name;
            snprintf(buffer, SIZE, "        Name: %s\n", clientName.c_str());
            result.append(buffer);

            const ResourceList& resources = info.resources;
            result.append("        Resources:\n");
            for (auto it = resources.begin(); it != resources.end(); it++) {
                snprintf(buffer, SIZE, "          %s\n", toString(it->second).c_str());
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
      mCpuBoostCount(0),
      mDeathRecipient(::ndk::ScopedAIBinder_DeathRecipient(
                      AIBinder_DeathRecipient_new(DeathNotifier::BinderDiedCallback))) {
    mSystemCB->noteResetVideo();
    // Create ResourceManagerMetrics that handles all the metrics.
    mResourceManagerMetrics = std::make_unique<ResourceManagerMetrics>(mProcessInfo);
}

//static
void ResourceManagerService::instantiate() {
    std::shared_ptr<ResourceManagerService> service =
            ::ndk::SharedRefBase::make<ResourceManagerService>();
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

void ResourceManagerService::onFirstAdded(const MediaResourceParcel& resource,
        const ResourceInfo& clientInfo) {
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
        mSystemCB->noteStartVideo(clientInfo.uid);
    }
}

void ResourceManagerService::onLastRemoved(const MediaResourceParcel& resource,
        const ResourceInfo& clientInfo) {
    if (resource.type == MediaResource::Type::kCpuBoost
            && resource.subType == MediaResource::SubType::kUnspecifiedSubType
            && mCpuBoostCount > 0) {
        if (--mCpuBoostCount == 0) {
            mSystemCB->requestCpusetBoost(false);
        }
    } else if (resource.type == MediaResource::Type::kBattery
            && (resource.subType == MediaResource::SubType::kHwVideoCodec
                || resource.subType == MediaResource::SubType::kSwVideoCodec)) {
        mSystemCB->noteStopVideo(clientInfo.uid);
    }
}

void ResourceManagerService::mergeResources(MediaResourceParcel& r1,
        const MediaResourceParcel& r2) {
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
        // Add it to the list of added resources for observers.
        auto it = resourceAdded.find(resType);
        if (it == resourceAdded.end()) {
            resourceAdded[resType] = res;
        } else {
            mergeResources(it->second, res);
        }
    }
    if (info.deathNotifier == nullptr && client != nullptr) {
        info.deathNotifier = std::make_shared<DeathNotifier>(
            client, ref<ResourceManagerService>(), clientInfo, mDeathRecipient.get());
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
        const auto resType = std::tuple(res.type, res.subType, res.id);

        if (res.value < 0) {
            ALOGW("Ignoring request to remove negative value of resource");
            continue;
        }
        // ignore if we don't have it
        if (info.resources.find(resType) != info.resources.end()) {
            MediaResourceParcel &resource = info.resources[resType];
            MediaResourceParcel actualRemoved = res;
            if (resource.value > res.value) {
                resource.value -= res.value;
            } else {
                onLastRemoved(res, info);
                actualRemoved.value = resource.value;
                info.resources.erase(resType);
            }

            // Add it to the list of removed resources for observers.
            auto it = resourceRemoved.find(resType);
            if (it == resourceRemoved.end()) {
                resourceRemoved[resType] = actualRemoved;
            } else {
                mergeResources(it->second, actualRemoved);
            }
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
    for (auto it = info.resources.begin(); it != info.resources.end(); it++) {
        onLastRemoved(it->second, info);
    }

    // Since this client has been removed, update the metrics collector.
    mResourceManagerMetrics->notifyClientReleased(clientInfo);

    if (mObserverService != nullptr && !info.resources.empty()) {
        mObserverService->onResourceRemoved(info.uid, pid, info.resources);
    }

    infos.erase(foundClient);
    return Status::ok();
}

void ResourceManagerService::getClientForResource_l(int callingPid,
        const MediaResourceParcel *res,
        PidUidVector* idVector,
        std::vector<std::shared_ptr<IResourceManagerClient>>* clients) {
    if (res == NULL) {
        return;
    }
    std::shared_ptr<IResourceManagerClient> client;
    if (getLowestPriorityBiggestClient_l(callingPid, res->type, res->subType, idVector, &client)) {
        clients->push_back(client);
    }
}

Status ResourceManagerService::reclaimResource(const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources, bool* _aidl_return) {
    int32_t callingPid = clientInfo.pid;
    std::string clientName = clientInfo.name;
    String8 log = String8::format("reclaimResource(callingPid %d, uid %d resources %s)",
            callingPid, clientInfo.uid, getString(resources).c_str());
    mServiceLog->add(log);
    *_aidl_return = false;

    std::vector<std::shared_ptr<IResourceManagerClient>> clients;
    PidUidVector idVector;
    {
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
            if (!mSupportsMultipleSecureCodecs) {
                if (!getAllClients_l(callingPid, MediaResource::Type::kSecureCodec,
                            secureCodec->subType, &idVector, &clients)) {
                    return Status::ok();
                }
            }
            if (!mSupportsSecureWithNonSecureCodec) {
                if (!getAllClients_l(callingPid, MediaResource::Type::kNonSecureCodec,
                            secureCodec->subType, &idVector, &clients)) {
                    return Status::ok();
                }
            }
        }
        if (nonSecureCodec != NULL) {
            if (!mSupportsSecureWithNonSecureCodec) {
                if (!getAllClients_l(callingPid, MediaResource::Type::kSecureCodec,
                        nonSecureCodec->subType, &idVector, &clients)) {
                    return Status::ok();
                }
            }
        }
        if (drmSession != NULL) {
            getClientForResource_l(callingPid, drmSession, &idVector, &clients);
            if (clients.size() == 0) {
                return Status::ok();
            }
        }

        if (clients.size() == 0) {
            // if no secure/non-secure codec conflict, run second pass to handle other resources.
            getClientForResource_l(callingPid, graphicMemory, &idVector, &clients);
        }

        if (clients.size() == 0) {
            // if we are here, run the third pass to free one codec with the same type.
            getClientForResource_l(callingPid, secureCodec, &idVector, &clients);
            getClientForResource_l(callingPid, nonSecureCodec, &idVector, &clients);
        }

        if (clients.size() == 0) {
            // if we are here, run the fourth pass to free one codec with the different type.
            if (secureCodec != NULL) {
                MediaResource temp(MediaResource::Type::kNonSecureCodec, secureCodec->subType, 1);
                getClientForResource_l(callingPid, &temp, &idVector, &clients);
            }
            if (nonSecureCodec != NULL) {
                MediaResource temp(MediaResource::Type::kSecureCodec, nonSecureCodec->subType, 1);
                getClientForResource_l(callingPid, &temp, &idVector, &clients);
            }
        }
    }

    *_aidl_return = reclaimUnconditionallyFrom(clients);

    // Log Reclaim Pushed Atom to statsd
    pushReclaimAtom(clientInfo, clients, idVector, *_aidl_return);

    return Status::ok();
}

void ResourceManagerService::pushReclaimAtom(const ClientInfoParcel& clientInfo,
                        const std::vector<std::shared_ptr<IResourceManagerClient>>& clients,
                        const PidUidVector& idVector, bool reclaimed) {
    int32_t callingPid = clientInfo.pid;
    int requesterPriority = -1;
    getPriority_l(callingPid, &requesterPriority);
    std::vector<int> priorities;
    priorities.push_back(requesterPriority);

    for (PidUidVector::const_reference id : idVector) {
        int targetPriority = -1;
        getPriority_l(id.first, &targetPriority);
        priorities.push_back(targetPriority);
    }
    mResourceManagerMetrics->pushReclaimAtom(clientInfo, priorities, clients,
                                             idVector, reclaimed);
}

bool ResourceManagerService::reclaimUnconditionallyFrom(
        const std::vector<std::shared_ptr<IResourceManagerClient>>& clients) {
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

    int failedClientPid = -1;
    {
        std::scoped_lock lock{mLock};
        bool found = false;
        for (auto& [pid, infos] : mMap) {
            for (const auto& [id, info] : infos) {
                if (info.client == failedClient) {
                    infos.erase(id);
                    found = true;
                    break;
                }
            }
            if (found) {
                failedClientPid = pid;
                break;
            }
        }
        if (found) {
            ALOGW("Failed to reclaim resources from client with pid %d", failedClientPid);
        } else {
            ALOGW("Failed to reclaim resources from unlocateable client");
        }
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
        mOverridePidMap.erase(originalPid);
        if (newPid != -1) {
            mOverridePidMap.emplace(originalPid, newPid);
            mResourceManagerMetrics->addPid(newPid);
        }
    }

    return Status::ok();
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
    removeProcessInfoOverride_l(pid);

    if (!mProcessInfo->overrideProcessInfo(pid, procState, oomScore)) {
        // Override value is rejected by ProcessInfo.
        return Status::fromServiceSpecificError(BAD_VALUE);
    }

    ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(pid),
                                .uid = 0,
                                .id = 0,
                                .name = "<unknown client>"};
    auto deathNotifier = std::make_shared<OverrideProcessInfoDeathNotifier>(
            client, ref<ResourceManagerService>(), clientInfo, mDeathRecipient.get());

    mProcessInfoOverrideMap.emplace(pid, ProcessInfoOverride{deathNotifier, client});

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

    std::vector<std::shared_ptr<IResourceManagerClient>> clients;
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
                        std::shared_ptr<IResourceManagerClient> client;
                        uid_t uid = 0;
                        if (getBiggestClientPendingRemoval_l(pid, type, subType, uid, &client)) {
                            clients.push_back(client);
                            continue;
                        }
                    }
                    break;
                // Non-codec resources are shared by audio, video and image codecs (no subtype).
                default:
                    std::shared_ptr<IResourceManagerClient> client;
                    uid_t uid = 0;
                    if (getBiggestClientPendingRemoval_l(pid, type,
                            MediaResource::SubType::kUnspecifiedSubType, uid, &client)) {
                        clients.push_back(client);
                    }
                    break;
            }
        }
    }

    if (!clients.empty()) {
        reclaimUnconditionallyFrom(clients);
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

bool ResourceManagerService::getAllClients_l(int callingPid, MediaResource::Type type,
        MediaResource::SubType subType,
        PidUidVector* idVector,
        std::vector<std::shared_ptr<IResourceManagerClient>>* clients) {
    std::vector<std::shared_ptr<IResourceManagerClient>> temp;
    PidUidVector tempIdList;

    for (auto& [pid, infos] : mMap) {
        for (const auto& [id, info] : infos) {
            if (hasResourceType(type, subType, info.resources)) {
                if (!isCallingPriorityHigher_l(callingPid, pid)) {
                    // some higher/equal priority process owns the resource,
                    // this request can't be fulfilled.
                    ALOGE("getAllClients_l: can't reclaim resource %s from pid %d",
                            asString(type), pid);
                    return false;
                }
                temp.push_back(info.client);
                tempIdList.emplace_back(pid, info.uid);
            }
        }
    }
    if (temp.size() == 0) {
        ALOGV("getAllClients_l: didn't find any resource %s", asString(type));
        return true;
    }

    clients->insert(std::end(*clients), std::begin(temp), std::end(temp));
    idVector->insert(std::end(*idVector), std::begin(tempIdList), std::end(tempIdList));
    return true;
}

bool ResourceManagerService::getLowestPriorityBiggestClient_l(int callingPid,
        MediaResource::Type type,
        MediaResource::SubType subType,
        PidUidVector* idVector,
        std::shared_ptr<IResourceManagerClient> *client) {
    int lowestPriorityPid;
    int lowestPriority;
    int callingPriority;
    uid_t uid = 0;

    // Before looking into other processes, check if we have clients marked for
    // pending removal in the same process.
    if (getBiggestClientPendingRemoval_l(callingPid, type, subType, uid, client)) {
        idVector->emplace_back(callingPid, uid);
        return true;
    }
    if (!getPriority_l(callingPid, &callingPriority)) {
        ALOGE("getLowestPriorityBiggestClient_l: can't get process priority for pid %d",
                callingPid);
        return false;
    }
    if (!getLowestPriorityPid_l(type, subType, &lowestPriorityPid, &lowestPriority)) {
        return false;
    }
    if (lowestPriority <= callingPriority) {
        ALOGE("getLowestPriorityBiggestClient_l: lowest priority %d vs caller priority %d",
                lowestPriority, callingPriority);
        return false;
    }

    if (!getBiggestClient_l(lowestPriorityPid, type, subType, uid, client)) {
        return false;
    }

    idVector->emplace_back(lowestPriorityPid, uid);
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
        MediaResource::SubType subType, uid_t& uid,
        std::shared_ptr<IResourceManagerClient> *client) {
    return getBiggestClient_l(pid, type, subType, uid, client, true /* pendingRemovalOnly */);
}

bool ResourceManagerService::getBiggestClient_l(int pid, MediaResource::Type type,
        MediaResource::SubType subType, uid_t& uid,
        std::shared_ptr<IResourceManagerClient> *client,
        bool pendingRemovalOnly) {
    PidResourceInfosMap::iterator found = mMap.find(pid);
    if (found == mMap.end()) {
        ALOGE_IF(!pendingRemovalOnly,
                 "getBiggestClient_l: can't find resource info for pid %d", pid);
        return false;
    }

    std::shared_ptr<IResourceManagerClient> clientTemp;
    uint64_t largestValue = 0;
    const ResourceInfos& infos = found->second;
    for (const auto& [id, info] : infos) {
        const ResourceList& resources = info.resources;
        if (pendingRemovalOnly && !info.pendingRemoval) {
            continue;
        }
        for (auto it = resources.begin(); it != resources.end(); it++) {
            const MediaResourceParcel &resource = it->second;
            if (hasResourceType(type, subType, resource)) {
                if (resource.value > largestValue) {
                    largestValue = resource.value;
                    clientTemp = info.client;
                    uid = info.uid;
                }
            }
        }
    }

    if (clientTemp == NULL) {
        ALOGE_IF(!pendingRemovalOnly,
                 "getBiggestClient_l: can't find resource type %s and subtype %s for pid %d",
                 asString(type), asString(subType), pid);
        return false;
    }

    *client = clientTemp;
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

} // namespace android
