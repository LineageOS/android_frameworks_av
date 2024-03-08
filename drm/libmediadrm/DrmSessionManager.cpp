/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "DrmSessionManager"
#include <utils/Log.h>

#include <aidl/android/media/IResourceManagerClient.h>
#include <aidl/android/media/IResourceManagerService.h>
#include <aidl/android/media/MediaResourceParcel.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <cutils/properties.h>
#include <mediadrm/DrmUtils.h>
#include <mediadrm/DrmSessionManager.h>
#include <unistd.h>
#include <utils/String8.h>

#include <vector>

namespace android {

using aidl::android::media::MediaResourceParcel;
using aidl::android::media::ClientInfoParcel;

using ::ndk::ScopedAStatus;

static String8 GetSessionIdString(const Vector<uint8_t> &sessionId) {
    String8 sessionIdStr;
    for (size_t i = 0; i < sessionId.size(); ++i) {
        sessionIdStr.appendFormat("%u ", sessionId[i]);
    }
    return sessionIdStr;
}

template <typename Byte = uint8_t>
static std::vector<Byte> toStdVec(const Vector<uint8_t> &vector) {
    auto v = reinterpret_cast<const Byte *>(vector.array());
    std::vector<Byte> vec(v, v + vector.size());
    return vec;
}

static Vector<uint8_t> toAndroidVec(const std::vector<uint8_t>& array) {
    Vector<uint8_t> vec;
    vec.appendArray(array.data(), array.size());
    return vec;
}

static std::vector<MediaResourceParcel> toResourceVec(
        const Vector<uint8_t> &sessionId, int64_t value) {
    using Type = aidl::android::media::MediaResourceType;
    using SubType = aidl::android::media::MediaResourceSubType;
    std::vector<MediaResourceParcel> resources;
    MediaResourceParcel resource{
            Type::kDrmSession, SubType::kUnspecifiedSubType,
            toStdVec<>(sessionId), value};
    resources.push_back(resource);
    return resources;
}

bool isEqualSessionId(const Vector<uint8_t> &sessionId1, const Vector<uint8_t> &sessionId2) {
    if (sessionId1.size() != sessionId2.size()) {
        return false;
    }
    for (size_t i = 0; i < sessionId1.size(); ++i) {
        if (sessionId1[i] != sessionId2[i]) {
            return false;
        }
    }
    return true;
}

sp<DrmSessionManager> DrmSessionManager::Instance() {
    static sp<DrmSessionManager> drmSessionManager = new DrmSessionManager();
    drmSessionManager->init();
    return drmSessionManager;
}

DrmSessionManager::DrmSessionManager()
    : DrmSessionManager(nullptr) {
}

DrmSessionManager::DrmSessionManager(const std::shared_ptr<IResourceManagerService> &service)
    : mService(service),
      mDeathRecipient(::ndk::ScopedAIBinder_DeathRecipient(
          AIBinder_DeathRecipient_new(ResourceManagerServiceDied))) {
    // Setting callback notification when DeathRecipient gets deleted.
    AIBinder_DeathRecipient_setOnUnlinked(mDeathRecipient.get(), BinderUnlinkedCallback);
}

DrmSessionManager::~DrmSessionManager() {
    if (mService != NULL) {
        AIBinder_unlinkToDeath(mService->asBinder().get(), mDeathRecipient.get(), this);
    }
}

status_t DrmSessionManager::init() {
    Mutex::Autolock lock(mLock);
    getResourceManagerService_l();
    if (mService == nullptr) {
        ALOGE("Failed to init ResourceManagerService");
        return DEAD_OBJECT;
    }

    return OK;
}

void DrmSessionManager::getResourceManagerService_l() {
    if (mService != nullptr) {
        return;
    }

    // Get binder interface to resource manager.
    ::ndk::SpAIBinder binder(AServiceManager_waitForService("media.resource_manager"));
    mService = IResourceManagerService::fromBinder(binder);
    if (mService == nullptr) {
        ALOGE("Failed to get ResourceManagerService");
        return;
    }

    // Create the context that is passed as cookie to the binder death notification.
    // The context gets deleted at BinderUnlinkedCallback.
    BinderDiedContext* context = new BinderDiedContext{
        .mDrmSessionManager = wp<DrmSessionManager>::fromExisting(this)};
    // Register for the callbacks by linking to death notification.
    AIBinder_linkToDeath(mService->asBinder().get(), mDeathRecipient.get(), context);

    // If the RM was restarted, re-register all the resources.
    if (mBinderDied) {
        reRegisterAllResources_l();
        mBinderDied = false;
    }
}

void DrmSessionManager::reRegisterAllResources_l() {
    if (mSessionMap.empty()) {
        // Nothing to register.
        ALOGV("No resources to add");
        return;
    }

    if (mService == nullptr) {
        ALOGW("Service isn't available");
        return;
    }

    // Go through the session map and re-register all the resources for those sessions.
    for (SessionInfoMap::const_iterator iter = mSessionMap.begin();
         iter != mSessionMap.end(); ++iter) {
        ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(iter->second.pid),
                                    .uid = static_cast<int32_t>(iter->second.uid),
                                    .id = iter->second.clientId};
        mService->addResource(clientInfo, iter->second.drm,
                              toResourceVec(toAndroidVec(iter->first), iter->second.resourceValue));
    }
}

void DrmSessionManager::addSession(int pid,
        const std::shared_ptr<IResourceManagerClient>& drm, const Vector<uint8_t> &sessionId) {
    uid_t uid = AIBinder_getCallingUid();
    ALOGV("addSession(pid %d, uid %d, drm %p, sessionId %s)", pid, uid, drm.get(),
            GetSessionIdString(sessionId).c_str());

    Mutex::Autolock lock(mLock);
    if (mService == NULL) {
        return;
    }

    static int64_t clientId = 0;
    mSessionMap[toStdVec(sessionId)] = (SessionInfo){pid, uid, clientId, drm, INT64_MAX};
    ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(pid),
                                .uid = static_cast<int32_t>(uid),
                                .id = clientId++};
    mService->addResource(clientInfo, drm, toResourceVec(sessionId, INT64_MAX));
}

void DrmSessionManager::useSession(const Vector<uint8_t> &sessionId) {
    ALOGV("useSession(%s)", GetSessionIdString(sessionId).c_str());

    Mutex::Autolock lock(mLock);
    auto it = mSessionMap.find(toStdVec(sessionId));
    if (mService == NULL || it == mSessionMap.end()) {
        return;
    }

    auto info = it->second;
    info.resourceValue = -1;
    ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(info.pid),
                                .uid = static_cast<int32_t>(info.uid),
                                .id = info.clientId};
    mService->addResource(clientInfo, NULL, toResourceVec(sessionId, -1));
}

void DrmSessionManager::removeSession(const Vector<uint8_t> &sessionId) {
    ALOGV("removeSession(%s)", GetSessionIdString(sessionId).c_str());

    Mutex::Autolock lock(mLock);
    auto it = mSessionMap.find(toStdVec(sessionId));
    if (mService == NULL || it == mSessionMap.end()) {
        return;
    }

    auto info = it->second;
    // removeClient instead of removeSession because each client has only one session
    ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(info.pid),
                                .uid = static_cast<int32_t>(info.uid),
                                .id = info.clientId};
    mService->removeClient(clientInfo);
    mSessionMap.erase(it);
}

bool DrmSessionManager::reclaimSession(int callingPid) {
    ALOGV("reclaimSession(%d)", callingPid);

    // unlock early because reclaimResource might callback into removeSession
    mLock.lock();
    std::shared_ptr<IResourceManagerService> service(mService);
    mLock.unlock();

    if (service == NULL) {
        return false;
    }

    // cannot update mSessionMap because we do not know which sessionId is reclaimed;
    // we rely on IResourceManagerClient to removeSession in reclaimResource
    Vector<uint8_t> placeHolder;
    bool success;
    uid_t uid = AIBinder_getCallingUid();
    ClientInfoParcel clientInfo{.pid = static_cast<int32_t>(callingPid),
                                .uid = static_cast<int32_t>(uid)};
    ScopedAStatus status = service->reclaimResource(
        clientInfo, toResourceVec(placeHolder, INT64_MAX), &success);
    return status.isOk() && success;
}

size_t DrmSessionManager::getSessionCount() const {
    Mutex::Autolock lock(mLock);
    return mSessionMap.size();
}

bool DrmSessionManager::containsSession(const Vector<uint8_t>& sessionId) const {
    Mutex::Autolock lock(mLock);
    return mSessionMap.count(toStdVec(sessionId));
}

void DrmSessionManager::binderDied() {
    ALOGW("ResourceManagerService died.");
    Mutex::Autolock lock(mLock);
    mService = nullptr;
    mBinderDied = true;
    // start an async operation that will reconnect with the RM and
    // re-registers all the resources.
    mGetServiceFuture = std::async(std::launch::async, [this] { getResourceManagerService(); });
}

void DrmSessionManager::ResourceManagerServiceDied(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);

    // Validate the context and check if the DrmSessionManager object is still in scope.
    if (context != nullptr) {
        sp<DrmSessionManager> thiz = context->mDrmSessionManager.promote();
        if (thiz != nullptr) {
            thiz->binderDied();
        } else {
            ALOGI("DrmSessionManager is out of scope already");
        }
    }
}

void DrmSessionManager::BinderUnlinkedCallback(void* cookie) {
    BinderDiedContext* context = reinterpret_cast<BinderDiedContext*>(cookie);
    // Since we don't need the context anymore, we are deleting it now.
    delete context;
}

}  // namespace android
