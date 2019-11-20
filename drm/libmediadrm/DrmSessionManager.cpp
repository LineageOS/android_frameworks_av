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

namespace {
void ResourceManagerServiceDied(void* cookie) {
    auto thiz = static_cast<DrmSessionManager*>(cookie);
    thiz->binderDied();
}
}

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

static std::vector<MediaResourceParcel> toResourceVec(
        const Vector<uint8_t> &sessionId, int64_t value) {
    using Type = aidl::android::media::MediaResourceType;
    using SubType = aidl::android::media::MediaResourceSubType;
    std::vector<MediaResourceParcel> resources;
    MediaResourceParcel resource{
            Type::kDrmSession, SubType::kUnspecifiedSubType,
            toStdVec<int8_t>(sessionId), value};
    resources.push_back(resource);
    return resources;
}

static std::shared_ptr<IResourceManagerService> getResourceManagerService() {
    ::ndk::SpAIBinder binder(AServiceManager_getService("media.resource_manager"));
    return IResourceManagerService::fromBinder(binder);
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
    auto drmSessionManager = new DrmSessionManager();
    drmSessionManager->init();
    return drmSessionManager;
}

DrmSessionManager::DrmSessionManager()
    : DrmSessionManager(getResourceManagerService()) {
}

DrmSessionManager::DrmSessionManager(const std::shared_ptr<IResourceManagerService> &service)
    : mService(service),
      mInitialized(false),
      mDeathRecipient(AIBinder_DeathRecipient_new(ResourceManagerServiceDied)) {
    if (mService == NULL) {
        ALOGE("Failed to init ResourceManagerService");
    }
}

DrmSessionManager::~DrmSessionManager() {
    if (mService != NULL) {
        AIBinder_unlinkToDeath(mService->asBinder().get(), mDeathRecipient.get(), this);
    }
}

void DrmSessionManager::init() {
    Mutex::Autolock lock(mLock);
    if (mInitialized) {
        return;
    }
    mInitialized = true;
    if (mService != NULL) {
        AIBinder_linkToDeath(mService->asBinder().get(), mDeathRecipient.get(), this);
    }
}

void DrmSessionManager::addSession(int pid,
        const std::shared_ptr<IResourceManagerClient>& drm, const Vector<uint8_t> &sessionId) {
    uid_t uid = AIBinder_getCallingUid();
    ALOGV("addSession(pid %d, uid %d, drm %p, sessionId %s)", pid, uid, drm.get(),
            GetSessionIdString(sessionId).string());

    Mutex::Autolock lock(mLock);
    if (mService == NULL) {
        return;
    }

    static int64_t clientId = 0;
    mSessionMap[toStdVec(sessionId)] = (SessionInfo){pid, uid, clientId};
    mService->addResource(pid, uid, clientId++, drm, toResourceVec(sessionId, INT64_MAX));
}

void DrmSessionManager::useSession(const Vector<uint8_t> &sessionId) {
    ALOGV("useSession(%s)", GetSessionIdString(sessionId).string());

    Mutex::Autolock lock(mLock);
    auto it = mSessionMap.find(toStdVec(sessionId));
    if (mService == NULL || it == mSessionMap.end()) {
        return;
    }

    auto info = it->second;
    mService->addResource(info.pid, info.uid, info.clientId, NULL, toResourceVec(sessionId, -1));
}

void DrmSessionManager::removeSession(const Vector<uint8_t> &sessionId) {
    ALOGV("removeSession(%s)", GetSessionIdString(sessionId).string());

    Mutex::Autolock lock(mLock);
    auto it = mSessionMap.find(toStdVec(sessionId));
    if (mService == NULL || it == mSessionMap.end()) {
        return;
    }

    auto info = it->second;
    mService->removeResource(info.pid, info.clientId, toResourceVec(sessionId, INT64_MAX));
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
    Vector<uint8_t> dummy;
    bool success;
    ScopedAStatus status = service->reclaimResource(callingPid, toResourceVec(dummy, INT64_MAX), &success);
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
    mService.reset();
}

}  // namespace android
