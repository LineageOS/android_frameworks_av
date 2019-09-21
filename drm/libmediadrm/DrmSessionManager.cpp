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

#include <binder/IPCThreadState.h>
#include <binder/IProcessInfoService.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>
#include <media/IResourceManagerClient.h>
#include <media/MediaResource.h>
#include <mediadrm/DrmSessionManager.h>
#include <unistd.h>
#include <utils/String8.h>

#include <vector>

#include "ResourceManagerService.h"

namespace android {

static String8 GetSessionIdString(const Vector<uint8_t> &sessionId) {
    String8 sessionIdStr;
    for (size_t i = 0; i < sessionId.size(); ++i) {
        sessionIdStr.appendFormat("%u ", sessionId[i]);
    }
    return sessionIdStr;
}

static std::vector<uint8_t> toStdVec(const Vector<uint8_t> &vector) {
    const uint8_t *v = vector.array();
    std::vector<uint8_t> vec(v, v + vector.size());
    return vec;
}

static uint64_t toClientId(const sp<IResourceManagerClient>& drm) {
    return reinterpret_cast<int64_t>(drm.get());
}

static Vector<MediaResource> toResourceVec(const Vector<uint8_t> &sessionId) {
    Vector<MediaResource> resources;
    // use UINT64_MAX to decrement through addition overflow
    resources.push_back(MediaResource(MediaResource::kDrmSession, toStdVec(sessionId), UINT64_MAX));
    return resources;
}

static sp<IResourceManagerService> getResourceManagerService() {
    if (property_get_bool("persist.device_config.media_native.mediadrmserver", 1)) {
        return new ResourceManagerService();
    }
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == NULL) {
        return NULL;
    }
    sp<IBinder> binder = sm->getService(String16("media.resource_manager"));
    return interface_cast<IResourceManagerService>(binder);
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
    : DrmSessionManager(getResourceManagerService()) {
}

DrmSessionManager::DrmSessionManager(const sp<IResourceManagerService> &service)
    : mService(service),
      mInitialized(false) {
    if (mService == NULL) {
        ALOGE("Failed to init ResourceManagerService");
    }
}

DrmSessionManager::~DrmSessionManager() {
    if (mService != NULL) {
        IInterface::asBinder(mService)->unlinkToDeath(this);
    }
}

void DrmSessionManager::init() {
    Mutex::Autolock lock(mLock);
    if (mInitialized) {
        return;
    }
    mInitialized = true;
    if (mService != NULL) {
        IInterface::asBinder(mService)->linkToDeath(this);
    }
}

void DrmSessionManager::addSession(int pid,
        const sp<IResourceManagerClient>& drm, const Vector<uint8_t> &sessionId) {
    uid_t uid = IPCThreadState::self()->getCallingUid();
    ALOGV("addSession(pid %d, uid %d, drm %p, sessionId %s)", pid, uid, drm.get(),
            GetSessionIdString(sessionId).string());

    Mutex::Autolock lock(mLock);
    if (mService == NULL) {
        return;
    }

    int64_t clientId = toClientId(drm);
    mSessionMap[toStdVec(sessionId)] = (SessionInfo){pid, uid, clientId};
    mService->addResource(pid, uid, clientId, drm, toResourceVec(sessionId));
}

void DrmSessionManager::useSession(const Vector<uint8_t> &sessionId) {
    ALOGV("useSession(%s)", GetSessionIdString(sessionId).string());

    Mutex::Autolock lock(mLock);
    auto it = mSessionMap.find(toStdVec(sessionId));
    if (mService == NULL || it == mSessionMap.end()) {
        return;
    }

    auto info = it->second;
    mService->addResource(info.pid, info.uid, info.clientId, NULL, toResourceVec(sessionId));
}

void DrmSessionManager::removeSession(const Vector<uint8_t> &sessionId) {
    ALOGV("removeSession(%s)", GetSessionIdString(sessionId).string());

    Mutex::Autolock lock(mLock);
    auto it = mSessionMap.find(toStdVec(sessionId));
    if (mService == NULL || it == mSessionMap.end()) {
        return;
    }

    auto info = it->second;
    mService->removeResource(info.pid, info.clientId, toResourceVec(sessionId));
    mSessionMap.erase(it);
}

bool DrmSessionManager::reclaimSession(int callingPid) {
    ALOGV("reclaimSession(%d)", callingPid);

    // unlock early because reclaimResource might callback into removeSession
    mLock.lock();
    sp<IResourceManagerService> service(mService);
    mLock.unlock();

    if (service == NULL) {
        return false;
    }

    // cannot update mSessionMap because we do not know which sessionId is reclaimed;
    // we rely on IResourceManagerClient to removeSession in reclaimResource
    Vector<uint8_t> dummy;
    return service->reclaimResource(callingPid, toResourceVec(dummy));
}

size_t DrmSessionManager::getSessionCount() const {
    Mutex::Autolock lock(mLock);
    return mSessionMap.size();
}

bool DrmSessionManager::containsSession(const Vector<uint8_t>& sessionId) const {
    Mutex::Autolock lock(mLock);
    return mSessionMap.count(toStdVec(sessionId));
}

void DrmSessionManager::binderDied(const wp<IBinder>& /*who*/) {
    ALOGW("ResourceManagerService died.");
    Mutex::Autolock lock(mLock);
    mService.clear();
}

}  // namespace android
