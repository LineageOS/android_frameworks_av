/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "TranscodingUidPolicy"

#include <aidl/android/media/BnResourceManagerClient.h>
#include <aidl/android/media/IResourceManagerService.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/content/pm/IPackageManagerNative.h>
#include <binder/ActivityManager.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionController.h>
#include <cutils/misc.h>  // FIRST_APPLICATION_UID
#include <cutils/multiuser.h>
#include <inttypes.h>
#include <media/TranscodingUidPolicy.h>
#include <utils/Log.h>

#include <utility>

namespace android {

constexpr static uid_t OFFLINE_UID = -1;
constexpr static const char* kTranscodingTag = "transcoding";

/*
 * The OOM score we're going to ask ResourceManager to use for our native transcoding
 * service. ResourceManager issues reclaims based on these scores. It gets the scores
 * from ActivityManagerService, which doesn't track native services. The values of the
 * OOM scores are defined in:
 * frameworks/base/services/core/java/com/android/server/am/ProcessList.java
 * We use SERVICE_ADJ which is lower priority than an app possibly visible to the
 * user, but higher priority than a cached app (which could be killed without disruption
 * to the user).
 */
constexpr static int32_t SERVICE_ADJ = 500;

using Status = ::ndk::ScopedAStatus;
using aidl::android::media::BnResourceManagerClient;
using aidl::android::media::IResourceManagerService;

/*
 * Placeholder ResourceManagerClient for registering process info override
 * with the IResourceManagerService. This is only used as a token by the service
 * to get notifications about binder death, not used for reclaiming resources.
 */
struct TranscodingUidPolicy::ResourceManagerClient : public BnResourceManagerClient {
    explicit ResourceManagerClient() = default;

    Status reclaimResource(bool* _aidl_return) override {
        *_aidl_return = false;
        return Status::ok();
    }

    Status getName(::std::string* _aidl_return) override {
        _aidl_return->clear();
        return Status::ok();
    }

    virtual ~ResourceManagerClient() = default;
};

struct TranscodingUidPolicy::UidObserver : public BnUidObserver,
                                           public virtual IBinder::DeathRecipient {
    explicit UidObserver(TranscodingUidPolicy* owner) : mOwner(owner) {}

    // IUidObserver
    void onUidGone(uid_t uid, bool disabled) override;
    void onUidActive(uid_t uid) override;
    void onUidIdle(uid_t uid, bool disabled) override;
    void onUidStateChanged(uid_t uid, int32_t procState, int64_t procStateSeq,
                           int32_t capability) override;

    // IBinder::DeathRecipient implementation
    void binderDied(const wp<IBinder>& who) override;

    TranscodingUidPolicy* mOwner;
};

void TranscodingUidPolicy::UidObserver::onUidGone(uid_t uid __unused, bool disabled __unused) {}

void TranscodingUidPolicy::UidObserver::onUidActive(uid_t uid __unused) {}

void TranscodingUidPolicy::UidObserver::onUidIdle(uid_t uid __unused, bool disabled __unused) {}

void TranscodingUidPolicy::UidObserver::onUidStateChanged(uid_t uid, int32_t procState,
                                                          int64_t procStateSeq __unused,
                                                          int32_t capability __unused) {
    mOwner->onUidStateChanged(uid, procState);
}

void TranscodingUidPolicy::UidObserver::binderDied(const wp<IBinder>& /*who*/) {
    ALOGW("TranscodingUidPolicy: ActivityManager has died");
    // TODO(chz): this is a rare event (since if the AMS is dead, the system is
    // probably dead as well). But we should try to reconnect.
    mOwner->setUidObserverRegistered(false);
}

////////////////////////////////////////////////////////////////////////////

//static
bool TranscodingUidPolicy::getNamesForUids(const std::vector<int32_t>& uids,
                                           std::vector<std::string>* names) {
    names->clear();
    sp<IServiceManager> sm(defaultServiceManager());
    sp<IBinder> binder(sm->getService(String16("package_native")));
    if (binder == nullptr) {
        ALOGE("getService package_native failed");
        return false;
    }

    sp<content::pm::IPackageManagerNative> packageMgr =
            interface_cast<content::pm::IPackageManagerNative>(binder);
    binder::Status status = packageMgr->getNamesForUids(uids, names);

    if (!status.isOk() || names->size() != uids.size()) {
        names->clear();
        return false;
    }
    return true;
}

//static
status_t TranscodingUidPolicy::getUidForPackage(String16 packageName, /*inout*/ uid_t& uid) {
    PermissionController pc;
    uid = pc.getPackageUid(packageName, 0);
    if (uid <= 0) {
        ALOGE("Unknown package: '%s'", String8(packageName).string());
        return BAD_VALUE;
    }

    uid = multiuser_get_uid(0 /*userId*/, uid);
    return NO_ERROR;
}

TranscodingUidPolicy::TranscodingUidPolicy()
      : mAm(std::make_shared<ActivityManager>()),
        mUidObserver(new UidObserver(this)),
        mRegistered(false),
        mTopUidState(ActivityManager::PROCESS_STATE_UNKNOWN) {
    registerSelf();
    setProcessInfoOverride();
}

TranscodingUidPolicy::~TranscodingUidPolicy() {
    unregisterSelf();
}

void TranscodingUidPolicy::registerSelf() {
    status_t res = mAm->linkToDeath(mUidObserver.get());
    mAm->registerUidObserver(
            mUidObserver.get(),
            ActivityManager::UID_OBSERVER_GONE | ActivityManager::UID_OBSERVER_IDLE |
                    ActivityManager::UID_OBSERVER_ACTIVE | ActivityManager::UID_OBSERVER_PROCSTATE,
            ActivityManager::PROCESS_STATE_UNKNOWN, String16(kTranscodingTag));

    if (res == OK) {
        Mutex::Autolock _l(mUidLock);

        mRegistered = true;
        ALOGI("TranscodingUidPolicy: Registered with ActivityManager");
    } else {
        mAm->unregisterUidObserver(mUidObserver.get());
    }
}

void TranscodingUidPolicy::unregisterSelf() {
    mAm->unregisterUidObserver(mUidObserver.get());
    mAm->unlinkToDeath(mUidObserver.get());

    Mutex::Autolock _l(mUidLock);

    mRegistered = false;

    ALOGI("TranscodingUidPolicy: Unregistered with ActivityManager");
}

void TranscodingUidPolicy::setProcessInfoOverride() {
    ::ndk::SpAIBinder binder(AServiceManager_getService("media.resource_manager"));
    std::shared_ptr<IResourceManagerService> service = IResourceManagerService::fromBinder(binder);
    if (service == nullptr) {
        ALOGE("Failed to get IResourceManagerService");
        return;
    }

    mProcInfoOverrideClient = ::ndk::SharedRefBase::make<ResourceManagerClient>();
    Status status = service->overrideProcessInfo(
            mProcInfoOverrideClient, getpid(), ActivityManager::PROCESS_STATE_SERVICE, SERVICE_ADJ);
    if (!status.isOk()) {
        ALOGW("Failed to setProcessInfoOverride.");
    }
}

void TranscodingUidPolicy::setUidObserverRegistered(bool registered) {
    Mutex::Autolock _l(mUidLock);

    mRegistered = registered;
}

void TranscodingUidPolicy::setCallback(const std::shared_ptr<UidPolicyCallbackInterface>& cb) {
    mUidPolicyCallback = cb;
}

void TranscodingUidPolicy::registerMonitorUid(uid_t uid) {
    Mutex::Autolock _l(mUidLock);
    if (uid == OFFLINE_UID) {
        ALOGW("Ignoring the offline uid");
        return;
    }
    if (mUidStateMap.find(uid) != mUidStateMap.end()) {
        ALOGE("%s: Trying to register uid: %d which is already monitored!", __FUNCTION__, uid);
        return;
    }

    int32_t state = ActivityManager::PROCESS_STATE_UNKNOWN;
    if (mRegistered && mAm->isUidActive(uid, String16(kTranscodingTag))) {
        state = mAm->getUidProcessState(uid, String16(kTranscodingTag));
    }

    ALOGV("%s: inserting new uid: %u, procState %d", __FUNCTION__, uid, state);

    mUidStateMap.emplace(std::pair<uid_t, int32_t>(uid, state));
    mStateUidMap[state].insert(uid);

    updateTopUid_l();
}

void TranscodingUidPolicy::unregisterMonitorUid(uid_t uid) {
    Mutex::Autolock _l(mUidLock);

    auto it = mUidStateMap.find(uid);
    if (it == mUidStateMap.end()) {
        ALOGE("%s: Trying to unregister uid: %d which is not monitored!", __FUNCTION__, uid);
        return;
    }

    auto stateIt = mStateUidMap.find(it->second);
    if (stateIt != mStateUidMap.end()) {
        stateIt->second.erase(uid);
        if (stateIt->second.empty()) {
            mStateUidMap.erase(stateIt);
        }
    }
    mUidStateMap.erase(it);

    updateTopUid_l();
}

bool TranscodingUidPolicy::isUidOnTop(uid_t uid) {
    Mutex::Autolock _l(mUidLock);

    return mTopUidState != ActivityManager::PROCESS_STATE_UNKNOWN &&
           mTopUidState == getProcState_l(uid);
}

std::unordered_set<uid_t> TranscodingUidPolicy::getTopUids() const {
    Mutex::Autolock _l(mUidLock);

    if (mTopUidState == ActivityManager::PROCESS_STATE_UNKNOWN) {
        return std::unordered_set<uid_t>();
    }

    return mStateUidMap.at(mTopUidState);
}

void TranscodingUidPolicy::onUidStateChanged(uid_t uid, int32_t procState) {
    ALOGV("onUidStateChanged: %u, procState %d", uid, procState);

    bool topUidSetChanged = false;
    std::unordered_set<uid_t> topUids;
    {
        Mutex::Autolock _l(mUidLock);
        auto it = mUidStateMap.find(uid);
        if (it != mUidStateMap.end() && it->second != procState) {
            // Top set changed if 1) the uid is in the current top uid set, or 2) the
            // new procState is at least the same priority as the current top uid state.
            bool isUidCurrentTop = mTopUidState != ActivityManager::PROCESS_STATE_UNKNOWN &&
                                   mStateUidMap[mTopUidState].count(uid) > 0;
            bool isNewStateHigherThanTop = procState != ActivityManager::PROCESS_STATE_UNKNOWN &&
                                           (procState <= mTopUidState ||
                                            mTopUidState == ActivityManager::PROCESS_STATE_UNKNOWN);
            topUidSetChanged = (isUidCurrentTop || isNewStateHigherThanTop);

            // Move uid to the new procState.
            mStateUidMap[it->second].erase(uid);
            mStateUidMap[procState].insert(uid);
            it->second = procState;

            if (topUidSetChanged) {
                updateTopUid_l();

                // Make a copy of the uid set for callback.
                topUids = mStateUidMap[mTopUidState];
            }
        }
    }

    ALOGV("topUidSetChanged: %d", topUidSetChanged);

    if (topUidSetChanged) {
        auto callback = mUidPolicyCallback.lock();
        if (callback != nullptr) {
            callback->onTopUidsChanged(topUids);
        }
    }
}

void TranscodingUidPolicy::updateTopUid_l() {
    mTopUidState = ActivityManager::PROCESS_STATE_UNKNOWN;

    // Find the lowest uid state (ignoring PROCESS_STATE_UNKNOWN) with some monitored uids.
    for (auto stateIt = mStateUidMap.begin(); stateIt != mStateUidMap.end(); stateIt++) {
        if (stateIt->first != ActivityManager::PROCESS_STATE_UNKNOWN && !stateIt->second.empty()) {
            mTopUidState = stateIt->first;
            break;
        }
    }

    ALOGV("%s: top uid state is %d", __FUNCTION__, mTopUidState);
}

int32_t TranscodingUidPolicy::getProcState_l(uid_t uid) {
    auto it = mUidStateMap.find(uid);
    if (it != mUidStateMap.end()) {
        return it->second;
    }
    return ActivityManager::PROCESS_STATE_UNKNOWN;
}

}  // namespace android
