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

#include <binder/ActivityManager.h>
#include <cutils/misc.h>  // FIRST_APPLICATION_UID
#include <inttypes.h>
#include <media/TranscodingUidPolicy.h>
#include <utils/Log.h>

#include <utility>

namespace android {

constexpr static uid_t OFFLINE_UID = -1;
constexpr static const char* kTranscodingTag = "transcoding";

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

TranscodingUidPolicy::TranscodingUidPolicy()
      : mAm(std::make_shared<ActivityManager>()),
        mUidObserver(new UidObserver(this)),
        mRegistered(false),
        mTopUidState(ActivityManager::PROCESS_STATE_UNKNOWN) {
    registerSelf();
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
    if (mRegistered && mAm->isUidActiveOrForeground(uid, String16(kTranscodingTag))) {
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
