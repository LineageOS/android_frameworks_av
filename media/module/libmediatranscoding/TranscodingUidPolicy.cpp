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

#include <android/activity_manager.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <inttypes.h>
#include <media/TranscodingDefs.h>
#include <media/TranscodingUidPolicy.h>
#include <utils/Log.h>

#include <utility>

namespace android {

constexpr static uid_t OFFLINE_UID = -1;
constexpr static int32_t IMPORTANCE_UNKNOWN = INT32_MAX;

TranscodingUidPolicy::TranscodingUidPolicy()
      : mUidObserver(nullptr), mRegistered(false), mTopUidState(IMPORTANCE_UNKNOWN) {
    registerSelf();
}

TranscodingUidPolicy::~TranscodingUidPolicy() {
    unregisterSelf();
}

void TranscodingUidPolicy::OnUidImportance(uid_t uid, int32_t uidImportance, void* cookie) {
    TranscodingUidPolicy* owner = reinterpret_cast<TranscodingUidPolicy*>(cookie);
    owner->onUidStateChanged(uid, uidImportance);
}

void TranscodingUidPolicy::registerSelf() {
    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        mUidObserver = AActivityManager_addUidImportanceListener(&OnUidImportance, -1, (void*)this);
    }

    if (mUidObserver == nullptr) {
        ALOGE("Failed to register uid observer");
        return;
    }

    Mutex::Autolock _l(mUidLock);
    mRegistered = true;
    ALOGI("Registered uid observer");
}

void TranscodingUidPolicy::unregisterSelf() {
    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        AActivityManager_removeUidImportanceListener(mUidObserver);
        mUidObserver = nullptr;

        Mutex::Autolock _l(mUidLock);
        mRegistered = false;
        ALOGI("Unregistered uid observer");
    } else {
        ALOGE("Failed to unregister uid observer");
    }
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

    int32_t state = IMPORTANCE_UNKNOWN;
    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        if (mRegistered && AActivityManager_isUidActive(uid)) {
            state = AActivityManager_getUidImportance(uid);
        }
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

    return mTopUidState != IMPORTANCE_UNKNOWN && mTopUidState == getProcState_l(uid);
}

std::unordered_set<uid_t> TranscodingUidPolicy::getTopUids() const {
    Mutex::Autolock _l(mUidLock);

    if (mTopUidState == IMPORTANCE_UNKNOWN) {
        return std::unordered_set<uid_t>();
    }

    return mStateUidMap.at(mTopUidState);
}

void TranscodingUidPolicy::onUidStateChanged(uid_t uid, int32_t procState) {
    ALOGV("onUidStateChanged: uid %u, procState %d", uid, procState);

    bool topUidSetChanged = false;
    bool isUidGone = false;
    std::unordered_set<uid_t> topUids;
    {
        Mutex::Autolock _l(mUidLock);
        auto it = mUidStateMap.find(uid);
        if (it != mUidStateMap.end() && it->second != procState) {
            isUidGone = (procState == AACTIVITYMANAGER_IMPORTANCE_GONE);

            topUids = mStateUidMap[mTopUidState];

            // Move uid to the new procState.
            mStateUidMap[it->second].erase(uid);
            mStateUidMap[procState].insert(uid);
            it->second = procState;

            updateTopUid_l();
            if (topUids != mStateUidMap[mTopUidState]) {
                // Make a copy of the uid set for callback.
                topUids = mStateUidMap[mTopUidState];
                topUidSetChanged = true;
            }
        }
    }

    ALOGV("topUidSetChanged: %d, isUidGone %d", topUidSetChanged, isUidGone);

    if (topUidSetChanged) {
        auto callback = mUidPolicyCallback.lock();
        if (callback != nullptr) {
            callback->onTopUidsChanged(topUids);
        }
    }
    if (isUidGone) {
        auto callback = mUidPolicyCallback.lock();
        if (callback != nullptr) {
            callback->onUidGone(uid);
        }
    }
}

void TranscodingUidPolicy::updateTopUid_l() {
    mTopUidState = IMPORTANCE_UNKNOWN;

    // Find the lowest uid state (ignoring PROCESS_STATE_UNKNOWN) with some monitored uids.
    for (auto stateIt = mStateUidMap.begin(); stateIt != mStateUidMap.end(); stateIt++) {
        if (stateIt->first != IMPORTANCE_UNKNOWN && !stateIt->second.empty()) {
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
    return IMPORTANCE_UNKNOWN;
}

}  // namespace android
