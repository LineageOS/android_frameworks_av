/*
 * Copyright (C) 2022 The Android Open Source Project
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
#define LOG_TAG "DrmHalListener"

#include <mediadrm/DrmHalListener.h>

using ::aidl::android::hardware::drm::KeyStatusType;
using ::android::hardware::hidl_vec;

namespace android {

static const Vector<uint8_t> toVector(const std::vector<uint8_t>& vec) {
    Vector<uint8_t> vector;
    vector.appendArray(vec.data(), vec.size());
    return *const_cast<const Vector<uint8_t>*>(&vector);
}

template <typename T = uint8_t>
static hidl_vec<T> toHidlVec(const Vector<T>& vector) {
    hidl_vec<T> vec;
    vec.setToExternal(const_cast<T*>(vector.array()), vector.size());
    return vec;
}

DrmHalListener::DrmHalListener(const std::shared_ptr<MediaDrmMetrics>& metrics)
    : mMetrics(metrics) {}

DrmHalListener::~DrmHalListener() {}

void DrmHalListener::setListener(const sp<IDrmClient>& listener) {
    Mutex::Autolock lock(mEventLock);
    mListener = listener;
}

::ndk::ScopedAStatus DrmHalListener::onEvent(EventTypeAidl eventTypeAidl,
                                         const std::vector<uint8_t>& sessionId,
                                         const std::vector<uint8_t>& data) {
    mMetrics->mEventCounter.Increment((uint32_t)eventTypeAidl);

    mEventLock.lock();
    sp<IDrmClient> listener = mListener;
    mEventLock.unlock();

    if (listener != NULL) {
        Mutex::Autolock lock(mNotifyLock);
        DrmPlugin::EventType eventType;
        switch (eventTypeAidl) {
            case EventTypeAidl::PROVISION_REQUIRED:
                eventType = DrmPlugin::kDrmPluginEventProvisionRequired;
                break;
            case EventTypeAidl::KEY_NEEDED:
                eventType = DrmPlugin::kDrmPluginEventKeyNeeded;
                break;
            case EventTypeAidl::KEY_EXPIRED:
                eventType = DrmPlugin::kDrmPluginEventKeyExpired;
                break;
            case EventTypeAidl::VENDOR_DEFINED:
                eventType = DrmPlugin::kDrmPluginEventVendorDefined;
                break;
            case EventTypeAidl::SESSION_RECLAIMED:
                eventType = DrmPlugin::kDrmPluginEventSessionReclaimed;
                break;
            default:
                return ::ndk::ScopedAStatus::ok();
        }

        listener->sendEvent(eventType, toHidlVec(toVector(sessionId)), toHidlVec(toVector(data)));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus DrmHalListener::onExpirationUpdate(const std::vector<uint8_t>& sessionId,
                                                    int64_t expiryTimeInMS) {
    mEventLock.lock();
    sp<IDrmClient> listener = mListener;
    mEventLock.unlock();

    if (listener != NULL) {
        Mutex::Autolock lock(mNotifyLock);
        listener->sendExpirationUpdate(toHidlVec(toVector(sessionId)), expiryTimeInMS);
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus DrmHalListener::onKeysChange(const std::vector<uint8_t>& sessionId,
                                              const std::vector<KeyStatusAidl>& keyStatusListAidl,
                                              bool hasNewUsableKey) {
    mEventLock.lock();
    sp<IDrmClient> listener = mListener;
    mEventLock.unlock();

    if (listener != NULL) {
        std::vector<DrmKeyStatus> keyStatusList;
        size_t nKeys = keyStatusListAidl.size();
        for (size_t i = 0; i < nKeys; ++i) {
            const KeyStatusAidl keyStatus = keyStatusListAidl[i];
            uint32_t type;
            switch (keyStatus.type) {
                case KeyStatusType::USABLE:
                    type = DrmPlugin::kKeyStatusType_Usable;
                    break;
                case KeyStatusType::EXPIRED:
                    type = DrmPlugin::kKeyStatusType_Expired;
                    break;
                case KeyStatusType::OUTPUT_NOT_ALLOWED:
                    type = DrmPlugin::kKeyStatusType_OutputNotAllowed;
                    break;
                case KeyStatusType::STATUS_PENDING:
                    type = DrmPlugin::kKeyStatusType_StatusPending;
                    break;
                case KeyStatusType::USABLE_IN_FUTURE:
                    type = DrmPlugin::kKeyStatusType_UsableInFuture;
                    break;
                case KeyStatusType::INTERNAL_ERROR:
                default:
                    type = DrmPlugin::kKeyStatusType_InternalError;
                    break;
            }
            keyStatusList.push_back({type, toHidlVec(toVector(keyStatus.keyId))});
            mMetrics->mKeyStatusChangeCounter.Increment((uint32_t)keyStatus.type);
        }

        Mutex::Autolock lock(mNotifyLock);
        listener->sendKeysChange(toHidlVec(toVector(sessionId)), keyStatusList, hasNewUsableKey);
    }
    else {
        // There's no listener. But we still want to count the key change
        // events.
        size_t nKeys = keyStatusListAidl.size();

        for (size_t i = 0; i < nKeys; i++) {
            mMetrics->mKeyStatusChangeCounter.Increment((uint32_t)keyStatusListAidl[i].type);
        }
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus DrmHalListener::onSessionLostState(const std::vector<uint8_t>& sessionId) {
    ::ndk::ScopedAStatus _aidl_status;
    mEventLock.lock();
    sp<IDrmClient> listener = mListener;
    mEventLock.unlock();

    if (listener != NULL) {
        Mutex::Autolock lock(mNotifyLock);
        listener->sendSessionLostState(toHidlVec(toVector(sessionId)));
    }

    return ::ndk::ScopedAStatus::ok();
}

}  // namespace android