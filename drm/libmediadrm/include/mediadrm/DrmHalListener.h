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

#ifndef DRM_HAL_LISTENER_H_
#define DRM_HAL_LISTENER_H_

#include <aidl/android/hardware/drm/BnDrmPluginListener.h>
#include <mediadrm/DrmMetrics.h>
#include <mediadrm/IDrmClient.h>

using EventTypeAidl = ::aidl::android::hardware::drm::EventType;
using KeyStatusAidl = ::aidl::android::hardware::drm::KeyStatus;
using aidl::android::hardware::drm::BnDrmPluginListener;

namespace android {
struct DrmHalListener : public BnDrmPluginListener {
    explicit DrmHalListener(const std::shared_ptr<MediaDrmMetrics>& in_metrics);
    ~DrmHalListener();
    ::ndk::ScopedAStatus onEvent(EventTypeAidl in_eventType,
                                 const std::vector<uint8_t>& in_sessionId,
                                 const std::vector<uint8_t>& in_data);
    ::ndk::ScopedAStatus onExpirationUpdate(const std::vector<uint8_t>& in_sessionId,
                                            int64_t in_expiryTimeInMS);
    ::ndk::ScopedAStatus onKeysChange(const std::vector<uint8_t>& in_sessionId,
                                      const std::vector<KeyStatusAidl>& in_keyStatusList,
                                      bool in_hasNewUsableKey);
    ::ndk::ScopedAStatus onSessionLostState(const std::vector<uint8_t>& in_sessionId);
    void setListener(const sp<IDrmClient>& listener);
private:
    std::shared_ptr<MediaDrmMetrics> mMetrics;
    sp<IDrmClient> mListener;
    mutable Mutex mEventLock;
    mutable Mutex mNotifyLock;
};
} // namespace android

#endif  // DRM_HAL_LISTENER_H_