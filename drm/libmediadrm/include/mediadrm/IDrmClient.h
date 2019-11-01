/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef ANDROID_IDRMCLIENT_H
#define ANDROID_IDRMCLIENT_H

#include <utils/RefBase.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <media/drm/DrmAPI.h>

#include <android/hardware/drm/1.2/types.h>
#include <hidl/HidlSupport.h>

#include <cstdint>
#include <vector>

namespace android {

struct DrmKeyStatus {
    const uint32_t type;
    const hardware::hidl_vec<uint8_t> keyId;
};

class IDrmClient: public IInterface
{
public:
    DECLARE_META_INTERFACE(DrmClient);

    virtual void sendEvent(
            DrmPlugin::EventType eventType,
            const hardware::hidl_vec<uint8_t> &sessionId,
            const hardware::hidl_vec<uint8_t> &data) = 0;

    virtual void sendExpirationUpdate(
            const hardware::hidl_vec<uint8_t> &sessionId,
            int64_t expiryTimeInMS) = 0;

    virtual void sendKeysChange(
            const hardware::hidl_vec<uint8_t> &sessionId,
            const std::vector<DrmKeyStatus> &keyStatusList,
            bool hasNewUsableKey) = 0;

    virtual void sendSessionLostState(
            const hardware::hidl_vec<uint8_t> &sessionId) = 0;

};

// ----------------------------------------------------------------------------

class BnDrmClient: public BnInterface<IDrmClient>
{
public:
    virtual status_t onTransact(uint32_t code,
                                const Parcel& data,
                                Parcel* reply,
                                uint32_t flags = 0);
};

}; // namespace android

#endif // ANDROID_IDRMCLIENT_H
