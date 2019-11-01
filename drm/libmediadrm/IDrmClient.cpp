/*
**
** Copyright 2013, The Android Open Source Project
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
#define LOG_TAG "IDrmClient"

#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/RefBase.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <hidl/HidlSupport.h>

#include <media/IMediaPlayerClient.h>
#include <mediadrm/DrmUtils.h>
#include <mediadrm/IDrmClient.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace android {

enum {
    SEND_EVENT = IBinder::FIRST_CALL_TRANSACTION,
    SEND_EXPIRATION_UPDATE,
    SEND_KEYS_CHANGE,
    SEND_SESSION_LOST_STATE,
};

namespace {

hardware::hidl_vec<uint8_t> ReadByteArray(const Parcel &obj, status_t *err)
{
    int32_t len = obj.readInt32();
    hardware::hidl_vec<uint8_t> ret;
    if (len < 0) {
        ALOGE("Invalid array len");
        *err = BAD_VALUE;
        return ret;
    }
    ret.resize(static_cast<size_t>(len));
    *err = obj.read(ret.data(), ret.size());
    return ret;
}

}

class BpDrmClient: public BpInterface<IDrmClient>
{
    template <typename F>
    void notify(uint32_t code, F fillParcel) {
        Parcel obj, reply;
        obj.writeInterfaceToken(IDrmClient::getInterfaceDescriptor());
        fillParcel(obj);
        remote()->transact(code, obj, &reply, IBinder::FLAG_ONEWAY);
    }

public:
    explicit BpDrmClient(const sp<IBinder>& impl)
        : BpInterface<IDrmClient>(impl)
    {
    }

    virtual void sendEvent(
            DrmPlugin::EventType eventType,
            const hardware::hidl_vec<uint8_t> &sessionId,
            const hardware::hidl_vec<uint8_t> &data)
    {
        auto fillParcel = [&] (Parcel &p) {
            DrmUtils::WriteEventToParcel(p, eventType, sessionId, data);
        };
        notify(SEND_EVENT, fillParcel);
    }

    virtual void sendExpirationUpdate(
            const hardware::hidl_vec<uint8_t> &sessionId,
            int64_t expiryTimeInMS)
    {
        auto fillParcel = [&] (Parcel &p) {
            DrmUtils::WriteExpirationUpdateToParcel(p, sessionId, expiryTimeInMS);
        };
        notify(SEND_EXPIRATION_UPDATE, fillParcel);
    }

    virtual void sendKeysChange(
            const hardware::hidl_vec<uint8_t> &sessionId,
            const std::vector<DrmKeyStatus> &keyStatusList,
            bool hasNewUsableKey)
    {
        auto fillParcel = [&] (Parcel &p) {
            DrmUtils::WriteKeysChange(p, sessionId, keyStatusList, hasNewUsableKey);
        };
        notify(SEND_KEYS_CHANGE, fillParcel);
    }

    virtual void sendSessionLostState(
            const hardware::hidl_vec<uint8_t> &sessionId)
    {
        auto fillParcel = [&] (Parcel &p) {
            DrmUtils::WriteByteArray(p, sessionId);
        };
        notify(SEND_SESSION_LOST_STATE, fillParcel);
    }
};

IMPLEMENT_META_INTERFACE(DrmClient, "android.media.IDrmClient");

// ----------------------------------------------------------------------

status_t BnDrmClient::onTransact(
    uint32_t code, const Parcel& obj, Parcel* reply, uint32_t flags)
{
    CHECK_INTERFACE(IDrmClient, obj, reply);
    status_t err = NO_ERROR;
    hardware::hidl_vec<uint8_t> sessionId(ReadByteArray(obj, &err));
    if (err != NO_ERROR) {
        ALOGE("Failed to read session id, error=%d", err);
        return err;
    }

    switch (code) {
        case SEND_EVENT: {
            hardware::hidl_vec<uint8_t> data(ReadByteArray(obj, &err));
            int eventType = obj.readInt32();
            if (err == NO_ERROR) {
                sendEvent(static_cast<DrmPlugin::EventType>(eventType), sessionId, data);
            }
            return err;
        } break;
        case SEND_EXPIRATION_UPDATE: {
            int64_t expiryTimeInMS = obj.readInt64();
            sendExpirationUpdate(sessionId, expiryTimeInMS);
            return NO_ERROR;
        } break;
        case SEND_KEYS_CHANGE: {
            // ...
            int32_t n = obj.readInt32();
            if (n < 0) {
                return BAD_VALUE;
            }
            std::vector<DrmKeyStatus> keyStatusList;
            for (int32_t i = 0; i < n; ++i) {
                hardware::hidl_vec<uint8_t> keyId(ReadByteArray(obj, &err));
                if (err != NO_ERROR) {
                    return err;
                }
                int32_t type = obj.readInt32();
                if (type < 0) {
                    return BAD_VALUE;
                }
                keyStatusList.push_back({static_cast<uint32_t>(type), keyId});
            }
            int32_t hasNewUsableKey = obj.readInt32();
            sendKeysChange(sessionId, keyStatusList, hasNewUsableKey);
            return NO_ERROR;
        } break;
        case SEND_SESSION_LOST_STATE: {
            sendSessionLostState(sessionId);
            return NO_ERROR;
        } break;
        default:
            return BBinder::onTransact(code, obj, reply, flags);
    }
}

} // namespace android
