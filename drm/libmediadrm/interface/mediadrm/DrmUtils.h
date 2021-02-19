/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_DRMUTILS_H
#define ANDROID_DRMUTILS_H

#include <android/hardware/drm/1.0/ICryptoFactory.h>
#include <android/hardware/drm/1.0/IDrmFactory.h>
#include <android/hardware/drm/1.4/IDrmPlugin.h>
#include <android/hardware/drm/1.4/types.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/Errors.h>  // for status_t
#include <utils/Log.h>
#include <utils/String8.h>
#include <utils/StrongPointer.h>
#include <utils/Vector.h>
#include <ctime>
#include <vector>


using namespace ::android::hardware::drm;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;

namespace android {

struct ICrypto;
struct IDrm;

namespace DrmUtils {

bool UseDrmService();

sp<IDrm> MakeDrm(status_t *pstatus = nullptr);

sp<ICrypto> MakeCrypto(status_t *pstatus = nullptr);

template<typename BA, typename PARCEL>
void WriteByteArray(PARCEL &obj, const BA &vec) {
    obj.writeInt32(vec.size());
    if (vec.size()) {
        obj.write(vec.data(), vec.size());
    }
}

template<typename ET, typename BA, typename PARCEL>
void WriteEventToParcel(
        PARCEL &obj,
        ET eventType,
        const BA &sessionId,
        const BA &data) {
    WriteByteArray(obj, sessionId);
    WriteByteArray(obj, data);
    obj.writeInt32(eventType);
}

template<typename BA, typename PARCEL>
void WriteExpirationUpdateToParcel(
        PARCEL &obj,
        const BA &sessionId,
        int64_t expiryTimeInMS) {
    WriteByteArray(obj, sessionId);
    obj.writeInt64(expiryTimeInMS);
}

template<typename BA, typename KSL, typename PARCEL>
void WriteKeysChange(
        PARCEL &obj,
        const BA &sessionId,
        const KSL &keyStatusList,
        bool hasNewUsableKey) {
    WriteByteArray(obj, sessionId);
    obj.writeInt32(keyStatusList.size());
    for (const auto &keyStatus : keyStatusList) {
        WriteByteArray(obj, keyStatus.keyId);
        obj.writeInt32(keyStatus.type);
    }
    obj.writeInt32(hasNewUsableKey);
}

std::vector<sp<::V1_0::IDrmFactory>> MakeDrmFactories(const uint8_t uuid[16] = nullptr);

std::vector<sp<::V1_0::IDrmPlugin>> MakeDrmPlugins(const uint8_t uuid[16],
                                                   const char *appPackageName);

std::vector<sp<::V1_0::ICryptoFactory>> MakeCryptoFactories(const uint8_t uuid[16]);

std::vector<sp<::V1_0::ICryptoPlugin>> MakeCryptoPlugins(const uint8_t uuid[16],
                                                         const void *initData, size_t initDataSize);

status_t toStatusT_1_4(::V1_4::Status status);

template<typename S>
inline status_t toStatusT(S status) {
    auto err = static_cast<::V1_4::Status>(status);
    return toStatusT_1_4(err);
}

template<typename T>
inline status_t toStatusT(const android::hardware::Return<T> &status) {
    auto t = static_cast<T>(status);
    auto err = static_cast<::V1_4::Status>(t);
    return toStatusT_1_4(err);
}

template<typename T, typename U>
status_t GetLogMessages(const sp<U> &obj, Vector<::V1_4::LogMessage> &logs) {
    sp<T> plugin = T::castFrom(obj);
    if (plugin == NULL) {
        return ERROR_UNSUPPORTED;
    }

    ::V1_4::Status err{};
    ::V1_4::IDrmPlugin::getLogMessages_cb cb = [&](
            ::V1_4::Status status,
            hidl_vec<::V1_4::LogMessage> hLogs) {
        if (::V1_4::Status::OK == status) {
            err = status;
            return;
        }
        logs.appendArray(hLogs.data(), hLogs.size());
    };

    Return<void> hResult = plugin->getLogMessages(cb);
    if (!hResult.isOk()) {
        return DEAD_OBJECT;
    }
    return toStatusT(err);
}

namespace {
static inline char logPriorityToChar(::V1_4::LogPriority priority) {
    char p = 'U';
    switch (priority) {
        case ::V1_4::LogPriority::VERBOSE:  p = 'V'; break;
        case ::V1_4::LogPriority::DEBUG:    p = 'D'; break;
        case ::V1_4::LogPriority::INFO:     p = 'I'; break;
        case ::V1_4::LogPriority::WARN:     p = 'W'; break;
        case ::V1_4::LogPriority::ERROR:    p = 'E'; break;
        case ::V1_4::LogPriority::FATAL:    p = 'F'; break;
        default: p = 'U'; break;
    }
    return p;
}
}

template<typename T>
std::string GetExceptionMessage(status_t err, const char *msg, const sp<T> &iface) {
    String8 msg8;
    if (msg) {
        msg8 += msg;
        msg8 += ": ";
    }
    auto errStr = StrCryptoError(err);
    msg8 += errStr.c_str();

    Vector<::V1_4::LogMessage> logs;
    if (iface->getLogMessages(logs) != NO_ERROR) {
        return msg8.c_str();
    }

    for (auto log: logs) {
        time_t seconds = log.timeMs / 1000;
        int ms = log.timeMs % 1000;
        char buf[64] = {0};
        std::string timeStr = "00-00 00:00:00";
        if (strftime(buf, sizeof buf, "%m-%d %H:%M:%S", std::localtime(&seconds))) {
            timeStr = buf;
        }

        char p = logPriorityToChar(log.priority);
        msg8 += String8::format("\n%s.%03d %c %s",
                timeStr.c_str(), ms, p, log.message.c_str());
    }

    return msg8.c_str();
}

} // namespace DrmUtils
} // namespace android
#endif // ANDROID_DRMUTILS_H
