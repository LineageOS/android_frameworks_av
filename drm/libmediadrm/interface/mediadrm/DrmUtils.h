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
#include <mediadrm/DrmMetricsLogger.h>
#include <mediadrm/DrmStatus.h>
#include <utils/Errors.h>  // for status_t
#include <utils/Log.h>
#include <utils/String8.h>
#include <utils/StrongPointer.h>
#include <utils/Vector.h>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <endian.h>
#include <inttypes.h>
#include <iterator>
#include <mutex>
#include <string>
#include <vector>
#include <aidl/android/hardware/drm/LogMessage.h>
#include <aidl/android/hardware/drm/Status.h>
#include <aidl/android/hardware/drm/IDrmFactory.h>

using namespace ::android::hardware::drm;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;

using ::aidl::android::hardware::drm::LogPriority;
using ::aidl::android::hardware::drm::LogMessage;
using ::aidl::android::hardware::drm::Uuid;
using StatusAidl = ::aidl::android::hardware::drm::Status;
using IDrmFactoryAidl = ::aidl::android::hardware::drm::IDrmFactory;

namespace android {

struct ICrypto;
struct IDrm;

namespace DrmUtils {

// Log APIs
class LogBuffer {
  public:
    static const int MAX_CAPACITY = 100;
    void addLog(const ::V1_4::LogMessage &log);
    Vector<::V1_4::LogMessage> getLogs();

  private:
    std::deque<::V1_4::LogMessage> mBuffer;
    std::mutex mMutex;
};

extern LogBuffer gLogBuf;

static inline int formatBuffer(char *buf, size_t size, const char *msg) {
    return snprintf(buf, size, "%s", msg);
}

template <typename First, typename... Args>
static inline int formatBuffer(char *buf, size_t size, const char *fmt, First first, Args... args) {
    return snprintf(buf, size, fmt, first, args...);
}

template <typename... Args>
void LogToBuffer(android_LogPriority level, const char *fmt, Args... args) {
    const int LOG_BUF_SIZE = 256;
    char buf[LOG_BUF_SIZE];
    int len = formatBuffer(buf, LOG_BUF_SIZE, fmt, args...);
    if (len <= 0) {
        return;
    }
    __android_log_write(level, LOG_TAG, buf);
    if (level >= ANDROID_LOG_INFO) {
        int64_t epochTimeMs =
                std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
        gLogBuf.addLog({epochTimeMs, static_cast<::V1_4::LogPriority>(level), buf});
    }
}

template <typename... Args>
void LogToBuffer(android_LogPriority level, const uint8_t uuid[16], const char *fmt, Args... args) {
    uint64_t uuid2[2] = {};
    std::memcpy(uuid2, uuid, sizeof(uuid2));
    std::string uuidFmt("uuid=[%" PRIx64 " %" PRIx64 "] ");
    uuidFmt += fmt;
    LogToBuffer(level, uuidFmt.c_str(), betoh64(uuid2[0]), betoh64(uuid2[1]), args...);
}

#ifndef LOG2BE
#define LOG2BE(...) LogToBuffer(ANDROID_LOG_ERROR, __VA_ARGS__)
#define LOG2BW(...) LogToBuffer(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOG2BI(...) LogToBuffer(ANDROID_LOG_INFO, __VA_ARGS__)
#define LOG2BD(...) LogToBuffer(ANDROID_LOG_DEBUG, __VA_ARGS__)
#define LOG2BV(...) LogToBuffer(ANDROID_LOG_VERBOSE, __VA_ARGS__)
#endif

bool UseDrmService();

sp<IDrm> MakeDrm(IDrmFrontend frontend = IDRM_JNI, status_t* pstatus = nullptr);

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

inline Uuid toAidlUuid(const uint8_t uuid[16]) {
    Uuid uuidAidl;
    for (int i = 0; i < 16; ++i) uuidAidl.uuid[i] = uuid[i];
    return uuidAidl;
}

std::vector<std::shared_ptr<IDrmFactoryAidl>> makeDrmFactoriesAidl();

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

DrmStatus statusAidlToDrmStatus(::ndk::ScopedAStatus& statusAidl);

template<typename T, typename U>
status_t GetLogMessagesAidl(const std::shared_ptr<U> &obj, Vector<::V1_4::LogMessage> &logs) {
    std::shared_ptr<T> plugin = obj;
    if (obj == NULL) {
        LOG2BW("%s obj is null", U::descriptor);
    } else if (plugin == NULL) {
        LOG2BW("Cannot cast %s obj to %s plugin", U::descriptor, T::descriptor);
    }

    std::vector<LogMessage> pluginLogsAidl;
    if (plugin != NULL) {
        if(!plugin->getLogMessages(&pluginLogsAidl).isOk()) {
            LOG2BW("%s::getLogMessages remote call failed", T::descriptor);
        }
    }

    std::vector<::V1_4::LogMessage> pluginLogs;
    for (LogMessage log : pluginLogsAidl) {
        ::V1_4::LogMessage logHidl;
        logHidl.timeMs = log.timeMs;
        // skip negative convert check as count of enum elements is 7
        logHidl.priority =  static_cast<::V1_4::LogPriority>((int32_t)log.priority);
        logHidl.message = log.message;
        pluginLogs.push_back(logHidl);
    }

    auto allLogs(gLogBuf.getLogs());
    LOG2BD("framework logs size %zu; plugin logs size %zu",
           allLogs.size(), pluginLogs.size());
    std::copy(pluginLogs.begin(), pluginLogs.end(), std::back_inserter(allLogs));
    std::sort(allLogs.begin(), allLogs.end(),
              [](const ::V1_4::LogMessage &a, const ::V1_4::LogMessage &b) {
                  return a.timeMs < b.timeMs;
              });

    logs.appendVector(allLogs);
    return OK;
}

template<typename T, typename U>
status_t GetLogMessages(const sp<U> &obj, Vector<::V1_4::LogMessage> &logs) {
    sp<T> plugin = T::castFrom(obj);
    if (obj == NULL) {
        LOG2BW("%s obj is null", U::descriptor);
    } else if (plugin == NULL) {
        LOG2BW("Cannot cast %s obj to %s plugin", U::descriptor, T::descriptor);
    }

    ::V1_4::Status err{};
    std::vector<::V1_4::LogMessage> pluginLogs;
    ::V1_4::IDrmPlugin::getLogMessages_cb cb = [&](
            ::V1_4::Status status,
            hidl_vec<::V1_4::LogMessage> hLogs) {
        if (::V1_4::Status::OK != status) {
            err = status;
            return;
        }
        pluginLogs.assign(hLogs.data(), hLogs.data() + hLogs.size());
    };

    Return<void> hResult;
    if (plugin != NULL) {
        hResult = plugin->getLogMessages(cb);
    }
    if (!hResult.isOk()) {
        LOG2BW("%s::getLogMessages remote call failed %s",
               T::descriptor, hResult.description().c_str());
    }

    auto allLogs(gLogBuf.getLogs());
    LOG2BD("framework logs size %zu; plugin logs size %zu",
           allLogs.size(), pluginLogs.size());
    std::copy(pluginLogs.begin(), pluginLogs.end(), std::back_inserter(allLogs));
    std::sort(allLogs.begin(), allLogs.end(),
              [](const ::V1_4::LogMessage &a, const ::V1_4::LogMessage &b) {
                  return a.timeMs < b.timeMs;
              });

    logs.appendVector(allLogs);
    return toStatusT(err);
}

std::string GetExceptionMessage(const DrmStatus & err, const char *defaultMsg,
                                const Vector<::V1_4::LogMessage> &logs);

template<typename T>
std::string GetExceptionMessage(const DrmStatus &err, const char *defaultMsg, const sp<T> &iface) {
    Vector<::V1_4::LogMessage> logs;
    if (iface != NULL) {
        iface->getLogMessages(logs);
    }
    return GetExceptionMessage(err, defaultMsg, logs);
}

} // namespace DrmUtils
} // namespace android
#endif // ANDROID_DRMUTILS_H
