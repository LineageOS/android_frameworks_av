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

//#define LOG_NDEBUG 0
#define LOG_TAG "DrmUtils"

#include <android/binder_manager.h>
#include <android/hardware/drm/1.0/ICryptoFactory.h>
#include <android/hardware/drm/1.0/ICryptoPlugin.h>
#include <android/hardware/drm/1.0/IDrmFactory.h>
#include <android/hardware/drm/1.0/IDrmPlugin.h>
#include <android/hardware/drm/1.1/ICryptoFactory.h>
#include <android/hardware/drm/1.1/IDrmFactory.h>
#include <android/hardware/drm/1.2/ICryptoFactory.h>
#include <android/hardware/drm/1.2/IDrmFactory.h>
#include <android/hardware/drm/1.3/ICryptoFactory.h>
#include <android/hardware/drm/1.3/IDrmFactory.h>
#include <android/hardware/drm/1.4/ICryptoFactory.h>
#include <android/hardware/drm/1.4/IDrmFactory.h>
#include <android/hidl/manager/1.2/IServiceManager.h>
#include <hidl/HidlSupport.h>
#include <json/json.h>

#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/String16.h>

#include <mediadrm/CryptoHal.h>
#include <mediadrm/DrmHal.h>
#include <mediadrm/DrmUtils.h>
#include <mediadrm/ICrypto.h>
#include <mediadrm/IDrm.h>

#include <map>
#include <string>

using HServiceManager = ::android::hidl::manager::V1_2::IServiceManager;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using namespace ::android::hardware::drm;

namespace android {
namespace DrmUtils {

namespace {

template <typename Hal>
Hal* MakeObject(status_t* pstatus) {
    status_t err = OK;
    status_t& status = pstatus ? *pstatus : err;
    auto obj = new Hal();
    status = obj->initCheck();
    if (status != OK && status != NO_INIT) {
        return NULL;
    }
    return obj;
}

template <typename Hal, typename V, typename M>
void MakeHidlFactories(const uint8_t uuid[16], V& factories, M& instances) {
    sp<HServiceManager> serviceManager = HServiceManager::getService();
    if (serviceManager == nullptr) {
        LOG2BE("Failed to get service manager");
        return;
    }

    serviceManager->listManifestByInterface(
            Hal::descriptor, [&](const hidl_vec<hidl_string>& registered) {
                for (const auto& instance : registered) {
                    auto factory = Hal::getService(instance);
                    if (factory != nullptr) {
                        instances[instance.c_str()] = Hal::descriptor;
                        if (!uuid) {
                            factories.push_back(factory);
                            continue;
                        }
                        auto supported = factory->isCryptoSchemeSupported(uuid);
                        if (!supported.isOk()) {
                            LOG2BE(uuid, "isCryptoSchemeSupported txn failed: %s",
                                   supported.description().c_str());
                            continue;
                        }
                        if (supported) {
                            factories.push_back(factory);
                        }
                    }
                }
            });
}

template <typename Hal, typename V>
void MakeHidlFactories(const uint8_t uuid[16], V& factories) {
    std::map<std::string, std::string> instances;
    MakeHidlFactories<Hal>(uuid, factories, instances);
}

hidl_vec<uint8_t> toHidlVec(const void* ptr, size_t size) {
    hidl_vec<uint8_t> vec(size);
    if (ptr != nullptr) {
        memcpy(vec.data(), ptr, size);
    }
    return vec;
}

hidl_array<uint8_t, 16> toHidlArray16(const uint8_t* ptr) {
    if (ptr == nullptr) {
        return hidl_array<uint8_t, 16>();
    }
    return hidl_array<uint8_t, 16>(ptr);
}

sp<::V1_0::IDrmPlugin> MakeDrmPlugin(const sp<::V1_0::IDrmFactory>& factory, const uint8_t uuid[16],
                                     const char* appPackageName) {
    sp<::V1_0::IDrmPlugin> plugin;
    auto err = factory->createPlugin(
            toHidlArray16(uuid), hidl_string(appPackageName),
            [&](::V1_0::Status status, const sp<::V1_0::IDrmPlugin>& hPlugin) {
                if (status != ::V1_0::Status::OK) {
                    LOG2BE(uuid, "MakeDrmPlugin failed: %d", status);
                    return;
                }
                plugin = hPlugin;
            });
    if (err.isOk()) {
        return plugin;
    } else {
        LOG2BE(uuid, "MakeDrmPlugin txn failed: %s", err.description().c_str());
        return nullptr;
    }
}

sp<::V1_0::ICryptoPlugin> MakeCryptoPlugin(const sp<::V1_0::ICryptoFactory>& factory,
                                           const uint8_t uuid[16], const void* initData,
                                           size_t initDataSize) {
    sp<::V1_0::ICryptoPlugin> plugin;
    auto err = factory->createPlugin(
            toHidlArray16(uuid), toHidlVec(initData, initDataSize),
            [&](::V1_0::Status status, const sp<::V1_0::ICryptoPlugin>& hPlugin) {
                if (status != ::V1_0::Status::OK) {
                    LOG2BE(uuid, "MakeCryptoPlugin failed: %d", status);
                    return;
                }
                plugin = hPlugin;
            });
    if (err.isOk()) {
        return plugin;
    } else {
        LOG2BE(uuid, "MakeCryptoPlugin txn failed: %s", err.description().c_str());
        return nullptr;
    }
}

}  // namespace

bool UseDrmService() {
    return property_get_bool("mediadrm.use_mediadrmserver", true);
}

std::vector<std::shared_ptr<IDrmFactoryAidl>> makeDrmFactoriesAidl() {
    std::vector<std::shared_ptr<IDrmFactoryAidl>> factories;
    AServiceManager_forEachDeclaredInstance(
        IDrmFactoryAidl::descriptor, static_cast<void*>(&factories),
        [](const char* instance, void* context) {
            auto fullName = std::string(IDrmFactoryAidl::descriptor) + "/" + std::string(instance);
            auto factory = IDrmFactoryAidl::fromBinder(
                    ::ndk::SpAIBinder(AServiceManager_waitForService(fullName.c_str())));
            if (factory == nullptr) {
                ALOGE("not found IDrmFactory. Instance name:[%s]", fullName.c_str());
                return;
            }

            ALOGI("found IDrmFactory. Instance name:[%s]", fullName.c_str());
            static_cast<std::vector<std::shared_ptr<IDrmFactoryAidl>>*>(context)->emplace_back(
                    factory);
        });

    return factories;
}

sp<IDrm> MakeDrm(status_t* pstatus) {
    return MakeObject<DrmHal>(pstatus);
}

sp<ICrypto> MakeCrypto(status_t* pstatus) {
    return MakeObject<CryptoHal>(pstatus);
}

std::vector<sp<::V1_0::IDrmFactory>> MakeDrmFactories(const uint8_t uuid[16]) {
    std::vector<sp<::V1_0::IDrmFactory>> drmFactories;
    std::map<std::string, std::string> instances;
    MakeHidlFactories<::V1_0::IDrmFactory>(uuid, drmFactories, instances);
    MakeHidlFactories<::V1_1::IDrmFactory>(uuid, drmFactories, instances);
    MakeHidlFactories<::V1_2::IDrmFactory>(uuid, drmFactories, instances);
    MakeHidlFactories<::V1_3::IDrmFactory>(uuid, drmFactories, instances);
    MakeHidlFactories<::V1_4::IDrmFactory>(uuid, drmFactories, instances);
    for (auto const& entry : instances) {
        LOG2BI("found instance=%s version=%s", entry.first.c_str(), entry.second.c_str());
    }
    return drmFactories;
}

std::vector<sp<::V1_0::IDrmPlugin>> MakeDrmPlugins(const uint8_t uuid[16],
                                                   const char* appPackageName) {
    std::vector<sp<::V1_0::IDrmPlugin>> plugins;
    for (const auto& factory : MakeDrmFactories(uuid)) {
        plugins.push_back(MakeDrmPlugin(factory, uuid, appPackageName));
    }
    return plugins;
}

std::vector<sp<::V1_0::ICryptoFactory>> MakeCryptoFactories(const uint8_t uuid[16]) {
    std::vector<sp<::V1_0::ICryptoFactory>> cryptoFactories;
    MakeHidlFactories<::V1_0::ICryptoFactory>(uuid, cryptoFactories);
    MakeHidlFactories<::V1_1::ICryptoFactory>(uuid, cryptoFactories);
    MakeHidlFactories<::V1_2::ICryptoFactory>(uuid, cryptoFactories);
    MakeHidlFactories<::V1_3::ICryptoFactory>(uuid, cryptoFactories);
    MakeHidlFactories<::V1_4::ICryptoFactory>(uuid, cryptoFactories);
    return cryptoFactories;
}

std::vector<sp<::V1_0::ICryptoPlugin>> MakeCryptoPlugins(const uint8_t uuid[16],
                                                         const void* initData,
                                                         size_t initDataSize) {
    std::vector<sp<::V1_0::ICryptoPlugin>> plugins;
    for (const auto& factory : MakeCryptoFactories(uuid)) {
        plugins.push_back(MakeCryptoPlugin(factory, uuid, initData, initDataSize));
    }
    return plugins;
}

status_t toStatusT_1_4(::V1_4::Status status) {
    switch (status) {
        case ::V1_4::Status::OK:
            return OK;
        case ::V1_4::Status::BAD_VALUE:
            return BAD_VALUE;
        case ::V1_4::Status::ERROR_DRM_CANNOT_HANDLE:
            return ERROR_DRM_CANNOT_HANDLE;
        case ::V1_4::Status::ERROR_DRM_DECRYPT:
            return ERROR_DRM_DECRYPT;
        case ::V1_4::Status::ERROR_DRM_DEVICE_REVOKED:
            return ERROR_DRM_DEVICE_REVOKED;
        case ::V1_4::Status::ERROR_DRM_FRAME_TOO_LARGE:
            return ERROR_DRM_FRAME_TOO_LARGE;
        case ::V1_4::Status::ERROR_DRM_INSUFFICIENT_OUTPUT_PROTECTION:
            return ERROR_DRM_INSUFFICIENT_OUTPUT_PROTECTION;
        case ::V1_4::Status::ERROR_DRM_INSUFFICIENT_SECURITY:
            return ERROR_DRM_INSUFFICIENT_SECURITY;
        case ::V1_4::Status::ERROR_DRM_INVALID_STATE:
            return ERROR_DRM_INVALID_STATE;
        case ::V1_4::Status::ERROR_DRM_LICENSE_EXPIRED:
            return ERROR_DRM_LICENSE_EXPIRED;
        case ::V1_4::Status::ERROR_DRM_NO_LICENSE:
            return ERROR_DRM_NO_LICENSE;
        case ::V1_4::Status::ERROR_DRM_NOT_PROVISIONED:
            return ERROR_DRM_NOT_PROVISIONED;
        case ::V1_4::Status::ERROR_DRM_RESOURCE_BUSY:
            return ERROR_DRM_RESOURCE_BUSY;
        case ::V1_4::Status::ERROR_DRM_RESOURCE_CONTENTION:
            return ERROR_DRM_RESOURCE_CONTENTION;
        case ::V1_4::Status::ERROR_DRM_SESSION_LOST_STATE:
            return ERROR_DRM_SESSION_LOST_STATE;
        case ::V1_4::Status::ERROR_DRM_SESSION_NOT_OPENED:
            return ERROR_DRM_SESSION_NOT_OPENED;

        // New in S / drm@1.4:
        case ::V1_4::Status::CANNOT_DECRYPT_ZERO_SUBSAMPLES:
            return ERROR_DRM_ZERO_SUBSAMPLES;
        case ::V1_4::Status::CRYPTO_LIBRARY_ERROR:
            return ERROR_DRM_CRYPTO_LIBRARY;
        case ::V1_4::Status::GENERAL_OEM_ERROR:
            return ERROR_DRM_GENERIC_OEM;
        case ::V1_4::Status::GENERAL_PLUGIN_ERROR:
            return ERROR_DRM_GENERIC_PLUGIN;
        case ::V1_4::Status::INIT_DATA_INVALID:
            return ERROR_DRM_INIT_DATA;
        case ::V1_4::Status::KEY_NOT_LOADED:
            return ERROR_DRM_KEY_NOT_LOADED;
        case ::V1_4::Status::LICENSE_PARSE_ERROR:
            return ERROR_DRM_LICENSE_PARSE;
        case ::V1_4::Status::LICENSE_POLICY_ERROR:
            return ERROR_DRM_LICENSE_POLICY;
        case ::V1_4::Status::LICENSE_RELEASE_ERROR:
            return ERROR_DRM_LICENSE_RELEASE;
        case ::V1_4::Status::LICENSE_REQUEST_REJECTED:
            return ERROR_DRM_LICENSE_REQUEST_REJECTED;
        case ::V1_4::Status::LICENSE_RESTORE_ERROR:
            return ERROR_DRM_LICENSE_RESTORE;
        case ::V1_4::Status::LICENSE_STATE_ERROR:
            return ERROR_DRM_LICENSE_STATE;
        case ::V1_4::Status::MALFORMED_CERTIFICATE:
            return ERROR_DRM_CERTIFICATE_MALFORMED;
        case ::V1_4::Status::MEDIA_FRAMEWORK_ERROR:
            return ERROR_DRM_MEDIA_FRAMEWORK;
        case ::V1_4::Status::MISSING_CERTIFICATE:
            return ERROR_DRM_CERTIFICATE_MISSING;
        case ::V1_4::Status::PROVISIONING_CERTIFICATE_ERROR:
            return ERROR_DRM_PROVISIONING_CERTIFICATE;
        case ::V1_4::Status::PROVISIONING_CONFIGURATION_ERROR:
            return ERROR_DRM_PROVISIONING_CONFIG;
        case ::V1_4::Status::PROVISIONING_PARSE_ERROR:
            return ERROR_DRM_PROVISIONING_PARSE;
        case ::V1_4::Status::PROVISIONING_REQUEST_REJECTED:
            return ERROR_DRM_PROVISIONING_REQUEST_REJECTED;
        case ::V1_4::Status::RETRYABLE_PROVISIONING_ERROR:
            return ERROR_DRM_PROVISIONING_RETRY;
        case ::V1_4::Status::SECURE_STOP_RELEASE_ERROR:
            return ERROR_DRM_SECURE_STOP_RELEASE;
        case ::V1_4::Status::STORAGE_READ_FAILURE:
            return ERROR_DRM_STORAGE_READ;
        case ::V1_4::Status::STORAGE_WRITE_FAILURE:
            return ERROR_DRM_STORAGE_WRITE;

        case ::V1_4::Status::ERROR_DRM_UNKNOWN:
        default:
            return ERROR_DRM_UNKNOWN;
    }
    return ERROR_DRM_UNKNOWN;
}

namespace {
char logPriorityToChar(::V1_4::LogPriority priority) {
    char p = 'U';
    switch (priority) {
        case ::V1_4::LogPriority::VERBOSE:
            p = 'V';
            break;
        case ::V1_4::LogPriority::DEBUG:
            p = 'D';
            break;
        case ::V1_4::LogPriority::INFO:
            p = 'I';
            break;
        case ::V1_4::LogPriority::WARN:
            p = 'W';
            break;
        case ::V1_4::LogPriority::ERROR:
            p = 'E';
            break;
        case ::V1_4::LogPriority::FATAL:
            p = 'F';
            break;
        default:
            p = 'U';
            break;
    }
    return p;
}
}  // namespace

std::string GetExceptionMessage(const DrmStatus &err, const char* defaultMsg,
                                const Vector<::V1_4::LogMessage>& logs) {
    std::string ruler("==============================");
    std::string header("Beginning of DRM Plugin Log");
    std::string footer("End of DRM Plugin Log");
    std::string msg(err.getErrorMessage());
    String8 msg8;
    if (!msg.empty()) {
        msg8 += msg.c_str();
        msg8 += ": ";
    } else if (defaultMsg) {
        msg8 += defaultMsg;
        msg8 += ": ";
    }
    msg8 += StrCryptoError(err).c_str();
    msg8 += String8::format("\ncdm err: %d, oem err: %d, ctx: %d",
                            err.getCdmErr(), err.getOemErr(), err.getContext());
    msg8 += String8::format("\n%s %s %s", ruler.c_str(), header.c_str(), ruler.c_str());

    for (auto log : logs) {
        time_t seconds = log.timeMs / 1000;
        int ms = log.timeMs % 1000;
        char buf[64] = {0};
        std::string timeStr = "00-00 00:00:00";
        if (strftime(buf, sizeof buf, "%m-%d %H:%M:%S", std::localtime(&seconds))) {
            timeStr = buf;
        }

        char p = logPriorityToChar(log.priority);
        msg8 += String8::format("\n  %s.%03d %c %s", timeStr.c_str(), ms, p, log.message.c_str());
    }

    msg8 += String8::format("\n%s %s %s", ruler.c_str(), footer.c_str(), ruler.c_str());
    return msg8.c_str();
}

void LogBuffer::addLog(const ::V1_4::LogMessage& log) {
    std::unique_lock<std::mutex> lock(mMutex);
    mBuffer.push_back(log);
    while (mBuffer.size() > MAX_CAPACITY) {
        mBuffer.pop_front();
    }
}

Vector<::V1_4::LogMessage> LogBuffer::getLogs() {
    std::unique_lock<std::mutex> lock(mMutex);
    Vector<::V1_4::LogMessage> logs;
    for (auto log : mBuffer) {
        logs.push_back(log);
    }
    return logs;
}

DrmStatus statusAidlToDrmStatus(::ndk::ScopedAStatus& statusAidl) {
    if (statusAidl.isOk()) return OK;
    if (statusAidl.getExceptionCode() != EX_SERVICE_SPECIFIC) return DEAD_OBJECT;
    auto astatus = static_cast<StatusAidl>(statusAidl.getServiceSpecificError());
    status_t status{};
    switch (astatus) {
    case StatusAidl::OK:
        status = OK;
        break;
    case StatusAidl::BAD_VALUE:
        status = BAD_VALUE;
        break;
    case StatusAidl::ERROR_DRM_CANNOT_HANDLE:
        status = ERROR_DRM_CANNOT_HANDLE;
        break;
    case StatusAidl::ERROR_DRM_DECRYPT:
        status = ERROR_DRM_DECRYPT;
        break;
    case StatusAidl::ERROR_DRM_DEVICE_REVOKED:
        status = ERROR_DRM_DEVICE_REVOKED;
        break;
    case StatusAidl::ERROR_DRM_FRAME_TOO_LARGE:
        status = ERROR_DRM_FRAME_TOO_LARGE;
        break;
    case StatusAidl::ERROR_DRM_INSUFFICIENT_OUTPUT_PROTECTION:
        status = ERROR_DRM_INSUFFICIENT_OUTPUT_PROTECTION;
        break;
    case StatusAidl::ERROR_DRM_INSUFFICIENT_SECURITY:
        status = ERROR_DRM_INSUFFICIENT_SECURITY;
        break;
    case StatusAidl::ERROR_DRM_INVALID_STATE:
        status = ERROR_DRM_INVALID_STATE;
        break;
    case StatusAidl::ERROR_DRM_LICENSE_EXPIRED:
        status = ERROR_DRM_LICENSE_EXPIRED;
        break;
    case StatusAidl::ERROR_DRM_NO_LICENSE:
        status = ERROR_DRM_NO_LICENSE;
        break;
    case StatusAidl::ERROR_DRM_NOT_PROVISIONED:
        status = ERROR_DRM_NOT_PROVISIONED;
        break;
    case StatusAidl::ERROR_DRM_RESOURCE_BUSY:
        status = ERROR_DRM_RESOURCE_BUSY;
        break;
    case StatusAidl::ERROR_DRM_RESOURCE_CONTENTION:
        status = ERROR_DRM_RESOURCE_CONTENTION;
        break;
    case StatusAidl::ERROR_DRM_SESSION_LOST_STATE:
        status = ERROR_DRM_SESSION_LOST_STATE;
        break;
    case StatusAidl::ERROR_DRM_SESSION_NOT_OPENED:
        status = ERROR_DRM_SESSION_NOT_OPENED;
        break;

    // New in S / drm@1.4:
    case StatusAidl::CANNOT_DECRYPT_ZERO_SUBSAMPLES:
        status = ERROR_DRM_ZERO_SUBSAMPLES;
        break;
    case StatusAidl::CRYPTO_LIBRARY_ERROR:
        status = ERROR_DRM_CRYPTO_LIBRARY;
        break;
    case StatusAidl::GENERAL_OEM_ERROR:
        status = ERROR_DRM_GENERIC_OEM;
        break;
    case StatusAidl::GENERAL_PLUGIN_ERROR:
        status = ERROR_DRM_GENERIC_PLUGIN;
        break;
    case StatusAidl::INIT_DATA_INVALID:
        status = ERROR_DRM_INIT_DATA;
        break;
    case StatusAidl::KEY_NOT_LOADED:
        status = ERROR_DRM_KEY_NOT_LOADED;
        break;
    case StatusAidl::LICENSE_PARSE_ERROR:
        status = ERROR_DRM_LICENSE_PARSE;
        break;
    case StatusAidl::LICENSE_POLICY_ERROR:
        status = ERROR_DRM_LICENSE_POLICY;
        break;
    case StatusAidl::LICENSE_RELEASE_ERROR:
        status = ERROR_DRM_LICENSE_RELEASE;
        break;
    case StatusAidl::LICENSE_REQUEST_REJECTED:
        status = ERROR_DRM_LICENSE_REQUEST_REJECTED;
        break;
    case StatusAidl::LICENSE_RESTORE_ERROR:
        status = ERROR_DRM_LICENSE_RESTORE;
        break;
    case StatusAidl::LICENSE_STATE_ERROR:
        status = ERROR_DRM_LICENSE_STATE;
        break;
    case StatusAidl::MALFORMED_CERTIFICATE:
        status = ERROR_DRM_CERTIFICATE_MALFORMED;
        break;
    case StatusAidl::MEDIA_FRAMEWORK_ERROR:
        status = ERROR_DRM_MEDIA_FRAMEWORK;
        break;
    case StatusAidl::MISSING_CERTIFICATE:
        status = ERROR_DRM_CERTIFICATE_MISSING;
        break;
    case StatusAidl::PROVISIONING_CERTIFICATE_ERROR:
        status = ERROR_DRM_PROVISIONING_CERTIFICATE;
        break;
    case StatusAidl::PROVISIONING_CONFIGURATION_ERROR:
        status = ERROR_DRM_PROVISIONING_CONFIG;
        break;
    case StatusAidl::PROVISIONING_PARSE_ERROR:
        status = ERROR_DRM_PROVISIONING_PARSE;
        break;
    case StatusAidl::PROVISIONING_REQUEST_REJECTED:
        status = ERROR_DRM_PROVISIONING_REQUEST_REJECTED;
        break;
    case StatusAidl::RETRYABLE_PROVISIONING_ERROR:
        status = ERROR_DRM_PROVISIONING_RETRY;
        break;
    case StatusAidl::SECURE_STOP_RELEASE_ERROR:
        status = ERROR_DRM_SECURE_STOP_RELEASE;
        break;
    case StatusAidl::STORAGE_READ_FAILURE:
        status = ERROR_DRM_STORAGE_READ;
        break;
    case StatusAidl::STORAGE_WRITE_FAILURE:
        status = ERROR_DRM_STORAGE_WRITE;
        break;

    case StatusAidl::ERROR_DRM_UNKNOWN:
    default:
        status = ERROR_DRM_UNKNOWN;
        break;
    }

    Json::Value errorDetails;
    Json::Reader reader;
    if (!reader.parse(statusAidl.getMessage(), errorDetails)) {
        return status;
    }

    int32_t cdmErr{}, oemErr{}, ctx{};
    std::string errMsg;
    auto val = errorDetails["cdmError"];
    if (!val.isNull()) {
        cdmErr = val.asInt();
    }
    val = errorDetails["oemError"];
    if (!val.isNull()) {
        oemErr = val.asInt();
    }
    val = errorDetails["context"];
    if (!val.isNull()) {
        ctx = val.asInt();
    }
    val = errorDetails["errorMessage"];
    if (!val.isNull()) {
        errMsg = val.asString();
    }
    return DrmStatus(status, cdmErr, oemErr, ctx, errMsg);
}

LogBuffer gLogBuf;
}  // namespace DrmUtils
}  // namespace android
