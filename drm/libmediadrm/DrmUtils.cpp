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
#include <android/hidl/manager/1.2/IServiceManager.h>
#include <hidl/HidlSupport.h>

#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/String16.h>
#include <cutils/properties.h>

#include <mediadrm/CryptoHal.h>
#include <mediadrm/DrmHal.h>
#include <mediadrm/DrmUtils.h>
#include <mediadrm/ICrypto.h>
#include <mediadrm/IDrm.h>

using HServiceManager = ::android::hidl::manager::V1_2::IServiceManager;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using namespace ::android::hardware::drm;

namespace android {
namespace DrmUtils {

namespace {

template<typename Hal>
Hal *MakeObject(status_t *pstatus) {
    status_t err = OK;
    status_t &status = pstatus ? *pstatus : err;
    auto obj = new Hal();
    status = obj->initCheck();
    if (status != OK && status != NO_INIT) {
        return NULL;
    }
    return obj;
}

template <typename Hal, typename V>
void MakeHidlFactories(const uint8_t uuid[16], V &factories) {
    sp<HServiceManager> serviceManager = HServiceManager::getService();
    if (serviceManager == nullptr) {
        ALOGE("Failed to get service manager");
        exit(-1);
    }

    serviceManager->listManifestByInterface(Hal::descriptor, [&](const hidl_vec<hidl_string> &registered) {
        for (const auto &instance : registered) {
            auto factory = Hal::getService(instance);
            if (factory != nullptr) {
                ALOGI("found %s %s", Hal::descriptor, instance.c_str());
                if (!uuid || factory->isCryptoSchemeSupported(uuid)) {
                    factories.push_back(factory);
                }
            }
        }
    });
}

hidl_vec<uint8_t> toHidlVec(const void *ptr, size_t size) {
    hidl_vec<uint8_t> vec(size);
    if (ptr != nullptr) {
        memcpy(vec.data(), ptr, size);
    }
    return vec;
}

hidl_array<uint8_t, 16> toHidlArray16(const uint8_t *ptr) {
    if (ptr == nullptr) {
        return hidl_array<uint8_t, 16>();
    }
    return hidl_array<uint8_t, 16>(ptr);
}

sp<::V1_0::IDrmPlugin> MakeDrmPlugin(const sp<::V1_0::IDrmFactory> &factory,
                                     const uint8_t uuid[16], const char *appPackageName) {
    sp<::V1_0::IDrmPlugin> plugin;
    factory->createPlugin(toHidlArray16(uuid), hidl_string(appPackageName),
                          [&](::V1_0::Status status, const sp<::V1_0::IDrmPlugin> &hPlugin) {
                              if (status != ::V1_0::Status::OK) {
                                  return;
                              }
                              plugin = hPlugin;
                          });
    return plugin;
}

sp<::V1_0::ICryptoPlugin> MakeCryptoPlugin(const sp<::V1_0::ICryptoFactory> &factory,
                                           const uint8_t uuid[16], const void *initData,
                                           size_t initDataSize) {
    sp<::V1_0::ICryptoPlugin> plugin;
    factory->createPlugin(toHidlArray16(uuid), toHidlVec(initData, initDataSize),
                          [&](::V1_0::Status status, const sp<::V1_0::ICryptoPlugin> &hPlugin) {
                              if (status != ::V1_0::Status::OK) {
                                  return;
                              }
                              plugin = hPlugin;
                          });
    return plugin;
}

} // namespace

bool UseDrmService() {
    return property_get_bool("mediadrm.use_mediadrmserver", true);
}

sp<IDrm> MakeDrm(status_t *pstatus) {
    return MakeObject<DrmHal>(pstatus);
}

sp<ICrypto> MakeCrypto(status_t *pstatus) {
    return MakeObject<CryptoHal>(pstatus);
}

std::vector<sp<::V1_0::IDrmFactory>> MakeDrmFactories(const uint8_t uuid[16]) {
    std::vector<sp<::V1_0::IDrmFactory>> drmFactories;
    MakeHidlFactories<::V1_0::IDrmFactory>(uuid, drmFactories);
    MakeHidlFactories<::V1_1::IDrmFactory>(uuid, drmFactories);
    MakeHidlFactories<::V1_2::IDrmFactory>(uuid, drmFactories);
    MakeHidlFactories<::V1_3::IDrmFactory>(uuid, drmFactories);
    return drmFactories;
}

std::vector<sp<::V1_0::IDrmPlugin>> MakeDrmPlugins(const uint8_t uuid[16],
                                              const char *appPackageName) {
    std::vector<sp<::V1_0::IDrmPlugin>> plugins;
    for (const auto &factory : MakeDrmFactories(uuid)) {
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
    return cryptoFactories;
}

std::vector<sp<ICryptoPlugin>> MakeCryptoPlugins(const uint8_t uuid[16], const void *initData,
                                                 size_t initDataSize) {
    std::vector<sp<ICryptoPlugin>> plugins;
    for (const auto &factory : MakeCryptoFactories(uuid)) {
        plugins.push_back(MakeCryptoPlugin(factory, uuid, initData, initDataSize));
    }
    return plugins;
}

}  // namespace DrmUtils
}  // namespace android
