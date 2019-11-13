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
#include <android/hardware/drm/1.1/ICryptoFactory.h>
#include <android/hardware/drm/1.2/ICryptoFactory.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/HidlSupport.h>

#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/String16.h>
#include <binder/IInterface.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>

#include <mediadrm/CryptoHal.h>
#include <mediadrm/DrmHal.h>
#include <mediadrm/DrmUtils.h>
#include <mediadrm/ICrypto.h>
#include <mediadrm/IDrm.h>
#include <mediadrm/IMediaDrmService.h>

using HServiceManager = ::android::hidl::manager::V1_0::IServiceManager;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using namespace ::android::hardware::drm;

namespace android {
namespace DrmUtils {

namespace {
template<typename Iface>
sp<Iface> MakeObjectWithService(status_t *pstatus) {
    status_t err = OK;
    status_t &status = pstatus ? *pstatus : err;
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.drm"));

    sp<IMediaDrmService> service = interface_cast<IMediaDrmService>(binder);
    if (service == NULL) {
        status = UNKNOWN_ERROR;
        return NULL;
    }

    auto obj = service->makeObject<Iface>();
    if (obj == NULL) {
        status = UNKNOWN_ERROR;
        return NULL;
    }

    status = obj->initCheck();
    if (status != OK && status != NO_INIT) {
        return NULL;
    }
    return obj;
}

template<typename Iface, typename Hal>
sp<Iface> MakeObject(status_t *pstatus) {
    if (UseDrmService()) {
        return MakeObjectWithService<Iface>(pstatus);
    } else {
        return new Hal();
    }
}

template <typename Hal, typename V>
void MakeCryptoFactories(const uint8_t uuid[16], V &cryptoFactories) {
    sp<HServiceManager> serviceManager = HServiceManager::getService();
    if (serviceManager == nullptr) {
        ALOGE("Failed to get service manager");
        exit(-1);
    }

    serviceManager->listByInterface(Hal::descriptor, [&](const hidl_vec<hidl_string> &registered) {
        for (const auto &instance : registered) {
            auto factory = Hal::getService(instance);
            if (factory != nullptr) {
                ALOGI("found %s %s", Hal::descriptor, instance.c_str());
                if (factory->isCryptoSchemeSupported(uuid)) {
                    cryptoFactories.push_back(factory);
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
    return MakeObject<IDrm, DrmHal>(pstatus);
}

sp<ICrypto> MakeCrypto(status_t *pstatus) {
    if (pstatus) {
        *pstatus = OK;
    }
    return new CryptoHal();
}

std::vector<sp<::V1_0::ICryptoFactory>> MakeCryptoFactories(const uint8_t uuid[16]) {
    std::vector<sp<::V1_0::ICryptoFactory>> cryptoFactories;
    MakeCryptoFactories<::V1_0::ICryptoFactory>(uuid, cryptoFactories);
    MakeCryptoFactories<::V1_1::ICryptoFactory>(uuid, cryptoFactories);
    MakeCryptoFactories<::V1_2::ICryptoFactory>(uuid, cryptoFactories);
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
