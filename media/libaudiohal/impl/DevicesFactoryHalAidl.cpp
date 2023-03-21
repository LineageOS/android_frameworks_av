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

#define LOG_TAG "DevicesFactoryHalAidl"
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/core/IModule.h>
#include <android/binder_manager.h>
#include <binder/IServiceManager.h>
#include <memory>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "DevicesFactoryHalAidl.h"

using namespace ::aidl::android::hardware::audio::core;
using ::android::detail::AudioHalVersionInfo;

namespace android {

DevicesFactoryHalAidl::DevicesFactoryHalAidl(std::shared_ptr<IConfig> iconfig)
    : mIConfig(std::move(iconfig)) {
    ALOG_ASSERT(iconfig != nullptr, "Provided default IConfig service is NULL");
}

// Opens a device with the specified name. To close the device, it is
// necessary to release references to the returned object.
status_t DevicesFactoryHalAidl::openDevice(const char *name, sp<DeviceHalInterface> *device) {
    if (name == nullptr || device == nullptr) {
        return BAD_VALUE;
    }

    std::shared_ptr<IModule> service;
    // FIXME: Normally we will list available HAL modules and connect to them,
    // however currently we still get the list of module names from the config.
    // Since the example service does not have all modules, the SM will wait
    // for the missing ones forever.
    if (strcmp(name, "primary") == 0 || strcmp(name, "r_submix") == 0 || strcmp(name, "usb") == 0) {
        if (strcmp(name, "primary") == 0) name = "default";
        auto serviceName = std::string(IModule::descriptor) + "/" + name;
        service = IModule::fromBinder(
                ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
        ALOGE_IF(service == nullptr, "%s fromBinder %s failed", __func__, serviceName.c_str());
    }
    // If the service is a nullptr, the device will not be really functional,
    // but will not crash either.
    *device = sp<DeviceHalAidl>::make(name, service);
    return OK;
}

status_t DevicesFactoryHalAidl::getHalPids(std::vector<pid_t> *pids) {
    if (pids == nullptr) {
        return BAD_VALUE;
    }
    // The functionality for retrieving debug infos of services is not exposed via the NDK.
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == nullptr) {
        return NO_INIT;
    }
    std::set<pid_t> pidsSet;
    const auto moduleServiceName = std::string(IModule::descriptor) + "/";
    auto debugInfos = sm->getServiceDebugInfo();
    for (const auto& info : debugInfos) {
        if (info.pid > 0 &&
                info.name.size() > moduleServiceName.size() && // '>' as there must be instance name
                info.name.substr(0, moduleServiceName.size()) == moduleServiceName) {
            pidsSet.insert(info.pid);
        }
    }
    *pids = {pidsSet.begin(), pidsSet.end()};
    return NO_ERROR;
}

status_t DevicesFactoryHalAidl::setCallbackOnce(sp<DevicesFactoryHalCallback> callback) {
    // Dynamic registration of module instances is not supported. The functionality
    // in the audio server which is related to this callback can be removed together
    // with HIDL support.
    ALOG_ASSERT(callback != nullptr);
    if (callback != nullptr) {
        callback->onNewDevicesAvailable();
    }
    return NO_ERROR;
}

AudioHalVersionInfo DevicesFactoryHalAidl::getHalVersion() const {
    int32_t versionNumber = 0;
    if (mIConfig != 0) {
        if (ndk::ScopedAStatus status = mIConfig->getInterfaceVersion(&versionNumber);
                !status.isOk()) {
            ALOGE("%s getInterfaceVersion failed: %s", __func__, status.getDescription().c_str());
        }
    } else {
        ALOGW("%s no IConfig instance", __func__);
    }
    // AIDL does not have minor version, fill 0 for all versions
    return AudioHalVersionInfo(AudioHalVersionInfo::Type::AIDL, versionNumber);
}

// Main entry-point to the shared library.
extern "C" __attribute__((visibility("default"))) void* createIDevicesFactoryImpl() {
    auto serviceName = std::string(IConfig::descriptor) + "/default";
    auto service = IConfig::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
    if (!service) {
        ALOGE("%s binder service %s not exist", __func__, serviceName.c_str());
        return nullptr;
    }
    return new DevicesFactoryHalAidl(service);
}

} // namespace android
