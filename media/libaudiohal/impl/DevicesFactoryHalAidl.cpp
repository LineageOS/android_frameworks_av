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

void DevicesFactoryHalAidl::onFirstRef() {
    ALOGE("%s not implemented yet", __func__);
}

// Opens a device with the specified name. To close the device, it is
// necessary to release references to the returned object.
status_t DevicesFactoryHalAidl::openDevice(const char *name, sp<DeviceHalInterface> *device) {
    if (name == nullptr || device == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet %s", __func__, name);
    return INVALID_OPERATION;

    // TODO: only support primary now ("default" means "primary")
    if (strcmp(name, "primary") != 0) {
        auto serviceName = std::string() + IModule::descriptor + "/default";
        auto service = IModule::fromBinder(
                ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
        ALOGW("%s fromBinder %s %s", __func__, IModule::descriptor, service ? "succ" : "fail");
        *device = new DeviceHalAidl(service);
    }
    return OK;
}

status_t DevicesFactoryHalAidl::getHalPids(std::vector<pid_t> *pids) {
    if (pids == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t DevicesFactoryHalAidl::setCallbackOnce(sp<DevicesFactoryHalCallback> callback) {
    if (callback == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

AudioHalVersionInfo DevicesFactoryHalAidl::getHalVersion() const {
    int32_t versionNumber = 0;
    if (mIConfig) {
        if (!mIConfig->getInterfaceVersion(&versionNumber).isOk()) {
            ALOGE("%s getInterfaceVersion failed", __func__);
        } else {
            ALOGI("%s getInterfaceVersion %d", __func__, versionNumber);
        }
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
