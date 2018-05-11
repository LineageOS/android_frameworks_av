/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <string.h>
#include <vector>

#define LOG_TAG "DevicesFactoryHalHidl"
//#define LOG_NDEBUG 0

#include <android/hardware/audio/4.0/IDevice.h>
#include <media/audiohal/hidl/HalDeathHandler.h>
#include <utils/Log.h>

#include "ConversionHelperHidl.h"
#include "DeviceHalHidl.h"
#include "DevicesFactoryHalHidl.h"

using ::android::hardware::audio::V4_0::IDevice;
using ::android::hardware::audio::V4_0::Result;
using ::android::hardware::Return;

namespace android {
namespace V4_0 {

DevicesFactoryHalHidl::DevicesFactoryHalHidl() {
    sp<IDevicesFactory> defaultFactory{IDevicesFactory::getService()};
    if (!defaultFactory) {
        ALOGE("Failed to obtain IDevicesFactory/default service, terminating process.");
        exit(1);
    }
    mDeviceFactories.push_back(defaultFactory);
    // The MSD factory is optional
    sp<IDevicesFactory> msdFactory{IDevicesFactory::getService(AUDIO_HAL_SERVICE_NAME_MSD)};
    if (msdFactory) {
        mDeviceFactories.push_back(msdFactory);
    }
    for (const auto& factory : mDeviceFactories) {
        // It is assumed that the DevicesFactoryHalInterface instance is owned
        // by AudioFlinger and thus have the same lifespan.
        factory->linkToDeath(HalDeathHandler::getInstance(), 0 /*cookie*/);
    }
}


static const char* idFromHal(const char *name, status_t* status) {
    *status = OK;
    return name;
}

status_t DevicesFactoryHalHidl::openDevice(const char *name, sp<DeviceHalInterface> *device) {
    if (mDeviceFactories.empty()) return NO_INIT;
    status_t status;
    auto hidlId = idFromHal(name, &status);
    if (status != OK) return status;
    Result retval = Result::NOT_INITIALIZED;
    for (const auto& factory : mDeviceFactories) {
        Return<void> ret = factory->openDevice(
                hidlId,
                [&](Result r, const sp<IDevice>& result) {
                    retval = r;
                    if (retval == Result::OK) {
                        *device = new DeviceHalHidl(result);
                    }
                });
        if (!ret.isOk()) return FAILED_TRANSACTION;
        switch (retval) {
            // Device was found and was initialized successfully.
            case Result::OK: return OK;
            // Device was found but failed to initalize.
            case Result::NOT_INITIALIZED: return NO_INIT;
            // Otherwise continue iterating.
            default: ;
        }
    }
    ALOGW("The specified device name is not recognized: \"%s\"", name);
    return BAD_VALUE;
}

} // namespace V4_0
} // namespace android
