/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "DevicesFactoryHalHybrid"
//#define LOG_NDEBUG 0

#include "DevicesFactoryHalHidl.h"
#include "DevicesFactoryHalHybrid.h"
#include "DevicesFactoryHalLocal.h"
#include <libaudiohal/FactoryHalHidl.h>

namespace android {
namespace CPP_VERSION {

DevicesFactoryHalHybrid::DevicesFactoryHalHybrid(sp<IDevicesFactory> hidlFactory)
        : mLocalFactory(new DevicesFactoryHalLocal()),
          mHidlFactory(new DevicesFactoryHalHidl(hidlFactory)) {
}

status_t DevicesFactoryHalHybrid::openDevice(const char *name, sp<DeviceHalInterface> *device) {
    if (mHidlFactory != 0 && strcmp(AUDIO_HARDWARE_MODULE_ID_A2DP, name) != 0 &&
        strcmp(AUDIO_HARDWARE_MODULE_ID_HEARING_AID, name) != 0) {
        return mHidlFactory->openDevice(name, device);
    }
    return mLocalFactory->openDevice(name, device);
}
} // namespace CPP_VERSION

template <>
sp<DevicesFactoryHalInterface> createFactoryHal<AudioHALVersion::CPP_VERSION>() {
    auto service = hardware::audio::CPP_VERSION::IDevicesFactory::getService();
    return service ? new CPP_VERSION::DevicesFactoryHalHybrid(service) : nullptr;
}

} // namespace android
