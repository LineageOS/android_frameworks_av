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

#ifndef ANDROID_HARDWARE_DEVICES_FACTORY_HAL_HYBRID_H
#define ANDROID_HARDWARE_DEVICES_FACTORY_HAL_HYBRID_H

#include PATH(android/hardware/audio/FILE_VERSION/IDevicesFactory.h)
#include <media/audiohal/DevicesFactoryHalInterface.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

using ::android::hardware::audio::CPP_VERSION::IDevicesFactory;

namespace android {
namespace CPP_VERSION {

class DevicesFactoryHalHybrid : public DevicesFactoryHalInterface
{
  public:
    DevicesFactoryHalHybrid(sp<IDevicesFactory> hidlFactory);

    // Opens a device with the specified name. To close the device, it is
    // necessary to release references to the returned object.
    virtual status_t openDevice(const char *name, sp<DeviceHalInterface> *device);

            status_t getHalPids(std::vector<pid_t> *pids) override;

            status_t setCallbackOnce(sp<DevicesFactoryHalCallback> callback) override;

  private:
    sp<DevicesFactoryHalInterface> mLocalFactory;
    sp<DevicesFactoryHalInterface> mHidlFactory;
};

} // namespace CPP_VERSION
} // namespace android

#endif // ANDROID_HARDWARE_DEVICES_FACTORY_HAL_HYBRID_H
