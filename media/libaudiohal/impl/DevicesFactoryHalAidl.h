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

#pragma once

#include <aidl/android/hardware/audio/core/IConfig.h>
#include <media/audiohal/DevicesFactoryHalInterface.h>
#include <utils/RefBase.h>

using namespace ::aidl::android::hardware::audio::core;

namespace android {

class DevicesFactoryHalAidl : public DevicesFactoryHalInterface
{
  public:
    explicit DevicesFactoryHalAidl(std::shared_ptr<IConfig> iConfig);
    void onFirstRef() override;

    // Opens a device with the specified name. To close the device, it is
    // necessary to release references to the returned object.
    status_t openDevice(const char *name, sp<DeviceHalInterface> *device) override;

    status_t getHalPids(std::vector<pid_t> *pids) override;

    status_t setCallbackOnce(sp<DevicesFactoryHalCallback> callback) override;

    android::detail::AudioHalVersionInfo getHalVersion() const override;

  private:
    std::shared_ptr<IConfig> mIConfig;
    virtual ~DevicesFactoryHalAidl() = default;
};

} // namespace android
