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
#include <aidl/android/media/audio/IHalAdapterVendorExtension.h>
#include <media/audiohal/DevicesFactoryHalInterface.h>
#include <utils/RefBase.h>

namespace android {

class DevicesFactoryHalAidl : public DevicesFactoryHalInterface
{
  public:
    explicit DevicesFactoryHalAidl(
            std::shared_ptr<::aidl::android::hardware::audio::core::IConfig> config);

    status_t getDeviceNames(std::vector<std::string> *names) override;

    // Opens a device with the specified name. To close the device, it is
    // necessary to release references to the returned object.
    status_t openDevice(const char *name, sp<DeviceHalInterface> *device) override;

    status_t getHalPids(std::vector<pid_t> *pids) override;

    status_t setCallbackOnce(sp<DevicesFactoryHalCallback> callback) override;

    android::detail::AudioHalVersionInfo getHalVersion() const override;

    status_t getSurroundSoundConfig(media::SurroundSoundConfig *config) override;

    status_t getEngineConfig(media::audio::common::AudioHalEngineConfig *config) override;

  private:
    const std::shared_ptr<::aidl::android::hardware::audio::core::IConfig> mConfig;
    std::optional<std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension>>
            mVendorExt;

    std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> getVendorExtension();

    ~DevicesFactoryHalAidl() = default;
};

} // namespace android
