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

#pragma once

#include <android/media/audio/common/AudioHalEngineConfig.h>
#include <android/media/SurroundSoundConfig.h>
#include <media/audiohal/DeviceHalInterface.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <vector>

#include "AudioHalVersionInfo.h"

namespace android {

class DevicesFactoryHalCallback : public RefBase
{
  public:
    virtual void onNewDevicesAvailable() = 0;
};

class DevicesFactoryHalInterface : public RefBase
{
  public:
    virtual status_t getDeviceNames(std::vector<std::string> *names) = 0;

    // Opens a device with the specified name. To close the device, it is
    // necessary to release references to the returned object.
    virtual status_t openDevice(const char *name, sp<DeviceHalInterface> *device) = 0;

    // Sets a DevicesFactoryHalCallback to notify the client.
    // The callback can be only set once.
    virtual status_t setCallbackOnce(sp<DevicesFactoryHalCallback> callback) = 0;

    virtual android::detail::AudioHalVersionInfo getHalVersion() const = 0;

    virtual status_t getSurroundSoundConfig(media::SurroundSoundConfig *config) = 0;

    virtual status_t getEngineConfig(media::audio::common::AudioHalEngineConfig *config) = 0;

    static sp<DevicesFactoryHalInterface> create();

  protected:
    // Subclasses can not be constructed directly by clients.
    DevicesFactoryHalInterface() {}

    virtual ~DevicesFactoryHalInterface() {}
};

} // namespace android
