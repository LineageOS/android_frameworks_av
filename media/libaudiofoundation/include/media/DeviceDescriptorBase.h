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

#pragma once

#include <vector>

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <media/AudioContainers.h>
#include <media/AudioPort.h>
#include <media/AudioDeviceTypeAddr.h>
#include <utils/Errors.h>
#include <cutils/config_utils.h>
#include <system/audio.h>
#include <system/audio_policy.h>

namespace android {

class DeviceDescriptorBase : public AudioPort, public AudioPortConfig
{
public:
     // Note that empty name refers by convention to a generic device.
    explicit DeviceDescriptorBase(audio_devices_t type);
    DeviceDescriptorBase(audio_devices_t type, const std::string& address);
    explicit DeviceDescriptorBase(const AudioDeviceTypeAddr& deviceTypeAddr);

    virtual ~DeviceDescriptorBase() {}

    audio_devices_t type() const { return mDeviceTypeAddr.mType; }
    std::string address() const { return mDeviceTypeAddr.mAddress; }
    void setAddress(const std::string &address) { mDeviceTypeAddr.mAddress = address; }
    const AudioDeviceTypeAddr& getDeviceTypeAddr() const { return mDeviceTypeAddr; }

    // AudioPortConfig
    virtual sp<AudioPort> getAudioPort() const {
        return static_cast<AudioPort*>(const_cast<DeviceDescriptorBase*>(this));
    }
    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
            const struct audio_port_config *srcConfig = NULL) const;

    // AudioPort
    virtual void toAudioPort(struct audio_port *port) const;

    status_t setEncapsulationModes(uint32_t encapsulationModes);
    status_t setEncapsulationMetadataTypes(uint32_t encapsulationMetadataTypes);

    void dump(std::string *dst, int spaces, int index,
              const char* extraInfo = nullptr, bool verbose = true) const;
    void log() const;
    std::string toString() const;

    bool equals(const sp<DeviceDescriptorBase>& other) const;

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;

protected:
    AudioDeviceTypeAddr mDeviceTypeAddr;
    uint32_t mEncapsulationModes = 0;
    uint32_t mEncapsulationMetadataTypes = 0;
};

using DeviceDescriptorBaseVector = std::vector<sp<DeviceDescriptorBase>>;

/**
 * Return human readable string for collection of DeviceDescriptorBase.
 * For a DeviceDescriptorBase, it contains port id, audio device type and address.
 */
std::string toString(const DeviceDescriptorBaseVector& devices);

/**
 * Return a set of device types and addresses from collection of DeviceDescriptorBase.
 */
AudioDeviceTypeAddrVector deviceTypeAddrsFromDescriptors(const DeviceDescriptorBaseVector& devices);

} // namespace android
