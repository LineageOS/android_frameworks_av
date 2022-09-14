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

#include <android/media/AudioPort.h>
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
    DeviceDescriptorBase(audio_devices_t type, const std::string& address,
            const FormatVector &encodedFormats = FormatVector{});
    DeviceDescriptorBase(const AudioDeviceTypeAddr& deviceTypeAddr,
            const FormatVector &encodedFormats = FormatVector{});

    virtual ~DeviceDescriptorBase() = default;

    audio_devices_t type() const { return mDeviceTypeAddr.mType; }
    const std::string& address() const { return mDeviceTypeAddr.address(); }
    void setAddress(const std::string &address);
    const AudioDeviceTypeAddr& getDeviceTypeAddr() const { return mDeviceTypeAddr; }

    const FormatVector& encodedFormats() const { return mEncodedFormats; }
    bool supportsFormat(audio_format_t format);

    // AudioPortConfig
    virtual sp<AudioPort> getAudioPort() const {
        return sp<AudioPort>::fromExisting(const_cast<DeviceDescriptorBase*>(this));
    }
    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
            const struct audio_port_config *srcConfig = NULL) const;

    // AudioPort
    virtual void toAudioPort(struct audio_port *port) const;
    virtual void toAudioPort(struct audio_port_v7 *port) const;

    status_t setEncapsulationModes(uint32_t encapsulationModes);
    status_t setEncapsulationMetadataTypes(uint32_t encapsulationMetadataTypes);

    void dump(std::string *dst, int spaces,
              const char* extraInfo = nullptr, bool verbose = true) const;
    void log() const;

    /**
     * Return a string to describe the DeviceDescriptor.
     *
     * @param includeSensitiveInfo sensitive information will be added when it is true.
     * @return a string that can be used to describe the DeviceDescriptor.
     */
    std::string toString(bool includeSensitiveInfo = false) const;

    bool equals(const sp<DeviceDescriptorBase>& other) const;

    status_t writeToParcelable(media::AudioPort* parcelable) const;
    status_t readFromParcelable(const media::AudioPort& parcelable);

protected:
    AudioDeviceTypeAddr mDeviceTypeAddr;
    FormatVector        mEncodedFormats;
    uint32_t mEncapsulationModes = 0;
    uint32_t mEncapsulationMetadataTypes = 0;
private:
    template <typename T, std::enable_if_t<std::is_same<T, struct audio_port>::value
                                        || std::is_same<T, struct audio_port_v7>::value, int> = 0>
    void toAudioPortInternal(T* port) const {
        AudioPort::toAudioPort(port);
        toAudioPortConfig(&port->active_config);
        port->id = mId;
        port->ext.device.type = mDeviceTypeAddr.mType;
        port->ext.device.encapsulation_modes = mEncapsulationModes;
        port->ext.device.encapsulation_metadata_types = mEncapsulationMetadataTypes;
        (void)audio_utils_strlcpy_zerofill(port->ext.device.address, mDeviceTypeAddr.getAddress());
    }
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

// Conversion routines, according to AidlConversion.h conventions.
ConversionResult<sp<DeviceDescriptorBase>>
aidl2legacy_DeviceDescriptorBase(const media::AudioPort& aidl);
ConversionResult<media::AudioPort>
legacy2aidl_DeviceDescriptorBase(const sp<DeviceDescriptorBase>& legacy);

} // namespace android
