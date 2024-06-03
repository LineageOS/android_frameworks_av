/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "DeviceDescriptor.h"
#include "PolicyAudioPort.h"
#include "policy.h"
#include <media/AudioContainers.h>
#include <utils/String8.h>
#include <system/audio.h>

namespace android {

class HwModule;

// the IOProfile class describes the capabilities of an output or input stream.
// It is currently assumed that all combination of listed parameters are supported.
// It is used by the policy manager to determine if an output or input is suitable for
// a given use case,  open/close it accordingly and connect/disconnect audio tracks
// to/from it.
class IOProfile : public AudioPort, public PolicyAudioPort
{
public:
    IOProfile(const std::string &name, audio_port_role_t role);

    virtual ~IOProfile() = default;

    // For a Profile aka MixPort, tag name and name are equivalent.
    virtual const std::string getTagName() const { return getName(); }

    virtual void addAudioProfile(const sp<AudioProfile> &profile) {
        addAudioProfileAndSort(mProfiles, profile);
    }

    virtual sp<AudioPort> asAudioPort() const {
        return static_cast<AudioPort*>(const_cast<IOProfile*>(this));
    }

    // FIXME: this is needed because shared MMAP stream clients use the same audio session.
    // Once capture clients are tracked individually and not per session this can be removed
    // MMAP no IRQ input streams do not have the default limitation of one active client
    // max as they can be used in shared mode by the same application.
    // NOTE: Please consider moving to AudioPort when addressing the FIXME
    // NOTE: this works for explicit values set in audio_policy_configuration.xml because
    // flags are parsed before maxActiveCount by the serializer.
    void setFlags(uint32_t flags) override
    {
        AudioPort::setFlags(flags);
        if (getRole() == AUDIO_PORT_ROLE_SINK && (flags & AUDIO_INPUT_FLAG_MMAP_NOIRQ) != 0) {
            maxActiveCount = 0;
        }
        refreshMixerBehaviors();
    }

    const MixerBehaviorSet& getMixerBehaviors() const {
        return mMixerBehaviors;
    }

    enum CompatibilityScore{
        NO_MATCH = 0,
        PARTIAL_MATCH = 1,
        EXACT_MATCH = 2
    };

    /**
     * @brief compatibilityScore: This method is used for input and direct output,
     * and is not used for other output.
     * Return the compatibility score to measure how much the IO profile is compatible
     * with specified parameters.
     * For input, flags is interpreted as audio_input_flags_t.
     * TODO: merge audio_output_flags_t and audio_input_flags_t.
     *
     * @param devices vector of devices to be checked for compatibility
     * @param samplingRate to be checked for compatibility. Must be specified
     * @param updatedSamplingRate if non-NULL, it is assigned the actual sample rate.
     * @param format to be checked for compatibility. Must be specified
     * @param updatedFormat if non-NULL, it is assigned the actual format
     * @param channelMask to be checked for compatibility. Must be specified
     * @param updatedChannelMask if non-NULL, it is assigned the actual channel mask
     * @param flags to be checked for compatibility
     * @param exactMatchRequiredForInputFlags true if exact match is required on flags
     * @return how the IO profile is compatible with the given parameters.
     */
    CompatibilityScore getCompatibilityScore(const DeviceVector &devices,
                                             uint32_t samplingRate,
                                             uint32_t *updatedSamplingRate,
                                             audio_format_t format,
                                             audio_format_t *updatedFormat,
                                             audio_channel_mask_t channelMask,
                                             audio_channel_mask_t *updatedChannelMask,
                                             // FIXME parameter type
                                             uint32_t flags,
                                             bool exactMatchRequiredForInputFlags = false) const;

    /**
     * @brief areAllDevicesSupported: Checks if the given devices are supported by the IO profile.
     *
     * @param devices vector of devices to be checked for compatibility
     * @return true if all devices are supported, false otherwise.
     */
    bool areAllDevicesSupported(const DeviceVector &devices) const;

    /**
     * @brief isCompatibleProfileForFlags: Checks if the IO profile is compatible with
     * specified flags.
     *
     * @param flags to be checked for compatibility
     * @param exactMatchRequiredForInputFlags true if exact match is required on flags
     * @return true if the profile is compatible, false otherwise.
     */
    bool isCompatibleProfileForFlags(uint32_t flags,
                                     bool exactMatchRequiredForInputFlags = false) const;

    void dump(String8 *dst, int spaces) const;
    void log();

    bool hasSupportedDevices() const { return !mSupportedDevices.isEmpty(); }

    bool supportsDeviceTypes(const DeviceTypeSet& deviceTypes) const
    {
        const bool areOutputDevices = Intersection(deviceTypes, getAudioDeviceInAllSet()).empty();
        const bool devicesSupported = !mSupportedDevices.getDevicesFromTypes(deviceTypes).empty();
        return devicesSupported &&
               (!areOutputDevices || devicesSupportEncodedFormats(deviceTypes));
    }

    /**
     * @brief getTag
     * @param deviceTypes to be considered
     * @return tagName of first matching device for the considered types, empty string otherwise.
     */
    std::string getTag(const DeviceTypeSet& deviceTypes) const
    {
        if (supportsDeviceTypes(deviceTypes)) {
            return mSupportedDevices.getDevicesFromTypes(deviceTypes).itemAt(0)->getTagName();
        }
        return {};
    }

    /**
     * @brief supportsDevice
     * @param device to be checked against
     *        forceCheckOnAddress if true, check on type and address whatever the type, otherwise
     *        the address enforcement is limited to "offical devices" that distinguishe on address
     * @return true if the device is supported by type (for non bus / remote submix devices),
     *         true if the device is supported (both type and address) for bus / remote submix
     *         false otherwise
     */
    bool supportsDevice(const sp<DeviceDescriptor> &device, bool forceCheckOnAddress = false) const
    {
        if (!device_distinguishes_on_address(device->type()) && !forceCheckOnAddress) {
            return supportsDeviceTypes(DeviceTypeSet({device->type()}));
        }
        return mSupportedDevices.contains(device);
    }

    bool devicesSupportEncodedFormats(DeviceTypeSet deviceTypes) const
    {
        if (deviceTypes.empty()) {
            return true; // required for getOffloadSupport() check
        }
        DeviceVector deviceList =
            mSupportedDevices.getDevicesFromTypes(deviceTypes);
        for (const auto& device : deviceList) {
            if (device->hasCurrentEncodedFormat()) {
                return true;
            }
        }
        return false;
    }

    bool containsSingleDeviceSupportingEncodedFormats(const sp<DeviceDescriptor>& device) const;

    void clearSupportedDevices() { mSupportedDevices.clear(); }
    void addSupportedDevice(const sp<DeviceDescriptor> &device)
    {
        mSupportedDevices.add(device);
    }
    void removeSupportedDevice(const sp<DeviceDescriptor> &device)
    {
        ssize_t ret = mSupportedDevices.indexOf(device);
        if (ret >= 0 && !mSupportedDevices.itemAt(ret)->isDynamic()) {
            // devices equality checks only type, address, name and format
            // Prevents from removing non dynamically added devices
            return;
        }
        mSupportedDevices.remove(device);
    }
    void setSupportedDevices(const DeviceVector &devices)
    {
        mSupportedDevices = devices;
    }

    const DeviceVector &getSupportedDevices() const { return mSupportedDevices; }

    bool canOpenNewIo() {
        if (maxOpenCount == 0 || curOpenCount < maxOpenCount) {
            return true;
        }
        return false;
    }

    bool canStartNewIo() {
        if (maxActiveCount == 0 || curActiveCount < maxActiveCount) {
            return true;
        }
        return false;
    }

    void toSupportedMixerAttributes(std::vector<audio_mixer_attributes_t>* mixerAttributes) const;

    status_t readFromParcelable(const media::AudioPortFw& parcelable);

    void importAudioPort(const audio_port_v7& port) override;

    // Number of streams currently opened for this profile.
    uint32_t     curOpenCount;
    // Number of streams currently active for this profile. This is not the number of active clients
    // (AudioTrack or AudioRecord) but the number of active HAL streams.
    uint32_t     curActiveCount;

private:
    void refreshMixerBehaviors();

    DeviceVector mSupportedDevices; // supported devices: this input/output can be routed from/to

    MixerBehaviorSet mMixerBehaviors;
};

class InputProfile : public IOProfile
{
public:
    explicit InputProfile(const std::string &name) : IOProfile(name, AUDIO_PORT_ROLE_SINK) {}
};

class OutputProfile : public IOProfile
{
public:
    explicit OutputProfile(const std::string &name) : IOProfile(name, AUDIO_PORT_ROLE_SOURCE) {}
};

} // namespace android
