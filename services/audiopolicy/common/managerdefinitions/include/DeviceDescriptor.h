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

#include "PolicyAudioPort.h"
#include <media/AudioContainers.h>
#include <media/DeviceDescriptorBase.h>
#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/SortedVector.h>
#include <cutils/config_utils.h>
#include <system/audio.h>
#include <system/audio_policy.h>

namespace android {

class AudioPolicyClientInterface;

class DeviceDescriptor : public DeviceDescriptorBase,
                         public PolicyAudioPort, public PolicyAudioPortConfig
{
public:
     // Note that empty name refers by convention to a generic device.
    explicit DeviceDescriptor(audio_devices_t type);
    DeviceDescriptor(audio_devices_t type, const std::string &tagName,
            const FormatVector &encodedFormats = FormatVector{});
    DeviceDescriptor(audio_devices_t type, const std::string &tagName,
            const std::string &address, const FormatVector &encodedFormats = FormatVector{});
    DeviceDescriptor(const AudioDeviceTypeAddr &deviceTypeAddr, const std::string &tagName = "",
            const FormatVector &encodedFormats = FormatVector{});

    virtual ~DeviceDescriptor() = default;

    virtual void addAudioProfile(const sp<AudioProfile> &profile) {
        addAudioProfileAndSort(mProfiles, profile);
    }

    virtual const std::string getTagName() const { return mTagName; }

    audio_format_t getEncodedFormat() { return mCurrentEncodedFormat; }

    void setEncodedFormat(audio_format_t format) {
        mCurrentEncodedFormat = format;
    }

    bool equals(const sp<DeviceDescriptor>& other) const;

    bool hasCurrentEncodedFormat() const;

    void setDynamic() { mIsDynamic = true; }
    bool isDynamic() const { return mIsDynamic; }

    // PolicyAudioPortConfig
    virtual sp<PolicyAudioPort> getPolicyAudioPort() const {
        return static_cast<PolicyAudioPort*>(const_cast<DeviceDescriptor*>(this));
    }

    // AudioPortConfig
    virtual status_t applyAudioPortConfig(const struct audio_port_config *config,
                                          struct audio_port_config *backupConfig = NULL);
    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
            const struct audio_port_config *srcConfig = NULL) const;

    // PolicyAudioPort
    virtual sp<AudioPort> asAudioPort() const {
        return static_cast<AudioPort*>(const_cast<DeviceDescriptor*>(this));
    }
    virtual void attach(const sp<HwModule>& module);
    virtual void detach();

    // AudioPort
    virtual void toAudioPort(struct audio_port *port) const;
    virtual void toAudioPort(struct audio_port_v7 *port) const;

    void importAudioPortAndPickAudioProfile(const sp<PolicyAudioPort>& policyPort,
                                            bool force = false);

    status_t readFromParcelable(const media::AudioPortFw& parcelable) override;

    void setEncapsulationInfoFromHal(AudioPolicyClientInterface *clientInterface);

    void setPreferredConfig(const audio_config_base_t * preferredConfig);

    void dump(String8 *dst, int spaces, bool verbose = true) const;

private:
    template <typename T, std::enable_if_t<std::is_same<T, struct audio_port>::value
                                        || std::is_same<T, struct audio_port_v7>::value, int> = 0>
    void toAudioPortInternal(T* port) const {
        DeviceDescriptorBase::toAudioPort(port);
        port->ext.device.hw_module = getModuleHandle();
    }

    std::string mTagName; // Unique human readable identifier for a device port found in conf file.
    audio_format_t      mCurrentEncodedFormat;
    bool                mIsDynamic = false;
    std::string         mDeclaredAddress; // Original device address
    std::optional<audio_config_base_t> mPreferredConfig;
};

class DeviceVector : public SortedVector<sp<DeviceDescriptor> >
{
public:
    DeviceVector() : SortedVector() {}
    explicit DeviceVector(const sp<DeviceDescriptor>& item) : DeviceVector()
    {
        add(item);
    }

    ssize_t add(const sp<DeviceDescriptor>& item);
    void add(const DeviceVector &devices);
    ssize_t remove(const sp<DeviceDescriptor>& item);
    void remove(const DeviceVector &devices);
    ssize_t indexOf(const sp<DeviceDescriptor>& item) const;

    DeviceTypeSet types() const { return mDeviceTypes; }

    // If 'address' is empty and 'codec' is AUDIO_FORMAT_DEFAULT, a device with a non-empty
    // address may be returned if there is no device with the specified 'type' and empty address.
    sp<DeviceDescriptor> getDevice(audio_devices_t type, const String8 &address,
                                   audio_format_t codec) const;
    DeviceVector getDevicesFromTypes(const DeviceTypeSet& types) const;
    DeviceVector getDevicesFromType(audio_devices_t type) const {
        return getDevicesFromTypes({type});
    }

    /**
     * @brief getDeviceFromId
     * @param id of the DeviceDescriptor to seach (aka Port handle).
     * @return DeviceDescriptor associated to port id if found, nullptr otherwise. If the id is
     * equal to AUDIO_PORT_HANDLE_NONE, it also returns a nullptr.
     */
    sp<DeviceDescriptor> getDeviceFromId(audio_port_handle_t id) const;
    sp<DeviceDescriptor> getDeviceFromTagName(const std::string &tagName) const;
    DeviceVector getDevicesFromHwModule(audio_module_handle_t moduleHandle) const;

    DeviceVector getFirstDevicesFromTypes(std::vector<audio_devices_t> orderedTypes) const;
    sp<DeviceDescriptor> getFirstExistingDevice(std::vector<audio_devices_t> orderedTypes) const;

    // Return device descriptor that is used to open an input/output stream.
    // Null pointer will be returned if
    //     1) this collection is empty
    //     2) the device descriptors are not the same category(input or output)
    //     3) there are more than one device type for input case
    //     4) the combination of all devices is invalid for selection
    sp<DeviceDescriptor> getDeviceForOpening() const;

    // Return the device descriptor that matches the given AudioDeviceTypeAddr
    sp<DeviceDescriptor> getDeviceFromDeviceTypeAddr(
            const AudioDeviceTypeAddr& deviceTypeAddr) const;

    // Return the device vector that contains device descriptor whose AudioDeviceTypeAddr appears
    // in the given AudioDeviceTypeAddrVector
    DeviceVector getDevicesFromDeviceTypeAddrVec(
            const AudioDeviceTypeAddrVector& deviceTypeAddrVector) const;

    // Return the device vector that contains device descriptor whose AudioDeviceTypeAddr appears
    // in the given AudioDeviceTypeAddrVector
    AudioDeviceTypeAddrVector toTypeAddrVector() const;

    // If there are devices with the given type and the devices to add is not empty,
    // remove all the devices with the given type and add all the devices to add.
    void replaceDevicesByType(audio_devices_t typeToRemove, const DeviceVector &devicesToAdd);

    bool containsDeviceAmongTypes(const DeviceTypeSet& deviceTypes) const {
        return !Intersection(mDeviceTypes, deviceTypes).empty();
    }

    bool containsDeviceWithType(audio_devices_t deviceType) const {
        return containsDeviceAmongTypes({deviceType});
    }

    bool onlyContainsDevicesWithType(audio_devices_t deviceType) const {
        return isSingleDeviceType(mDeviceTypes, deviceType);
    }

    bool onlyContainsDevice(const sp<DeviceDescriptor>& item) const {
        return this->size() == 1 && contains(item);
    }

    bool contains(const sp<DeviceDescriptor>& item) const { return indexOf(item) >= 0; }

    /**
     * @brief containsAtLeastOne
     * @param devices vector of devices to check against.
     * @return true if the DeviceVector contains at list one of the devices from the given vector.
     */
    bool containsAtLeastOne(const DeviceVector &devices) const;

    /**
     * @brief containsAllDevices
     * @param devices vector of devices to check against.
     * @return true if the DeviceVector contains all the devices from the given vector
     */
    bool containsAllDevices(const DeviceVector &devices) const;

    /**
     * @brief filter the devices supported by this collection against another collection
     * @param devices to filter against
     * @return a filtered DeviceVector
     */
    DeviceVector filter(const DeviceVector &devices) const;

    /**
     * @brief filter the devices supported by this collection before sending
     * then to the Engine via AudioPolicyManagerObserver interface
     * @return a filtered DeviceVector
     */
    DeviceVector filterForEngine() const;

    /**
     * @brief merge two vectors. As SortedVector Implementation is buggy (it does not check the size
     * of the destination vector, only of the source, it provides a safe implementation
     * @param devices source device vector to merge with
     * @return size of the merged vector.
     */
    ssize_t merge(const DeviceVector &devices)
    {
        if (isEmpty()) {
            add(devices);
            return size();
        }
        ssize_t ret = SortedVector::merge(devices);
        refreshTypes();
        return ret;
    }

    /**
     * @brief operator == DeviceVector are equals if all the DeviceDescriptor can be found (aka
     * DeviceDescriptor with same type and address) and the vector has same size.
     * @param right DeviceVector to compare to.
     * @return true if right contains the same device and has the same size.
     */
    bool operator==(const DeviceVector &right) const
    {
        if (size() != right.size()) {
            return false;
        }
        for (const auto &device : *this) {
            if (right.indexOf(device) < 0) {
                return false;
            }
        }
        return true;
    }

    bool operator!=(const DeviceVector &right) const
    {
        return !operator==(right);
    }

    /**
     * @brief getFirstValidAddress
     * @return the first valid address of a list of device, "" if no device with valid address
     * found.
     * This helper function helps maintaining compatibility with legacy where we used to have a
     * devices mask and an address.
     */
    String8 getFirstValidAddress() const
    {
        for (const auto &device : *this) {
            if (device->address() != "") {
                return String8(device->address().c_str());
            }
        }
        return String8("");
    }

    const AudioProfileVector& getSupportedProfiles() { return mSupportedProfiles; }

    // Return a string to describe the DeviceVector. The sensitive information will only be
    // added to the string if `includeSensitiveInfo` is true.
    std::string toString(bool includeSensitiveInfo = false) const;

    void dump(String8 *dst, const String8 &tag, int spaces = 0, bool verbose = true) const;

protected:
    int     do_compare(const void* lhs, const void* rhs) const;
private:
    void refreshTypes();
    void refreshAudioProfiles();
    DeviceTypeSet mDeviceTypes;
    AudioProfileVector mSupportedProfiles;
};

} // namespace android
