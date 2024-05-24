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

#define LOG_TAG "APM::Devices"
//#define LOG_NDEBUG 0

#include <set>

#include <android-base/stringprintf.h>
#include <audio_utils/string.h>
#include <media/AudioParameter.h>
#include <media/TypeConverter.h>
#include <AudioPolicyInterface.h>
#include "DeviceDescriptor.h"
#include "TypeConverter.h"
#include "HwModule.h"

namespace android {

DeviceDescriptor::DeviceDescriptor(audio_devices_t type) :
        DeviceDescriptor(type, "" /*tagName*/)
{
}

DeviceDescriptor::DeviceDescriptor(audio_devices_t type,
                                   const std::string &tagName,
                                   const FormatVector &encodedFormats) :
        DeviceDescriptor(type, tagName, "" /*address*/, encodedFormats)
{
}

DeviceDescriptor::DeviceDescriptor(audio_devices_t type,
                                   const std::string &tagName,
                                   const std::string &address,
                                   const FormatVector &encodedFormats) :
        DeviceDescriptor(AudioDeviceTypeAddr(type, address), tagName, encodedFormats)
{
}

// Let DeviceDescriptorBase initialize the address since it handles specific cases like
// legacy remote submix where "0" is added as default address.
DeviceDescriptor::DeviceDescriptor(const AudioDeviceTypeAddr &deviceTypeAddr,
                                   const std::string &tagName,
                                   const FormatVector &encodedFormats) :
        DeviceDescriptorBase(deviceTypeAddr, encodedFormats), mTagName(tagName),
        mDeclaredAddress(DeviceDescriptorBase::address())
{
    mCurrentEncodedFormat = AUDIO_FORMAT_DEFAULT;
}

void DeviceDescriptor::attach(const sp<HwModule>& module)
{
    PolicyAudioPort::attach(module);
    mId = getNextUniqueId();
}

void DeviceDescriptor::detach() {
    mId = AUDIO_PORT_HANDLE_NONE;
    PolicyAudioPort::detach();
    // The device address may have been overwritten on device connection
    setAddress(mDeclaredAddress);
    // Device Port does not have a name unless provided by setDeviceConnectionState
    setName("");
}

template<typename T>
bool checkEqual(const T& f1, const T& f2)
{
    std::set<typename T::value_type> s1(f1.begin(), f1.end());
    std::set<typename T::value_type> s2(f2.begin(), f2.end());
    return s1 == s2;
}

bool DeviceDescriptor::equals(const sp<DeviceDescriptor>& other) const
{
    // Devices are considered equal if they:
    // - are of the same type (a device type cannot be AUDIO_DEVICE_NONE)
    // - have the same address
    // - have the same encodingFormats (if device supports encoding)
    if (other == 0) {
        return false;
    }

    return mDeviceTypeAddr.equals(other->mDeviceTypeAddr) &&
           checkEqual(mEncodedFormats, other->mEncodedFormats);
}

bool DeviceDescriptor::hasCurrentEncodedFormat() const
{
    if (!device_has_encoding_capability(type())) {
        return true;
    }
    if (mEncodedFormats.empty()) {
        return true;
    }

    return (mCurrentEncodedFormat != AUDIO_FORMAT_DEFAULT);
}

status_t DeviceDescriptor::applyAudioPortConfig(const struct audio_port_config *config,
                                                audio_port_config *backupConfig)
{
    struct audio_port_config localBackupConfig = { .config_mask = config->config_mask };
    status_t status = NO_ERROR;

    toAudioPortConfig(&localBackupConfig);
    if ((status = validationBeforeApplyConfig(config)) == NO_ERROR) {
        AudioPortConfig::applyAudioPortConfig(config, backupConfig);
    }

    if (backupConfig != NULL) {
        *backupConfig = localBackupConfig;
    }
    return status;
}

void DeviceDescriptor::toAudioPortConfig(struct audio_port_config *dstConfig,
                                         const struct audio_port_config *srcConfig) const
{
    DeviceDescriptorBase::toAudioPortConfig(dstConfig, srcConfig);
    dstConfig->ext.device.hw_module = getModuleHandle();
    if (mPreferredConfig.has_value()) {
        if (mPreferredConfig->format != AUDIO_FORMAT_DEFAULT) {
            dstConfig->config_mask |= AUDIO_PORT_CONFIG_FORMAT;
            dstConfig->format = mPreferredConfig->format;
        }
        if (mPreferredConfig->sample_rate != 0) {
            dstConfig->config_mask |= AUDIO_PORT_CONFIG_SAMPLE_RATE;
            dstConfig->sample_rate = mPreferredConfig->sample_rate;
        }
        if (mPreferredConfig->channel_mask != AUDIO_CHANNEL_NONE) {
            dstConfig->config_mask |= AUDIO_PORT_CONFIG_CHANNEL_MASK;
            dstConfig->channel_mask = mPreferredConfig->channel_mask;
        }
    }
}

void DeviceDescriptor::toAudioPort(struct audio_port *port) const
{
    ALOGV("DeviceDescriptor::toAudioPort() handle %d type %08x", mId, mDeviceTypeAddr.mType);
    toAudioPortInternal(port);
}

void DeviceDescriptor::toAudioPort(struct audio_port_v7 *port) const {
    ALOGV("DeviceDescriptor::toAudioPort() v7 handle %d type %08x", mId, mDeviceTypeAddr.mType);
    toAudioPortInternal(port);
}

void DeviceDescriptor::importAudioPortAndPickAudioProfile(
        const sp<PolicyAudioPort>& policyPort, bool force) {
    if (!force && !policyPort->asAudioPort()->hasDynamicAudioProfile()) {
        return;
    }
    AudioPort::importAudioPort(policyPort->asAudioPort());
    policyPort->pickAudioProfile(mSamplingRate, mChannelMask, mFormat);
}

status_t DeviceDescriptor::readFromParcelable(const media::AudioPortFw& parcelable) {
    RETURN_STATUS_IF_ERROR(DeviceDescriptorBase::readFromParcelable(parcelable));
    mDeclaredAddress = DeviceDescriptorBase::address();
    return OK;
}

void DeviceDescriptor::setEncapsulationInfoFromHal(
        AudioPolicyClientInterface *clientInterface) {
    AudioParameter param(String8(mDeviceTypeAddr.getAddress()));
    param.addInt(String8(AudioParameter::keyRouting), mDeviceTypeAddr.mType);
    param.addKey(String8(AUDIO_PARAMETER_DEVICE_SUP_ENCAPSULATION_MODES));
    param.addKey(String8(AUDIO_PARAMETER_DEVICE_SUP_ENCAPSULATION_METADATA_TYPES));
    String8 reply = clientInterface->getParameters(AUDIO_IO_HANDLE_NONE, param.toString());
    AudioParameter repliedParameters(reply);
    int value;
    if (repliedParameters.getInt(
            String8(AUDIO_PARAMETER_DEVICE_SUP_ENCAPSULATION_MODES), value) == NO_ERROR) {
        if (setEncapsulationModes(value) != NO_ERROR) {
            ALOGE("Failed to set encapsulation mode(%d)", value);
        }
    }
    if (repliedParameters.getInt(
            String8(AUDIO_PARAMETER_DEVICE_SUP_ENCAPSULATION_METADATA_TYPES), value) == NO_ERROR) {
        if (setEncapsulationMetadataTypes(value) != NO_ERROR) {
            ALOGE("Failed to set encapsulation metadata types(%d)", value);
        }
    }
}

void DeviceDescriptor::setPreferredConfig(const audio_config_base_t* preferredConfig) {
    if (preferredConfig == nullptr) {
        mPreferredConfig.reset();
    } else {
        mPreferredConfig = *preferredConfig;
    }
}

void DeviceDescriptor::dump(String8 *dst, int spaces, bool verbose) const
{
    String8 extraInfo;
    if (!mTagName.empty()) {
        extraInfo.appendFormat("\"%s\"", mTagName.c_str());
    }

    std::string descBaseDumpStr;
    DeviceDescriptorBase::dump(&descBaseDumpStr, spaces, extraInfo.c_str(), verbose);
    dst->append(descBaseDumpStr.c_str());

    if (mPreferredConfig.has_value()) {
        dst->append(base::StringPrintf(
                "%*sPreferred Config: format=%#x, channelMask=%#x, sampleRate=%u\n",
                spaces, "", mPreferredConfig.value().format, mPreferredConfig.value().channel_mask,
                mPreferredConfig.value().sample_rate).c_str());
    }
}


void DeviceVector::refreshTypes()
{
    mDeviceTypes.clear();
    for (size_t i = 0; i < size(); i++) {
        mDeviceTypes.insert(itemAt(i)->type());
    }
    ALOGV("DeviceVector::refreshTypes() mDeviceTypes %s", dumpDeviceTypes(mDeviceTypes).c_str());
}

void DeviceVector::refreshAudioProfiles() {
    if (empty()) {
        mSupportedProfiles.clear();
        return;
    }
    mSupportedProfiles = itemAt(0)->getAudioProfiles();
    for (size_t i = 1; i < size(); ++i) {
        mSupportedProfiles = intersectAudioProfiles(
                mSupportedProfiles, itemAt(i)->getAudioProfiles());
    }
}

ssize_t DeviceVector::indexOf(const sp<DeviceDescriptor>& item) const
{
    for (size_t i = 0; i < size(); i++) {
        if (itemAt(i)->equals(item)) { // item may be null sp<>, i.e. AUDIO_DEVICE_NONE
            return i;
        }
    }
    return -1;
}

void DeviceVector::add(const DeviceVector &devices)
{
    bool added = false;
    for (const auto& device : devices) {
        if (device && indexOf(device) < 0 && SortedVector::add(device) >= 0) {
            added = true;
        }
    }
    if (added) {
        refreshTypes();
        refreshAudioProfiles();
    }
}

ssize_t DeviceVector::add(const sp<DeviceDescriptor>& item)
{
    if (!item) {
        ALOGW("DeviceVector::%s() null device", __func__);
        return -1;
    }
    ssize_t ret = indexOf(item);

    if (ret < 0) {
        ret = SortedVector::add(item);
        if (ret >= 0) {
            refreshTypes();
            refreshAudioProfiles();
        }
    } else {
        ALOGW("DeviceVector::add device %08x already in", item->type());
        ret = -1;
    }
    return ret;
}

int DeviceVector::do_compare(const void* lhs, const void* rhs) const {
    const auto ldevice = *reinterpret_cast<const sp<DeviceDescriptor>*>(lhs);
    const auto rdevice = *reinterpret_cast<const sp<DeviceDescriptor>*>(rhs);
    int ret = 0;

    // sort by type.
    ret = compare_type(ldevice->type(), rdevice->type());
    if (ret != 0)
        return ret;
    // for same type higher priority for latest device.
    ret = compare_type(rdevice->getId(), ldevice->getId());
    if (ret != 0)
        return ret;
    // fallback to default sort using pointer address
    return SortedVector::do_compare(lhs, rhs);
}

ssize_t DeviceVector::remove(const sp<DeviceDescriptor>& item)
{
    ssize_t ret = indexOf(item);

    if (ret < 0) {
        ALOGW("DeviceVector::remove device %08x not in", item->type());
    } else {
        ret = SortedVector::removeAt(ret);
        if (ret >= 0) {
            refreshTypes();
            refreshAudioProfiles();
        }
    }
    return ret;
}

void DeviceVector::remove(const DeviceVector &devices)
{
    for (const auto& device : devices) {
        remove(device);
    }
}

DeviceVector DeviceVector::getDevicesFromHwModule(audio_module_handle_t moduleHandle) const
{
    DeviceVector devices;
    for (const auto& device : *this) {
        if (device->getModuleHandle() == moduleHandle) {
            devices.add(device);
        }
    }
    return devices;
}

sp<DeviceDescriptor> DeviceVector::getDevice(audio_devices_t type, const String8& address,
                                             audio_format_t format) const
{
    sp<DeviceDescriptor> device;
    for (size_t i = 0; i < size(); i++) {
        if (itemAt(i)->type() == type) {
            // If format is specified, match it and ignore address
            // Otherwise if address is specified match it
            // Otherwise always match
            if (((address == "" || (itemAt(i)->address().compare(address.c_str()) == 0)) &&
                 format == AUDIO_FORMAT_DEFAULT) ||
                (itemAt(i)->supportsFormat(format) && format != AUDIO_FORMAT_DEFAULT)) {
                device = itemAt(i);
                if (itemAt(i)->address().compare(address.c_str()) == 0) {
                    break;
                }
            }
        }
    }
    ALOGV("DeviceVector::%s() for type %08x address \"%s\" found %p format %08x",
            __func__, type, address.c_str(), device.get(), format);
    return device;
}

sp<DeviceDescriptor> DeviceVector::getDeviceFromId(audio_port_handle_t id) const
{
    if (id != AUDIO_PORT_HANDLE_NONE) {
        for (const auto& device : *this) {
            if (device->getId() == id) {
                return device;
            }
        }
    }
    return nullptr;
}

DeviceVector DeviceVector::getDevicesFromTypes(const DeviceTypeSet& types) const
{
    DeviceVector devices;
    if (types.empty()) {
        return devices;
    }
    for (size_t i = 0; i < size(); i++) {
        if (types.count(itemAt(i)->type()) != 0) {
            devices.add(itemAt(i));
            ALOGV("DeviceVector::%s() for type %08x found %p",
                    __func__, itemAt(i)->type(), itemAt(i).get());
        }
    }
    return devices;
}

sp<DeviceDescriptor> DeviceVector::getDeviceFromTagName(const std::string &tagName) const
{
    for (const auto& device : *this) {
        if (device->getTagName() == tagName) {
            return device;
        }
    }
    return nullptr;
}

DeviceVector DeviceVector::getFirstDevicesFromTypes(
        std::vector<audio_devices_t> orderedTypes) const
{
    DeviceVector devices;
    for (auto deviceType : orderedTypes) {
        if (!(devices = getDevicesFromType(deviceType)).isEmpty()) {
            break;
        }
    }
    return devices;
}

sp<DeviceDescriptor> DeviceVector::getFirstExistingDevice(
        std::vector<audio_devices_t> orderedTypes) const {
    sp<DeviceDescriptor> device;
    for (auto deviceType : orderedTypes) {
        if ((device = getDevice(deviceType, String8(""), AUDIO_FORMAT_DEFAULT)) != nullptr) {
            break;
        }
    }
    return device;
}

sp<DeviceDescriptor> DeviceVector::getDeviceForOpening() const
{
    if (isEmpty()) {
        // Return nullptr if this collection is empty.
        return nullptr;
    } else if (areAllOfSameDeviceType(types(), audio_call_is_input_device)) {
        // For input case, return the first one when there is only one device.
        return size() > 1 ? nullptr : *begin();
    } else if (areAllOfSameDeviceType(types(), audio_is_output_device)) {
        // For output case, return the device descriptor according to apm strategy.
        audio_devices_t deviceType = apm_extract_one_audio_device(types());
        return deviceType == AUDIO_DEVICE_NONE ? nullptr :
                getDevice(deviceType, String8(""), AUDIO_FORMAT_DEFAULT);
    }
    // Return null pointer if the devices are not all input/output device.
    return nullptr;
}

sp<DeviceDescriptor> DeviceVector::getDeviceFromDeviceTypeAddr(
            const AudioDeviceTypeAddr& deviceTypeAddr) const {
    return getDevice(deviceTypeAddr.mType, String8(deviceTypeAddr.getAddress()),
            AUDIO_FORMAT_DEFAULT);
}

DeviceVector DeviceVector::getDevicesFromDeviceTypeAddrVec(
        const AudioDeviceTypeAddrVector& deviceTypeAddrVector) const {
    DeviceVector devices;
    for (const auto& deviceTypeAddr : deviceTypeAddrVector) {
        sp<DeviceDescriptor> device = getDeviceFromDeviceTypeAddr(deviceTypeAddr);
        if (device != nullptr) {
            devices.add(device);
        }
    }
    return devices;
}

AudioDeviceTypeAddrVector DeviceVector::toTypeAddrVector() const {
    AudioDeviceTypeAddrVector result;
    for (const auto& device : *this) {
        result.push_back(AudioDeviceTypeAddr(device->type(), device->address()));
    }
    return result;
}

void DeviceVector::replaceDevicesByType(
        audio_devices_t typeToRemove, const DeviceVector &devicesToAdd) {
    DeviceVector devicesToRemove = getDevicesFromType(typeToRemove);
    if (!devicesToRemove.isEmpty() && !devicesToAdd.isEmpty()) {
        remove(devicesToRemove);
        add(devicesToAdd);
    }
}

void DeviceVector::dump(String8 *dst, const String8 &tag, int spaces, bool verbose) const
{
    if (isEmpty()) {
        return;
    }
    dst->appendFormat("%*s%s devices (%zu):\n", spaces, "", tag.c_str(), size());
    for (size_t i = 0; i < size(); i++) {
        const std::string prefix = base::StringPrintf("%*s %zu. ", spaces, "", i + 1);
        dst->appendFormat("%s", prefix.c_str());
        itemAt(i)->dump(dst, prefix.size(), verbose);
    }
}

std::string DeviceVector::toString(bool includeSensitiveInfo) const
{
    if (isEmpty()) {
        return {"AUDIO_DEVICE_NONE"};
    }
    std::string result = {"{"};
    for (const auto &device : *this) {
        if (device != *begin()) {
           result += ";";
        }
        result += device->toString(includeSensitiveInfo);
    }
    return result + "}";
}

DeviceVector DeviceVector::filter(const DeviceVector &devices) const
{
    DeviceVector filteredDevices;
    for (const auto &device : *this) {
        if (devices.contains(device)) {
            filteredDevices.add(device);
        }
    }
    return filteredDevices;
}

bool DeviceVector::containsAtLeastOne(const DeviceVector &devices) const
{
    return !filter(devices).isEmpty();
}

bool DeviceVector::containsAllDevices(const DeviceVector &devices) const
{
    return filter(devices).size() == devices.size();
}

DeviceVector DeviceVector::filterForEngine() const
{
    DeviceVector filteredDevices;
    for (const auto &device : *this) {
        if (audio_is_remote_submix_device(device->type()) && device->address() != "0") {
            continue;
        }
        filteredDevices.add(device);
    }
    return filteredDevices;
}

} // namespace android
