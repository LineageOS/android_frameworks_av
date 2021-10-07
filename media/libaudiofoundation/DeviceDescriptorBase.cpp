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

#define LOG_TAG "DeviceDescriptorBase"
//#define LOG_NDEBUG 0

#include <android-base/stringprintf.h>
#include <audio_utils/string.h>
#include <media/AidlConversion.h>
#include <media/DeviceDescriptorBase.h>
#include <media/TypeConverter.h>

namespace android {

DeviceDescriptorBase::DeviceDescriptorBase(audio_devices_t type) :
        DeviceDescriptorBase(type, "")
{
}

DeviceDescriptorBase::DeviceDescriptorBase(audio_devices_t type, const std::string& address) :
        DeviceDescriptorBase(AudioDeviceTypeAddr(type, address))
{
}

DeviceDescriptorBase::DeviceDescriptorBase(const AudioDeviceTypeAddr &deviceTypeAddr) :
        AudioPort("", AUDIO_PORT_TYPE_DEVICE,
                  audio_is_output_device(deviceTypeAddr.mType) ? AUDIO_PORT_ROLE_SINK :
                                         AUDIO_PORT_ROLE_SOURCE),
        mDeviceTypeAddr(deviceTypeAddr)
{
    if (mDeviceTypeAddr.address().empty() && audio_is_remote_submix_device(mDeviceTypeAddr.mType)) {
        mDeviceTypeAddr.setAddress("0");
    }
}

void DeviceDescriptorBase::setAddress(const std::string &address) {
    mDeviceTypeAddr.setAddress(address);
}

void DeviceDescriptorBase::toAudioPortConfig(struct audio_port_config *dstConfig,
                                             const struct audio_port_config *srcConfig) const
{
    dstConfig->config_mask = AUDIO_PORT_CONFIG_GAIN;
    if (mSamplingRate != 0) {
        dstConfig->config_mask |= AUDIO_PORT_CONFIG_SAMPLE_RATE;
    }
    if (mChannelMask != AUDIO_CHANNEL_NONE) {
        dstConfig->config_mask |= AUDIO_PORT_CONFIG_CHANNEL_MASK;
    }
    if (mFormat != AUDIO_FORMAT_INVALID) {
        dstConfig->config_mask |= AUDIO_PORT_CONFIG_FORMAT;
    }

    if (srcConfig != NULL) {
        dstConfig->config_mask |= srcConfig->config_mask;
    }

    AudioPortConfig::toAudioPortConfig(dstConfig, srcConfig);

    dstConfig->role = audio_is_output_device(mDeviceTypeAddr.mType) ?
                        AUDIO_PORT_ROLE_SINK : AUDIO_PORT_ROLE_SOURCE;
    dstConfig->type = AUDIO_PORT_TYPE_DEVICE;
    dstConfig->ext.device.type = mDeviceTypeAddr.mType;

    (void)audio_utils_strlcpy_zerofill(dstConfig->ext.device.address, mDeviceTypeAddr.getAddress());
}

void DeviceDescriptorBase::toAudioPort(struct audio_port *port) const
{
    ALOGV("DeviceDescriptorBase::toAudioPort() handle %d type %08x", mId, mDeviceTypeAddr.mType);
    toAudioPortInternal(port);
}

void DeviceDescriptorBase::toAudioPort(struct audio_port_v7 *port) const {
    ALOGV("DeviceDescriptorBase::toAudioPort() v7 handle %d type %08x", mId, mDeviceTypeAddr.mType);
    toAudioPortInternal(port);
}

status_t DeviceDescriptorBase::setEncapsulationModes(uint32_t encapsulationModes) {
    if ((encapsulationModes & ~AUDIO_ENCAPSULATION_MODE_ALL_POSITION_BITS) != 0) {
        return BAD_VALUE;
    }
    mEncapsulationModes = encapsulationModes & ~(1 << AUDIO_ENCAPSULATION_MODE_NONE);
    return NO_ERROR;
}

status_t DeviceDescriptorBase::setEncapsulationMetadataTypes(uint32_t encapsulationMetadataTypes) {
    if ((encapsulationMetadataTypes & ~AUDIO_ENCAPSULATION_METADATA_TYPE_ALL_POSITION_BITS) != 0) {
        return BAD_VALUE;
    }
    mEncapsulationMetadataTypes =
            encapsulationMetadataTypes & ~(1 << AUDIO_ENCAPSULATION_METADATA_TYPE_NONE);
    return NO_ERROR;
}

void DeviceDescriptorBase::dump(std::string *dst, int spaces, int index,
                                const char* extraInfo, bool verbose) const
{
    dst->append(base::StringPrintf("%*sDevice %d:\n", spaces, "", index + 1));
    if (mId != 0) {
        dst->append(base::StringPrintf("%*s- id: %2d\n", spaces, "", mId));
    }

    if (extraInfo != nullptr) {
        dst->append(extraInfo);
    }

    dst->append(base::StringPrintf("%*s- type: %-48s\n",
            spaces, "", ::android::toString(mDeviceTypeAddr.mType).c_str()));

    dst->append(base::StringPrintf(
            "%*s- supported encapsulation modes: %u\n", spaces, "", mEncapsulationModes));
    dst->append(base::StringPrintf(
            "%*s- supported encapsulation metadata types: %u\n",
            spaces, "", mEncapsulationMetadataTypes));

    if (mDeviceTypeAddr.address().size() != 0) {
        dst->append(base::StringPrintf(
                "%*s- address: %-32s\n", spaces, "", mDeviceTypeAddr.getAddress()));
    }
    AudioPort::dump(dst, spaces, verbose);
}

std::string DeviceDescriptorBase::toString(bool includeSensitiveInfo) const
{
    return mDeviceTypeAddr.toString(includeSensitiveInfo);
}

void DeviceDescriptorBase::log() const
{
    ALOGI("Device id:%d type:0x%08X:%s, addr:%s", mId,  mDeviceTypeAddr.mType,
          ::android::toString(mDeviceTypeAddr.mType).c_str(),
          mDeviceTypeAddr.getAddress());

    AudioPort::log("  ");
}

bool DeviceDescriptorBase::equals(const sp<DeviceDescriptorBase> &other) const
{
    return other != nullptr &&
           static_cast<const AudioPort*>(this)->equals(other) &&
           static_cast<const AudioPortConfig*>(this)->equals(other) &&
           mDeviceTypeAddr.equals(other->mDeviceTypeAddr);
}


status_t DeviceDescriptorBase::writeToParcel(Parcel *parcel) const
{
    media::AudioPort parcelable;
    return writeToParcelable(&parcelable)
        ?: parcelable.writeToParcel(parcel);
}

status_t DeviceDescriptorBase::writeToParcelable(media::AudioPort* parcelable) const {
    AudioPort::writeToParcelable(parcelable);
    AudioPortConfig::writeToParcelable(&parcelable->activeConfig);
    parcelable->id = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_handle_t_int32_t(mId));

    media::AudioPortDeviceExt ext;
    ext.device = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioDeviceTypeAddress(mDeviceTypeAddr));
    ext.encapsulationModes = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioEncapsulationMode_mask(mEncapsulationModes));
    ext.encapsulationMetadataTypes = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioEncapsulationMetadataType_mask(mEncapsulationMetadataTypes));
    UNION_SET(parcelable->ext, device, std::move(ext));
    return OK;
}

status_t DeviceDescriptorBase::readFromParcel(const Parcel *parcel) {
    media::AudioPort parcelable;
    return parcelable.readFromParcel(parcel)
        ?: readFromParcelable(parcelable);
}

status_t DeviceDescriptorBase::readFromParcelable(const media::AudioPort& parcelable) {
    if (parcelable.type != media::AudioPortType::DEVICE) {
        return BAD_VALUE;
    }
    status_t status = AudioPort::readFromParcelable(parcelable)
                      ?: AudioPortConfig::readFromParcelable(parcelable.activeConfig);
    if (status != OK) {
        return status;
    }

    media::AudioPortDeviceExt ext = VALUE_OR_RETURN_STATUS(UNION_GET(parcelable.ext, device));
    mDeviceTypeAddr = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioDeviceTypeAddress(ext.device));
    mEncapsulationModes = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioEncapsulationMode_mask(ext.encapsulationModes));
    mEncapsulationMetadataTypes = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioEncapsulationMetadataType_mask(ext.encapsulationMetadataTypes));
    return OK;
}

std::string toString(const DeviceDescriptorBaseVector& devices)
{
    std::string ret;
    for (const auto& device : devices) {
        if (device != *devices.begin()) {
            ret += ";";
        }
        ret += device->toString();
    }
    return ret;
}

AudioDeviceTypeAddrVector deviceTypeAddrsFromDescriptors(const DeviceDescriptorBaseVector& devices)
{
    AudioDeviceTypeAddrVector deviceTypeAddrs;
    for (const auto& device : devices) {
        deviceTypeAddrs.push_back(device->getDeviceTypeAddr());
    }
    return deviceTypeAddrs;
}

ConversionResult<sp<DeviceDescriptorBase>>
aidl2legacy_DeviceDescriptorBase(const media::AudioPort& aidl) {
    sp<DeviceDescriptorBase> result = new DeviceDescriptorBase(AUDIO_DEVICE_NONE);
    status_t status = result->readFromParcelable(aidl);
    if (status != OK) {
        return base::unexpected(status);
    }
    return result;
}

ConversionResult<media::AudioPort>
legacy2aidl_DeviceDescriptorBase(const sp<DeviceDescriptorBase>& legacy) {
    media::AudioPort aidl;
    status_t status = legacy->writeToParcelable(&aidl);
    if (status != OK) {
        return base::unexpected(status);
    }
    return aidl;
}

} // namespace android
