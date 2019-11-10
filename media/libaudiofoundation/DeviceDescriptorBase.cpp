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
    if (mDeviceTypeAddr.mAddress.empty() && audio_is_remote_submix_device(mDeviceTypeAddr.mType)) {
        mDeviceTypeAddr.mAddress = "0";
    }
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
    AudioPort::toAudioPort(port);
    toAudioPortConfig(&port->active_config);
    port->id = mId;
    port->ext.device.type = mDeviceTypeAddr.mType;
    (void)audio_utils_strlcpy_zerofill(port->ext.device.address, mDeviceTypeAddr.getAddress());
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

    if (mDeviceTypeAddr.mAddress.size() != 0) {
        dst->append(base::StringPrintf(
                "%*s- address: %-32s\n", spaces, "", mDeviceTypeAddr.getAddress()));
    }
    AudioPort::dump(dst, spaces, verbose);
}

std::string DeviceDescriptorBase::toString() const
{
    std::stringstream sstream;
    sstream << "type:0x" << std::hex << type() << ",@:" << mDeviceTypeAddr.mAddress;
    return sstream.str();
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
    status_t status = NO_ERROR;
    if ((status = AudioPort::writeToParcel(parcel)) != NO_ERROR) return status;
    if ((status = AudioPortConfig::writeToParcel(parcel)) != NO_ERROR) return status;
    if ((status = parcel->writeParcelable(mDeviceTypeAddr)) != NO_ERROR) return status;
    return status;
}

status_t DeviceDescriptorBase::readFromParcel(const Parcel *parcel)
{
    status_t status = NO_ERROR;
    if ((status = AudioPort::readFromParcel(parcel)) != NO_ERROR) return status;
    if ((status = AudioPortConfig::readFromParcel(parcel)) != NO_ERROR) return status;
    if ((status = parcel->readParcelable(&mDeviceTypeAddr)) != NO_ERROR) return status;
    return status;
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

} // namespace android
