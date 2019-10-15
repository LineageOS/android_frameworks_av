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
    AudioPort("", AUDIO_PORT_TYPE_DEVICE,
              audio_is_output_device(type) ? AUDIO_PORT_ROLE_SINK :
                                             AUDIO_PORT_ROLE_SOURCE),
    mDeviceType(type)
{
    if (audio_is_remote_submix_device(type)) {
        mAddress = "0";
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

    dstConfig->role = audio_is_output_device(mDeviceType) ?
                        AUDIO_PORT_ROLE_SINK : AUDIO_PORT_ROLE_SOURCE;
    dstConfig->type = AUDIO_PORT_TYPE_DEVICE;
    dstConfig->ext.device.type = mDeviceType;

    (void)audio_utils_strlcpy_zerofill(dstConfig->ext.device.address, mAddress.c_str());
}

void DeviceDescriptorBase::toAudioPort(struct audio_port *port) const
{
    ALOGV("DeviceDescriptorBase::toAudioPort() handle %d type %08x", mId, mDeviceType);
    AudioPort::toAudioPort(port);
    toAudioPortConfig(&port->active_config);
    port->id = mId;
    port->ext.device.type = mDeviceType;
    (void)audio_utils_strlcpy_zerofill(port->ext.device.address, mAddress.c_str());
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
            spaces, "", ::android::toString(mDeviceType).c_str()));

    if (mAddress.size() != 0) {
        dst->append(base::StringPrintf("%*s- address: %-32s\n", spaces, "", mAddress.c_str()));
    }
    AudioPort::dump(dst, spaces, verbose);
}

std::string DeviceDescriptorBase::toString() const
{
    std::stringstream sstream;
    sstream << "type:0x" << std::hex << type() << ",@:" << mAddress;
    return sstream.str();
}

void DeviceDescriptorBase::log() const
{
    ALOGI("Device id:%d type:0x%08X:%s, addr:%s", mId,  mDeviceType,
          ::android::toString(mDeviceType).c_str(),
          mAddress.c_str());

    AudioPort::log("  ");
}

bool DeviceDescriptorBase::equals(const sp<DeviceDescriptorBase> &other) const
{
    return other != nullptr &&
           static_cast<const AudioPort*>(this)->equals(other) &&
           static_cast<const AudioPortConfig*>(this)->equals(other) &&
           mAddress.compare(other->address()) == 0 &&
           mDeviceType == other->type();
}

status_t DeviceDescriptorBase::writeToParcel(Parcel *parcel) const
{
    status_t status = NO_ERROR;
    if ((status = AudioPort::writeToParcel(parcel)) != NO_ERROR) return status;
    if ((status = AudioPortConfig::writeToParcel(parcel)) != NO_ERROR) return status;
    if ((status = parcel->writeUtf8AsUtf16(mAddress)) != NO_ERROR) return status;
    if ((status = parcel->writeUint32(mDeviceType)) != NO_ERROR) return status;
    return status;
}

status_t DeviceDescriptorBase::readFromParcel(const Parcel *parcel)
{
    status_t status = NO_ERROR;
    if ((status = AudioPort::readFromParcel(parcel)) != NO_ERROR) return status;
    if ((status = AudioPortConfig::readFromParcel(parcel)) != NO_ERROR) return status;
    if ((status = parcel->readUtf8FromUtf16(&mAddress)) != NO_ERROR) return status;
    if ((status = parcel->readUint32(&mDeviceType)) != NO_ERROR) return status;
    return status;
}

} // namespace android
