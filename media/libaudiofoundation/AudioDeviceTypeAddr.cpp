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

#include <media/AudioDeviceTypeAddr.h>
#include <arpa/inet.h>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>

#include <media/AidlConversion.h>

namespace android {

namespace {

static const std::string SUPPRESSED = "SUPPRESSED";
static const std::regex MAC_ADDRESS_REGEX("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}");

bool isSenstiveAddress(const std::string &address) {
    if (std::regex_match(address, MAC_ADDRESS_REGEX)) {
        return true;
    }

    sockaddr_storage ss4;
    if (inet_pton(AF_INET, address.c_str(), &ss4) > 0) {
        return true;
    }

    sockaddr_storage ss6;
    if (inet_pton(AF_INET6, address.c_str(), &ss6) > 0) {
        return true;
    }

    return false;
}

} // namespace

AudioDeviceTypeAddr::AudioDeviceTypeAddr(audio_devices_t type, const std::string &address) :
        mType(type), mAddress(address) {
    mIsAddressSensitive = isSenstiveAddress(mAddress);
}

const char* AudioDeviceTypeAddr::getAddress() const {
    return mAddress.c_str();
}

const std::string& AudioDeviceTypeAddr::address() const {
    return mAddress;
}

void AudioDeviceTypeAddr::setAddress(const std::string& address) {
    mAddress = address;
    mIsAddressSensitive = isSenstiveAddress(mAddress);
}

bool AudioDeviceTypeAddr::equals(const AudioDeviceTypeAddr& other) const {
    return mType == other.mType && mAddress == other.mAddress;
}

bool AudioDeviceTypeAddr::operator<(const AudioDeviceTypeAddr& other) const {
    if (mType < other.mType)  return true;
    if (mType > other.mType)  return false;

    if (mAddress < other.mAddress)  return true;
    // if (mAddress > other.mAddress)  return false;

    return false;
}

bool AudioDeviceTypeAddr::operator==(const AudioDeviceTypeAddr &rhs) const {
    return equals(rhs);
}

bool AudioDeviceTypeAddr::operator!=(const AudioDeviceTypeAddr &rhs) const {
    return !operator==(rhs);
}

void AudioDeviceTypeAddr::reset() {
    mType = AUDIO_DEVICE_NONE;
    setAddress("");
}

std::string AudioDeviceTypeAddr::toString(bool includeSensitiveInfo) const {
    std::stringstream sstream;
    sstream << "type:0x" << std::hex << mType;
    // IP and MAC address are sensitive information. The sensitive information will be suppressed
    // is `includeSensitiveInfo` is false.
    sstream << ",@:"
            << (!includeSensitiveInfo && mIsAddressSensitive ? SUPPRESSED : mAddress);
    return sstream.str();
}

status_t AudioDeviceTypeAddr::readFromParcel(const Parcel *parcel) {
    status_t status;
    uint32_t rawDeviceType;
    if ((status = parcel->readUint32(&rawDeviceType)) != NO_ERROR) return status;
    mType = static_cast<audio_devices_t>(rawDeviceType);
    status = parcel->readUtf8FromUtf16(&mAddress);
    return status;
}

status_t AudioDeviceTypeAddr::writeToParcel(Parcel *parcel) const {
    status_t status;
    if ((status = parcel->writeUint32(mType)) != NO_ERROR) return status;
    status = parcel->writeUtf8AsUtf16(mAddress);
    return status;
}


DeviceTypeSet getAudioDeviceTypes(const AudioDeviceTypeAddrVector& deviceTypeAddrs) {
    DeviceTypeSet deviceTypes;
    for (const auto& deviceTypeAddr : deviceTypeAddrs) {
        deviceTypes.insert(deviceTypeAddr.mType);
    }
    return deviceTypes;
}

AudioDeviceTypeAddrVector excludeDeviceTypeAddrsFrom(
        const AudioDeviceTypeAddrVector& devices,
        const AudioDeviceTypeAddrVector& devicesToExclude) {
    std::set<AudioDeviceTypeAddr> devicesToExcludeSet(
            devicesToExclude.begin(), devicesToExclude.end());
    AudioDeviceTypeAddrVector remainedDevices;
    for (const auto& device : devices) {
        if (devicesToExcludeSet.count(device) == 0) {
            remainedDevices.push_back(device);
        }
    }
    return remainedDevices;
}

std::string dumpAudioDeviceTypeAddrVector(const AudioDeviceTypeAddrVector& deviceTypeAddrs,
                                          bool includeSensitiveInfo) {
    std::stringstream stream;
    for (auto it = deviceTypeAddrs.begin(); it != deviceTypeAddrs.end(); ++it) {
        if (it != deviceTypeAddrs.begin()) {
            stream << " ";
        }
        stream << it->toString(includeSensitiveInfo);
    }
    return stream.str();
}

ConversionResult<AudioDeviceTypeAddr>
aidl2legacy_AudioDeviceTypeAddress(const media::AudioDevice& aidl) {
    audio_devices_t type = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_devices_t(aidl.type));
    return AudioDeviceTypeAddr(type, aidl.address);
}

ConversionResult<media::AudioDevice>
legacy2aidl_AudioDeviceTypeAddress(const AudioDeviceTypeAddr& legacy) {
    media::AudioDevice aidl;
    aidl.type = VALUE_OR_RETURN(legacy2aidl_audio_devices_t_int32_t(legacy.mType));
    aidl.address = legacy.getAddress();
    return aidl;
}

} // namespace android
