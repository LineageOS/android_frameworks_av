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

namespace android {

const char* AudioDeviceTypeAddr::getAddress() const {
    return mAddress.c_str();
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

void AudioDeviceTypeAddr::reset() {
    mType = AUDIO_DEVICE_NONE;
    mAddress = "";
}

status_t AudioDeviceTypeAddr::readFromParcel(const Parcel *parcel) {
    status_t status;
    if ((status = parcel->readUint32(&mType)) != NO_ERROR) return status;
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

}