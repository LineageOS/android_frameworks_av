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

#include <string>
#include <vector>

#include <android/media/AudioDevice.h>
#include <binder/Parcelable.h>
#include <binder/Parcel.h>
#include <media/AudioContainers.h>
#include <media/AidlConversionUtil.h>
#include <system/audio.h>
#include <utils/Errors.h>

namespace android {

class AudioDeviceTypeAddr : public Parcelable {
public:
    AudioDeviceTypeAddr() = default;

    AudioDeviceTypeAddr(audio_devices_t type, const std::string& address);

    const char* getAddress() const;

    const std::string& address() const;

    void setAddress(const std::string& address);

    bool isAddressSensitive();

    bool equals(const AudioDeviceTypeAddr& other) const;

    AudioDeviceTypeAddr& operator= (const AudioDeviceTypeAddr&) = default;

    bool operator<(const AudioDeviceTypeAddr& other) const;

    bool operator==(const AudioDeviceTypeAddr& rhs) const;

    bool operator!=(const AudioDeviceTypeAddr& rhs) const;

    void reset();

    std::string toString(bool includeSensitiveInfo=false) const;

    status_t readFromParcel(const Parcel *parcel) override;

    status_t writeToParcel(Parcel *parcel) const override;

    audio_devices_t mType = AUDIO_DEVICE_NONE;

private:
    std::string mAddress;
    bool mIsAddressSensitive;
};

using AudioDeviceTypeAddrVector = std::vector<AudioDeviceTypeAddr>;

/**
 * Return a collection of audio device types from a collection of AudioDeviceTypeAddr
 */
DeviceTypeSet getAudioDeviceTypes(const AudioDeviceTypeAddrVector& deviceTypeAddrs);

/**
 * Return a collection of AudioDeviceTypeAddrs that are shown in `devices` but not
 * in `devicesToExclude`
 */
AudioDeviceTypeAddrVector excludeDeviceTypeAddrsFrom(
        const AudioDeviceTypeAddrVector& devices,
        const AudioDeviceTypeAddrVector& devicesToExclude);

std::string dumpAudioDeviceTypeAddrVector(const AudioDeviceTypeAddrVector& deviceTypeAddrs,
                                          bool includeSensitiveInfo=false);

// Conversion routines, according to AidlConversion.h conventions.
ConversionResult<AudioDeviceTypeAddr>
aidl2legacy_AudioDeviceTypeAddress(const media::AudioDevice& aidl);
ConversionResult<media::AudioDevice>
legacy2aidl_AudioDeviceTypeAddress(const AudioDeviceTypeAddr& legacy);

} // namespace android
