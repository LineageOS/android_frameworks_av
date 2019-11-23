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

#include <binder/Parcelable.h>
#include <binder/Parcel.h>
#include <media/AudioContainers.h>
#include <system/audio.h>
#include <utils/Errors.h>

namespace android {

struct AudioDeviceTypeAddr : public Parcelable {
    AudioDeviceTypeAddr() = default;

    AudioDeviceTypeAddr(audio_devices_t type, const std::string& address) :
            mType(type), mAddress(address) {}

    const char* getAddress() const;

    bool equals(const AudioDeviceTypeAddr& other) const;

    AudioDeviceTypeAddr& operator= (const AudioDeviceTypeAddr&) = default;

    bool operator<(const AudioDeviceTypeAddr& other) const;

    void reset();

    status_t readFromParcel(const Parcel *parcel) override;

    status_t writeToParcel(Parcel *parcel) const override;

    audio_devices_t mType = AUDIO_DEVICE_NONE;
    std::string mAddress;
};

using AudioDeviceTypeAddrVector = std::vector<AudioDeviceTypeAddr>;

/**
 * Return a collection of audio device types from a collection of AudioDeviceTypeAddr
 */
DeviceTypeSet getAudioDeviceTypes(const AudioDeviceTypeAddrVector& deviceTypeAddrs);

}
