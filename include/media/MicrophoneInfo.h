/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_MICROPHONE_INFO_H
#define ANDROID_MICROPHONE_INFO_H

#include <android/media/MicrophoneInfoData.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <media/AidlConversionUtil.h>
#include <system/audio.h>

namespace android {
namespace media {

class MicrophoneInfo : public Parcelable {
public:
    MicrophoneInfo() = default;
    MicrophoneInfo(const MicrophoneInfo& microphoneInfo) = default;
    MicrophoneInfo(audio_microphone_characteristic_t& characteristic) {
        mDeviceId = std::string(&characteristic.device_id[0]);
        mPortId = characteristic.id;
        mType = characteristic.device;
        mAddress = std::string(&characteristic.address[0]);
        mDeviceLocation = characteristic.location;
        mDeviceGroup = characteristic.group;
        mIndexInTheGroup = characteristic.index_in_the_group;
        mGeometricLocation.push_back(characteristic.geometric_location.x);
        mGeometricLocation.push_back(characteristic.geometric_location.y);
        mGeometricLocation.push_back(characteristic.geometric_location.z);
        mOrientation.push_back(characteristic.orientation.x);
        mOrientation.push_back(characteristic.orientation.y);
        mOrientation.push_back(characteristic.orientation.z);
        std::vector<float> frequencies;
        std::vector<float> responses;
        for (size_t i = 0; i < characteristic.num_frequency_responses; i++) {
            frequencies.push_back(characteristic.frequency_responses[0][i]);
            responses.push_back(characteristic.frequency_responses[1][i]);
        }
        mFrequencyResponses.push_back(frequencies);
        mFrequencyResponses.push_back(responses);
        for (size_t i = 0; i < AUDIO_CHANNEL_COUNT_MAX; i++) {
            mChannelMapping.push_back(characteristic.channel_mapping[i]);
        }
        mSensitivity = characteristic.sensitivity;
        mMaxSpl = characteristic.max_spl;
        mMinSpl = characteristic.min_spl;
        mDirectionality = characteristic.directionality;
    }

    virtual ~MicrophoneInfo() = default;

    virtual status_t writeToParcel(Parcel* parcel) const {
        MicrophoneInfoData parcelable;
        return writeToParcelable(&parcelable)
               ?: parcelable.writeToParcel(parcel);
    }

    virtual status_t writeToParcelable(MicrophoneInfoData* parcelable) const {
#if defined(BACKEND_NDK)
        using ::aidl::android::convertReinterpret;
#endif
        parcelable->deviceId = mDeviceId;
        parcelable->portId = mPortId;
        parcelable->type = VALUE_OR_RETURN_STATUS(convertReinterpret<int32_t>(mType));
        parcelable->address = mAddress;
        parcelable->deviceGroup = mDeviceGroup;
        parcelable->indexInTheGroup = mIndexInTheGroup;
        parcelable->geometricLocation = mGeometricLocation;
        parcelable->orientation = mOrientation;
        if (mFrequencyResponses.size() != 2) {
            return BAD_VALUE;
        }
        parcelable->frequencies = mFrequencyResponses[0];
        parcelable->frequencyResponses = mFrequencyResponses[1];
        parcelable->channelMapping = mChannelMapping;
        parcelable->sensitivity = mSensitivity;
        parcelable->maxSpl = mMaxSpl;
        parcelable->minSpl = mMinSpl;
        parcelable->directionality = mDirectionality;
        return OK;
    }

    virtual status_t readFromParcel(const Parcel* parcel) {
        MicrophoneInfoData data;
        return data.readFromParcel(parcel)
            ?: readFromParcelable(data);
    }

    virtual status_t readFromParcelable(const MicrophoneInfoData& parcelable) {
#if defined(BACKEND_NDK)
        using ::aidl::android::convertReinterpret;
#endif
        mDeviceId = parcelable.deviceId;
        mPortId = parcelable.portId;
        mType = VALUE_OR_RETURN_STATUS(convertReinterpret<uint32_t>(parcelable.type));
        mAddress = parcelable.address;
        mDeviceLocation = parcelable.deviceLocation;
        mDeviceGroup = parcelable.deviceGroup;
        mIndexInTheGroup = parcelable.indexInTheGroup;
        if (parcelable.geometricLocation.size() != 3) {
            return BAD_VALUE;
        }
        mGeometricLocation = parcelable.geometricLocation;
        if (parcelable.orientation.size() != 3) {
            return BAD_VALUE;
        }
        mOrientation = parcelable.orientation;
        if (parcelable.frequencies.size() != parcelable.frequencyResponses.size()) {
            return BAD_VALUE;
        }

        mFrequencyResponses.push_back(parcelable.frequencies);
        mFrequencyResponses.push_back(parcelable.frequencyResponses);
        if (parcelable.channelMapping.size() != AUDIO_CHANNEL_COUNT_MAX) {
            return BAD_VALUE;
        }
        mChannelMapping = parcelable.channelMapping;
        mSensitivity = parcelable.sensitivity;
        mMaxSpl = parcelable.maxSpl;
        mMinSpl = parcelable.minSpl;
        mDirectionality = parcelable.directionality;
        return OK;
    }

    std::string getDeviceId() const {
        return mDeviceId;
    }

    int getPortId() const {
        return mPortId;
    }

    unsigned int getType() const {
        return mType;
    }

    std::string getAddress() const {
        return mAddress;
    }

    int getDeviceLocation() const {
        return mDeviceLocation;
    }

    int getDeviceGroup() const {
        return mDeviceGroup;
    }

    int getIndexInTheGroup() const {
        return mIndexInTheGroup;
    }

    const std::vector<float>& getGeometricLocation() const {
        return mGeometricLocation;
    }

    const std::vector<float>& getOrientation() const {
        return mOrientation;
    }

    const std::vector<std::vector<float>>& getFrequencyResponses() const {
        return mFrequencyResponses;
    }

    const std::vector<int>& getChannelMapping() const {
        return mChannelMapping;
    }

    float getSensitivity() const {
        return mSensitivity;
    }

    float getMaxSpl() const {
        return mMaxSpl;
    }

    float getMinSpl() const {
        return mMinSpl;
    }

    int getDirectionality() const {
        return mDirectionality;
    }

private:
    std::string mDeviceId;
    int32_t mPortId;
    uint32_t mType;
    std::string mAddress;
    int32_t mDeviceLocation;
    int32_t mDeviceGroup;
    int32_t mIndexInTheGroup;
    std::vector<float> mGeometricLocation;
    std::vector<float> mOrientation;
    std::vector<std::vector<float>> mFrequencyResponses;
    std::vector<int> mChannelMapping;
    float mSensitivity;
    float mMaxSpl;
    float mMinSpl;
    int32_t mDirectionality;
};

#if defined(BACKEND_NDK)
using ::aidl::ConversionResult;
#endif

// Conversion routines, according to AidlConversion.h conventions.
inline ConversionResult<MicrophoneInfo>
aidl2legacy_MicrophoneInfo(const media::MicrophoneInfoData& aidl) {
    MicrophoneInfo legacy;
    RETURN_IF_ERROR(legacy.readFromParcelable(aidl));
    return legacy;
}

inline ConversionResult<media::MicrophoneInfoData>
legacy2aidl_MicrophoneInfo(const MicrophoneInfo& legacy) {
    media::MicrophoneInfoData aidl;
    RETURN_IF_ERROR(legacy.writeToParcelable(&aidl));
    return aidl;
}

} // namespace media
} // namespace android

#endif
