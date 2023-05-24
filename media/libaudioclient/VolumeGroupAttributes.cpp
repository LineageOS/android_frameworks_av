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

#define LOG_TAG "VolumeGroupAttributes"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <binder/Parcel.h>

#include <media/AidlConversion.h>
#include <media/AudioProductStrategy.h>
#include <media/VolumeGroupAttributes.h>
#include <media/PolicyAidlConversion.h>

namespace android {

int VolumeGroupAttributes::matchesScore(const audio_attributes_t &attributes) const {
    return AudioProductStrategy::attributesMatchesScore(mAttributes, attributes);
}

status_t VolumeGroupAttributes::readFromParcel(const Parcel* parcel) {
    media::AudioAttributesEx aidl;
    RETURN_STATUS_IF_ERROR(aidl.readFromParcel(parcel));
    *this = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioAttributesEx_VolumeGroupAttributes(aidl));
    return OK;
}

status_t VolumeGroupAttributes::writeToParcel(Parcel* parcel) const {
    media::AudioAttributesEx aidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_VolumeGroupAttributes_AudioAttributesEx(*this));
    return aidl.writeToParcel(parcel);
}

ConversionResult<media::AudioAttributesEx>
legacy2aidl_VolumeGroupAttributes_AudioAttributesEx(const VolumeGroupAttributes& legacy) {
    media::AudioAttributesEx aidl;
    aidl.attributes = VALUE_OR_RETURN(
            legacy2aidl_audio_attributes_t_AudioAttributes(legacy.getAttributes()));
    aidl.streamType = VALUE_OR_RETURN(
            legacy2aidl_audio_stream_type_t_AudioStreamType(legacy.getStreamType()));
    aidl.groupId = VALUE_OR_RETURN(legacy2aidl_volume_group_t_int32_t(legacy.getGroupId()));
    return aidl;
}

ConversionResult<VolumeGroupAttributes>
aidl2legacy_AudioAttributesEx_VolumeGroupAttributes(const media::AudioAttributesEx& aidl) {
    return VolumeGroupAttributes(VALUE_OR_RETURN(aidl2legacy_int32_t_volume_group_t(aidl.groupId)),
                           VALUE_OR_RETURN(aidl2legacy_AudioStreamType_audio_stream_type_t(
                                   aidl.streamType)),
                           VALUE_OR_RETURN(aidl2legacy_AudioAttributes_audio_attributes_t(
                                   aidl.attributes)));
}

} // namespace android
