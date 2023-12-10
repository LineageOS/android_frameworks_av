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

#define LOG_TAG "AudioVolumeGroup"

//#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <binder/Parcel.h>

#include <media/AidlConversion.h>
#include <media/AudioVolumeGroup.h>
#include <media/PolicyAidlConversion.h>

namespace android {

using media::audio::common::AudioStreamType;

status_t AudioVolumeGroup::readFromParcel(const Parcel *parcel)
{
    media::AudioVolumeGroup aidl;
    RETURN_STATUS_IF_ERROR(aidl.readFromParcel(parcel));
    *this = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioVolumeGroup(aidl));
    return OK;
}

status_t AudioVolumeGroup::writeToParcel(Parcel *parcel) const
{
    media::AudioVolumeGroup aidl = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioVolumeGroup(*this));
    return aidl.writeToParcel(parcel);
}

ConversionResult<media::AudioVolumeGroup>
legacy2aidl_AudioVolumeGroup(const AudioVolumeGroup& legacy) {
    media::AudioVolumeGroup aidl;
    aidl.groupId = VALUE_OR_RETURN(legacy2aidl_volume_group_t_int32_t(legacy.getId()));
    aidl.name = legacy.getName();
    aidl.audioAttributes = VALUE_OR_RETURN(
            convertContainer<std::vector<media::audio::common::AudioAttributes>>(
                    legacy.getAudioAttributes(),
                    legacy2aidl_audio_attributes_t_AudioAttributes));
    aidl.streams = VALUE_OR_RETURN(
            convertContainer<std::vector<AudioStreamType>>(legacy.getStreamTypes(),
            legacy2aidl_audio_stream_type_t_AudioStreamType));
    return aidl;
}

ConversionResult<AudioVolumeGroup>
aidl2legacy_AudioVolumeGroup(const media::AudioVolumeGroup& aidl) {
    return AudioVolumeGroup(
            aidl.name,
            VALUE_OR_RETURN(aidl2legacy_int32_t_volume_group_t(aidl.groupId)),
            VALUE_OR_RETURN(convertContainer<AttributesVector>(
                    aidl.audioAttributes,
                    aidl2legacy_AudioAttributes_audio_attributes_t)),
            VALUE_OR_RETURN(convertContainer<StreamTypeVector>(
                    aidl.streams,
                    aidl2legacy_AudioStreamType_audio_stream_type_t))
    );
}

} // namespace android
