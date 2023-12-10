/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <limits>
#include <type_traits>

#include <system/audio.h>

#include <android/media/AudioClient.h>
#include <android/media/AudioDirectMode.h>
#include <android/media/AudioIoConfigEvent.h>
#include <android/media/AudioIoDescriptor.h>
#include <android/media/AudioPortFw.h>
#include <android/media/AudioPortConfigFw.h>
#include <android/media/AudioPortDeviceExtSys.h>
#include <android/media/AudioTimestampInternal.h>
#include <android/media/AudioUniqueIdUse.h>
#include <android/media/EffectDescriptor.h>
#include <android/media/MicrophoneInfoFw.h>
#include <android/media/TrackSecondaryOutputInfo.h>

#include <android/media/SharedFileRegion.h>
#include <binder/IMemory.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioClient.h>
#include <media/AudioCommonTypes.h>
#include <media/AudioIoDescriptor.h>
#include <media/AudioTimestamp.h>
#include <system/audio_effect.h>

namespace android {

ConversionResult<audio_io_config_event_t> aidl2legacy_AudioIoConfigEvent_audio_io_config_event_t(
        media::AudioIoConfigEvent aidl);
ConversionResult<media::AudioIoConfigEvent> legacy2aidl_audio_io_config_event_t_AudioIoConfigEvent(
        audio_io_config_event_t legacy);

ConversionResult<audio_port_role_t> aidl2legacy_AudioPortRole_audio_port_role_t(
        media::AudioPortRole aidl);
ConversionResult<media::AudioPortRole> legacy2aidl_audio_port_role_t_AudioPortRole(
        audio_port_role_t legacy);

ConversionResult<audio_port_type_t> aidl2legacy_AudioPortType_audio_port_type_t(
        media::AudioPortType aidl);
ConversionResult<media::AudioPortType> legacy2aidl_audio_port_type_t_AudioPortType(
        audio_port_type_t legacy);

ConversionResult<audio_port_config_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(
        const media::audio::common::AudioPortDeviceExt& aidl,
        const media::AudioPortDeviceExtSys& aidlDeviceExt);
status_t legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(
        const audio_port_config_device_ext& legacy,
        media::audio::common::AudioPortDeviceExt* aidl,
        media::AudioPortDeviceExtSys* aidlDeviceExt);

ConversionResult<audio_port_config_mix_ext> aidl2legacy_AudioPortMixExt(
        const media::audio::common::AudioPortMixExt& aidl, media::AudioPortRole role,
        const media::AudioPortMixExtSys& aidlMixExt);
status_t legacy2aidl_AudioPortMixExt(
        const audio_port_config_mix_ext& legacy, audio_port_role_t role,
        media::audio::common::AudioPortMixExt* aidl, media::AudioPortMixExtSys* aidlMixExt);

ConversionResult<audio_port_config_session_ext>
aidl2legacy_int32_t_audio_port_config_session_ext(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_port_config_session_ext_AudioPortConfigSessionExt(
        const audio_port_config_session_ext& legacy);

// portId needs to be set when dealing with the HAL.
ConversionResult<audio_port_config> aidl2legacy_AudioPortConfigFw_audio_port_config(
        const media::AudioPortConfigFw& aidl, int32_t* aidlPortId = nullptr);
ConversionResult<media::AudioPortConfigFw> legacy2aidl_audio_port_config_AudioPortConfigFw(
        const audio_port_config& legacy, int32_t portId = 0);

ConversionResult<struct audio_patch> aidl2legacy_AudioPatchFw_audio_patch(
        const media::AudioPatchFw& aidl);
ConversionResult<media::AudioPatchFw> legacy2aidl_audio_patch_AudioPatchFw(
        const struct audio_patch& legacy);

ConversionResult<sp<AudioIoDescriptor>> aidl2legacy_AudioIoDescriptor_AudioIoDescriptor(
        const media::AudioIoDescriptor& aidl);
ConversionResult<media::AudioIoDescriptor> legacy2aidl_AudioIoDescriptor_AudioIoDescriptor(
        const sp<AudioIoDescriptor>& legacy);

ConversionResult<AudioClient> aidl2legacy_AudioClient_AudioClient(
        const media::AudioClient& aidl);
ConversionResult<media::AudioClient> legacy2aidl_AudioClient_AudioClient(
        const AudioClient& legacy);

ConversionResult<sp<IMemory>>
aidl2legacy_SharedFileRegion_IMemory(const media::SharedFileRegion& aidl);
ConversionResult<media::SharedFileRegion>
legacy2aidl_IMemory_SharedFileRegion(const sp<IMemory>& legacy);

ConversionResult<sp<::android::IMemory>> aidl2legacy_NullableSharedFileRegion_IMemory(
        const std::optional<media::SharedFileRegion>& aidl);
ConversionResult<std::optional<media::SharedFileRegion>>
legacy2aidl_NullableIMemory_SharedFileRegion(const sp<IMemory>& legacy);

ConversionResult<AudioTimestamp>
aidl2legacy_AudioTimestampInternal_AudioTimestamp(const media::AudioTimestampInternal& aidl);
ConversionResult<media::AudioTimestampInternal>
legacy2aidl_AudioTimestamp_AudioTimestampInternal(const AudioTimestamp& legacy);

ConversionResult<effect_descriptor_t>
aidl2legacy_EffectDescriptor_effect_descriptor_t(const media::EffectDescriptor& aidl);
ConversionResult<media::EffectDescriptor> legacy2aidl_effect_descriptor_t_EffectDescriptor(
        const effect_descriptor_t& legacy);

ConversionResult<audio_port_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_device_ext(
        const media::audio::common::AudioPortDeviceExt& aidl,
        const media::AudioPortDeviceExtSys& aidlDeviceExt);
status_t legacy2aidl_audio_port_device_ext_AudioPortDeviceExt(
        const audio_port_device_ext& legacy,
        media::audio::common::AudioPortDeviceExt* aidl,
        media::AudioPortDeviceExtSys* aidlDeviceExt);

ConversionResult<audio_port_mix_ext>
aidl2legacy_AudioPortMixExt_audio_port_mix_ext(
        const media::audio::common::AudioPortMixExt& aidl,
        const media::AudioPortMixExtSys& aidlMixExt);
status_t legacy2aidl_audio_port_mix_ext_AudioPortMixExt(
        const audio_port_mix_ext& legacy,
        media::audio::common::AudioPortMixExt* aidl,
        media::AudioPortMixExtSys* aidlMixExt);

ConversionResult<audio_port_session_ext>
aidl2legacy_int32_t_audio_port_session_ext(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_audio_port_session_ext_int32_t(const audio_port_session_ext& legacy);

ConversionResult<audio_port_v7>
aidl2legacy_AudioPortFw_audio_port_v7(const media::AudioPortFw& aidl);
ConversionResult<media::AudioPortFw>
legacy2aidl_audio_port_v7_AudioPortFw(const audio_port_v7& legacy);

ConversionResult<audio_unique_id_use_t>
aidl2legacy_AudioUniqueIdUse_audio_unique_id_use_t(media::AudioUniqueIdUse aidl);
ConversionResult<media::AudioUniqueIdUse>
legacy2aidl_audio_unique_id_use_t_AudioUniqueIdUse(audio_unique_id_use_t legacy);

ConversionResult<volume_group_t>
aidl2legacy_int32_t_volume_group_t(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_volume_group_t_int32_t(volume_group_t legacy);

using TrackSecondaryOutputInfoPair = std::pair<audio_port_handle_t, std::vector<audio_io_handle_t>>;
ConversionResult<TrackSecondaryOutputInfoPair>
aidl2legacy_TrackSecondaryOutputInfo_TrackSecondaryOutputInfoPair(
        const media::TrackSecondaryOutputInfo& aidl);
ConversionResult<media::TrackSecondaryOutputInfo>
legacy2aidl_TrackSecondaryOutputInfoPair_TrackSecondaryOutputInfo(
        const TrackSecondaryOutputInfoPair& legacy);

ConversionResult<audio_direct_mode_t>
aidl2legacy_AudioDirectMode_audio_direct_mode_t(media::AudioDirectMode aidl);
ConversionResult<media::AudioDirectMode>
legacy2aidl_audio_direct_mode_t_AudioDirectMode(audio_direct_mode_t legacy);

ConversionResult<audio_direct_mode_t> aidl2legacy_int32_t_audio_direct_mode_t_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_direct_mode_t_int32_t_mask(audio_direct_mode_t legacy);

ConversionResult<audio_microphone_characteristic_t>
aidl2legacy_MicrophoneInfoFw_audio_microphone_characteristic_t(
        const media::MicrophoneInfoFw& aidl);
ConversionResult<media::MicrophoneInfoFw>
legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(
        const audio_microphone_characteristic_t& legacy);

}  // namespace android
