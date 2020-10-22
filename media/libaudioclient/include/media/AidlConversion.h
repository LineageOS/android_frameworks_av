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

#include <system/audio.h>

#include <android-base/result.h>
#include <android/media/AudioGainMode.h>
#include <android/media/AudioInputFlags.h>
#include <android/media/AudioIoConfigEvent.h>
#include <android/media/AudioIoDescriptor.h>
#include <android/media/AudioOutputFlags.h>
#include <android/media/AudioPortConfigType.h>

#include <media/AudioIoDescriptor.h>

namespace android {

template <typename T>
using ConversionResult = base::expected<T, status_t>;

// The legacy enum is unnamed. Thus, we use int.
ConversionResult<int> aidl2legacy_AudioPortConfigType(media::AudioPortConfigType aidl);
// The legacy enum is unnamed. Thus, we use int.
ConversionResult<media::AudioPortConfigType> legacy2aidl_AudioPortConfigType(int legacy);

ConversionResult<unsigned int> aidl2legacy_int32_t_config_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_config_mask_int32_t(unsigned int legacy);

ConversionResult<audio_channel_mask_t> aidl2legacy_int32_t_audio_channel_mask_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_channel_mask_t_int32_t(audio_channel_mask_t legacy);

ConversionResult<audio_io_config_event> aidl2legacy_AudioIoConfigEvent_audio_io_config_event(
        media::AudioIoConfigEvent aidl);
ConversionResult<media::AudioIoConfigEvent> legacy2aidl_audio_io_config_event_AudioIoConfigEvent(
        audio_io_config_event legacy);

ConversionResult<audio_port_role_t> aidl2legacy_AudioPortRole_audio_port_role_t(
        media::AudioPortRole aidl);
ConversionResult<media::AudioPortRole> legacy2aidl_audio_port_role_t_AudioPortRole(
        audio_port_role_t legacy);

ConversionResult<audio_port_type_t> aidl2legacy_AudioPortType_audio_port_type_t(
        media::AudioPortType aidl);
ConversionResult<media::AudioPortType> legacy2aidl_audio_port_type_t_AudioPortType(
        audio_port_type_t legacy);

ConversionResult<audio_format_t> aidl2legacy_AudioFormat_audio_format_t(
        media::audio::common::AudioFormat aidl);
ConversionResult<media::audio::common::AudioFormat> legacy2aidl_audio_format_t_AudioFormat(
        audio_format_t legacy);

ConversionResult<int> aidl2legacy_AudioGainMode_int(media::AudioGainMode aidl);
ConversionResult<media::AudioGainMode> legacy2aidl_int_AudioGainMode(int legacy);

ConversionResult<audio_gain_mode_t> aidl2legacy_int32_t_audio_gain_mode_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_gain_mode_t_int32_t(audio_gain_mode_t legacy);

ConversionResult<audio_devices_t> aidl2legacy_int32_t_audio_devices_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_devices_t_int32_t(audio_devices_t legacy);

ConversionResult<audio_gain_config> aidl2legacy_AudioGainConfig_audio_gain_config(
        const media::AudioGainConfig& aidl, media::AudioPortRole role, media::AudioPortType type);
ConversionResult<media::AudioGainConfig> legacy2aidl_audio_gain_config_AudioGainConfig(
        const audio_gain_config& legacy, audio_port_role_t role, audio_port_type_t type);

ConversionResult<audio_input_flags_t> aidl2legacy_AudioInputFlags_audio_input_flags_t(
        media::AudioInputFlags aidl);
ConversionResult<media::AudioInputFlags> legacy2aidl_audio_input_flags_t_AudioInputFlags(
        audio_input_flags_t legacy);

ConversionResult<audio_output_flags_t> aidl2legacy_AudioOutputFlags_audio_output_flags_t(
        media::AudioOutputFlags aidl);
ConversionResult<media::AudioOutputFlags> legacy2aidl_audio_output_flags_t_AudioOutputFlags(
        audio_output_flags_t legacy);

ConversionResult<audio_input_flags_t> aidl2legacy_audio_input_flags_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_input_flags_mask(audio_input_flags_t legacy);

ConversionResult<audio_output_flags_t> aidl2legacy_audio_output_flags_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_output_flags_mask(audio_output_flags_t legacy);

ConversionResult<audio_io_flags> aidl2legacy_AudioIoFlags_audio_io_flags(
        const media::AudioIoFlags& aidl, media::AudioPortRole role, media::AudioPortType type);
ConversionResult<media::AudioIoFlags> legacy2aidl_audio_io_flags_AudioIoFlags(
        const audio_io_flags& legacy, audio_port_role_t role, audio_port_type_t type);

ConversionResult<audio_port_config_device_ext> aidl2legacy_AudioPortConfigDeviceExt(
        const media::AudioPortConfigDeviceExt& aidl);
ConversionResult<media::AudioPortConfigDeviceExt> legacy2aidl_AudioPortConfigDeviceExt(
        const audio_port_config_device_ext& legacy);

ConversionResult<audio_stream_type_t> aidl2legacy_AudioStreamType_audio_stream_type_t(
        media::AudioStreamType aidl);
ConversionResult<media::AudioStreamType> legacy2aidl_audio_stream_type_t_AudioStreamType(
        audio_stream_type_t legacy);

ConversionResult<audio_source_t> aidl2legacy_AudioSourceType_audio_source_t(
        media::AudioSourceType aidl);
ConversionResult<media::AudioSourceType> legacy2aidl_audio_source_t_AudioSourceType(
        audio_source_t legacy);

ConversionResult<audio_session_t> aidl2legacy_AudioSessionType_audio_session_t(
        media::AudioSessionType aidl);
ConversionResult<media::AudioSessionType> legacy2aidl_audio_session_t_AudioSessionType(
        audio_session_t legacy);

ConversionResult<audio_port_config_mix_ext> aidl2legacy_AudioPortConfigMixExt(
        const media::AudioPortConfigMixExt& aidl, media::AudioPortRole role);
ConversionResult<media::AudioPortConfigMixExt> legacy2aidl_AudioPortConfigMixExt(
        const audio_port_config_mix_ext& legacy, audio_port_role_t role);

ConversionResult<audio_port_config_session_ext> aidl2legacy_AudioPortConfigSessionExt(
        const media::AudioPortConfigSessionExt& aidl);
ConversionResult<media::AudioPortConfigSessionExt> legacy2aidl_AudioPortConfigSessionExt(
        const audio_port_config_session_ext& legacy);

ConversionResult<audio_port_config> aidl2legacy_AudioPortConfig_audio_port_config(
        const media::AudioPortConfig& aidl);
ConversionResult<media::AudioPortConfig> legacy2aidl_audio_port_config_AudioPortConfig(
        const audio_port_config& legacy);

ConversionResult<struct audio_patch> aidl2legacy_AudioPatch_audio_patch(
        const media::AudioPatch& aidl);
ConversionResult<media::AudioPatch> legacy2aidl_audio_patch_AudioPatch(
        const struct audio_patch& legacy);

ConversionResult<sp<AudioIoDescriptor>> aidl2legacy_AudioIoDescriptor_AudioIoDescriptor(
        const media::AudioIoDescriptor& aidl);
ConversionResult<media::AudioIoDescriptor> legacy2aidl_AudioIoDescriptor_AudioIoDescriptor(
        const sp<AudioIoDescriptor>& legacy);

}  // namespace android
