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

#include <android/media/AudioAttributesInternal.h>
#include <android/media/AudioClient.h>
#include <android/media/AudioDirectMode.h>
#include <android/media/AudioDualMonoMode.h>
#include <android/media/AudioFlag.h>
#include <android/media/AudioIoConfigEvent.h>
#include <android/media/AudioIoDescriptor.h>
#include <android/media/AudioPlaybackRate.h>
#include <android/media/AudioPort.h>
#include <android/media/AudioPortConfig.h>
#include <android/media/AudioPortDeviceExtSys.h>
#include <android/media/AudioTimestampInternal.h>
#include <android/media/AudioUniqueIdUse.h>
#include <android/media/EffectDescriptor.h>
#include <android/media/LatencyMode.h>
#include <android/media/TrackSecondaryOutputInfo.h>
#include <android/media/audio/common/AudioChannelLayout.h>
#include <android/media/audio/common/AudioConfig.h>
#include <android/media/audio/common/AudioConfigBase.h>
#include <android/media/audio/common/AudioContentType.h>
#include <android/media/audio/common/AudioDeviceDescription.h>
#include <android/media/audio/common/AudioEncapsulationMetadataType.h>
#include <android/media/audio/common/AudioEncapsulationMode.h>
#include <android/media/audio/common/AudioEncapsulationType.h>
#include <android/media/audio/common/AudioFormatDescription.h>
#include <android/media/audio/common/AudioGain.h>
#include <android/media/audio/common/AudioGainConfig.h>
#include <android/media/audio/common/AudioGainMode.h>
#include <android/media/audio/common/AudioInputFlags.h>
#include <android/media/audio/common/AudioMode.h>
#include <android/media/audio/common/AudioOffloadInfo.h>
#include <android/media/audio/common/AudioOutputFlags.h>
#include <android/media/audio/common/AudioPortExt.h>
#include <android/media/audio/common/AudioPortMixExt.h>
#include <android/media/audio/common/AudioProfile.h>
#include <android/media/audio/common/AudioSource.h>
#include <android/media/audio/common/AudioStandard.h>
#include <android/media/audio/common/AudioUsage.h>
#include <android/media/audio/common/AudioUuid.h>
#include <android/media/audio/common/ExtraAudioDescriptor.h>

#include <android/media/SharedFileRegion.h>
#include <binder/IMemory.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioClient.h>
#include <media/AudioCommonTypes.h>
#include <media/AudioIoDescriptor.h>
#include <media/AudioTimestamp.h>
#include <system/audio_effect.h>

namespace android {

// maxSize is the size of the C-string buffer (including the 0-terminator), NOT the max length of
// the string.
status_t aidl2legacy_string(std::string_view aidl, char* dest, size_t maxSize);
ConversionResult<std::string> legacy2aidl_string(const char* legacy, size_t maxSize);

ConversionResult<audio_module_handle_t> aidl2legacy_int32_t_audio_module_handle_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_module_handle_t_int32_t(audio_module_handle_t legacy);

ConversionResult<audio_io_handle_t> aidl2legacy_int32_t_audio_io_handle_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_io_handle_t_int32_t(audio_io_handle_t legacy);

ConversionResult<audio_port_handle_t> aidl2legacy_int32_t_audio_port_handle_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_port_handle_t_int32_t(audio_port_handle_t legacy);

ConversionResult<audio_patch_handle_t> aidl2legacy_int32_t_audio_patch_handle_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_patch_handle_t_int32_t(audio_patch_handle_t legacy);

ConversionResult<audio_unique_id_t> aidl2legacy_int32_t_audio_unique_id_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_unique_id_t_int32_t(audio_unique_id_t legacy);

ConversionResult<audio_hw_sync_t> aidl2legacy_int32_t_audio_hw_sync_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_hw_sync_t_int32_t(audio_hw_sync_t legacy);

ConversionResult<unsigned int> aidl2legacy_int32_t_config_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_config_mask_int32_t(unsigned int legacy);

ConversionResult<pid_t> aidl2legacy_int32_t_pid_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_pid_t_int32_t(pid_t legacy);

ConversionResult<uid_t> aidl2legacy_int32_t_uid_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_uid_t_int32_t(uid_t legacy);

ConversionResult<String8> aidl2legacy_string_view_String8(std::string_view aidl);
ConversionResult<std::string> legacy2aidl_String8_string(const String8& legacy);

ConversionResult<String16> aidl2legacy_string_view_String16(std::string_view aidl);
ConversionResult<std::string> legacy2aidl_String16_string(const String16& legacy);

ConversionResult<std::optional<String16>>
aidl2legacy_optional_string_view_optional_String16(std::optional<std::string_view> aidl);
ConversionResult<std::optional<std::string_view>>
legacy2aidl_optional_String16_optional_string(std::optional<String16> legacy);

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

ConversionResult<audio_channel_mask_t> aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
        const media::audio::common::AudioChannelLayout& aidl, bool isInput);
ConversionResult<media::audio::common::AudioChannelLayout>
legacy2aidl_audio_channel_mask_t_AudioChannelLayout(audio_channel_mask_t legacy, bool isInput);

ConversionResult<audio_devices_t> aidl2legacy_AudioDeviceDescription_audio_devices_t(
        const media::audio::common::AudioDeviceDescription& aidl);
ConversionResult<media::audio::common::AudioDeviceDescription>
legacy2aidl_audio_devices_t_AudioDeviceDescription(audio_devices_t legacy);

status_t aidl2legacy_AudioDevice_audio_device(
        const media::audio::common::AudioDevice& aidl,
        audio_devices_t* legacyType, char* legacyAddress);
status_t aidl2legacy_AudioDevice_audio_device(
        const media::audio::common::AudioDevice& aidl,
        audio_devices_t* legacyType, String8* legacyAddress);
status_t aidl2legacy_AudioDevice_audio_device(
        const media::audio::common::AudioDevice& aidl,
        audio_devices_t* legacyType, std::string* legacyAddress);
ConversionResult<media::audio::common::AudioDevice>
legacy2aidl_audio_device_AudioDevice(
        audio_devices_t legacyType, const char* legacyAddress);
ConversionResult<media::audio::common::AudioDevice>
legacy2aidl_audio_device_AudioDevice(
        audio_devices_t legacyType, const String8& legacyAddress);

ConversionResult<audio_format_t> aidl2legacy_AudioFormatDescription_audio_format_t(
        const media::audio::common::AudioFormatDescription& aidl);
ConversionResult<media::audio::common::AudioFormatDescription>
legacy2aidl_audio_format_t_AudioFormatDescription(audio_format_t legacy);

ConversionResult<audio_gain_mode_t>
aidl2legacy_AudioGainMode_audio_gain_mode_t(media::audio::common::AudioGainMode aidl);
ConversionResult<media::audio::common::AudioGainMode>
legacy2aidl_audio_gain_mode_t_AudioGainMode(audio_gain_mode_t legacy);

ConversionResult<audio_gain_mode_t> aidl2legacy_int32_t_audio_gain_mode_t_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_gain_mode_t_int32_t_mask(audio_gain_mode_t legacy);

ConversionResult<audio_gain_config> aidl2legacy_AudioGainConfig_audio_gain_config(
        const media::audio::common::AudioGainConfig& aidl, bool isInput);
ConversionResult<media::audio::common::AudioGainConfig>
legacy2aidl_audio_gain_config_AudioGainConfig(const audio_gain_config& legacy, bool isInput);

ConversionResult<audio_input_flags_t>
aidl2legacy_AudioInputFlags_audio_input_flags_t(media::audio::common::AudioInputFlags aidl);
ConversionResult<media::audio::common::AudioInputFlags>
legacy2aidl_audio_input_flags_t_AudioInputFlags(audio_input_flags_t legacy);

ConversionResult<audio_output_flags_t>
aidl2legacy_AudioOutputFlags_audio_output_flags_t(media::audio::common::AudioOutputFlags aidl);
ConversionResult<media::audio::common::AudioOutputFlags>
legacy2aidl_audio_output_flags_t_AudioOutputFlags(audio_output_flags_t legacy);

ConversionResult<audio_input_flags_t> aidl2legacy_int32_t_audio_input_flags_t_mask(
        int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_input_flags_t_int32_t_mask(
        audio_input_flags_t legacy);

ConversionResult<audio_output_flags_t> aidl2legacy_int32_t_audio_output_flags_t_mask(
        int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_output_flags_t_int32_t_mask(
        audio_output_flags_t legacy);

ConversionResult<audio_io_flags> aidl2legacy_AudioIoFlags_audio_io_flags(
        const media::audio::common::AudioIoFlags& aidl, bool isInput);
ConversionResult<media::audio::common::AudioIoFlags> legacy2aidl_audio_io_flags_AudioIoFlags(
        const audio_io_flags& legacy, bool isInput);

ConversionResult<audio_port_config_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(
        const media::audio::common::AudioPortDeviceExt& aidl,
        const media::AudioPortDeviceExtSys& aidlDeviceExt);
status_t legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(
        const audio_port_config_device_ext& legacy,
        media::audio::common::AudioPortDeviceExt* aidl,
        media::AudioPortDeviceExtSys* aidlDeviceExt);

ConversionResult<audio_stream_type_t> aidl2legacy_AudioStreamType_audio_stream_type_t(
        media::audio::common::AudioStreamType aidl);
ConversionResult<media::audio::common::AudioStreamType>
legacy2aidl_audio_stream_type_t_AudioStreamType(audio_stream_type_t legacy);

ConversionResult<audio_source_t> aidl2legacy_AudioSource_audio_source_t(
        media::audio::common::AudioSource aidl);
ConversionResult<media::audio::common::AudioSource>
        legacy2aidl_audio_source_t_AudioSource(
        audio_source_t legacy);

ConversionResult<audio_session_t> aidl2legacy_int32_t_audio_session_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_session_t_int32_t(audio_session_t legacy);

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

ConversionResult<AudioClient> aidl2legacy_AudioClient_AudioClient(
        const media::AudioClient& aidl);
ConversionResult<media::AudioClient> legacy2aidl_AudioClient_AudioClient(
        const AudioClient& legacy);

ConversionResult<audio_content_type_t>
aidl2legacy_AudioContentType_audio_content_type_t(
        media::audio::common::AudioContentType aidl);
ConversionResult<media::audio::common::AudioContentType>
legacy2aidl_audio_content_type_t_AudioContentType(audio_content_type_t legacy);

ConversionResult<audio_usage_t>
aidl2legacy_AudioUsage_audio_usage_t(media::audio::common::AudioUsage aidl);
ConversionResult<media::audio::common::AudioUsage>
legacy2aidl_audio_usage_t_AudioUsage(audio_usage_t legacy);

ConversionResult<audio_flags_mask_t>
aidl2legacy_AudioFlag_audio_flags_mask_t(media::AudioFlag aidl);
ConversionResult<media::AudioFlag>
legacy2aidl_audio_flags_mask_t_AudioFlag(audio_flags_mask_t legacy);

ConversionResult<audio_flags_mask_t>
aidl2legacy_int32_t_audio_flags_mask_t_mask(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_audio_flags_mask_t_int32_t_mask(audio_flags_mask_t legacy);

ConversionResult<audio_attributes_t>
aidl2legacy_AudioAttributesInternal_audio_attributes_t(const media::AudioAttributesInternal& aidl);
ConversionResult<media::AudioAttributesInternal>
legacy2aidl_audio_attributes_t_AudioAttributesInternal(const audio_attributes_t& legacy);

ConversionResult<audio_encapsulation_mode_t>
aidl2legacy_AudioEncapsulationMode_audio_encapsulation_mode_t(
        media::audio::common::AudioEncapsulationMode aidl);
ConversionResult<media::audio::common::AudioEncapsulationMode>
legacy2aidl_audio_encapsulation_mode_t_AudioEncapsulationMode(audio_encapsulation_mode_t legacy);

ConversionResult<audio_offload_info_t>
aidl2legacy_AudioOffloadInfo_audio_offload_info_t(
        const media::audio::common::AudioOffloadInfo& aidl);
ConversionResult<media::audio::common::AudioOffloadInfo>
legacy2aidl_audio_offload_info_t_AudioOffloadInfo(const audio_offload_info_t& legacy);

ConversionResult<audio_config_t>
aidl2legacy_AudioConfig_audio_config_t(const media::audio::common::AudioConfig& aidl, bool isInput);
ConversionResult<media::audio::common::AudioConfig>
legacy2aidl_audio_config_t_AudioConfig(const audio_config_t& legacy, bool isInput);

ConversionResult<audio_config_base_t>
aidl2legacy_AudioConfigBase_audio_config_base_t(
        const media::audio::common::AudioConfigBase& aidl, bool isInput);
ConversionResult<media::audio::common::AudioConfigBase>
legacy2aidl_audio_config_base_t_AudioConfigBase(const audio_config_base_t& legacy, bool isInput);

ConversionResult<sp<IMemory>>
aidl2legacy_SharedFileRegion_IMemory(const media::SharedFileRegion& aidl);
ConversionResult<media::SharedFileRegion>
legacy2aidl_IMemory_SharedFileRegion(const sp<IMemory>& legacy);

ConversionResult<sp<IMemory>>
aidl2legacy_NullableSharedFileRegion_IMemory(const std::optional<media::SharedFileRegion>& aidl);
ConversionResult<std::optional<media::SharedFileRegion>>
legacy2aidl_NullableIMemory_SharedFileRegion(const sp<IMemory>& legacy);

ConversionResult<AudioTimestamp>
aidl2legacy_AudioTimestampInternal_AudioTimestamp(const media::AudioTimestampInternal& aidl);
ConversionResult<media::AudioTimestampInternal>
legacy2aidl_AudioTimestamp_AudioTimestampInternal(const AudioTimestamp& legacy);

ConversionResult<audio_uuid_t>
aidl2legacy_AudioUuid_audio_uuid_t(const media::audio::common::AudioUuid& aidl);
ConversionResult<media::audio::common::AudioUuid>
legacy2aidl_audio_uuid_t_AudioUuid(const audio_uuid_t& legacy);

ConversionResult<effect_descriptor_t>
aidl2legacy_EffectDescriptor_effect_descriptor_t(const media::EffectDescriptor& aidl);
ConversionResult<media::EffectDescriptor>
legacy2aidl_effect_descriptor_t_EffectDescriptor(const effect_descriptor_t& legacy);

ConversionResult<audio_encapsulation_metadata_type_t>
aidl2legacy_AudioEncapsulationMetadataType_audio_encapsulation_metadata_type_t(
        media::audio::common::AudioEncapsulationMetadataType aidl);
ConversionResult<media::audio::common::AudioEncapsulationMetadataType>
legacy2aidl_audio_encapsulation_metadata_type_t_AudioEncapsulationMetadataType(
        audio_encapsulation_metadata_type_t legacy);

ConversionResult<uint32_t>
aidl2legacy_AudioEncapsulationMode_mask(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_AudioEncapsulationMode_mask(uint32_t legacy);

ConversionResult<uint32_t>
aidl2legacy_AudioEncapsulationMetadataType_mask(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_AudioEncapsulationMetadataType_mask(uint32_t legacy);

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

ConversionResult<audio_profile>
aidl2legacy_AudioProfile_audio_profile(
        const media::audio::common::AudioProfile& aidl, bool isInput);
ConversionResult<media::audio::common::AudioProfile>
legacy2aidl_audio_profile_AudioProfile(const audio_profile& legacy, bool isInput);

ConversionResult<audio_gain>
aidl2legacy_AudioGain_audio_gain(const media::audio::common::AudioGain& aidl, bool isInput);
ConversionResult<media::audio::common::AudioGain>
legacy2aidl_audio_gain_AudioGain(const audio_gain& legacy, bool isInput);

ConversionResult<audio_port_v7>
aidl2legacy_AudioPort_audio_port_v7(const media::AudioPort& aidl);
ConversionResult<media::AudioPort>
legacy2aidl_audio_port_v7_AudioPort(const audio_port_v7& legacy);

ConversionResult<audio_mode_t>
aidl2legacy_AudioMode_audio_mode_t(media::audio::common::AudioMode aidl);
ConversionResult<media::audio::common::AudioMode>
legacy2aidl_audio_mode_t_AudioMode(audio_mode_t legacy);

ConversionResult<audio_unique_id_use_t>
aidl2legacy_AudioUniqueIdUse_audio_unique_id_use_t(media::AudioUniqueIdUse aidl);
ConversionResult<media::AudioUniqueIdUse>
legacy2aidl_audio_unique_id_use_t_AudioUniqueIdUse(audio_unique_id_use_t legacy);

ConversionResult<volume_group_t>
aidl2legacy_int32_t_volume_group_t(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_volume_group_t_int32_t(volume_group_t legacy);

ConversionResult<audio_dual_mono_mode_t>
aidl2legacy_AudioDualMonoMode_audio_dual_mono_mode_t(media::AudioDualMonoMode aidl);
ConversionResult<media::AudioDualMonoMode>
legacy2aidl_audio_dual_mono_mode_t_AudioDualMonoMode(audio_dual_mono_mode_t legacy);

ConversionResult<audio_timestretch_fallback_mode_t>
aidl2legacy_int32_t_audio_timestretch_fallback_mode_t(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_audio_timestretch_fallback_mode_t_int32_t(audio_timestretch_fallback_mode_t legacy);

ConversionResult<audio_timestretch_stretch_mode_t>
aidl2legacy_int32_t_audio_timestretch_stretch_mode_t(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_audio_timestretch_stretch_mode_t_int32_t(audio_timestretch_stretch_mode_t legacy);

ConversionResult<audio_playback_rate_t>
aidl2legacy_AudioPlaybackRate_audio_playback_rate_t(const media::AudioPlaybackRate& aidl);
ConversionResult<media::AudioPlaybackRate>
legacy2aidl_audio_playback_rate_t_AudioPlaybackRate(const audio_playback_rate_t& legacy);

ConversionResult<audio_standard_t>
aidl2legacy_AudioStandard_audio_standard_t(media::audio::common::AudioStandard aidl);
ConversionResult<media::audio::common::AudioStandard>
legacy2aidl_audio_standard_t_AudioStandard(audio_standard_t legacy);

ConversionResult<audio_extra_audio_descriptor>
aidl2legacy_ExtraAudioDescriptor_audio_extra_audio_descriptor(
        const media::audio::common::ExtraAudioDescriptor& aidl);
ConversionResult<media::audio::common::ExtraAudioDescriptor>
legacy2aidl_audio_extra_audio_descriptor_ExtraAudioDescriptor(
        const audio_extra_audio_descriptor& legacy);

ConversionResult<audio_encapsulation_type_t>
aidl2legacy_AudioEncapsulationType_audio_encapsulation_type_t(
        const media::audio::common::AudioEncapsulationType& aidl);
ConversionResult<media::audio::common::AudioEncapsulationType>
legacy2aidl_audio_encapsulation_type_t_AudioEncapsulationType(
        const audio_encapsulation_type_t & legacy);

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

ConversionResult<audio_latency_mode_t>
aidl2legacy_LatencyMode_audio_latency_mode_t(media::LatencyMode aidl);
ConversionResult<media::LatencyMode>
legacy2aidl_audio_latency_mode_t_LatencyMode(audio_latency_mode_t legacy);

}  // namespace android
