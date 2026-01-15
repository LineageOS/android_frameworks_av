/*
 * Copyright (C) 2023 The Android Open Source Project
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

// WARNING: This file is intended for multiple inclusion.
// Do not include directly, use 'AidlConversionCppNdk.h'.
#if (defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_CPP_NDK_NDK)) || \
    (!defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_CPP_NDK_CPP))
#if defined(BACKEND_NDK_IMPL)
#define AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_CPP_NDK_NDK
#else
#define AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_CPP_NDK_CPP
#endif  // BACKEND_NDK_IMPL

#include <limits>
#include <type_traits>

/**
 * Can handle conversion between AIDL (both CPP and NDK backend) and legacy type.
 * Controlled by the cflags preprocessor in Android.bp.
 */
#if defined(BACKEND_NDK_IMPL)
#define PREFIX(f) <aidl/f>
#else
#define PREFIX(f) <f>
#endif

#include PREFIX(android/media/audio/common/AudioAttributes.h)
#include PREFIX(android/media/audio/common/AudioChannelLayout.h)
#include PREFIX(android/media/audio/common/AudioConfig.h)
#include PREFIX(android/media/audio/common/AudioConfigBase.h)
#include PREFIX(android/media/audio/common/AudioContentType.h)
#include PREFIX(android/media/audio/common/AudioDeviceDescription.h)
#include PREFIX(android/media/audio/common/AudioDualMonoMode.h)
#include PREFIX(android/media/audio/common/AudioEncapsulationMetadataType.h)
#include PREFIX(android/media/audio/common/AudioEncapsulationMode.h)
#include PREFIX(android/media/audio/common/AudioEncapsulationType.h)
#include PREFIX(android/media/audio/common/AudioFlag.h)
#include PREFIX(android/media/audio/common/AudioFormatDescription.h)
#include PREFIX(android/media/audio/common/AudioGain.h)
#include PREFIX(android/media/audio/common/AudioGainConfig.h)
#include PREFIX(android/media/audio/common/AudioGainMode.h)
#include PREFIX(android/media/audio/common/AudioInputFlags.h)
#include PREFIX(android/media/audio/common/AudioIoFlags.h)
#include PREFIX(android/media/audio/common/AudioLatencyMode.h)
#include PREFIX(android/media/audio/common/AudioMode.h)
#include PREFIX(android/media/audio/common/AudioOffloadInfo.h)
#include PREFIX(android/media/audio/common/AudioOutputFlags.h)
#include PREFIX(android/media/audio/common/AudioPort.h)
#include PREFIX(android/media/audio/common/AudioPortConfig.h)
#include PREFIX(android/media/audio/common/AudioPortExt.h)
#include PREFIX(android/media/audio/common/AudioPortMixExt.h)
#include PREFIX(android/media/audio/common/AudioPlaybackRate.h)
#include PREFIX(android/media/audio/common/AudioProfile.h)
#include PREFIX(android/media/audio/common/AudioSource.h)
#include PREFIX(android/media/audio/common/AudioStandard.h)
#include PREFIX(android/media/audio/common/AudioUsage.h)
#include PREFIX(android/media/audio/common/AudioUuid.h)
#include PREFIX(android/media/audio/common/ExtraAudioDescriptor.h)
#include PREFIX(android/media/audio/common/Int.h)
#include PREFIX(android/media/audio/common/MicrophoneDynamicInfo.h)
#include PREFIX(android/media/audio/common/MicrophoneInfo.h)
#undef PREFIX

#include <system/audio.h>
#include <system/audio_effect.h>

#if defined(BACKEND_NDK_IMPL)
namespace aidl {
#endif

namespace android {

// maxSize is the size of the C-string buffer (including the 0-terminator), NOT the max length of
// the string.
::android::status_t aidl2legacy_string(std::string_view aidl, char* dest, size_t maxSize);
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

ConversionResult<::android::String8> aidl2legacy_string_view_String8(std::string_view aidl);
ConversionResult<std::string> legacy2aidl_String8_string(const ::android::String8& legacy);

ConversionResult<::android::String16> aidl2legacy_string_view_String16(std::string_view aidl);
ConversionResult<std::string> legacy2aidl_String16_string(const ::android::String16& legacy);

ConversionResult<std::optional<::android::String16>>
aidl2legacy_optional_string_view_optional_String16(std::optional<std::string_view> aidl);
ConversionResult<std::optional<std::string_view>>
legacy2aidl_optional_String16_optional_string(std::optional<::android::String16> legacy);

ConversionResult<audio_channel_mask_t> aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
        const media::audio::common::AudioChannelLayout& aidl, bool isInput);
ConversionResult<media::audio::common::AudioChannelLayout>
legacy2aidl_audio_channel_mask_t_AudioChannelLayout(audio_channel_mask_t legacy, bool isInput);

audio_channel_mask_t aidl2legacy_AudioChannelLayout_layout_audio_channel_mask_t_bits(
        int aidlLayout, bool isInput);
int legacy2aidl_audio_channel_mask_t_bits_AudioChannelLayout_layout(
        audio_channel_mask_t legacy, bool isInput);

enum class AudioPortDirection {
    INPUT, OUTPUT
};
ConversionResult<AudioPortDirection> portDirection(audio_port_role_t role, audio_port_type_t type);
ConversionResult<audio_port_role_t> portRole(AudioPortDirection direction, audio_port_type_t type);

ConversionResult<audio_config_t>
aidl2legacy_AudioConfig_audio_config_t(const media::audio::common::AudioConfig& aidl, bool isInput);
ConversionResult<media::audio::common::AudioConfig>
legacy2aidl_audio_config_t_AudioConfig(const audio_config_t& legacy, bool isInput);

ConversionResult<audio_config_base_t>
aidl2legacy_AudioConfigBase_audio_config_base_t(
        const media::audio::common::AudioConfigBase& aidl, bool isInput);
ConversionResult<media::audio::common::AudioConfigBase>
legacy2aidl_audio_config_base_t_AudioConfigBase(const audio_config_base_t& legacy, bool isInput);

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

ConversionResult<audio_session_t> aidl2legacy_int32_t_audio_session_t(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_session_t_int32_t(audio_session_t legacy);

ConversionResult<audio_content_type_t>
aidl2legacy_AudioContentType_audio_content_type_t(
        media::audio::common::AudioContentType aidl);
ConversionResult<media::audio::common::AudioContentType>
legacy2aidl_audio_content_type_t_AudioContentType(audio_content_type_t legacy);

ConversionResult<audio_devices_t> aidl2legacy_AudioDeviceDescription_audio_devices_t(
        const media::audio::common::AudioDeviceDescription& aidl);
ConversionResult<media::audio::common::AudioDeviceDescription>
legacy2aidl_audio_devices_t_AudioDeviceDescription(audio_devices_t legacy);

media::audio::common::AudioDeviceAddress::Tag suggestDeviceAddressTag(
        const media::audio::common::AudioDeviceDescription& description);

::android::status_t aidl2legacy_AudioDevice_audio_device(
        const media::audio::common::AudioDevice& aidl, audio_devices_t* legacyType,
        char* legacyAddress);
::android::status_t aidl2legacy_AudioDevice_audio_device(
        const media::audio::common::AudioDevice& aidl, audio_devices_t* legacyType,
        ::android::String8* legacyAddress);
::android::status_t aidl2legacy_AudioDevice_audio_device(
        const media::audio::common::AudioDevice& aidl, audio_devices_t* legacyType,
        std::string* legacyAddress);

ConversionResult<media::audio::common::AudioDevice> legacy2aidl_audio_device_AudioDevice(
        audio_devices_t legacyType, const char* legacyAddress);
ConversionResult<media::audio::common::AudioDevice> legacy2aidl_audio_device_AudioDevice(
        audio_devices_t legacyType, const ::android::String8& legacyAddress);
ConversionResult<media::audio::common::AudioDevice> legacy2aidl_audio_device_AudioDevice(
        audio_devices_t legacyType, const std::string& legacyAddress);

ConversionResult<audio_extra_audio_descriptor>
aidl2legacy_ExtraAudioDescriptor_audio_extra_audio_descriptor(
        const media::audio::common::ExtraAudioDescriptor& aidl);

ConversionResult<media::audio::common::ExtraAudioDescriptor>
legacy2aidl_audio_extra_audio_descriptor_ExtraAudioDescriptor(
        const audio_extra_audio_descriptor& legacy);

ConversionResult<audio_encapsulation_metadata_type_t>
aidl2legacy_AudioEncapsulationMetadataType_audio_encapsulation_metadata_type_t(
        media::audio::common::AudioEncapsulationMetadataType aidl);
ConversionResult<media::audio::common::AudioEncapsulationMetadataType>
legacy2aidl_audio_encapsulation_metadata_type_t_AudioEncapsulationMetadataType(
        audio_encapsulation_metadata_type_t legacy);

ConversionResult<uint32_t> aidl2legacy_AudioEncapsulationMetadataType_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_AudioEncapsulationMetadataType_mask(uint32_t legacy);

ConversionResult<audio_encapsulation_mode_t>
aidl2legacy_AudioEncapsulationMode_audio_encapsulation_mode_t(
        media::audio::common::AudioEncapsulationMode aidl);
ConversionResult<media::audio::common::AudioEncapsulationMode>
legacy2aidl_audio_encapsulation_mode_t_AudioEncapsulationMode(audio_encapsulation_mode_t legacy);

ConversionResult<uint32_t> aidl2legacy_AudioEncapsulationMode_mask(int32_t aidl);
ConversionResult<int32_t> legacy2aidl_AudioEncapsulationMode_mask(uint32_t legacy);

ConversionResult<audio_encapsulation_type_t>
aidl2legacy_AudioEncapsulationType_audio_encapsulation_type_t(
        const media::audio::common::AudioEncapsulationType& aidl);
ConversionResult<media::audio::common::AudioEncapsulationType>
legacy2aidl_audio_encapsulation_type_t_AudioEncapsulationType(
        const audio_encapsulation_type_t& legacy);

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

ConversionResult<audio_gain>
aidl2legacy_AudioGain_audio_gain(const media::audio::common::AudioGain& aidl, bool isInput);
ConversionResult<media::audio::common::AudioGain>
legacy2aidl_audio_gain_AudioGain(const audio_gain& legacy, bool isInput);

ConversionResult<audio_input_flags_t>
aidl2legacy_AudioInputFlags_audio_input_flags_t(media::audio::common::AudioInputFlags aidl);
ConversionResult<media::audio::common::AudioInputFlags>
legacy2aidl_audio_input_flags_t_AudioInputFlags(audio_input_flags_t legacy);

ConversionResult<audio_mode_t>
aidl2legacy_AudioMode_audio_mode_t(media::audio::common::AudioMode aidl);
ConversionResult<media::audio::common::AudioMode>
legacy2aidl_audio_mode_t_AudioMode(audio_mode_t legacy);

ConversionResult<audio_offload_info_t>
aidl2legacy_AudioOffloadInfo_audio_offload_info_t(
        const media::audio::common::AudioOffloadInfo& aidl);
ConversionResult<media::audio::common::AudioOffloadInfo>
legacy2aidl_audio_offload_info_t_AudioOffloadInfo(const audio_offload_info_t& legacy);

ConversionResult<audio_output_flags_t>
aidl2legacy_AudioOutputFlags_audio_output_flags_t(media::audio::common::AudioOutputFlags aidl);
ConversionResult<media::audio::common::AudioOutputFlags>
legacy2aidl_audio_output_flags_t_AudioOutputFlags(audio_output_flags_t legacy);

ConversionResult<audio_stream_type_t>
aidl2legacy_AudioStreamType_audio_stream_type_t(media::audio::common::AudioStreamType aidl);
ConversionResult<media::audio::common::AudioStreamType>
legacy2aidl_audio_stream_type_t_AudioStreamType(audio_stream_type_t legacy);

// This type is unnamed in the original definition, thus we name it here.
using audio_port_config_mix_ext_usecase = decltype(audio_port_config_mix_ext::usecase);
ConversionResult<audio_port_config_mix_ext_usecase>
aidl2legacy_AudioPortMixExtUseCase_audio_port_config_mix_ext_usecase(
        const media::audio::common::AudioPortMixExtUseCase& aidl, bool isInput);
ConversionResult<media::audio::common::AudioPortMixExtUseCase>
legacy2aidl_audio_port_config_mix_ext_usecase_AudioPortMixExtUseCase(
        const audio_port_config_mix_ext_usecase& legacy, bool isInput);

ConversionResult<audio_port_config_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(
        const media::audio::common::AudioPortDeviceExt& aidl);
ConversionResult<media::audio::common::AudioPortDeviceExt>
        legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(
        const audio_port_config_device_ext& legacy);

::android::status_t aidl2legacy_AudioPortConfig_audio_port_config(
        const media::audio::common::AudioPortConfig& aidl, bool isInput,
        audio_port_config* legacy, int32_t* portId);
ConversionResult<media::audio::common::AudioPortConfig>
legacy2aidl_audio_port_config_AudioPortConfig(
        const audio_port_config& legacy, bool isInput, int32_t portId);

ConversionResult<audio_port_mix_ext> aidl2legacy_AudioPortMixExt_audio_port_mix_ext(
        const media::audio::common::AudioPortMixExt& aidl);
ConversionResult<media::audio::common::AudioPortMixExt>
legacy2aidl_audio_port_mix_ext_AudioPortMixExt(
        const audio_port_mix_ext& legacy);

ConversionResult<audio_port_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_device_ext(
        const media::audio::common::AudioPortDeviceExt& aidl);
ConversionResult<media::audio::common::AudioPortDeviceExt>
legacy2aidl_audio_port_device_ext_AudioPortDeviceExt(
        const audio_port_device_ext& legacy);

ConversionResult<audio_port_v7>
aidl2legacy_AudioPort_audio_port_v7(
        const media::audio::common::AudioPort& aidl, bool isInput);
ConversionResult<media::audio::common::AudioPort>
legacy2aidl_audio_port_v7_AudioPort(const audio_port_v7& legacy, bool isInput);

ConversionResult<audio_profile> aidl2legacy_AudioProfile_audio_profile(
        const media::audio::common::AudioProfile& aidl, bool isInput);
ConversionResult<media::audio::common::AudioProfile> legacy2aidl_audio_profile_AudioProfile(
        const audio_profile& legacy, bool isInput);

ConversionResult<audio_standard_t> aidl2legacy_AudioStandard_audio_standard_t(
        media::audio::common::AudioStandard aidl);
ConversionResult<media::audio::common::AudioStandard> legacy2aidl_audio_standard_t_AudioStandard(
        audio_standard_t legacy);

ConversionResult<audio_source_t> aidl2legacy_AudioSource_audio_source_t(
        media::audio::common::AudioSource aidl);
ConversionResult<media::audio::common::AudioSource> legacy2aidl_audio_source_t_AudioSource(
        audio_source_t legacy);

ConversionResult<audio_usage_t> aidl2legacy_AudioUsage_audio_usage_t(
        media::audio::common::AudioUsage aidl);
ConversionResult<media::audio::common::AudioUsage> legacy2aidl_audio_usage_t_AudioUsage(
        audio_usage_t legacy);

ConversionResult<audio_flags_mask_t>
aidl2legacy_AudioFlag_audio_flags_mask_t(media::audio::common::AudioFlag aidl);
ConversionResult<media::audio::common::AudioFlag>
legacy2aidl_audio_flags_mask_t_AudioFlag(audio_flags_mask_t legacy);

ConversionResult<audio_flags_mask_t>
aidl2legacy_int32_t_audio_flags_mask_t_mask(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_audio_flags_mask_t_int32_t_mask(audio_flags_mask_t legacy);

ConversionResult<std::string>
aidl2legacy_AudioTags_string(const std::vector<std::string>& aidl);
ConversionResult<std::vector<std::string>>
legacy2aidl_string_AudioTags(const std::string& legacy);

ConversionResult<audio_attributes_t>
aidl2legacy_AudioAttributes_audio_attributes_t(const media::audio::common::AudioAttributes& aidl);
ConversionResult<media::audio::common::AudioAttributes>
legacy2aidl_audio_attributes_t_AudioAttributes(const audio_attributes_t& legacy);

ConversionResult<audio_uuid_t> aidl2legacy_AudioUuid_audio_uuid_t(
        const media::audio::common::AudioUuid &aidl);
ConversionResult<media::audio::common::AudioUuid> legacy2aidl_audio_uuid_t_AudioUuid(
        const audio_uuid_t& legacy);

ConversionResult<audio_dual_mono_mode_t>
aidl2legacy_AudioDualMonoMode_audio_dual_mono_mode_t(media::audio::common::AudioDualMonoMode aidl);
ConversionResult<media::audio::common::AudioDualMonoMode>
legacy2aidl_audio_dual_mono_mode_t_AudioDualMonoMode(audio_dual_mono_mode_t legacy);

ConversionResult<audio_timestretch_fallback_mode_t>
aidl2legacy_TimestretchFallbackMode_audio_timestretch_fallback_mode_t(
        media::audio::common::AudioPlaybackRate::TimestretchFallbackMode aidl);
ConversionResult<media::audio::common::AudioPlaybackRate::TimestretchFallbackMode>
legacy2aidl_audio_timestretch_fallback_mode_t_TimestretchFallbackMode(
        audio_timestretch_fallback_mode_t legacy);

ConversionResult<audio_timestretch_stretch_mode_t>
aidl2legacy_TimestretchMode_audio_timestretch_stretch_mode_t(
        media::audio::common::AudioPlaybackRate::TimestretchMode aidl);
ConversionResult<media::audio::common::AudioPlaybackRate::TimestretchMode>
legacy2aidl_audio_timestretch_stretch_mode_t_TimestretchMode(
        audio_timestretch_stretch_mode_t legacy);

ConversionResult<audio_playback_rate_t>
aidl2legacy_AudioPlaybackRate_audio_playback_rate_t(
        const media::audio::common::AudioPlaybackRate& aidl);
ConversionResult<media::audio::common::AudioPlaybackRate>
legacy2aidl_audio_playback_rate_t_AudioPlaybackRate(const audio_playback_rate_t& legacy);

ConversionResult<audio_latency_mode_t>
aidl2legacy_AudioLatencyMode_audio_latency_mode_t(media::audio::common::AudioLatencyMode aidl);
ConversionResult<media::audio::common::AudioLatencyMode>
legacy2aidl_audio_latency_mode_t_AudioLatencyMode(audio_latency_mode_t legacy);

ConversionResult<audio_microphone_location_t>
aidl2legacy_MicrophoneInfoLocation_audio_microphone_location_t(
        media::audio::common::MicrophoneInfo::Location aidl);
ConversionResult<media::audio::common::MicrophoneInfo::Location>
legacy2aidl_audio_microphone_location_t_MicrophoneInfoLocation(audio_microphone_location_t legacy);

ConversionResult<audio_microphone_group_t> aidl2legacy_int32_t_audio_microphone_group_t(
        int32_t aidl);
ConversionResult<int32_t> legacy2aidl_audio_microphone_group_t_int32_t(
        audio_microphone_group_t legacy);

ConversionResult<audio_microphone_directionality_t>
aidl2legacy_MicrophoneInfoDirectionality_audio_microphone_directionality_t(
        media::audio::common::MicrophoneInfo::Directionality aidl);
ConversionResult<media::audio::common::MicrophoneInfo::Directionality>
legacy2aidl_audio_microphone_directionality_t_MicrophoneInfoDirectionality(
        audio_microphone_directionality_t legacy);

ConversionResult<audio_microphone_coordinate>
aidl2legacy_MicrophoneInfoCoordinate_audio_microphone_coordinate(
        const media::audio::common::MicrophoneInfo::Coordinate& aidl);
ConversionResult<media::audio::common::MicrophoneInfo::Coordinate>
legacy2aidl_audio_microphone_coordinate_MicrophoneInfoCoordinate(
        const audio_microphone_coordinate& legacy);

ConversionResult<audio_microphone_channel_mapping_t>
aidl2legacy_MicrophoneDynamicInfoChannelMapping_audio_microphone_channel_mapping_t(
        media::audio::common::MicrophoneDynamicInfo::ChannelMapping aidl);
ConversionResult<media::audio::common::MicrophoneDynamicInfo::ChannelMapping>
legacy2aidl_audio_microphone_channel_mapping_t_MicrophoneDynamicInfoChannelMapping(
        audio_microphone_channel_mapping_t legacy);

ConversionResult<audio_microphone_characteristic_t>
aidl2legacy_MicrophoneInfos_audio_microphone_characteristic_t(
        const media::audio::common::MicrophoneInfo& aidlInfo,
        const media::audio::common::MicrophoneDynamicInfo& aidlDynamic);
::android::status_t
legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfos(
        const audio_microphone_characteristic_t& legacy,
        media::audio::common::MicrophoneInfo* aidlInfo,
        media::audio::common::MicrophoneDynamicInfo* aidlDynamic);

}  // namespace android

#if defined(BACKEND_NDK_IMPL)
} // aidl
#endif

// (defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_CPP_NDK_NDK)) || \
// (!defined(BACKEND_NDK_IMPL) && !defined(AUDIO_AIDL_CONVERSION_AIDL_CONVERSION_CPP_NDK_CPP))
#endif
