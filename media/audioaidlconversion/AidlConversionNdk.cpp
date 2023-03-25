/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <sstream>
#include <utility>

#include <system/audio.h>
#define LOG_TAG "AidlConversionNdk"
//#define LOG_NDEBUG 0
#include <utils/Log.h>
#include <utils/Errors.h>

#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <Utils.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// AIDL NDK backend to legacy audio data structure conversion utilities.

namespace aidl {
namespace android {

using hardware::audio::common::PlaybackTrackMetadata;
using hardware::audio::common::RecordTrackMetadata;
using ::android::BAD_VALUE;
using ::android::OK;

namespace {

::android::status_t combineString(
        const std::vector<std::string>& v, char separator, std::string* result) {
    std::ostringstream oss;
    for (const auto& s : v) {
        if (oss.tellp() > 0) {
            oss << separator;
        }
        if (s.find(separator) == std::string::npos) {
            oss << s;
        } else {
            ALOGE("%s: string \"%s\" contains separator character \"%c\"",
                    __func__, s.c_str(), separator);
            return BAD_VALUE;
        }
    }
    *result = oss.str();
    return OK;
}

std::vector<std::string> splitString(const std::string& s, char separator) {
    std::istringstream iss(s);
    std::string t;
    std::vector<std::string> result;
    while (std::getline(iss, t, separator)) {
        result.push_back(std::move(t));
    }
    return result;
}

std::vector<std::string> filterOutNonVendorTags(const std::vector<std::string>& tags) {
    std::vector<std::string> result;
    std::copy_if(tags.begin(), tags.end(), std::back_inserter(result),
            ::aidl::android::hardware::audio::common::maybeVendorExtension);
    return result;
}

}  // namespace

// buffer_provider_t is not supported thus skipped
ConversionResult<buffer_config_t> aidl2legacy_AudioConfig_buffer_config_t(
        const media::audio::common::AudioConfig& aidl, bool isInput) {
    buffer_config_t legacy;

    legacy.samplingRate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.base.sampleRate));
    legacy.mask |= EFFECT_CONFIG_SMP_RATE;

    legacy.channels = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.base.channelMask, isInput));
    legacy.mask |= EFFECT_CONFIG_CHANNELS;

    legacy.format =
            VALUE_OR_RETURN(aidl2legacy_AudioFormatDescription_audio_format_t(aidl.base.format));
    legacy.mask |= EFFECT_CONFIG_FORMAT;
    legacy.buffer.frameCount = aidl.frameCount;

    // TODO: add accessMode and mask
    return legacy;
}

ConversionResult<media::audio::common::AudioConfig>
legacy2aidl_buffer_config_t_AudioConfig(const buffer_config_t& legacy, bool isInput) {
    media::audio::common::AudioConfig aidl;

    if (legacy.mask & EFFECT_CONFIG_SMP_RATE) {
        aidl.base.sampleRate = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.samplingRate));
    }
    if (legacy.mask & EFFECT_CONFIG_CHANNELS) {
        aidl.base.channelMask = VALUE_OR_RETURN(legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                static_cast<audio_channel_mask_t>(legacy.channels), isInput));
    }
    if (legacy.mask & EFFECT_CONFIG_FORMAT) {
        aidl.base.format = VALUE_OR_RETURN(legacy2aidl_audio_format_t_AudioFormatDescription(
                static_cast<audio_format_t>(legacy.format)));
    }
    aidl.frameCount = legacy.buffer.frameCount;

    // TODO: add accessMode and mask
    return aidl;
}

::android::status_t aidl2legacy_AudioAttributesTags(
        const std::vector<std::string>& aidl, char* legacy) {
    std::string aidlTags;
    RETURN_STATUS_IF_ERROR(combineString(
                    filterOutNonVendorTags(aidl), AUDIO_ATTRIBUTES_TAGS_SEPARATOR, &aidlTags));
    RETURN_STATUS_IF_ERROR(aidl2legacy_string(aidlTags, legacy, AUDIO_ATTRIBUTES_TAGS_MAX_SIZE));
    return OK;
}

ConversionResult<std::vector<std::string>> legacy2aidl_AudioAttributesTags(const char* legacy) {
    std::string legacyTags = VALUE_OR_RETURN(legacy2aidl_string(
                    legacy, AUDIO_ATTRIBUTES_TAGS_MAX_SIZE));
    return filterOutNonVendorTags(splitString(legacyTags, AUDIO_ATTRIBUTES_TAGS_SEPARATOR));
}

ConversionResult<playback_track_metadata_v7>
aidl2legacy_PlaybackTrackMetadata_playback_track_metadata_v7(const PlaybackTrackMetadata& aidl) {
    playback_track_metadata_v7 legacy;
    legacy.base.usage = VALUE_OR_RETURN(aidl2legacy_AudioUsage_audio_usage_t(aidl.usage));
    legacy.base.content_type = VALUE_OR_RETURN(aidl2legacy_AudioContentType_audio_content_type_t(
                    aidl.contentType));
    legacy.base.gain = aidl.gain;
    legacy.channel_mask = VALUE_OR_RETURN(aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
                    aidl.channelMask, false /*isInput*/));
    RETURN_IF_ERROR(aidl2legacy_AudioAttributesTags(aidl.tags, legacy.tags));
    return legacy;
}

ConversionResult<PlaybackTrackMetadata>
legacy2aidl_playback_track_metadata_v7_PlaybackTrackMetadata(
        const playback_track_metadata_v7& legacy) {
    PlaybackTrackMetadata aidl;
    aidl.usage = VALUE_OR_RETURN(legacy2aidl_audio_usage_t_AudioUsage(legacy.base.usage));
    aidl.contentType = VALUE_OR_RETURN(legacy2aidl_audio_content_type_t_AudioContentType(
                    legacy.base.content_type));
    aidl.gain = legacy.base.gain;
    aidl.channelMask = VALUE_OR_RETURN(legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                    legacy.channel_mask, false /*isInput*/));
    aidl.tags = VALUE_OR_RETURN(legacy2aidl_AudioAttributesTags(legacy.tags));
    return aidl;
}

ConversionResult<record_track_metadata_v7>
aidl2legacy_RecordTrackMetadata_record_track_metadata_v7(const RecordTrackMetadata& aidl) {
    record_track_metadata_v7 legacy;
    legacy.base.source = VALUE_OR_RETURN(aidl2legacy_AudioSource_audio_source_t(aidl.source));
    legacy.base.gain = aidl.gain;
    if (aidl.destinationDevice.has_value()) {
        RETURN_IF_ERROR(aidl2legacy_AudioDevice_audio_device(aidl.destinationDevice.value(),
                        &legacy.base.dest_device, legacy.base.dest_device_address));
    } else {
        legacy.base.dest_device = AUDIO_DEVICE_NONE;
    }
    legacy.channel_mask = VALUE_OR_RETURN(aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
                    aidl.channelMask, true /*isInput*/));
    RETURN_IF_ERROR(aidl2legacy_AudioAttributesTags(aidl.tags, legacy.tags));
    return legacy;
}

ConversionResult<RecordTrackMetadata>
legacy2aidl_record_track_metadata_v7_RecordTrackMetadata(const record_track_metadata_v7& legacy) {
    RecordTrackMetadata aidl;
    aidl.source = VALUE_OR_RETURN(legacy2aidl_audio_source_t_AudioSource(legacy.base.source));
    aidl.gain = legacy.base.gain;
    if (legacy.base.dest_device != AUDIO_DEVICE_NONE) {
        aidl.destinationDevice = VALUE_OR_RETURN(legacy2aidl_audio_device_AudioDevice(
                        legacy.base.dest_device, legacy.base.dest_device_address));
    }
    aidl.channelMask = VALUE_OR_RETURN(legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                    legacy.channel_mask, true /*isInput*/));
    aidl.tags = VALUE_OR_RETURN(legacy2aidl_AudioAttributesTags(legacy.tags));
    return aidl;
}

}  // namespace android
}  // aidl
