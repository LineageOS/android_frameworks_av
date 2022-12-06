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

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

#define LOG_TAG "AidlConversion"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "media/AidlConversion.h"

#include <media/ShmemCompat.h>
#include <media/stagefright/foundation/MediaDefs.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// Utilities

namespace android {

using base::unexpected;
using media::audio::common::AudioChannelLayout;
using media::audio::common::AudioConfig;
using media::audio::common::AudioConfigBase;
using media::audio::common::AudioContentType;
using media::audio::common::AudioDevice;
using media::audio::common::AudioDeviceAddress;
using media::audio::common::AudioDeviceDescription;
using media::audio::common::AudioDeviceType;
using media::audio::common::AudioEncapsulationMetadataType;
using media::audio::common::AudioEncapsulationMode;
using media::audio::common::AudioEncapsulationType;
using media::audio::common::AudioFormatDescription;
using media::audio::common::AudioFormatType;
using media::audio::common::AudioGain;
using media::audio::common::AudioGainConfig;
using media::audio::common::AudioGainMode;
using media::audio::common::AudioInputFlags;
using media::audio::common::AudioIoFlags;
using media::audio::common::AudioMode;
using media::audio::common::AudioOffloadInfo;
using media::audio::common::AudioOutputFlags;
using media::audio::common::AudioPortDeviceExt;
using media::audio::common::AudioPortExt;
using media::audio::common::AudioPortMixExt;
using media::audio::common::AudioPortMixExtUseCase;
using media::audio::common::AudioProfile;
using media::audio::common::AudioSource;
using media::audio::common::AudioStandard;
using media::audio::common::AudioStreamType;
using media::audio::common::AudioUsage;
using media::audio::common::AudioUuid;
using media::audio::common::ExtraAudioDescriptor;
using media::audio::common::Int;
using media::audio::common::PcmType;

namespace {

enum class Direction {
    INPUT, OUTPUT
};

ConversionResult<Direction> direction(media::AudioPortRole role, media::AudioPortType type) {
    switch (type) {
        case media::AudioPortType::NONE:
        case media::AudioPortType::SESSION:
            break;  // must be listed  -Werror,-Wswitch
        case media::AudioPortType::DEVICE:
            switch (role) {
                case media::AudioPortRole::NONE:
                     break;  // must be listed  -Werror,-Wswitch
                case media::AudioPortRole::SOURCE:
                    return Direction::INPUT;
                case media::AudioPortRole::SINK:
                    return Direction::OUTPUT;
            }
            break;
        case media::AudioPortType::MIX:
            switch (role) {
                case media::AudioPortRole::NONE:
                     break;  // must be listed  -Werror,-Wswitch
                case media::AudioPortRole::SOURCE:
                    return Direction::OUTPUT;
                case media::AudioPortRole::SINK:
                    return Direction::INPUT;
            }
            break;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<Direction> direction(audio_port_role_t role, audio_port_type_t type) {
    switch (type) {
        case AUDIO_PORT_TYPE_NONE:
        case AUDIO_PORT_TYPE_SESSION:
            break;  // must be listed  -Werror,-Wswitch
        case AUDIO_PORT_TYPE_DEVICE:
            switch (role) {
                case AUDIO_PORT_ROLE_NONE:
                     break;  // must be listed  -Werror,-Wswitch
                case AUDIO_PORT_ROLE_SOURCE:
                    return Direction::INPUT;
                case AUDIO_PORT_ROLE_SINK:
                    return Direction::OUTPUT;
            }
            break;
        case AUDIO_PORT_TYPE_MIX:
            switch (role) {
                case AUDIO_PORT_ROLE_NONE:
                     break;  // must be listed  -Werror,-Wswitch
                case AUDIO_PORT_ROLE_SOURCE:
                    return Direction::OUTPUT;
                case AUDIO_PORT_ROLE_SINK:
                    return Direction::INPUT;
            }
            break;
    }
    return unexpected(BAD_VALUE);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////////////////////////
// Converters

status_t aidl2legacy_string(std::string_view aidl, char* dest, size_t maxSize) {
    if (aidl.size() > maxSize - 1) {
        return BAD_VALUE;
    }
    aidl.copy(dest, aidl.size());
    dest[aidl.size()] = '\0';
    return OK;
}

ConversionResult<std::string> legacy2aidl_string(const char* legacy, size_t maxSize) {
    if (legacy == nullptr) {
        return unexpected(BAD_VALUE);
    }
    if (strnlen(legacy, maxSize) == maxSize) {
        // No null-terminator.
        return unexpected(BAD_VALUE);
    }
    return std::string(legacy);
}

ConversionResult<audio_module_handle_t> aidl2legacy_int32_t_audio_module_handle_t(int32_t aidl) {
    return convertReinterpret<audio_module_handle_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_audio_module_handle_t_int32_t(audio_module_handle_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_io_handle_t> aidl2legacy_int32_t_audio_io_handle_t(int32_t aidl) {
    return convertReinterpret<audio_io_handle_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_audio_io_handle_t_int32_t(audio_io_handle_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_port_handle_t> aidl2legacy_int32_t_audio_port_handle_t(int32_t aidl) {
    return convertReinterpret<audio_port_handle_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_audio_port_handle_t_int32_t(audio_port_handle_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_patch_handle_t> aidl2legacy_int32_t_audio_patch_handle_t(int32_t aidl) {
    return convertReinterpret<audio_patch_handle_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_audio_patch_handle_t_int32_t(audio_patch_handle_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_unique_id_t> aidl2legacy_int32_t_audio_unique_id_t(int32_t aidl) {
    return convertReinterpret<audio_unique_id_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_audio_unique_id_t_int32_t(audio_unique_id_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_hw_sync_t> aidl2legacy_int32_t_audio_hw_sync_t(int32_t aidl) {
    return convertReinterpret<audio_hw_sync_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_audio_hw_sync_t_int32_t(audio_hw_sync_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<pid_t> aidl2legacy_int32_t_pid_t(int32_t aidl) {
    return convertReinterpret<pid_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_pid_t_int32_t(pid_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<uid_t> aidl2legacy_int32_t_uid_t(int32_t aidl) {
    return convertReinterpret<uid_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_uid_t_int32_t(uid_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<String16> aidl2legacy_string_view_String16(std::string_view aidl) {
    return String16(aidl.data(), aidl.size());
}

ConversionResult<std::string> legacy2aidl_String16_string(const String16& legacy) {
    return std::string(String8(legacy).c_str());
}

// TODO b/182392769: create an optional -> optional util
ConversionResult<std::optional<String16>>
aidl2legacy_optional_string_view_optional_String16(std::optional<std::string_view> aidl) {
    if (!aidl.has_value()) {
        return std::nullopt;
    }
    ConversionResult<String16> conversion =
        VALUE_OR_RETURN(aidl2legacy_string_view_String16(aidl.value()));
    return conversion.value();
}

ConversionResult<std::optional<std::string_view>>
legacy2aidl_optional_String16_optional_string(std::optional<String16> legacy) {
  if (!legacy.has_value()) {
    return std::nullopt;
  }
  ConversionResult<std::string> conversion =
      VALUE_OR_RETURN(legacy2aidl_String16_string(legacy.value()));
  return conversion.value();
}

ConversionResult<String8> aidl2legacy_string_view_String8(std::string_view aidl) {
    return String8(aidl.data(), aidl.size());
}

ConversionResult<std::string> legacy2aidl_String8_string(const String8& legacy) {
    return std::string(legacy.c_str());
}

ConversionResult<audio_io_config_event_t> aidl2legacy_AudioIoConfigEvent_audio_io_config_event_t(
        media::AudioIoConfigEvent aidl) {
    switch (aidl) {
        case media::AudioIoConfigEvent::OUTPUT_REGISTERED:
            return AUDIO_OUTPUT_REGISTERED;
        case media::AudioIoConfigEvent::OUTPUT_OPENED:
            return AUDIO_OUTPUT_OPENED;
        case media::AudioIoConfigEvent::OUTPUT_CLOSED:
            return AUDIO_OUTPUT_CLOSED;
        case media::AudioIoConfigEvent::OUTPUT_CONFIG_CHANGED:
            return AUDIO_OUTPUT_CONFIG_CHANGED;
        case media::AudioIoConfigEvent::INPUT_REGISTERED:
            return AUDIO_INPUT_REGISTERED;
        case media::AudioIoConfigEvent::INPUT_OPENED:
            return AUDIO_INPUT_OPENED;
        case media::AudioIoConfigEvent::INPUT_CLOSED:
            return AUDIO_INPUT_CLOSED;
        case media::AudioIoConfigEvent::INPUT_CONFIG_CHANGED:
            return AUDIO_INPUT_CONFIG_CHANGED;
        case media::AudioIoConfigEvent::CLIENT_STARTED:
            return AUDIO_CLIENT_STARTED;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioIoConfigEvent> legacy2aidl_audio_io_config_event_t_AudioIoConfigEvent(
        audio_io_config_event_t legacy) {
    switch (legacy) {
        case AUDIO_OUTPUT_REGISTERED:
            return media::AudioIoConfigEvent::OUTPUT_REGISTERED;
        case AUDIO_OUTPUT_OPENED:
            return media::AudioIoConfigEvent::OUTPUT_OPENED;
        case AUDIO_OUTPUT_CLOSED:
            return media::AudioIoConfigEvent::OUTPUT_CLOSED;
        case AUDIO_OUTPUT_CONFIG_CHANGED:
            return media::AudioIoConfigEvent::OUTPUT_CONFIG_CHANGED;
        case AUDIO_INPUT_REGISTERED:
            return media::AudioIoConfigEvent::INPUT_REGISTERED;
        case AUDIO_INPUT_OPENED:
            return media::AudioIoConfigEvent::INPUT_OPENED;
        case AUDIO_INPUT_CLOSED:
            return media::AudioIoConfigEvent::INPUT_CLOSED;
        case AUDIO_INPUT_CONFIG_CHANGED:
            return media::AudioIoConfigEvent::INPUT_CONFIG_CHANGED;
        case AUDIO_CLIENT_STARTED:
            return media::AudioIoConfigEvent::CLIENT_STARTED;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_port_role_t> aidl2legacy_AudioPortRole_audio_port_role_t(
        media::AudioPortRole aidl) {
    switch (aidl) {
        case media::AudioPortRole::NONE:
            return AUDIO_PORT_ROLE_NONE;
        case media::AudioPortRole::SOURCE:
            return AUDIO_PORT_ROLE_SOURCE;
        case media::AudioPortRole::SINK:
            return AUDIO_PORT_ROLE_SINK;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioPortRole> legacy2aidl_audio_port_role_t_AudioPortRole(
        audio_port_role_t legacy) {
    switch (legacy) {
        case AUDIO_PORT_ROLE_NONE:
            return media::AudioPortRole::NONE;
        case AUDIO_PORT_ROLE_SOURCE:
            return media::AudioPortRole::SOURCE;
        case AUDIO_PORT_ROLE_SINK:
            return media::AudioPortRole::SINK;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_port_type_t> aidl2legacy_AudioPortType_audio_port_type_t(
        media::AudioPortType aidl) {
    switch (aidl) {
        case media::AudioPortType::NONE:
            return AUDIO_PORT_TYPE_NONE;
        case media::AudioPortType::DEVICE:
            return AUDIO_PORT_TYPE_DEVICE;
        case media::AudioPortType::MIX:
            return AUDIO_PORT_TYPE_MIX;
        case media::AudioPortType::SESSION:
            return AUDIO_PORT_TYPE_SESSION;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioPortType> legacy2aidl_audio_port_type_t_AudioPortType(
        audio_port_type_t legacy) {
    switch (legacy) {
        case AUDIO_PORT_TYPE_NONE:
            return media::AudioPortType::NONE;
        case AUDIO_PORT_TYPE_DEVICE:
            return media::AudioPortType::DEVICE;
        case AUDIO_PORT_TYPE_MIX:
            return media::AudioPortType::MIX;
        case AUDIO_PORT_TYPE_SESSION:
            return media::AudioPortType::SESSION;
    }
    return unexpected(BAD_VALUE);
}

namespace {

namespace detail {
using AudioChannelBitPair = std::pair<audio_channel_mask_t, int>;
using AudioChannelBitPairs = std::vector<AudioChannelBitPair>;
using AudioChannelPair = std::pair<audio_channel_mask_t, AudioChannelLayout>;
using AudioChannelPairs = std::vector<AudioChannelPair>;
using AudioDevicePair = std::pair<audio_devices_t, AudioDeviceDescription>;
using AudioDevicePairs = std::vector<AudioDevicePair>;
using AudioFormatPair = std::pair<audio_format_t, AudioFormatDescription>;
using AudioFormatPairs = std::vector<AudioFormatPair>;
}

const detail::AudioChannelBitPairs& getInAudioChannelBits() {
    static const detail::AudioChannelBitPairs pairs = {
        { AUDIO_CHANNEL_IN_LEFT, AudioChannelLayout::CHANNEL_FRONT_LEFT },
        { AUDIO_CHANNEL_IN_RIGHT, AudioChannelLayout::CHANNEL_FRONT_RIGHT },
        // AUDIO_CHANNEL_IN_FRONT is at the end
        { AUDIO_CHANNEL_IN_BACK, AudioChannelLayout::CHANNEL_BACK_CENTER },
        // AUDIO_CHANNEL_IN_*_PROCESSED not supported
        // AUDIO_CHANNEL_IN_PRESSURE not supported
        // AUDIO_CHANNEL_IN_*_AXIS not supported
        // AUDIO_CHANNEL_IN_VOICE_* not supported
        { AUDIO_CHANNEL_IN_BACK_LEFT, AudioChannelLayout::CHANNEL_BACK_LEFT },
        { AUDIO_CHANNEL_IN_BACK_RIGHT, AudioChannelLayout::CHANNEL_BACK_RIGHT },
        { AUDIO_CHANNEL_IN_CENTER, AudioChannelLayout::CHANNEL_FRONT_CENTER },
        { AUDIO_CHANNEL_IN_LOW_FREQUENCY, AudioChannelLayout::CHANNEL_LOW_FREQUENCY },
        { AUDIO_CHANNEL_IN_TOP_LEFT, AudioChannelLayout::CHANNEL_TOP_SIDE_LEFT },
        { AUDIO_CHANNEL_IN_TOP_RIGHT, AudioChannelLayout::CHANNEL_TOP_SIDE_RIGHT },
        // When going from aidl to legacy, IN_CENTER is used
        { AUDIO_CHANNEL_IN_FRONT, AudioChannelLayout::CHANNEL_FRONT_CENTER }
    };
    return pairs;
}

const detail::AudioChannelPairs& getInAudioChannelPairs() {
    static const detail::AudioChannelPairs pairs = {
#define DEFINE_INPUT_LAYOUT(n)                                                 \
            {                                                                  \
                AUDIO_CHANNEL_IN_##n,                                          \
                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>( \
                        AudioChannelLayout::LAYOUT_##n)                        \
            }

        DEFINE_INPUT_LAYOUT(MONO),
        DEFINE_INPUT_LAYOUT(STEREO),
        DEFINE_INPUT_LAYOUT(FRONT_BACK),
        // AUDIO_CHANNEL_IN_6 not supported
        DEFINE_INPUT_LAYOUT(2POINT0POINT2),
        DEFINE_INPUT_LAYOUT(2POINT1POINT2),
        DEFINE_INPUT_LAYOUT(3POINT0POINT2),
        DEFINE_INPUT_LAYOUT(3POINT1POINT2),
        DEFINE_INPUT_LAYOUT(5POINT1)
#undef DEFINE_INPUT_LAYOUT
    };
    return pairs;
}

const detail::AudioChannelBitPairs& getOutAudioChannelBits() {
    static const detail::AudioChannelBitPairs pairs = {
#define DEFINE_OUTPUT_BITS(n)                                                  \
            { AUDIO_CHANNEL_OUT_##n, AudioChannelLayout::CHANNEL_##n }

        DEFINE_OUTPUT_BITS(FRONT_LEFT),
        DEFINE_OUTPUT_BITS(FRONT_RIGHT),
        DEFINE_OUTPUT_BITS(FRONT_CENTER),
        DEFINE_OUTPUT_BITS(LOW_FREQUENCY),
        DEFINE_OUTPUT_BITS(BACK_LEFT),
        DEFINE_OUTPUT_BITS(BACK_RIGHT),
        DEFINE_OUTPUT_BITS(FRONT_LEFT_OF_CENTER),
        DEFINE_OUTPUT_BITS(FRONT_RIGHT_OF_CENTER),
        DEFINE_OUTPUT_BITS(BACK_CENTER),
        DEFINE_OUTPUT_BITS(SIDE_LEFT),
        DEFINE_OUTPUT_BITS(SIDE_RIGHT),
        DEFINE_OUTPUT_BITS(TOP_CENTER),
        DEFINE_OUTPUT_BITS(TOP_FRONT_LEFT),
        DEFINE_OUTPUT_BITS(TOP_FRONT_CENTER),
        DEFINE_OUTPUT_BITS(TOP_FRONT_RIGHT),
        DEFINE_OUTPUT_BITS(TOP_BACK_LEFT),
        DEFINE_OUTPUT_BITS(TOP_BACK_CENTER),
        DEFINE_OUTPUT_BITS(TOP_BACK_RIGHT),
        DEFINE_OUTPUT_BITS(TOP_SIDE_LEFT),
        DEFINE_OUTPUT_BITS(TOP_SIDE_RIGHT),
        DEFINE_OUTPUT_BITS(BOTTOM_FRONT_LEFT),
        DEFINE_OUTPUT_BITS(BOTTOM_FRONT_CENTER),
        DEFINE_OUTPUT_BITS(BOTTOM_FRONT_RIGHT),
        DEFINE_OUTPUT_BITS(LOW_FREQUENCY_2),
        DEFINE_OUTPUT_BITS(FRONT_WIDE_LEFT),
        DEFINE_OUTPUT_BITS(FRONT_WIDE_RIGHT),
#undef DEFINE_OUTPUT_BITS
        { AUDIO_CHANNEL_OUT_HAPTIC_A, AudioChannelLayout::CHANNEL_HAPTIC_A },
        { AUDIO_CHANNEL_OUT_HAPTIC_B, AudioChannelLayout::CHANNEL_HAPTIC_B }
    };
    return pairs;
}

const detail::AudioChannelPairs& getOutAudioChannelPairs() {
    static const detail::AudioChannelPairs pairs = {
#define DEFINE_OUTPUT_LAYOUT(n)                                                \
            {                                                                  \
                AUDIO_CHANNEL_OUT_##n,                                         \
                AudioChannelLayout::make<AudioChannelLayout::Tag::layoutMask>( \
                        AudioChannelLayout::LAYOUT_##n)                        \
            }

        DEFINE_OUTPUT_LAYOUT(MONO),
        DEFINE_OUTPUT_LAYOUT(STEREO),
        DEFINE_OUTPUT_LAYOUT(2POINT1),
        DEFINE_OUTPUT_LAYOUT(TRI),
        DEFINE_OUTPUT_LAYOUT(TRI_BACK),
        DEFINE_OUTPUT_LAYOUT(3POINT1),
        DEFINE_OUTPUT_LAYOUT(2POINT0POINT2),
        DEFINE_OUTPUT_LAYOUT(2POINT1POINT2),
        DEFINE_OUTPUT_LAYOUT(3POINT0POINT2),
        DEFINE_OUTPUT_LAYOUT(3POINT1POINT2),
        DEFINE_OUTPUT_LAYOUT(QUAD),
        DEFINE_OUTPUT_LAYOUT(QUAD_SIDE),
        DEFINE_OUTPUT_LAYOUT(SURROUND),
        DEFINE_OUTPUT_LAYOUT(PENTA),
        DEFINE_OUTPUT_LAYOUT(5POINT1),
        DEFINE_OUTPUT_LAYOUT(5POINT1_SIDE),
        DEFINE_OUTPUT_LAYOUT(5POINT1POINT2),
        DEFINE_OUTPUT_LAYOUT(5POINT1POINT4),
        DEFINE_OUTPUT_LAYOUT(6POINT1),
        DEFINE_OUTPUT_LAYOUT(7POINT1),
        DEFINE_OUTPUT_LAYOUT(7POINT1POINT2),
        DEFINE_OUTPUT_LAYOUT(7POINT1POINT4),
        DEFINE_OUTPUT_LAYOUT(13POINT_360RA),
        DEFINE_OUTPUT_LAYOUT(22POINT2),
        DEFINE_OUTPUT_LAYOUT(MONO_HAPTIC_A),
        DEFINE_OUTPUT_LAYOUT(STEREO_HAPTIC_A),
        DEFINE_OUTPUT_LAYOUT(HAPTIC_AB),
        DEFINE_OUTPUT_LAYOUT(MONO_HAPTIC_AB),
        DEFINE_OUTPUT_LAYOUT(STEREO_HAPTIC_AB)
#undef DEFINE_OUTPUT_LAYOUT
    };
    return pairs;
}

const detail::AudioChannelPairs& getVoiceAudioChannelPairs() {
    static const detail::AudioChannelPairs pairs = {
#define DEFINE_VOICE_LAYOUT(n)                                                 \
            {                                                                  \
                AUDIO_CHANNEL_IN_VOICE_##n,                                    \
                AudioChannelLayout::make<AudioChannelLayout::Tag::voiceMask>(  \
                        AudioChannelLayout::VOICE_##n)                         \
            }
        DEFINE_VOICE_LAYOUT(UPLINK_MONO),
        DEFINE_VOICE_LAYOUT(DNLINK_MONO),
        DEFINE_VOICE_LAYOUT(CALL_MONO)
#undef DEFINE_VOICE_LAYOUT
    };
    return pairs;
}

AudioDeviceDescription make_AudioDeviceDescription(AudioDeviceType type,
        const std::string& connection = "") {
    AudioDeviceDescription result;
    result.type = type;
    result.connection = connection;
    return result;
}

void append_AudioDeviceDescription(detail::AudioDevicePairs& pairs,
        audio_devices_t inputType, audio_devices_t outputType,
        AudioDeviceType inType, AudioDeviceType outType,
        const std::string& connection = "") {
    pairs.push_back(std::make_pair(inputType, make_AudioDeviceDescription(inType, connection)));
    pairs.push_back(std::make_pair(outputType, make_AudioDeviceDescription(outType, connection)));
}

const detail::AudioDevicePairs& getAudioDevicePairs() {
    static const detail::AudioDevicePairs pairs = []() {
        detail::AudioDevicePairs pairs = {{
            {
                AUDIO_DEVICE_NONE, AudioDeviceDescription{}
            },
            {
                AUDIO_DEVICE_OUT_EARPIECE, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_SPEAKER_EARPIECE)
            },
            {
                AUDIO_DEVICE_OUT_SPEAKER, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_SPEAKER)
            },
            {
                AUDIO_DEVICE_OUT_WIRED_HEADPHONE, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_HEADPHONE,
                        AudioDeviceDescription::CONNECTION_ANALOG())
            },
            {
                AUDIO_DEVICE_OUT_BLUETOOTH_SCO, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_DEVICE,
                        AudioDeviceDescription::CONNECTION_BT_SCO())
            },
            {
                AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_CARKIT,
                        AudioDeviceDescription::CONNECTION_BT_SCO())
            },
            {
                AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_HEADPHONE,
                        AudioDeviceDescription::CONNECTION_BT_A2DP())
            },
            {
                AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_SPEAKER,
                        AudioDeviceDescription::CONNECTION_BT_A2DP())
            },
            {
                AUDIO_DEVICE_OUT_TELEPHONY_TX, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_TELEPHONY_TX)
            },
            {
                AUDIO_DEVICE_OUT_AUX_LINE, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_LINE_AUX)
            },
            {
                AUDIO_DEVICE_OUT_SPEAKER_SAFE, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_SPEAKER_SAFE)
            },
            {
                AUDIO_DEVICE_OUT_HEARING_AID, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_HEARING_AID,
                        AudioDeviceDescription::CONNECTION_WIRELESS())
            },
            {
                AUDIO_DEVICE_OUT_ECHO_CANCELLER, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_ECHO_CANCELLER)
            },
            {
                AUDIO_DEVICE_OUT_BLE_SPEAKER, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_SPEAKER,
                        AudioDeviceDescription::CONNECTION_BT_LE())
            },
            {
                AUDIO_DEVICE_OUT_BLE_BROADCAST, make_AudioDeviceDescription(
                        AudioDeviceType::OUT_BROADCAST,
                        AudioDeviceDescription::CONNECTION_BT_LE())
            },
            // AUDIO_DEVICE_IN_AMBIENT and IN_COMMUNICATION are removed since they were deprecated.
            {
                AUDIO_DEVICE_IN_BUILTIN_MIC, make_AudioDeviceDescription(
                        AudioDeviceType::IN_MICROPHONE)
            },
            {
                AUDIO_DEVICE_IN_BACK_MIC, make_AudioDeviceDescription(
                        AudioDeviceType::IN_MICROPHONE_BACK)
            },
            {
                AUDIO_DEVICE_IN_TELEPHONY_RX, make_AudioDeviceDescription(
                        AudioDeviceType::IN_TELEPHONY_RX)
            },
            {
                AUDIO_DEVICE_IN_TV_TUNER, make_AudioDeviceDescription(
                        AudioDeviceType::IN_TV_TUNER)
            },
            {
                AUDIO_DEVICE_IN_LOOPBACK, make_AudioDeviceDescription(
                        AudioDeviceType::IN_LOOPBACK)
            },
            {
                AUDIO_DEVICE_IN_BLUETOOTH_BLE, make_AudioDeviceDescription(
                        AudioDeviceType::IN_DEVICE,
                        AudioDeviceDescription::CONNECTION_BT_LE())
            },
            {
                AUDIO_DEVICE_IN_ECHO_REFERENCE, make_AudioDeviceDescription(
                        AudioDeviceType::IN_ECHO_REFERENCE)
            }
        }};
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_DEFAULT, AUDIO_DEVICE_OUT_DEFAULT,
                AudioDeviceType::IN_DEFAULT, AudioDeviceType::OUT_DEFAULT);
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_WIRED_HEADSET, AUDIO_DEVICE_OUT_WIRED_HEADSET,
                AudioDeviceType::IN_HEADSET, AudioDeviceType::OUT_HEADSET,
                AudioDeviceDescription::CONNECTION_ANALOG());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                AudioDeviceType::IN_HEADSET, AudioDeviceType::OUT_HEADSET,
                AudioDeviceDescription::CONNECTION_BT_SCO());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_HDMI, AUDIO_DEVICE_OUT_HDMI,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_HDMI());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_REMOTE_SUBMIX, AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
                AudioDeviceType::IN_SUBMIX, AudioDeviceType::OUT_SUBMIX);
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_ANLG_DOCK_HEADSET, AUDIO_DEVICE_OUT_ANLG_DOCK_HEADSET,
                AudioDeviceType::IN_DOCK, AudioDeviceType::OUT_DOCK,
                AudioDeviceDescription::CONNECTION_ANALOG());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_DGTL_DOCK_HEADSET, AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET,
                AudioDeviceType::IN_DOCK, AudioDeviceType::OUT_DOCK,
                AudioDeviceDescription::CONNECTION_USB());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_USB_ACCESSORY, AUDIO_DEVICE_OUT_USB_ACCESSORY,
                AudioDeviceType::IN_ACCESSORY, AudioDeviceType::OUT_ACCESSORY,
                AudioDeviceDescription::CONNECTION_USB());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_DEVICE_OUT_USB_DEVICE,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_USB());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_FM_TUNER, AUDIO_DEVICE_OUT_FM,
                AudioDeviceType::IN_FM_TUNER, AudioDeviceType::OUT_FM);
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_LINE, AUDIO_DEVICE_OUT_LINE,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_ANALOG());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_SPDIF, AUDIO_DEVICE_OUT_SPDIF,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_SPDIF());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_BLUETOOTH_A2DP, AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_BT_A2DP());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_IP, AUDIO_DEVICE_OUT_IP,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_IP_V4());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_BUS, AUDIO_DEVICE_OUT_BUS,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_BUS());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_PROXY, AUDIO_DEVICE_OUT_PROXY,
                AudioDeviceType::IN_AFE_PROXY, AudioDeviceType::OUT_AFE_PROXY);
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_USB_HEADSET, AUDIO_DEVICE_OUT_USB_HEADSET,
                AudioDeviceType::IN_HEADSET, AudioDeviceType::OUT_HEADSET,
                AudioDeviceDescription::CONNECTION_USB());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_HDMI_ARC, AUDIO_DEVICE_OUT_HDMI_ARC,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_HDMI_ARC());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_HDMI_EARC, AUDIO_DEVICE_OUT_HDMI_EARC,
                AudioDeviceType::IN_DEVICE, AudioDeviceType::OUT_DEVICE,
                AudioDeviceDescription::CONNECTION_HDMI_EARC());
        append_AudioDeviceDescription(pairs,
                AUDIO_DEVICE_IN_BLE_HEADSET, AUDIO_DEVICE_OUT_BLE_HEADSET,
                AudioDeviceType::IN_HEADSET, AudioDeviceType::OUT_HEADSET,
                AudioDeviceDescription::CONNECTION_BT_LE());
        return pairs;
    }();
    return pairs;
}

AudioFormatDescription make_AudioFormatDescription(AudioFormatType type) {
    AudioFormatDescription result;
    result.type = type;
    return result;
}

AudioFormatDescription make_AudioFormatDescription(PcmType pcm) {
    auto result = make_AudioFormatDescription(AudioFormatType::PCM);
    result.pcm = pcm;
    return result;
}

AudioFormatDescription make_AudioFormatDescription(const std::string& encoding) {
    AudioFormatDescription result;
    result.encoding = encoding;
    return result;
}

AudioFormatDescription make_AudioFormatDescription(PcmType transport,
        const std::string& encoding) {
    auto result = make_AudioFormatDescription(encoding);
    result.pcm = transport;
    return result;
}

const detail::AudioFormatPairs& getAudioFormatPairs() {
    static const detail::AudioFormatPairs pairs = {{
        {
            AUDIO_FORMAT_INVALID,
            make_AudioFormatDescription(AudioFormatType::SYS_RESERVED_INVALID)
        },
        {
            AUDIO_FORMAT_DEFAULT, AudioFormatDescription{}
        },
        {
            AUDIO_FORMAT_PCM_16_BIT, make_AudioFormatDescription(PcmType::INT_16_BIT)
        },
        {
            AUDIO_FORMAT_PCM_8_BIT, make_AudioFormatDescription(PcmType::UINT_8_BIT)
        },
        {
            AUDIO_FORMAT_PCM_32_BIT, make_AudioFormatDescription(PcmType::INT_32_BIT)
        },
        {
            AUDIO_FORMAT_PCM_8_24_BIT, make_AudioFormatDescription(PcmType::FIXED_Q_8_24)
        },
        {
            AUDIO_FORMAT_PCM_FLOAT, make_AudioFormatDescription(PcmType::FLOAT_32_BIT)
        },
        {
            AUDIO_FORMAT_PCM_24_BIT_PACKED, make_AudioFormatDescription(PcmType::INT_24_BIT)
        },
        {
            AUDIO_FORMAT_MP3, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_MPEG)
        },
        {
            AUDIO_FORMAT_AMR_NB, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AMR_NB)
        },
        {
            AUDIO_FORMAT_AMR_WB, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AMR_WB)
        },
        {
            AUDIO_FORMAT_AAC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_MP4)
        },
        {
            AUDIO_FORMAT_AAC_MAIN, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_MAIN)
        },
        {
            AUDIO_FORMAT_AAC_LC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_LC)
        },
        {
            AUDIO_FORMAT_AAC_SSR, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_SSR)
        },
        {
            AUDIO_FORMAT_AAC_LTP, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_LTP)
        },
        {
            AUDIO_FORMAT_AAC_HE_V1, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_HE_V1)
        },
        {
            AUDIO_FORMAT_AAC_SCALABLE,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_SCALABLE)
        },
        {
            AUDIO_FORMAT_AAC_ERLC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ERLC)
        },
        {
            AUDIO_FORMAT_AAC_LD, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_LD)
        },
        {
            AUDIO_FORMAT_AAC_HE_V2, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_HE_V2)
        },
        {
            AUDIO_FORMAT_AAC_ELD, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ELD)
        },
        {
            AUDIO_FORMAT_AAC_XHE, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_XHE)
        },
        // AUDIO_FORMAT_HE_AAC_V1 and HE_AAC_V2 are removed since they were deprecated long time
        // ago.
        {
            AUDIO_FORMAT_VORBIS, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_VORBIS)
        },
        {
            AUDIO_FORMAT_OPUS, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_OPUS)
        },
        {
            AUDIO_FORMAT_AC3, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AC3)
        },
        {
            AUDIO_FORMAT_E_AC3, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_EAC3)
        },
        {
            AUDIO_FORMAT_E_AC3_JOC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_EAC3_JOC)
        },
        {
            AUDIO_FORMAT_DTS, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DTS)
        },
        {
            AUDIO_FORMAT_DTS_HD, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DTS_HD)
        },
        // In the future, we would like to represent encapsulated bitstreams as
        // nested AudioFormatDescriptions. The legacy 'AUDIO_FORMAT_IEC61937' type doesn't
        // specify the format of the encapsulated bitstream.
        {
            AUDIO_FORMAT_IEC61937,
            make_AudioFormatDescription(PcmType::INT_16_BIT, MEDIA_MIMETYPE_AUDIO_IEC61937)
        },
        {
            AUDIO_FORMAT_DOLBY_TRUEHD,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DOLBY_TRUEHD)
        },
        {
            AUDIO_FORMAT_EVRC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_EVRC)
        },
        {
            AUDIO_FORMAT_EVRCB, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_EVRCB)
        },
        {
            AUDIO_FORMAT_EVRCWB, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_EVRCWB)
        },
        {
            AUDIO_FORMAT_EVRCNW, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_EVRCNW)
        },
        {
            AUDIO_FORMAT_AAC_ADIF, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADIF)
        },
        {
            AUDIO_FORMAT_WMA, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_WMA)
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_WMA_PRO, make_AudioFormatDescription("audio/x-ms-wma.pro")
        },
        {
            AUDIO_FORMAT_AMR_WB_PLUS, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AMR_WB_PLUS)
        },
        {
            AUDIO_FORMAT_MP2, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_II)
        },
        {
            AUDIO_FORMAT_QCELP, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_QCELP)
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_DSD, make_AudioFormatDescription("audio/vnd.sony.dsd")
        },
        {
            AUDIO_FORMAT_FLAC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_FLAC)
        },
        {
            AUDIO_FORMAT_ALAC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_ALAC)
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_APE, make_AudioFormatDescription("audio/x-ape")
        },
        {
            AUDIO_FORMAT_AAC_ADTS, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_MAIN,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_MAIN)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_LC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LC)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_SSR,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SSR)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_LTP,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LTP)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_HE_V1,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V1)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_SCALABLE,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SCALABLE)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_ERLC,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ERLC)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_LD, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LD)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_HE_V2,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V2)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_ELD,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ELD)
        },
        {
            AUDIO_FORMAT_AAC_ADTS_XHE,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_ADTS_XHE)
        },
        {
            // Note: not in the IANA registry. "vnd.octel.sbc" is not BT SBC.
            AUDIO_FORMAT_SBC, make_AudioFormatDescription("audio/x-sbc")
        },
        {
            AUDIO_FORMAT_APTX, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_APTX)
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_APTX_HD, make_AudioFormatDescription("audio/vnd.qcom.aptx.hd")
        },
        {
            AUDIO_FORMAT_AC4, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AC4)
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_LDAC, make_AudioFormatDescription("audio/vnd.sony.ldac")
        },
        {
            AUDIO_FORMAT_MAT, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DOLBY_MAT)
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_MAT_1_0,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DOLBY_MAT + std::string(".1.0"))
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_MAT_2_0,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DOLBY_MAT + std::string(".2.0"))
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_MAT_2_1,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DOLBY_MAT + std::string(".2.1"))
        },
        {
            AUDIO_FORMAT_AAC_LATM, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC)
        },
        {
            AUDIO_FORMAT_AAC_LATM_LC, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_LATM_LC)
        },
        {
            AUDIO_FORMAT_AAC_LATM_HE_V1,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V1)
        },
        {
            AUDIO_FORMAT_AAC_LATM_HE_V2,
            make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V2)
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_CELT, make_AudioFormatDescription("audio/x-celt")
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_APTX_ADAPTIVE, make_AudioFormatDescription("audio/vnd.qcom.aptx.adaptive")
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_LHDC, make_AudioFormatDescription("audio/vnd.savitech.lhdc")
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_LHDC_LL, make_AudioFormatDescription("audio/vnd.savitech.lhdc.ll")
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_APTX_TWSP, make_AudioFormatDescription("audio/vnd.qcom.aptx.twsp")
        },
        {
            // Note: not in the IANA registry.
            AUDIO_FORMAT_LC3, make_AudioFormatDescription("audio/x-lc3")
        },
        {
            AUDIO_FORMAT_MPEGH, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_MPEGH_MHM1)
        },
        {
            AUDIO_FORMAT_MPEGH_BL_L3, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L3)
        },
        {
            AUDIO_FORMAT_MPEGH_BL_L4, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L4)
        },
        {
            AUDIO_FORMAT_MPEGH_LC_L3, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L3)
        },
        {
            AUDIO_FORMAT_MPEGH_LC_L4, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L4)
        },
        {
            AUDIO_FORMAT_IEC60958,
            make_AudioFormatDescription(PcmType::INT_24_BIT, MEDIA_MIMETYPE_AUDIO_IEC60958)
        },
        {
            AUDIO_FORMAT_DTS_UHD, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DTS_UHD)
        },
        {
            AUDIO_FORMAT_DRA, make_AudioFormatDescription(MEDIA_MIMETYPE_AUDIO_DRA)
        },
    }};
    return pairs;
}

template<typename S, typename T>
std::unordered_map<S, T> make_DirectMap(const std::vector<std::pair<S, T>>& v) {
    std::unordered_map<S, T> result(v.begin(), v.end());
    LOG_ALWAYS_FATAL_IF(result.size() != v.size(), "Duplicate key elements detected");
    return result;
}

template<typename S, typename T>
std::unordered_map<S, T> make_DirectMap(
        const std::vector<std::pair<S, T>>& v1, const std::vector<std::pair<S, T>>& v2) {
    std::unordered_map<S, T> result(v1.begin(), v1.end());
    LOG_ALWAYS_FATAL_IF(result.size() != v1.size(), "Duplicate key elements detected in v1");
    result.insert(v2.begin(), v2.end());
    LOG_ALWAYS_FATAL_IF(result.size() != v1.size() + v2.size(),
            "Duplicate key elements detected in v1+v2");
    return result;
}

template<typename S, typename T>
std::unordered_map<T, S> make_ReverseMap(const std::vector<std::pair<S, T>>& v) {
    std::unordered_map<T, S> result;
    std::transform(v.begin(), v.end(), std::inserter(result, result.begin()),
            [](const std::pair<S, T>& p) {
                return std::make_pair(p.second, p.first);
            });
    LOG_ALWAYS_FATAL_IF(result.size() != v.size(), "Duplicate key elements detected");
    return result;
}

}  // namespace

audio_channel_mask_t aidl2legacy_AudioChannelLayout_layout_audio_channel_mask_t_bits(
        int aidlLayout, bool isInput) {
    auto& bitMapping = isInput ? getInAudioChannelBits() : getOutAudioChannelBits();
    const int aidlLayoutInitial = aidlLayout; // for error message
    audio_channel_mask_t legacy = AUDIO_CHANNEL_NONE;
    for (const auto& bitPair : bitMapping) {
        if ((aidlLayout & bitPair.second) == bitPair.second) {
            legacy = static_cast<audio_channel_mask_t>(legacy | bitPair.first);
            aidlLayout &= ~bitPair.second;
            if (aidlLayout == 0) {
                return legacy;
            }
        }
    }
    ALOGE("%s: aidl layout 0x%x contains bits 0x%x that have no match to legacy %s bits",
            __func__, aidlLayoutInitial, aidlLayout, isInput ? "input" : "output");
    return AUDIO_CHANNEL_NONE;
}

ConversionResult<audio_channel_mask_t> aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
        const AudioChannelLayout& aidl, bool isInput) {
    using ReverseMap = std::unordered_map<AudioChannelLayout, audio_channel_mask_t>;
    using Tag = AudioChannelLayout::Tag;
    static const ReverseMap mIn = make_ReverseMap(getInAudioChannelPairs());
    static const ReverseMap mOut = make_ReverseMap(getOutAudioChannelPairs());
    static const ReverseMap mVoice = make_ReverseMap(getVoiceAudioChannelPairs());

    auto convert = [](const AudioChannelLayout& aidl, const ReverseMap& m,
            const char* func, const char* type) -> ConversionResult<audio_channel_mask_t> {
        if (auto it = m.find(aidl); it != m.end()) {
            return it->second;
        } else {
            ALOGW("%s: no legacy %s audio_channel_mask_t found for %s", func, type,
                    aidl.toString().c_str());
            return unexpected(BAD_VALUE);
        }
    };

    switch (aidl.getTag()) {
        case Tag::none:
            return AUDIO_CHANNEL_NONE;
        case Tag::invalid:
            return AUDIO_CHANNEL_INVALID;
        case Tag::indexMask:
            // Index masks do not have pre-defined values.
            if (const int bits = aidl.get<Tag::indexMask>();
                    __builtin_popcount(bits) != 0 &&
                    __builtin_popcount(bits) <= AUDIO_CHANNEL_COUNT_MAX) {
                return audio_channel_mask_from_representation_and_bits(
                        AUDIO_CHANNEL_REPRESENTATION_INDEX, bits);
            } else {
                ALOGE("%s: invalid indexMask value 0x%x in %s",
                        __func__, bits, aidl.toString().c_str());
                return unexpected(BAD_VALUE);
            }
        case Tag::layoutMask:
            // The fast path is to find a direct match for some known layout mask.
            if (const auto layoutMatch = convert(aidl, isInput ? mIn : mOut, __func__,
                    isInput ? "input" : "output");
                    layoutMatch.ok()) {
                return layoutMatch;
            }
            // If a match for a predefined layout wasn't found, make a custom one from bits.
            if (audio_channel_mask_t bitMask =
                    aidl2legacy_AudioChannelLayout_layout_audio_channel_mask_t_bits(
                            aidl.get<Tag::layoutMask>(), isInput);
                    bitMask != AUDIO_CHANNEL_NONE) {
                return bitMask;
            }
            return unexpected(BAD_VALUE);
        case Tag::voiceMask:
            return convert(aidl, mVoice, __func__, "voice");
    }
    ALOGE("%s: unexpected tag value %d", __func__, aidl.getTag());
    return unexpected(BAD_VALUE);
}

int legacy2aidl_audio_channel_mask_t_bits_AudioChannelLayout_layout(
        audio_channel_mask_t legacy, bool isInput) {
    auto& bitMapping = isInput ? getInAudioChannelBits() : getOutAudioChannelBits();
    const int legacyInitial = legacy; // for error message
    int aidlLayout = 0;
    for (const auto& bitPair : bitMapping) {
        if ((legacy & bitPair.first) == bitPair.first) {
            aidlLayout |= bitPair.second;
            legacy = static_cast<audio_channel_mask_t>(legacy & ~bitPair.first);
            if (legacy == 0) {
                return aidlLayout;
            }
        }
    }
    ALOGE("%s: legacy %s audio_channel_mask_t 0x%x contains unrecognized bits 0x%x",
            __func__, isInput ? "input" : "output", legacyInitial, legacy);
    return 0;
}

ConversionResult<AudioChannelLayout> legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
        audio_channel_mask_t legacy, bool isInput) {
    using DirectMap = std::unordered_map<audio_channel_mask_t, AudioChannelLayout>;
    using Tag = AudioChannelLayout::Tag;
    static const DirectMap mInAndVoice = make_DirectMap(
            getInAudioChannelPairs(), getVoiceAudioChannelPairs());
    static const DirectMap mOut = make_DirectMap(getOutAudioChannelPairs());

    auto convert = [](const audio_channel_mask_t legacy, const DirectMap& m,
            const char* func, const char* type) -> ConversionResult<AudioChannelLayout> {
        if (auto it = m.find(legacy); it != m.end()) {
            return it->second;
        } else {
            ALOGW("%s: no AudioChannelLayout found for legacy %s audio_channel_mask_t value 0x%x",
                    func, type, legacy);
            return unexpected(BAD_VALUE);
        }
    };

    if (legacy == AUDIO_CHANNEL_NONE) {
        return AudioChannelLayout{};
    } else if (legacy == AUDIO_CHANNEL_INVALID) {
        return AudioChannelLayout::make<Tag::invalid>(0);
    }

    const audio_channel_representation_t repr = audio_channel_mask_get_representation(legacy);
    if (repr == AUDIO_CHANNEL_REPRESENTATION_INDEX) {
        if (audio_channel_mask_is_valid(legacy)) {
            const int indexMask = VALUE_OR_RETURN(
                    convertIntegral<int>(audio_channel_mask_get_bits(legacy)));
            return AudioChannelLayout::make<Tag::indexMask>(indexMask);
        } else {
            ALOGE("%s: legacy audio_channel_mask_t value 0x%x is invalid", __func__, legacy);
            return unexpected(BAD_VALUE);
        }
    } else if (repr == AUDIO_CHANNEL_REPRESENTATION_POSITION) {
        // The fast path is to find a direct match for some known layout mask.
        if (const auto layoutMatch = convert(legacy, isInput ? mInAndVoice : mOut, __func__,
                isInput ? "input / voice" : "output");
                layoutMatch.ok()) {
            return layoutMatch;
        }
        // If a match for a predefined layout wasn't found, make a custom one from bits,
        // rejecting those with voice channel bits.
        if (!isInput ||
                (legacy & (AUDIO_CHANNEL_IN_VOICE_UPLINK | AUDIO_CHANNEL_IN_VOICE_DNLINK)) == 0) {
            if (int bitMaskLayout =
                    legacy2aidl_audio_channel_mask_t_bits_AudioChannelLayout_layout(
                            legacy, isInput);
                    bitMaskLayout != 0) {
                return AudioChannelLayout::make<Tag::layoutMask>(bitMaskLayout);
            }
        } else {
            ALOGE("%s: legacy audio_channel_mask_t value 0x%x contains voice bits",
                    __func__, legacy);
        }
        return unexpected(BAD_VALUE);
    }

    ALOGE("%s: unknown representation %d in audio_channel_mask_t value 0x%x",
            __func__, repr, legacy);
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_devices_t> aidl2legacy_AudioDeviceDescription_audio_devices_t(
        const AudioDeviceDescription& aidl) {
    static const std::unordered_map<AudioDeviceDescription, audio_devices_t> m =
            make_ReverseMap(getAudioDevicePairs());
    if (auto it = m.find(aidl); it != m.end()) {
        return it->second;
    } else {
        ALOGE("%s: no legacy audio_devices_t found for %s", __func__, aidl.toString().c_str());
        return unexpected(BAD_VALUE);
    }
}

ConversionResult<AudioDeviceDescription> legacy2aidl_audio_devices_t_AudioDeviceDescription(
        audio_devices_t legacy) {
    static const std::unordered_map<audio_devices_t, AudioDeviceDescription> m =
            make_DirectMap(getAudioDevicePairs());
    if (auto it = m.find(legacy); it != m.end()) {
        return it->second;
    } else {
        ALOGE("%s: no AudioDeviceDescription found for legacy audio_devices_t value 0x%x",
                __func__, legacy);
        return unexpected(BAD_VALUE);
    }
}

status_t aidl2legacy_AudioDevice_audio_device(
        const AudioDevice& aidl,
        audio_devices_t* legacyType, char* legacyAddress) {
    *legacyType = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(aidl.type));
    return aidl2legacy_string(
                    aidl.address.get<AudioDeviceAddress::id>(),
                    legacyAddress, AUDIO_DEVICE_MAX_ADDRESS_LEN);
}

status_t aidl2legacy_AudioDevice_audio_device(
        const AudioDevice& aidl,
        audio_devices_t* legacyType, String8* legacyAddress) {
    *legacyType = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(aidl.type));
    *legacyAddress = VALUE_OR_RETURN_STATUS(aidl2legacy_string_view_String8(
                    aidl.address.get<AudioDeviceAddress::id>()));
    return OK;
}

status_t aidl2legacy_AudioDevice_audio_device(
        const AudioDevice& aidl,
        audio_devices_t* legacyType, std::string* legacyAddress) {
    *legacyType = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(aidl.type));
    *legacyAddress = aidl.address.get<AudioDeviceAddress::id>();
    return OK;
}

ConversionResult<AudioDevice> legacy2aidl_audio_device_AudioDevice(
        audio_devices_t legacyType, const char* legacyAddress) {
    AudioDevice aidl;
    aidl.type = VALUE_OR_RETURN(
            legacy2aidl_audio_devices_t_AudioDeviceDescription(legacyType));
    const std::string aidl_id = VALUE_OR_RETURN(
            legacy2aidl_string(legacyAddress, AUDIO_DEVICE_MAX_ADDRESS_LEN));
    aidl.address = AudioDeviceAddress::make<AudioDeviceAddress::id>(aidl_id);
    return aidl;
}

ConversionResult<AudioDevice>
legacy2aidl_audio_device_AudioDevice(
        audio_devices_t legacyType, const String8& legacyAddress) {
    AudioDevice aidl;
    aidl.type = VALUE_OR_RETURN(
            legacy2aidl_audio_devices_t_AudioDeviceDescription(legacyType));
    const std::string aidl_id = VALUE_OR_RETURN(
            legacy2aidl_String8_string(legacyAddress));
    aidl.address = AudioDeviceAddress::make<AudioDeviceAddress::id>(aidl_id);
    return aidl;
}

ConversionResult<audio_format_t> aidl2legacy_AudioFormatDescription_audio_format_t(
        const AudioFormatDescription& aidl) {
    static const std::unordered_map<AudioFormatDescription, audio_format_t> m =
            make_ReverseMap(getAudioFormatPairs());
    if (auto it = m.find(aidl); it != m.end()) {
        return it->second;
    } else {
        ALOGE("%s: no legacy audio_format_t found for %s", __func__, aidl.toString().c_str());
        return unexpected(BAD_VALUE);
    }
}

ConversionResult<AudioFormatDescription> legacy2aidl_audio_format_t_AudioFormatDescription(
        audio_format_t legacy) {
    static const std::unordered_map<audio_format_t, AudioFormatDescription> m =
            make_DirectMap(getAudioFormatPairs());
    if (auto it = m.find(legacy); it != m.end()) {
        return it->second;
    } else {
        ALOGE("%s: no AudioFormatDescription found for legacy audio_format_t value 0x%x",
                __func__, legacy);
        return unexpected(BAD_VALUE);
    }
}

ConversionResult<audio_gain_mode_t> aidl2legacy_AudioGainMode_audio_gain_mode_t(
        AudioGainMode aidl) {
    switch (aidl) {
        case AudioGainMode::JOINT:
            return AUDIO_GAIN_MODE_JOINT;
        case AudioGainMode::CHANNELS:
            return AUDIO_GAIN_MODE_CHANNELS;
        case AudioGainMode::RAMP:
            return AUDIO_GAIN_MODE_RAMP;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioGainMode> legacy2aidl_audio_gain_mode_t_AudioGainMode(
        audio_gain_mode_t legacy) {
    switch (legacy) {
        case AUDIO_GAIN_MODE_JOINT:
            return AudioGainMode::JOINT;
        case AUDIO_GAIN_MODE_CHANNELS:
            return AudioGainMode::CHANNELS;
        case AUDIO_GAIN_MODE_RAMP:
            return AudioGainMode::RAMP;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_gain_mode_t> aidl2legacy_int32_t_audio_gain_mode_t_mask(int32_t aidl) {
    return convertBitmask<audio_gain_mode_t, int32_t, audio_gain_mode_t, AudioGainMode>(
            aidl, aidl2legacy_AudioGainMode_audio_gain_mode_t,
            // AudioGainMode is index-based.
            indexToEnum_index<AudioGainMode>,
            // AUDIO_GAIN_MODE_* constants are mask-based.
            enumToMask_bitmask<audio_gain_mode_t, audio_gain_mode_t>);
}

ConversionResult<int32_t> legacy2aidl_audio_gain_mode_t_int32_t_mask(audio_gain_mode_t legacy) {
    return convertBitmask<int32_t, audio_gain_mode_t, AudioGainMode, audio_gain_mode_t>(
            legacy, legacy2aidl_audio_gain_mode_t_AudioGainMode,
            // AUDIO_GAIN_MODE_* constants are mask-based.
            indexToEnum_bitmask<audio_gain_mode_t>,
            // AudioGainMode is index-based.
            enumToMask_index<int32_t, AudioGainMode>);
}

ConversionResult<audio_gain_config> aidl2legacy_AudioGainConfig_audio_gain_config(
        const AudioGainConfig& aidl, bool isInput) {
    audio_gain_config legacy;
    legacy.index = VALUE_OR_RETURN(convertIntegral<int>(aidl.index));
    legacy.mode = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_gain_mode_t_mask(aidl.mode));
    legacy.channel_mask = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.channelMask, isInput));
    const bool isJoint = bitmaskIsSet(aidl.mode, AudioGainMode::JOINT);
    size_t numValues = isJoint ? 1
                               : isInput ? audio_channel_count_from_in_mask(legacy.channel_mask)
                                         : audio_channel_count_from_out_mask(legacy.channel_mask);
    if (aidl.values.size() != numValues || aidl.values.size() > std::size(legacy.values)) {
        return unexpected(BAD_VALUE);
    }
    for (size_t i = 0; i < numValues; ++i) {
        legacy.values[i] = VALUE_OR_RETURN(convertIntegral<int>(aidl.values[i]));
    }
    legacy.ramp_duration_ms = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.rampDurationMs));
    return legacy;
}

ConversionResult<AudioGainConfig> legacy2aidl_audio_gain_config_AudioGainConfig(
        const audio_gain_config& legacy, bool isInput) {
    AudioGainConfig aidl;
    aidl.index = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.index));
    aidl.mode = VALUE_OR_RETURN(legacy2aidl_audio_gain_mode_t_int32_t_mask(legacy.mode));
    aidl.channelMask = VALUE_OR_RETURN(
            legacy2aidl_audio_channel_mask_t_AudioChannelLayout(legacy.channel_mask, isInput));
    const bool isJoint = (legacy.mode & AUDIO_GAIN_MODE_JOINT) != 0;
    size_t numValues = isJoint ? 1
                               : isInput ? audio_channel_count_from_in_mask(legacy.channel_mask)
                                         : audio_channel_count_from_out_mask(legacy.channel_mask);
    aidl.values.resize(numValues);
    for (size_t i = 0; i < numValues; ++i) {
        aidl.values[i] = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.values[i]));
    }
    aidl.rampDurationMs = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.ramp_duration_ms));
    return aidl;
}

ConversionResult<audio_input_flags_t> aidl2legacy_AudioInputFlags_audio_input_flags_t(
        AudioInputFlags aidl) {
    switch (aidl) {
        case AudioInputFlags::FAST:
            return AUDIO_INPUT_FLAG_FAST;
        case AudioInputFlags::HW_HOTWORD:
            return AUDIO_INPUT_FLAG_HW_HOTWORD;
        case AudioInputFlags::RAW:
            return AUDIO_INPUT_FLAG_RAW;
        case AudioInputFlags::SYNC:
            return AUDIO_INPUT_FLAG_SYNC;
        case AudioInputFlags::MMAP_NOIRQ:
            return AUDIO_INPUT_FLAG_MMAP_NOIRQ;
        case AudioInputFlags::VOIP_TX:
            return AUDIO_INPUT_FLAG_VOIP_TX;
        case AudioInputFlags::HW_AV_SYNC:
            return AUDIO_INPUT_FLAG_HW_AV_SYNC;
        case AudioInputFlags::DIRECT:
            return AUDIO_INPUT_FLAG_DIRECT;
        case AudioInputFlags::ULTRASOUND:
            return AUDIO_INPUT_FLAG_ULTRASOUND;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioInputFlags> legacy2aidl_audio_input_flags_t_AudioInputFlags(
        audio_input_flags_t legacy) {
    switch (legacy) {
        case AUDIO_INPUT_FLAG_NONE:
            break; // shouldn't get here. must be listed  -Werror,-Wswitch
        case AUDIO_INPUT_FLAG_FAST:
            return AudioInputFlags::FAST;
        case AUDIO_INPUT_FLAG_HW_HOTWORD:
            return AudioInputFlags::HW_HOTWORD;
        case AUDIO_INPUT_FLAG_RAW:
            return AudioInputFlags::RAW;
        case AUDIO_INPUT_FLAG_SYNC:
            return AudioInputFlags::SYNC;
        case AUDIO_INPUT_FLAG_MMAP_NOIRQ:
            return AudioInputFlags::MMAP_NOIRQ;
        case AUDIO_INPUT_FLAG_VOIP_TX:
            return AudioInputFlags::VOIP_TX;
        case AUDIO_INPUT_FLAG_HW_AV_SYNC:
            return AudioInputFlags::HW_AV_SYNC;
        case AUDIO_INPUT_FLAG_DIRECT:
            return AudioInputFlags::DIRECT;
        case AUDIO_INPUT_FLAG_ULTRASOUND:
            return AudioInputFlags::ULTRASOUND;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_output_flags_t> aidl2legacy_AudioOutputFlags_audio_output_flags_t(
        AudioOutputFlags aidl) {
    switch (aidl) {
        case AudioOutputFlags::DIRECT:
            return AUDIO_OUTPUT_FLAG_DIRECT;
        case AudioOutputFlags::PRIMARY:
            return AUDIO_OUTPUT_FLAG_PRIMARY;
        case AudioOutputFlags::FAST:
            return AUDIO_OUTPUT_FLAG_FAST;
        case AudioOutputFlags::DEEP_BUFFER:
            return AUDIO_OUTPUT_FLAG_DEEP_BUFFER;
        case AudioOutputFlags::COMPRESS_OFFLOAD:
            return AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD;
        case AudioOutputFlags::NON_BLOCKING:
            return AUDIO_OUTPUT_FLAG_NON_BLOCKING;
        case AudioOutputFlags::HW_AV_SYNC:
            return AUDIO_OUTPUT_FLAG_HW_AV_SYNC;
        case AudioOutputFlags::TTS:
            return AUDIO_OUTPUT_FLAG_TTS;
        case AudioOutputFlags::RAW:
            return AUDIO_OUTPUT_FLAG_RAW;
        case AudioOutputFlags::SYNC:
            return AUDIO_OUTPUT_FLAG_SYNC;
        case AudioOutputFlags::IEC958_NONAUDIO:
            return AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO;
        case AudioOutputFlags::DIRECT_PCM:
            return AUDIO_OUTPUT_FLAG_DIRECT_PCM;
        case AudioOutputFlags::MMAP_NOIRQ:
            return AUDIO_OUTPUT_FLAG_MMAP_NOIRQ;
        case AudioOutputFlags::VOIP_RX:
            return AUDIO_OUTPUT_FLAG_VOIP_RX;
        case AudioOutputFlags::INCALL_MUSIC:
            return AUDIO_OUTPUT_FLAG_INCALL_MUSIC;
        case AudioOutputFlags::GAPLESS_OFFLOAD:
            return AUDIO_OUTPUT_FLAG_GAPLESS_OFFLOAD;
        case AudioOutputFlags::ULTRASOUND:
            return AUDIO_OUTPUT_FLAG_ULTRASOUND;
        case AudioOutputFlags::SPATIALIZER:
            return AUDIO_OUTPUT_FLAG_SPATIALIZER;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioOutputFlags> legacy2aidl_audio_output_flags_t_AudioOutputFlags(
        audio_output_flags_t legacy) {
    switch (legacy) {
        case AUDIO_OUTPUT_FLAG_NONE:
            break; // shouldn't get here. must be listed  -Werror,-Wswitch
        case AUDIO_OUTPUT_FLAG_DIRECT:
            return AudioOutputFlags::DIRECT;
        case AUDIO_OUTPUT_FLAG_PRIMARY:
            return AudioOutputFlags::PRIMARY;
        case AUDIO_OUTPUT_FLAG_FAST:
            return AudioOutputFlags::FAST;
        case AUDIO_OUTPUT_FLAG_DEEP_BUFFER:
            return AudioOutputFlags::DEEP_BUFFER;
        case AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD:
            return AudioOutputFlags::COMPRESS_OFFLOAD;
        case AUDIO_OUTPUT_FLAG_NON_BLOCKING:
            return AudioOutputFlags::NON_BLOCKING;
        case AUDIO_OUTPUT_FLAG_HW_AV_SYNC:
            return AudioOutputFlags::HW_AV_SYNC;
        case AUDIO_OUTPUT_FLAG_TTS:
            return AudioOutputFlags::TTS;
        case AUDIO_OUTPUT_FLAG_RAW:
            return AudioOutputFlags::RAW;
        case AUDIO_OUTPUT_FLAG_SYNC:
            return AudioOutputFlags::SYNC;
        case AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO:
            return AudioOutputFlags::IEC958_NONAUDIO;
        case AUDIO_OUTPUT_FLAG_DIRECT_PCM:
            return AudioOutputFlags::DIRECT_PCM;
        case AUDIO_OUTPUT_FLAG_MMAP_NOIRQ:
            return AudioOutputFlags::MMAP_NOIRQ;
        case AUDIO_OUTPUT_FLAG_VOIP_RX:
            return AudioOutputFlags::VOIP_RX;
        case AUDIO_OUTPUT_FLAG_INCALL_MUSIC:
            return AudioOutputFlags::INCALL_MUSIC;
        case AUDIO_OUTPUT_FLAG_GAPLESS_OFFLOAD:
            return AudioOutputFlags::GAPLESS_OFFLOAD;
        case AUDIO_OUTPUT_FLAG_ULTRASOUND:
            return AudioOutputFlags::ULTRASOUND;
        case AUDIO_OUTPUT_FLAG_SPATIALIZER:
            return AudioOutputFlags::SPATIALIZER;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_input_flags_t> aidl2legacy_int32_t_audio_input_flags_t_mask(
        int32_t aidl) {
    using LegacyMask = std::underlying_type_t<audio_input_flags_t>;

    LegacyMask converted = VALUE_OR_RETURN(
            (convertBitmask<LegacyMask, int32_t, audio_input_flags_t, AudioInputFlags>(
                    aidl, aidl2legacy_AudioInputFlags_audio_input_flags_t,
                    indexToEnum_index<AudioInputFlags>,
                    enumToMask_bitmask<LegacyMask, audio_input_flags_t>)));
    return static_cast<audio_input_flags_t>(converted);
}

ConversionResult<int32_t> legacy2aidl_audio_input_flags_t_int32_t_mask(
        audio_input_flags_t legacy) {
    using LegacyMask = std::underlying_type_t<audio_input_flags_t>;

    LegacyMask legacyMask = static_cast<LegacyMask>(legacy);
    return convertBitmask<int32_t, LegacyMask, AudioInputFlags, audio_input_flags_t>(
            legacyMask, legacy2aidl_audio_input_flags_t_AudioInputFlags,
            indexToEnum_bitmask<audio_input_flags_t>,
            enumToMask_index<int32_t, AudioInputFlags>);
}

ConversionResult<audio_output_flags_t> aidl2legacy_int32_t_audio_output_flags_t_mask(
        int32_t aidl) {
    return convertBitmask<audio_output_flags_t,
            int32_t,
            audio_output_flags_t,
            AudioOutputFlags>(
            aidl, aidl2legacy_AudioOutputFlags_audio_output_flags_t,
            indexToEnum_index<AudioOutputFlags>,
            enumToMask_bitmask<audio_output_flags_t, audio_output_flags_t>);
}

ConversionResult<int32_t> legacy2aidl_audio_output_flags_t_int32_t_mask(
        audio_output_flags_t legacy) {
    using LegacyMask = std::underlying_type_t<audio_output_flags_t>;

    LegacyMask legacyMask = static_cast<LegacyMask>(legacy);
    return convertBitmask<int32_t, LegacyMask, AudioOutputFlags, audio_output_flags_t>(
            legacyMask, legacy2aidl_audio_output_flags_t_AudioOutputFlags,
            indexToEnum_bitmask<audio_output_flags_t>,
            enumToMask_index<int32_t, AudioOutputFlags>);
}

ConversionResult<audio_io_flags> aidl2legacy_AudioIoFlags_audio_io_flags(
        const AudioIoFlags& aidl, bool isInput) {
    audio_io_flags legacy;
    if (isInput) {
        legacy.input = VALUE_OR_RETURN(
                aidl2legacy_int32_t_audio_input_flags_t_mask(
                        VALUE_OR_RETURN(UNION_GET(aidl, input))));
    } else {
        legacy.output = VALUE_OR_RETURN(
                aidl2legacy_int32_t_audio_output_flags_t_mask(
                        VALUE_OR_RETURN(UNION_GET(aidl, output))));
    }
    return legacy;
}

ConversionResult<AudioIoFlags> legacy2aidl_audio_io_flags_AudioIoFlags(
        const audio_io_flags& legacy, bool isInput) {
    AudioIoFlags aidl;
    if (isInput) {
        UNION_SET(aidl, input,
                VALUE_OR_RETURN(legacy2aidl_audio_input_flags_t_int32_t_mask(legacy.input)));
    } else {
        UNION_SET(aidl, output,
                VALUE_OR_RETURN(legacy2aidl_audio_output_flags_t_int32_t_mask(legacy.output)));
    }
    return aidl;
}

ConversionResult<audio_port_config_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(
        const AudioPortDeviceExt& aidl, const media::AudioPortDeviceExtSys& aidlDeviceExt) {
    audio_port_config_device_ext legacy;
    legacy.hw_module = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_module_handle_t(aidlDeviceExt.hwModule));
    RETURN_IF_ERROR(aidl2legacy_AudioDevice_audio_device(
                    aidl.device, &legacy.type, legacy.address));
    return legacy;
}

status_t legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(
        const audio_port_config_device_ext& legacy,
        AudioPortDeviceExt* aidl, media::AudioPortDeviceExtSys* aidlDeviceExt) {
    aidlDeviceExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    aidl->device = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_device_AudioDevice(legacy.type, legacy.address));
    return OK;
}

ConversionResult<audio_stream_type_t> aidl2legacy_AudioStreamType_audio_stream_type_t(
        AudioStreamType aidl) {
    switch (aidl) {
        case AudioStreamType::INVALID:
            break;  // return error
        case AudioStreamType::SYS_RESERVED_DEFAULT:
            return AUDIO_STREAM_DEFAULT;
        case AudioStreamType::VOICE_CALL:
            return AUDIO_STREAM_VOICE_CALL;
        case AudioStreamType::SYSTEM:
            return AUDIO_STREAM_SYSTEM;
        case AudioStreamType::RING:
            return AUDIO_STREAM_RING;
        case AudioStreamType::MUSIC:
            return AUDIO_STREAM_MUSIC;
        case AudioStreamType::ALARM:
            return AUDIO_STREAM_ALARM;
        case AudioStreamType::NOTIFICATION:
            return AUDIO_STREAM_NOTIFICATION;
        case AudioStreamType::BLUETOOTH_SCO:
            return AUDIO_STREAM_BLUETOOTH_SCO;
        case AudioStreamType::ENFORCED_AUDIBLE:
            return AUDIO_STREAM_ENFORCED_AUDIBLE;
        case AudioStreamType::DTMF:
            return AUDIO_STREAM_DTMF;
        case AudioStreamType::TTS:
            return AUDIO_STREAM_TTS;
        case AudioStreamType::ACCESSIBILITY:
            return AUDIO_STREAM_ACCESSIBILITY;
        case AudioStreamType::ASSISTANT:
            return AUDIO_STREAM_ASSISTANT;
        case AudioStreamType::SYS_RESERVED_REROUTING:
            return AUDIO_STREAM_REROUTING;
        case AudioStreamType::SYS_RESERVED_PATCH:
            return AUDIO_STREAM_PATCH;
        case AudioStreamType::CALL_ASSISTANT:
            return AUDIO_STREAM_CALL_ASSISTANT;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioStreamType> legacy2aidl_audio_stream_type_t_AudioStreamType(
        audio_stream_type_t legacy) {
    switch (legacy) {
        case AUDIO_STREAM_DEFAULT:
            return AudioStreamType::SYS_RESERVED_DEFAULT;
        case AUDIO_STREAM_VOICE_CALL:
            return AudioStreamType::VOICE_CALL;
        case AUDIO_STREAM_SYSTEM:
            return AudioStreamType::SYSTEM;
        case AUDIO_STREAM_RING:
            return AudioStreamType::RING;
        case AUDIO_STREAM_MUSIC:
            return AudioStreamType::MUSIC;
        case AUDIO_STREAM_ALARM:
            return AudioStreamType::ALARM;
        case AUDIO_STREAM_NOTIFICATION:
            return AudioStreamType::NOTIFICATION;
        case AUDIO_STREAM_BLUETOOTH_SCO:
            return AudioStreamType::BLUETOOTH_SCO;
        case AUDIO_STREAM_ENFORCED_AUDIBLE:
            return AudioStreamType::ENFORCED_AUDIBLE;
        case AUDIO_STREAM_DTMF:
            return AudioStreamType::DTMF;
        case AUDIO_STREAM_TTS:
            return AudioStreamType::TTS;
        case AUDIO_STREAM_ACCESSIBILITY:
            return AudioStreamType::ACCESSIBILITY;
        case AUDIO_STREAM_ASSISTANT:
            return AudioStreamType::ASSISTANT;
        case AUDIO_STREAM_REROUTING:
            return AudioStreamType::SYS_RESERVED_REROUTING;
        case AUDIO_STREAM_PATCH:
            return AudioStreamType::SYS_RESERVED_PATCH;
        case AUDIO_STREAM_CALL_ASSISTANT:
            return AudioStreamType::CALL_ASSISTANT;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_source_t> aidl2legacy_AudioSource_audio_source_t(
        AudioSource aidl) {
    switch (aidl) {
        case AudioSource::SYS_RESERVED_INVALID:
            return AUDIO_SOURCE_INVALID;
        case AudioSource::DEFAULT:
            return AUDIO_SOURCE_DEFAULT;
        case AudioSource::MIC:
            return AUDIO_SOURCE_MIC;
        case AudioSource::VOICE_UPLINK:
            return AUDIO_SOURCE_VOICE_UPLINK;
        case AudioSource::VOICE_DOWNLINK:
            return AUDIO_SOURCE_VOICE_DOWNLINK;
        case AudioSource::VOICE_CALL:
            return AUDIO_SOURCE_VOICE_CALL;
        case AudioSource::CAMCORDER:
            return AUDIO_SOURCE_CAMCORDER;
        case AudioSource::VOICE_RECOGNITION:
            return AUDIO_SOURCE_VOICE_RECOGNITION;
        case AudioSource::VOICE_COMMUNICATION:
            return AUDIO_SOURCE_VOICE_COMMUNICATION;
        case AudioSource::REMOTE_SUBMIX:
            return AUDIO_SOURCE_REMOTE_SUBMIX;
        case AudioSource::UNPROCESSED:
            return AUDIO_SOURCE_UNPROCESSED;
        case AudioSource::VOICE_PERFORMANCE:
            return AUDIO_SOURCE_VOICE_PERFORMANCE;
        case AudioSource::ULTRASOUND:
            return AUDIO_SOURCE_ULTRASOUND;
        case AudioSource::ECHO_REFERENCE:
            return AUDIO_SOURCE_ECHO_REFERENCE;
        case AudioSource::FM_TUNER:
            return AUDIO_SOURCE_FM_TUNER;
        case AudioSource::HOTWORD:
            return AUDIO_SOURCE_HOTWORD;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioSource> legacy2aidl_audio_source_t_AudioSource(
        audio_source_t legacy) {
    switch (legacy) {
        case AUDIO_SOURCE_INVALID:
            return AudioSource::SYS_RESERVED_INVALID;
        case AUDIO_SOURCE_DEFAULT:
            return AudioSource::DEFAULT;
        case AUDIO_SOURCE_MIC:
            return AudioSource::MIC;
        case AUDIO_SOURCE_VOICE_UPLINK:
            return AudioSource::VOICE_UPLINK;
        case AUDIO_SOURCE_VOICE_DOWNLINK:
            return AudioSource::VOICE_DOWNLINK;
        case AUDIO_SOURCE_VOICE_CALL:
            return AudioSource::VOICE_CALL;
        case AUDIO_SOURCE_CAMCORDER:
            return AudioSource::CAMCORDER;
        case AUDIO_SOURCE_VOICE_RECOGNITION:
            return AudioSource::VOICE_RECOGNITION;
        case AUDIO_SOURCE_VOICE_COMMUNICATION:
            return AudioSource::VOICE_COMMUNICATION;
        case AUDIO_SOURCE_REMOTE_SUBMIX:
            return AudioSource::REMOTE_SUBMIX;
        case AUDIO_SOURCE_UNPROCESSED:
            return AudioSource::UNPROCESSED;
        case AUDIO_SOURCE_VOICE_PERFORMANCE:
            return AudioSource::VOICE_PERFORMANCE;
        case AUDIO_SOURCE_ULTRASOUND:
            return AudioSource::ULTRASOUND;
        case AUDIO_SOURCE_ECHO_REFERENCE:
            return AudioSource::ECHO_REFERENCE;
        case AUDIO_SOURCE_FM_TUNER:
            return AudioSource::FM_TUNER;
        case AUDIO_SOURCE_HOTWORD:
            return AudioSource::HOTWORD;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_session_t> aidl2legacy_int32_t_audio_session_t(int32_t aidl) {
    return convertReinterpret<audio_session_t>(aidl);
}

ConversionResult<int32_t> legacy2aidl_audio_session_t_int32_t(audio_session_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

// This type is unnamed in the original definition, thus we name it here.
using audio_port_config_mix_ext_usecase = decltype(audio_port_config_mix_ext::usecase);

ConversionResult<audio_port_config_mix_ext_usecase> aidl2legacy_AudioPortMixExtUseCase(
        const AudioPortMixExtUseCase& aidl, media::AudioPortRole role) {
    audio_port_config_mix_ext_usecase legacy;

    switch (role) {
        case media::AudioPortRole::NONE:
            // Just verify that the union is empty.
            VALUE_OR_RETURN(UNION_GET(aidl, unspecified));
            return legacy;

        case media::AudioPortRole::SOURCE:
            // This is not a bug. A SOURCE role corresponds to the stream field.
            legacy.stream = VALUE_OR_RETURN(aidl2legacy_AudioStreamType_audio_stream_type_t(
                    VALUE_OR_RETURN(UNION_GET(aidl, stream))));
            return legacy;

        case media::AudioPortRole::SINK:
            // This is not a bug. A SINK role corresponds to the source field.
            legacy.source = VALUE_OR_RETURN(aidl2legacy_AudioSource_audio_source_t(
                    VALUE_OR_RETURN(UNION_GET(aidl, source))));
            return legacy;
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<AudioPortMixExtUseCase> legacy2aidl_AudioPortMixExtUseCase(
        const audio_port_config_mix_ext_usecase& legacy, audio_port_role_t role) {
    AudioPortMixExtUseCase aidl;

    switch (role) {
        case AUDIO_PORT_ROLE_NONE:
            UNION_SET(aidl, unspecified, false);
            return aidl;
        case AUDIO_PORT_ROLE_SOURCE:
            // This is not a bug. A SOURCE role corresponds to the stream field.
            UNION_SET(aidl, stream, VALUE_OR_RETURN(
                    legacy2aidl_audio_stream_type_t_AudioStreamType(legacy.stream)));
            return aidl;
        case AUDIO_PORT_ROLE_SINK:
            // This is not a bug. A SINK role corresponds to the source field.
            UNION_SET(aidl, source,
                      VALUE_OR_RETURN(legacy2aidl_audio_source_t_AudioSource(legacy.source)));
            return aidl;
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<audio_port_config_mix_ext> aidl2legacy_AudioPortMixExt(
        const AudioPortMixExt& aidl, media::AudioPortRole role,
        const media::AudioPortMixExtSys& aidlMixExt) {
    audio_port_config_mix_ext legacy;
    legacy.hw_module = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_module_handle_t(aidlMixExt.hwModule));
    legacy.handle = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_io_handle_t(aidl.handle));
    legacy.usecase = VALUE_OR_RETURN(aidl2legacy_AudioPortMixExtUseCase(aidl.usecase, role));
    return legacy;
}

status_t legacy2aidl_AudioPortMixExt(
        const audio_port_config_mix_ext& legacy, audio_port_role_t role,
        AudioPortMixExt* aidl, media::AudioPortMixExtSys* aidlMixExt) {
    aidlMixExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    aidl->handle = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(legacy.handle));
    aidl->usecase = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioPortMixExtUseCase(legacy.usecase, role));
    return OK;
}

ConversionResult<audio_port_config_session_ext>
aidl2legacy_int32_t_audio_port_config_session_ext(int32_t aidl) {
    audio_port_config_session_ext legacy;
    legacy.session = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl));
    return legacy;
}

ConversionResult<int32_t>
legacy2aidl_audio_port_config_session_ext_int32_t(
        const audio_port_config_session_ext& legacy) {
    return legacy2aidl_audio_session_t_int32_t(legacy.session);
}

// This type is unnamed in the original definition, thus we name it here.
using audio_port_config_ext = decltype(audio_port_config::ext);

ConversionResult<audio_port_config_ext> aidl2legacy_AudioPortExt_audio_port_config_ext(
        const AudioPortExt& aidl, media::AudioPortType type,
        media::AudioPortRole role, const media::AudioPortExtSys& aidlSys) {
    audio_port_config_ext legacy;
    switch (type) {
        case media::AudioPortType::NONE:
            // Just verify that the union is empty.
            VALUE_OR_RETURN(UNION_GET(aidl, unspecified));
            return legacy;
        case media::AudioPortType::DEVICE:
            legacy.device = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, device)),
                            VALUE_OR_RETURN(UNION_GET(aidlSys, device))));
            return legacy;
        case media::AudioPortType::MIX:
            legacy.mix = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortMixExt(
                            VALUE_OR_RETURN(UNION_GET(aidl, mix)), role,
                            VALUE_OR_RETURN(UNION_GET(aidlSys, mix))));
            return legacy;
        case media::AudioPortType::SESSION:
            legacy.session = VALUE_OR_RETURN(
                    aidl2legacy_int32_t_audio_port_config_session_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, session))));
            return legacy;

    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

status_t legacy2aidl_AudioPortExt(
        const audio_port_config_ext& legacy, audio_port_type_t type, audio_port_role_t role,
        AudioPortExt* aidl, media::AudioPortExtSys* aidlSys) {
    switch (type) {
        case AUDIO_PORT_TYPE_NONE:
            UNION_SET(*aidl, unspecified, false);
            UNION_SET(*aidlSys, unspecified, false);
            return OK;
        case AUDIO_PORT_TYPE_DEVICE: {
            AudioPortDeviceExt device;
            media::AudioPortDeviceExtSys deviceSys;
            RETURN_STATUS_IF_ERROR(
                    legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(
                            legacy.device, &device, &deviceSys));
            UNION_SET(*aidl, device, device);
            UNION_SET(*aidlSys, device, deviceSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_MIX: {
            AudioPortMixExt mix;
            media::AudioPortMixExtSys mixSys;
            RETURN_STATUS_IF_ERROR(legacy2aidl_AudioPortMixExt(legacy.mix, role, &mix, &mixSys));
            UNION_SET(*aidl, mix, mix);
            UNION_SET(*aidlSys, mix, mixSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_SESSION:
            UNION_SET(*aidl, session, VALUE_OR_RETURN_STATUS(
                            legacy2aidl_audio_port_config_session_ext_int32_t(legacy.session)));
            UNION_SET(*aidlSys, unspecified, false);
            return OK;
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<audio_port_config> aidl2legacy_AudioPortConfig_audio_port_config(
        const media::AudioPortConfig& aidl) {
    audio_port_config legacy{};
    legacy.id = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_port_handle_t(aidl.hal.id));
    legacy.role = VALUE_OR_RETURN(aidl2legacy_AudioPortRole_audio_port_role_t(aidl.sys.role));
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioPortType_audio_port_type_t(aidl.sys.type));
    const bool isInput =
            VALUE_OR_RETURN(direction(aidl.sys.role, aidl.sys.type)) == Direction::INPUT;
    if (aidl.hal.sampleRate.has_value()) {
        legacy.sample_rate = VALUE_OR_RETURN(
                convertIntegral<unsigned int>(aidl.hal.sampleRate.value().value));
        legacy.config_mask |= AUDIO_PORT_CONFIG_SAMPLE_RATE;
    }
    if (aidl.hal.channelMask.has_value()) {
        legacy.channel_mask =
                VALUE_OR_RETURN(
                        aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
                                aidl.hal.channelMask.value(), isInput));
        legacy.config_mask |= AUDIO_PORT_CONFIG_CHANNEL_MASK;
    }
    if (aidl.hal.format.has_value()) {
        legacy.format = VALUE_OR_RETURN(
                aidl2legacy_AudioFormatDescription_audio_format_t(aidl.hal.format.value()));
        legacy.config_mask |= AUDIO_PORT_CONFIG_FORMAT;
    }
    if (aidl.hal.gain.has_value()) {
        legacy.gain = VALUE_OR_RETURN(aidl2legacy_AudioGainConfig_audio_gain_config(
                        aidl.hal.gain.value(), isInput));
        legacy.config_mask |= AUDIO_PORT_CONFIG_GAIN;
    }
    if (aidl.hal.flags.has_value()) {
        legacy.flags = VALUE_OR_RETURN(
                aidl2legacy_AudioIoFlags_audio_io_flags(aidl.hal.flags.value(), isInput));
        legacy.config_mask |= AUDIO_PORT_CONFIG_FLAGS;
    }
    legacy.ext = VALUE_OR_RETURN(
            aidl2legacy_AudioPortExt_audio_port_config_ext(
                    aidl.hal.ext, aidl.sys.type, aidl.sys.role, aidl.sys.ext));
    return legacy;
}

ConversionResult<media::AudioPortConfig> legacy2aidl_audio_port_config_AudioPortConfig(
        const audio_port_config& legacy) {
    media::AudioPortConfig aidl;
    aidl.hal.id = VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(legacy.id));
    aidl.sys.role = VALUE_OR_RETURN(legacy2aidl_audio_port_role_t_AudioPortRole(legacy.role));
    aidl.sys.type = VALUE_OR_RETURN(legacy2aidl_audio_port_type_t_AudioPortType(legacy.type));
    const bool isInput = VALUE_OR_RETURN(
            direction(legacy.role, legacy.type)) == Direction::INPUT;
    if (legacy.config_mask & AUDIO_PORT_CONFIG_SAMPLE_RATE) {
        Int aidl_sampleRate;
        aidl_sampleRate.value = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.sample_rate));
        aidl.hal.sampleRate = aidl_sampleRate;
    }
    if (legacy.config_mask & AUDIO_PORT_CONFIG_CHANNEL_MASK) {
        aidl.hal.channelMask = VALUE_OR_RETURN(
                legacy2aidl_audio_channel_mask_t_AudioChannelLayout(legacy.channel_mask, isInput));
    }
    if (legacy.config_mask & AUDIO_PORT_CONFIG_FORMAT) {
        aidl.hal.format = VALUE_OR_RETURN(
                legacy2aidl_audio_format_t_AudioFormatDescription(legacy.format));
    }
    if (legacy.config_mask & AUDIO_PORT_CONFIG_GAIN) {
        aidl.hal.gain = VALUE_OR_RETURN(
                legacy2aidl_audio_gain_config_AudioGainConfig(legacy.gain, isInput));
    }
    if (legacy.config_mask & AUDIO_PORT_CONFIG_FLAGS) {
        aidl.hal.flags = VALUE_OR_RETURN(
                legacy2aidl_audio_io_flags_AudioIoFlags(legacy.flags, isInput));
    }
    RETURN_IF_ERROR(legacy2aidl_AudioPortExt(legacy.ext, legacy.type, legacy.role,
                    &aidl.hal.ext, &aidl.sys.ext));
    return aidl;
}

ConversionResult<struct audio_patch> aidl2legacy_AudioPatch_audio_patch(
        const media::AudioPatch& aidl) {
    struct audio_patch legacy;
    legacy.id = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_patch_handle_t(aidl.id));
    legacy.num_sinks = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.sinks.size()));
    if (legacy.num_sinks > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (size_t i = 0; i < legacy.num_sinks; ++i) {
        legacy.sinks[i] =
                VALUE_OR_RETURN(aidl2legacy_AudioPortConfig_audio_port_config(aidl.sinks[i]));
    }
    legacy.num_sources = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.sources.size()));
    if (legacy.num_sources > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (size_t i = 0; i < legacy.num_sources; ++i) {
        legacy.sources[i] =
                VALUE_OR_RETURN(aidl2legacy_AudioPortConfig_audio_port_config(aidl.sources[i]));
    }
    return legacy;
}

ConversionResult<media::AudioPatch> legacy2aidl_audio_patch_AudioPatch(
        const struct audio_patch& legacy) {
    media::AudioPatch aidl;
    aidl.id = VALUE_OR_RETURN(legacy2aidl_audio_patch_handle_t_int32_t(legacy.id));

    if (legacy.num_sinks > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (unsigned int i = 0; i < legacy.num_sinks; ++i) {
        aidl.sinks.push_back(
                VALUE_OR_RETURN(legacy2aidl_audio_port_config_AudioPortConfig(legacy.sinks[i])));
    }
    if (legacy.num_sources > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (unsigned int i = 0; i < legacy.num_sources; ++i) {
        aidl.sources.push_back(
                VALUE_OR_RETURN(legacy2aidl_audio_port_config_AudioPortConfig(legacy.sources[i])));
    }
    return aidl;
}

ConversionResult<sp<AudioIoDescriptor>> aidl2legacy_AudioIoDescriptor_AudioIoDescriptor(
        const media::AudioIoDescriptor& aidl) {
    const audio_io_handle_t io_handle = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_io_handle_t(aidl.ioHandle));
    const struct audio_patch patch = VALUE_OR_RETURN(
            aidl2legacy_AudioPatch_audio_patch(aidl.patch));
    const bool isInput = aidl.isInput;
    const uint32_t sampling_rate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.samplingRate));
    const audio_format_t format = VALUE_OR_RETURN(
            aidl2legacy_AudioFormatDescription_audio_format_t(aidl.format));
    const audio_channel_mask_t channel_mask = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.channelMask, isInput));
    const size_t frame_count = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCount));
    const size_t frame_count_hal = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCountHAL));
    const uint32_t latency = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.latency));
    const audio_port_handle_t port_id = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_port_handle_t(aidl.portId));
    return sp<AudioIoDescriptor>::make(io_handle, patch, isInput, sampling_rate, format,
            channel_mask, frame_count, frame_count_hal, latency, port_id);
}

ConversionResult<media::AudioIoDescriptor> legacy2aidl_AudioIoDescriptor_AudioIoDescriptor(
        const sp<AudioIoDescriptor>& legacy) {
    media::AudioIoDescriptor aidl;
    aidl.ioHandle = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(legacy->getIoHandle()));
    aidl.patch = VALUE_OR_RETURN(legacy2aidl_audio_patch_AudioPatch(legacy->getPatch()));
    aidl.isInput = legacy->getIsInput();
    aidl.samplingRate = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy->getSamplingRate()));
    aidl.format = VALUE_OR_RETURN(
            legacy2aidl_audio_format_t_AudioFormatDescription(legacy->getFormat()));
    aidl.channelMask = VALUE_OR_RETURN(legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                    legacy->getChannelMask(), legacy->getIsInput()));
    aidl.frameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy->getFrameCount()));
    aidl.frameCountHAL = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy->getFrameCountHAL()));
    aidl.latency = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy->getLatency()));
    aidl.portId = VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(legacy->getPortId()));
    return aidl;
}

ConversionResult<AudioClient> aidl2legacy_AudioClient_AudioClient(
        const media::AudioClient& aidl) {
    AudioClient legacy;
    legacy.clientTid = VALUE_OR_RETURN(aidl2legacy_int32_t_pid_t(aidl.clientTid));
    legacy.attributionSource = aidl.attributionSource;
    return legacy;
}

ConversionResult<media::AudioClient> legacy2aidl_AudioClient_AudioClient(
        const AudioClient& legacy) {
    media::AudioClient aidl;
    aidl.clientTid = VALUE_OR_RETURN(legacy2aidl_pid_t_int32_t(legacy.clientTid));
    aidl.attributionSource = legacy.attributionSource;
    return aidl;
}

ConversionResult<audio_content_type_t>
aidl2legacy_AudioContentType_audio_content_type_t(AudioContentType aidl) {
    switch (aidl) {
        case AudioContentType::UNKNOWN:
            return AUDIO_CONTENT_TYPE_UNKNOWN;
        case AudioContentType::SPEECH:
            return AUDIO_CONTENT_TYPE_SPEECH;
        case AudioContentType::MUSIC:
            return AUDIO_CONTENT_TYPE_MUSIC;
        case AudioContentType::MOVIE:
            return AUDIO_CONTENT_TYPE_MOVIE;
        case AudioContentType::SONIFICATION:
            return AUDIO_CONTENT_TYPE_SONIFICATION;
        case AudioContentType::ULTRASOUND:
            return AUDIO_CONTENT_TYPE_ULTRASOUND;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioContentType>
legacy2aidl_audio_content_type_t_AudioContentType(audio_content_type_t legacy) {
    switch (legacy) {
        case AUDIO_CONTENT_TYPE_UNKNOWN:
            return AudioContentType::UNKNOWN;
        case AUDIO_CONTENT_TYPE_SPEECH:
            return AudioContentType::SPEECH;
        case AUDIO_CONTENT_TYPE_MUSIC:
            return AudioContentType::MUSIC;
        case AUDIO_CONTENT_TYPE_MOVIE:
            return AudioContentType::MOVIE;
        case AUDIO_CONTENT_TYPE_SONIFICATION:
            return AudioContentType::SONIFICATION;
        case AUDIO_CONTENT_TYPE_ULTRASOUND:
            return AudioContentType::ULTRASOUND;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_usage_t>
aidl2legacy_AudioUsage_audio_usage_t(AudioUsage aidl) {
    switch (aidl) {
        case AudioUsage::INVALID:
            break;  // return error
        case AudioUsage::UNKNOWN:
            return AUDIO_USAGE_UNKNOWN;
        case AudioUsage::MEDIA:
            return AUDIO_USAGE_MEDIA;
        case AudioUsage::VOICE_COMMUNICATION:
            return AUDIO_USAGE_VOICE_COMMUNICATION;
        case AudioUsage::VOICE_COMMUNICATION_SIGNALLING:
            return AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING;
        case AudioUsage::ALARM:
            return AUDIO_USAGE_ALARM;
        case AudioUsage::NOTIFICATION:
            return AUDIO_USAGE_NOTIFICATION;
        case AudioUsage::NOTIFICATION_TELEPHONY_RINGTONE:
            return AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE;
        case AudioUsage::SYS_RESERVED_NOTIFICATION_COMMUNICATION_REQUEST:
            return AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST;
        case AudioUsage::SYS_RESERVED_NOTIFICATION_COMMUNICATION_INSTANT:
            return AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT;
        case AudioUsage::SYS_RESERVED_NOTIFICATION_COMMUNICATION_DELAYED:
            return AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED;
        case AudioUsage::NOTIFICATION_EVENT:
            return AUDIO_USAGE_NOTIFICATION_EVENT;
        case AudioUsage::ASSISTANCE_ACCESSIBILITY:
            return AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY;
        case AudioUsage::ASSISTANCE_NAVIGATION_GUIDANCE:
            return AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE;
        case AudioUsage::ASSISTANCE_SONIFICATION:
            return AUDIO_USAGE_ASSISTANCE_SONIFICATION;
        case AudioUsage::GAME:
            return AUDIO_USAGE_GAME;
        case AudioUsage::VIRTUAL_SOURCE:
            return AUDIO_USAGE_VIRTUAL_SOURCE;
        case AudioUsage::ASSISTANT:
            return AUDIO_USAGE_ASSISTANT;
        case AudioUsage::CALL_ASSISTANT:
            return AUDIO_USAGE_CALL_ASSISTANT;
        case AudioUsage::EMERGENCY:
            return AUDIO_USAGE_EMERGENCY;
        case AudioUsage::SAFETY:
            return AUDIO_USAGE_SAFETY;
        case AudioUsage::VEHICLE_STATUS:
            return AUDIO_USAGE_VEHICLE_STATUS;
        case AudioUsage::ANNOUNCEMENT:
            return AUDIO_USAGE_ANNOUNCEMENT;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioUsage>
legacy2aidl_audio_usage_t_AudioUsage(audio_usage_t legacy) {
    switch (legacy) {
        case AUDIO_USAGE_UNKNOWN:
            return AudioUsage::UNKNOWN;
        case AUDIO_USAGE_MEDIA:
            return AudioUsage::MEDIA;
        case AUDIO_USAGE_VOICE_COMMUNICATION:
            return AudioUsage::VOICE_COMMUNICATION;
        case AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING:
            return AudioUsage::VOICE_COMMUNICATION_SIGNALLING;
        case AUDIO_USAGE_ALARM:
            return AudioUsage::ALARM;
        case AUDIO_USAGE_NOTIFICATION:
            return AudioUsage::NOTIFICATION;
        case AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE:
            return AudioUsage::NOTIFICATION_TELEPHONY_RINGTONE;
        case AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST:
            return AudioUsage::SYS_RESERVED_NOTIFICATION_COMMUNICATION_REQUEST;
        case AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT:
            return AudioUsage::SYS_RESERVED_NOTIFICATION_COMMUNICATION_INSTANT;
        case AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED:
            return AudioUsage::SYS_RESERVED_NOTIFICATION_COMMUNICATION_DELAYED;
        case AUDIO_USAGE_NOTIFICATION_EVENT:
            return AudioUsage::NOTIFICATION_EVENT;
        case AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY:
            return AudioUsage::ASSISTANCE_ACCESSIBILITY;
        case AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE:
            return AudioUsage::ASSISTANCE_NAVIGATION_GUIDANCE;
        case AUDIO_USAGE_ASSISTANCE_SONIFICATION:
            return AudioUsage::ASSISTANCE_SONIFICATION;
        case AUDIO_USAGE_GAME:
            return AudioUsage::GAME;
        case AUDIO_USAGE_VIRTUAL_SOURCE:
            return AudioUsage::VIRTUAL_SOURCE;
        case AUDIO_USAGE_ASSISTANT:
            return AudioUsage::ASSISTANT;
        case AUDIO_USAGE_CALL_ASSISTANT:
            return AudioUsage::CALL_ASSISTANT;
        case AUDIO_USAGE_EMERGENCY:
            return AudioUsage::EMERGENCY;
        case AUDIO_USAGE_SAFETY:
            return AudioUsage::SAFETY;
        case AUDIO_USAGE_VEHICLE_STATUS:
            return AudioUsage::VEHICLE_STATUS;
        case AUDIO_USAGE_ANNOUNCEMENT:
            return AudioUsage::ANNOUNCEMENT;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_flags_mask_t>
aidl2legacy_AudioFlag_audio_flags_mask_t(media::AudioFlag aidl) {
    switch (aidl) {
        case media::AudioFlag::AUDIBILITY_ENFORCED:
            return AUDIO_FLAG_AUDIBILITY_ENFORCED;
        case media::AudioFlag::SECURE:
            return AUDIO_FLAG_SECURE;
        case media::AudioFlag::SCO:
            return AUDIO_FLAG_SCO;
        case media::AudioFlag::BEACON:
            return AUDIO_FLAG_BEACON;
        case media::AudioFlag::HW_AV_SYNC:
            return AUDIO_FLAG_HW_AV_SYNC;
        case media::AudioFlag::HW_HOTWORD:
            return AUDIO_FLAG_HW_HOTWORD;
        case media::AudioFlag::BYPASS_INTERRUPTION_POLICY:
            return AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY;
        case media::AudioFlag::BYPASS_MUTE:
            return AUDIO_FLAG_BYPASS_MUTE;
        case media::AudioFlag::LOW_LATENCY:
            return AUDIO_FLAG_LOW_LATENCY;
        case media::AudioFlag::DEEP_BUFFER:
            return AUDIO_FLAG_DEEP_BUFFER;
        case media::AudioFlag::NO_MEDIA_PROJECTION:
            return AUDIO_FLAG_NO_MEDIA_PROJECTION;
        case media::AudioFlag::MUTE_HAPTIC:
            return AUDIO_FLAG_MUTE_HAPTIC;
        case media::AudioFlag::NO_SYSTEM_CAPTURE:
            return AUDIO_FLAG_NO_SYSTEM_CAPTURE;
        case media::AudioFlag::CAPTURE_PRIVATE:
            return AUDIO_FLAG_CAPTURE_PRIVATE;
        case media::AudioFlag::CONTENT_SPATIALIZED:
            return AUDIO_FLAG_CONTENT_SPATIALIZED;
        case media::AudioFlag::NEVER_SPATIALIZE:
            return AUDIO_FLAG_NEVER_SPATIALIZE;
        case media::AudioFlag::CALL_REDIRECTION:
            return AUDIO_FLAG_CALL_REDIRECTION;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioFlag>
legacy2aidl_audio_flags_mask_t_AudioFlag(audio_flags_mask_t legacy) {
    switch (legacy) {
        case AUDIO_FLAG_NONE:
            return unexpected(BAD_VALUE);
        case AUDIO_FLAG_AUDIBILITY_ENFORCED:
            return media::AudioFlag::AUDIBILITY_ENFORCED;
        case AUDIO_FLAG_SECURE:
            return media::AudioFlag::SECURE;
        case AUDIO_FLAG_SCO:
            return media::AudioFlag::SCO;
        case AUDIO_FLAG_BEACON:
            return media::AudioFlag::BEACON;
        case AUDIO_FLAG_HW_AV_SYNC:
            return media::AudioFlag::HW_AV_SYNC;
        case AUDIO_FLAG_HW_HOTWORD:
            return media::AudioFlag::HW_HOTWORD;
        case AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY:
            return media::AudioFlag::BYPASS_INTERRUPTION_POLICY;
        case AUDIO_FLAG_BYPASS_MUTE:
            return media::AudioFlag::BYPASS_MUTE;
        case AUDIO_FLAG_LOW_LATENCY:
            return media::AudioFlag::LOW_LATENCY;
        case AUDIO_FLAG_DEEP_BUFFER:
            return media::AudioFlag::DEEP_BUFFER;
        case AUDIO_FLAG_NO_MEDIA_PROJECTION:
            return media::AudioFlag::NO_MEDIA_PROJECTION;
        case AUDIO_FLAG_MUTE_HAPTIC:
            return media::AudioFlag::MUTE_HAPTIC;
        case AUDIO_FLAG_NO_SYSTEM_CAPTURE:
            return media::AudioFlag::NO_SYSTEM_CAPTURE;
        case AUDIO_FLAG_CAPTURE_PRIVATE:
            return media::AudioFlag::CAPTURE_PRIVATE;
        case AUDIO_FLAG_CONTENT_SPATIALIZED:
            return media::AudioFlag::CONTENT_SPATIALIZED;
        case AUDIO_FLAG_NEVER_SPATIALIZE:
            return media::AudioFlag::NEVER_SPATIALIZE;
        case AUDIO_FLAG_CALL_REDIRECTION:
            return media::AudioFlag::CALL_REDIRECTION;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_flags_mask_t>
aidl2legacy_int32_t_audio_flags_mask_t_mask(int32_t aidl) {
    return convertBitmask<audio_flags_mask_t, int32_t, audio_flags_mask_t, media::AudioFlag>(
            aidl, aidl2legacy_AudioFlag_audio_flags_mask_t, indexToEnum_index<media::AudioFlag>,
            enumToMask_bitmask<audio_flags_mask_t, audio_flags_mask_t>);
}

ConversionResult<int32_t>
legacy2aidl_audio_flags_mask_t_int32_t_mask(audio_flags_mask_t legacy) {
    return convertBitmask<int32_t, audio_flags_mask_t, media::AudioFlag, audio_flags_mask_t>(
            legacy, legacy2aidl_audio_flags_mask_t_AudioFlag,
            indexToEnum_bitmask<audio_flags_mask_t>,
            enumToMask_index<int32_t, media::AudioFlag>);
}

ConversionResult<audio_attributes_t>
aidl2legacy_AudioAttributesInternal_audio_attributes_t(const media::AudioAttributesInternal& aidl) {
    audio_attributes_t legacy;
    legacy.content_type = VALUE_OR_RETURN(
            aidl2legacy_AudioContentType_audio_content_type_t(aidl.contentType));
    legacy.usage = VALUE_OR_RETURN(aidl2legacy_AudioUsage_audio_usage_t(aidl.usage));
    legacy.source = VALUE_OR_RETURN(aidl2legacy_AudioSource_audio_source_t(aidl.source));
    legacy.flags = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_flags_mask_t_mask(aidl.flags));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.tags, legacy.tags, sizeof(legacy.tags)));
    return legacy;
}

ConversionResult<media::AudioAttributesInternal>
legacy2aidl_audio_attributes_t_AudioAttributesInternal(const audio_attributes_t& legacy) {
    media::AudioAttributesInternal aidl;
    aidl.contentType = VALUE_OR_RETURN(
            legacy2aidl_audio_content_type_t_AudioContentType(legacy.content_type));
    aidl.usage = VALUE_OR_RETURN(legacy2aidl_audio_usage_t_AudioUsage(legacy.usage));
    aidl.source = VALUE_OR_RETURN(legacy2aidl_audio_source_t_AudioSource(legacy.source));
    aidl.flags = VALUE_OR_RETURN(legacy2aidl_audio_flags_mask_t_int32_t_mask(legacy.flags));
    aidl.tags = VALUE_OR_RETURN(legacy2aidl_string(legacy.tags, sizeof(legacy.tags)));
    return aidl;
}

ConversionResult<audio_encapsulation_mode_t>
aidl2legacy_AudioEncapsulationMode_audio_encapsulation_mode_t(AudioEncapsulationMode aidl) {
    switch (aidl) {
        case AudioEncapsulationMode::INVALID:
            break;  // return error
        case AudioEncapsulationMode::NONE:
            return AUDIO_ENCAPSULATION_MODE_NONE;
        case AudioEncapsulationMode::ELEMENTARY_STREAM:
            return AUDIO_ENCAPSULATION_MODE_ELEMENTARY_STREAM;
        case AudioEncapsulationMode::HANDLE:
            return AUDIO_ENCAPSULATION_MODE_HANDLE;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioEncapsulationMode>
legacy2aidl_audio_encapsulation_mode_t_AudioEncapsulationMode(audio_encapsulation_mode_t legacy) {
    switch (legacy) {
        case AUDIO_ENCAPSULATION_MODE_NONE:
            return AudioEncapsulationMode::NONE;
        case AUDIO_ENCAPSULATION_MODE_ELEMENTARY_STREAM:
            return AudioEncapsulationMode::ELEMENTARY_STREAM;
        case AUDIO_ENCAPSULATION_MODE_HANDLE:
            return AudioEncapsulationMode::HANDLE;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_offload_info_t>
aidl2legacy_AudioOffloadInfo_audio_offload_info_t(const AudioOffloadInfo& aidl) {
    audio_offload_info_t legacy = AUDIO_INFO_INITIALIZER;
    audio_config_base_t base = VALUE_OR_RETURN(
            aidl2legacy_AudioConfigBase_audio_config_base_t(aidl.base, false /*isInput*/));
    legacy.sample_rate = base.sample_rate;
    legacy.channel_mask = base.channel_mask;
    legacy.format = base.format;
    legacy.stream_type = VALUE_OR_RETURN(
            aidl2legacy_AudioStreamType_audio_stream_type_t(aidl.streamType));
    legacy.bit_rate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.bitRatePerSecond));
    legacy.duration_us = VALUE_OR_RETURN(convertIntegral<int64_t>(aidl.durationUs));
    legacy.has_video = aidl.hasVideo;
    legacy.is_streaming = aidl.isStreaming;
    legacy.bit_width = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.bitWidth));
    legacy.offload_buffer_size = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.offloadBufferSize));
    legacy.usage = VALUE_OR_RETURN(aidl2legacy_AudioUsage_audio_usage_t(aidl.usage));
    legacy.encapsulation_mode = VALUE_OR_RETURN(
            aidl2legacy_AudioEncapsulationMode_audio_encapsulation_mode_t(aidl.encapsulationMode));
    legacy.content_id = VALUE_OR_RETURN(convertReinterpret<int32_t>(aidl.contentId));
    legacy.sync_id = VALUE_OR_RETURN(convertReinterpret<int32_t>(aidl.syncId));
    return legacy;
}

ConversionResult<AudioOffloadInfo>
legacy2aidl_audio_offload_info_t_AudioOffloadInfo(const audio_offload_info_t& legacy) {
    AudioOffloadInfo aidl;
    // Version 0.1 fields.
    if (legacy.size < offsetof(audio_offload_info_t, usage) + sizeof(audio_offload_info_t::usage)) {
        return unexpected(BAD_VALUE);
    }
    const audio_config_base_t base = { .sample_rate = legacy.sample_rate,
        .channel_mask = legacy.channel_mask, .format = legacy.format };
    aidl.base = VALUE_OR_RETURN(legacy2aidl_audio_config_base_t_AudioConfigBase(
                    base, false /*isInput*/));
    aidl.streamType = VALUE_OR_RETURN(
            legacy2aidl_audio_stream_type_t_AudioStreamType(legacy.stream_type));
    aidl.bitRatePerSecond = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.bit_rate));
    aidl.durationUs = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy.duration_us));
    aidl.hasVideo = legacy.has_video;
    aidl.isStreaming = legacy.is_streaming;
    aidl.bitWidth = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.bit_width));
    aidl.offloadBufferSize = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.offload_buffer_size));
    aidl.usage = VALUE_OR_RETURN(legacy2aidl_audio_usage_t_AudioUsage(legacy.usage));

    // Version 0.2 fields.
    if (legacy.version >= AUDIO_OFFLOAD_INFO_VERSION_0_2) {
        if (legacy.size <
            offsetof(audio_offload_info_t, sync_id) + sizeof(audio_offload_info_t::sync_id)) {
            return unexpected(BAD_VALUE);
        }
        aidl.encapsulationMode = VALUE_OR_RETURN(
                legacy2aidl_audio_encapsulation_mode_t_AudioEncapsulationMode(
                        legacy.encapsulation_mode));
        aidl.contentId = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy.content_id));
        aidl.syncId = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy.sync_id));
    }
    return aidl;
}

ConversionResult<audio_config_t>
aidl2legacy_AudioConfig_audio_config_t(const AudioConfig& aidl, bool isInput) {
    const audio_config_base_t legacyBase = VALUE_OR_RETURN(
            aidl2legacy_AudioConfigBase_audio_config_base_t(aidl.base, isInput));
    audio_config_t legacy = AUDIO_CONFIG_INITIALIZER;
    legacy.sample_rate = legacyBase.sample_rate;
    legacy.channel_mask = legacyBase.channel_mask;
    legacy.format = legacyBase.format;
    legacy.offload_info = VALUE_OR_RETURN(
            aidl2legacy_AudioOffloadInfo_audio_offload_info_t(aidl.offloadInfo));
    legacy.frame_count = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.frameCount));
    return legacy;
}

ConversionResult<AudioConfig>
legacy2aidl_audio_config_t_AudioConfig(const audio_config_t& legacy, bool isInput) {
    const audio_config_base_t base = { .sample_rate = legacy.sample_rate,
        .channel_mask = legacy.channel_mask, .format = legacy.format };
    AudioConfig aidl;
    aidl.base = VALUE_OR_RETURN(legacy2aidl_audio_config_base_t_AudioConfigBase(base, isInput));
    aidl.offloadInfo = VALUE_OR_RETURN(
            legacy2aidl_audio_offload_info_t_AudioOffloadInfo(legacy.offload_info));
    aidl.frameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy.frame_count));
    return aidl;
}

ConversionResult<audio_config_base_t>
aidl2legacy_AudioConfigBase_audio_config_base_t(const AudioConfigBase& aidl, bool isInput) {
    audio_config_base_t legacy;
    legacy.sample_rate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.sampleRate));
    legacy.channel_mask = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.channelMask, isInput));
    legacy.format = VALUE_OR_RETURN(aidl2legacy_AudioFormatDescription_audio_format_t(aidl.format));
    return legacy;
}

ConversionResult<AudioConfigBase>
legacy2aidl_audio_config_base_t_AudioConfigBase(const audio_config_base_t& legacy, bool isInput) {
    AudioConfigBase aidl;
    aidl.sampleRate = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.sample_rate));
    aidl.channelMask = VALUE_OR_RETURN(
            legacy2aidl_audio_channel_mask_t_AudioChannelLayout(legacy.channel_mask, isInput));
    aidl.format = VALUE_OR_RETURN(legacy2aidl_audio_format_t_AudioFormatDescription(legacy.format));
    return aidl;
}

ConversionResult<sp<IMemory>>
aidl2legacy_SharedFileRegion_IMemory(const media::SharedFileRegion& aidl) {
    sp<IMemory> legacy;
    if (!convertSharedFileRegionToIMemory(aidl, &legacy)) {
        return unexpected(BAD_VALUE);
    }
    return legacy;
}

ConversionResult<media::SharedFileRegion>
legacy2aidl_IMemory_SharedFileRegion(const sp<IMemory>& legacy) {
    media::SharedFileRegion aidl;
    if (!convertIMemoryToSharedFileRegion(legacy, &aidl)) {
        return unexpected(BAD_VALUE);
    }
    return aidl;
}

ConversionResult<sp<IMemory>>
aidl2legacy_NullableSharedFileRegion_IMemory(const std::optional<media::SharedFileRegion>& aidl) {
    sp<IMemory> legacy;
    if (!convertNullableSharedFileRegionToIMemory(aidl, &legacy)) {
        return unexpected(BAD_VALUE);
    }
    return legacy;
}

ConversionResult<std::optional<media::SharedFileRegion>>
legacy2aidl_NullableIMemory_SharedFileRegion(const sp<IMemory>& legacy) {
    std::optional<media::SharedFileRegion> aidl;
    if (!convertNullableIMemoryToSharedFileRegion(legacy, &aidl)) {
        return unexpected(BAD_VALUE);
    }
    return aidl;
}

ConversionResult<AudioTimestamp>
aidl2legacy_AudioTimestampInternal_AudioTimestamp(const media::AudioTimestampInternal& aidl) {
    AudioTimestamp legacy;
    legacy.mPosition = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.position));
    legacy.mTime.tv_sec = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.sec));
    legacy.mTime.tv_nsec = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.nsec));
    return legacy;
}

ConversionResult<media::AudioTimestampInternal>
legacy2aidl_AudioTimestamp_AudioTimestampInternal(const AudioTimestamp& legacy) {
    media::AudioTimestampInternal aidl;
    aidl.position = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.mPosition));
    aidl.sec = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy.mTime.tv_sec));
    aidl.nsec = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.mTime.tv_nsec));
    return aidl;
}

ConversionResult<audio_uuid_t>
aidl2legacy_AudioUuid_audio_uuid_t(const AudioUuid& aidl) {
    audio_uuid_t legacy;
    legacy.timeLow = VALUE_OR_RETURN(convertReinterpret<uint32_t>(aidl.timeLow));
    legacy.timeMid = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.timeMid));
    legacy.timeHiAndVersion = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.timeHiAndVersion));
    legacy.clockSeq = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.clockSeq));
    if (aidl.node.size() != std::size(legacy.node)) {
        return unexpected(BAD_VALUE);
    }
    std::copy(aidl.node.begin(), aidl.node.end(), legacy.node);
    return legacy;
}

ConversionResult<AudioUuid>
legacy2aidl_audio_uuid_t_AudioUuid(const audio_uuid_t& legacy) {
    AudioUuid aidl;
    aidl.timeLow = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy.timeLow));
    aidl.timeMid = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.timeMid));
    aidl.timeHiAndVersion = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.timeHiAndVersion));
    aidl.clockSeq = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.clockSeq));
    std::copy(legacy.node, legacy.node + std::size(legacy.node), std::back_inserter(aidl.node));
    return aidl;
}

ConversionResult<effect_descriptor_t>
aidl2legacy_EffectDescriptor_effect_descriptor_t(const media::EffectDescriptor& aidl) {
    effect_descriptor_t legacy;
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.type));
    legacy.uuid = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.uuid));
    legacy.apiVersion = VALUE_OR_RETURN(convertReinterpret<uint32_t>(aidl.apiVersion));
    legacy.flags = VALUE_OR_RETURN(convertReinterpret<uint32_t>(aidl.flags));
    legacy.cpuLoad = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.cpuLoad));
    legacy.memoryUsage = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.memoryUsage));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.name, legacy.name, sizeof(legacy.name)));
    RETURN_IF_ERROR(
            aidl2legacy_string(aidl.implementor, legacy.implementor, sizeof(legacy.implementor)));
    return legacy;
}

ConversionResult<media::EffectDescriptor>
legacy2aidl_effect_descriptor_t_EffectDescriptor(const effect_descriptor_t& legacy) {
    media::EffectDescriptor aidl;
    aidl.type = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.type));
    aidl.uuid = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.uuid));
    aidl.apiVersion = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy.apiVersion));
    aidl.flags = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy.flags));
    aidl.cpuLoad = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.cpuLoad));
    aidl.memoryUsage = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.memoryUsage));
    aidl.name = VALUE_OR_RETURN(legacy2aidl_string(legacy.name, sizeof(legacy.name)));
    aidl.implementor = VALUE_OR_RETURN(
            legacy2aidl_string(legacy.implementor, sizeof(legacy.implementor)));
    return aidl;
}

ConversionResult<audio_encapsulation_metadata_type_t>
aidl2legacy_AudioEncapsulationMetadataType_audio_encapsulation_metadata_type_t(
        AudioEncapsulationMetadataType aidl) {
    switch (aidl) {
        case AudioEncapsulationMetadataType::NONE:
            return AUDIO_ENCAPSULATION_METADATA_TYPE_NONE;
        case AudioEncapsulationMetadataType::FRAMEWORK_TUNER:
            return AUDIO_ENCAPSULATION_METADATA_TYPE_FRAMEWORK_TUNER;
        case AudioEncapsulationMetadataType::DVB_AD_DESCRIPTOR:
            return AUDIO_ENCAPSULATION_METADATA_TYPE_DVB_AD_DESCRIPTOR;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioEncapsulationMetadataType>
legacy2aidl_audio_encapsulation_metadata_type_t_AudioEncapsulationMetadataType(
        audio_encapsulation_metadata_type_t legacy) {
    switch (legacy) {
        case AUDIO_ENCAPSULATION_METADATA_TYPE_NONE:
            return AudioEncapsulationMetadataType::NONE;
        case AUDIO_ENCAPSULATION_METADATA_TYPE_FRAMEWORK_TUNER:
            return AudioEncapsulationMetadataType::FRAMEWORK_TUNER;
        case AUDIO_ENCAPSULATION_METADATA_TYPE_DVB_AD_DESCRIPTOR:
            return AudioEncapsulationMetadataType::DVB_AD_DESCRIPTOR;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<uint32_t>
aidl2legacy_AudioEncapsulationMode_mask(int32_t aidl) {
    return convertBitmask<uint32_t,
            int32_t,
            audio_encapsulation_mode_t,
            AudioEncapsulationMode>(
            aidl, aidl2legacy_AudioEncapsulationMode_audio_encapsulation_mode_t,
            indexToEnum_index<AudioEncapsulationMode>,
            enumToMask_index<uint32_t, audio_encapsulation_mode_t>);
}

ConversionResult<int32_t>
legacy2aidl_AudioEncapsulationMode_mask(uint32_t legacy) {
    return convertBitmask<int32_t,
            uint32_t,
            AudioEncapsulationMode,
            audio_encapsulation_mode_t>(
            legacy, legacy2aidl_audio_encapsulation_mode_t_AudioEncapsulationMode,
            indexToEnum_index<audio_encapsulation_mode_t>,
            enumToMask_index<int32_t, AudioEncapsulationMode>);
}

ConversionResult<uint32_t>
aidl2legacy_AudioEncapsulationMetadataType_mask(int32_t aidl) {
    return convertBitmask<uint32_t,
            int32_t,
            audio_encapsulation_metadata_type_t,
            AudioEncapsulationMetadataType>(
            aidl, aidl2legacy_AudioEncapsulationMetadataType_audio_encapsulation_metadata_type_t,
            indexToEnum_index<AudioEncapsulationMetadataType>,
            enumToMask_index<uint32_t, audio_encapsulation_metadata_type_t>);
}

ConversionResult<int32_t>
legacy2aidl_AudioEncapsulationMetadataType_mask(uint32_t legacy) {
    return convertBitmask<int32_t,
            uint32_t,
            AudioEncapsulationMetadataType,
            audio_encapsulation_metadata_type_t>(
            legacy, legacy2aidl_audio_encapsulation_metadata_type_t_AudioEncapsulationMetadataType,
            indexToEnum_index<audio_encapsulation_metadata_type_t>,
            enumToMask_index<int32_t, AudioEncapsulationMetadataType>);
}

ConversionResult<audio_port_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_device_ext(
        const AudioPortDeviceExt& aidl, const media::AudioPortDeviceExtSys& aidlSys) {
    audio_port_device_ext legacy;
    legacy.hw_module = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_module_handle_t(aidlSys.hwModule));
    RETURN_IF_ERROR(aidl2legacy_AudioDevice_audio_device(
                    aidl.device, &legacy.type, legacy.address));
    legacy.encapsulation_modes = VALUE_OR_RETURN(
            aidl2legacy_AudioEncapsulationMode_mask(aidlSys.encapsulationModes));
    legacy.encapsulation_metadata_types = VALUE_OR_RETURN(
            aidl2legacy_AudioEncapsulationMetadataType_mask(
                    aidlSys.encapsulationMetadataTypes));
    return legacy;
}

status_t legacy2aidl_audio_port_device_ext_AudioPortDeviceExt(
        const audio_port_device_ext& legacy,
        AudioPortDeviceExt* aidl, media::AudioPortDeviceExtSys* aidlDeviceExt) {
    aidlDeviceExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    aidl->device = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_device_AudioDevice(legacy.type, legacy.address));
    aidlDeviceExt->encapsulationModes = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioEncapsulationMode_mask(legacy.encapsulation_modes));
    aidlDeviceExt->encapsulationMetadataTypes = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioEncapsulationMetadataType_mask(legacy.encapsulation_metadata_types));
    return OK;
}

ConversionResult<audio_port_mix_ext>
aidl2legacy_AudioPortMixExt_audio_port_mix_ext(
        const AudioPortMixExt& aidl, const media::AudioPortMixExtSys& aidlSys) {
    audio_port_mix_ext legacy{};
    legacy.hw_module = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_module_handle_t(aidlSys.hwModule));
    legacy.handle = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_io_handle_t(aidl.handle));
    return legacy;
}

status_t
legacy2aidl_audio_port_mix_ext_AudioPortMixExt(const audio_port_mix_ext& legacy,
        AudioPortMixExt* aidl, media::AudioPortMixExtSys* aidlMixExt) {
    aidlMixExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    aidl->handle = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(legacy.handle));
    return OK;
}

ConversionResult<audio_port_session_ext>
aidl2legacy_int32_t_audio_port_session_ext(int32_t aidl) {
    audio_port_session_ext legacy;
    legacy.session = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl));
    return legacy;
}

ConversionResult<int32_t>
legacy2aidl_audio_port_session_ext_int32_t(const audio_port_session_ext& legacy) {
    return legacy2aidl_audio_session_t_int32_t(legacy.session);
}

// This type is unnamed in the original definition, thus we name it here.
using audio_port_v7_ext = decltype(audio_port_v7::ext);

ConversionResult<audio_port_v7_ext> aidl2legacy_AudioPortExt_audio_port_v7_ext(
        const AudioPortExt& aidl, media::AudioPortType type,
        const media::AudioPortExtSys& aidlSys) {
    audio_port_v7_ext legacy;
    switch (type) {
        case media::AudioPortType::NONE:
            // Just verify that the union is empty.
            VALUE_OR_RETURN(UNION_GET(aidl, unspecified));
            return legacy;
        case media::AudioPortType::DEVICE:
            legacy.device = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortDeviceExt_audio_port_device_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, device)),
                            VALUE_OR_RETURN(UNION_GET(aidlSys, device))));
            return legacy;
        case media::AudioPortType::MIX:
            legacy.mix = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortMixExt_audio_port_mix_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, mix)),
                            VALUE_OR_RETURN(UNION_GET(aidlSys, mix))));
            return legacy;
        case media::AudioPortType::SESSION:
            legacy.session = VALUE_OR_RETURN(
                    aidl2legacy_int32_t_audio_port_session_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, session))));
            return legacy;

    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

status_t legacy2aidl_AudioPortExt(
        const audio_port_v7_ext& legacy, audio_port_type_t type,
        AudioPortExt* aidl, media::AudioPortExtSys* aidlSys) {
    switch (type) {
        case AUDIO_PORT_TYPE_NONE:
            UNION_SET(*aidl, unspecified, false);
            UNION_SET(*aidlSys, unspecified, false);
            return OK;
        case AUDIO_PORT_TYPE_DEVICE: {
            AudioPortDeviceExt device;
            media::AudioPortDeviceExtSys deviceSys;
            RETURN_STATUS_IF_ERROR(
                    legacy2aidl_audio_port_device_ext_AudioPortDeviceExt(
                            legacy.device, &device, &deviceSys));
            UNION_SET(*aidl, device, device);
            UNION_SET(*aidlSys, device, deviceSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_MIX: {
            AudioPortMixExt mix;
            media::AudioPortMixExtSys mixSys;
            RETURN_STATUS_IF_ERROR(
                    legacy2aidl_audio_port_mix_ext_AudioPortMixExt(
                            legacy.mix, &mix, &mixSys));
            UNION_SET(*aidl, mix, mix);
            UNION_SET(*aidlSys, mix, mixSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_SESSION:
            UNION_SET(*aidl, session, VALUE_OR_RETURN_STATUS(
                            legacy2aidl_audio_port_session_ext_int32_t(legacy.session)));
            UNION_SET(*aidlSys, unspecified, false);
            return OK;
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<audio_profile>
aidl2legacy_AudioProfile_audio_profile(const AudioProfile& aidl, bool isInput) {
    audio_profile legacy;
    legacy.format = VALUE_OR_RETURN(aidl2legacy_AudioFormatDescription_audio_format_t(aidl.format));

    if (aidl.sampleRates.size() > std::size(legacy.sample_rates)) {
        return unexpected(BAD_VALUE);
    }
    RETURN_IF_ERROR(
            convertRange(aidl.sampleRates.begin(), aidl.sampleRates.end(), legacy.sample_rates,
                         convertIntegral<int32_t, unsigned int>));
    legacy.num_sample_rates = aidl.sampleRates.size();

    if (aidl.channelMasks.size() > std::size(legacy.channel_masks)) {
        return unexpected(BAD_VALUE);
    }
    RETURN_IF_ERROR(
            convertRange(aidl.channelMasks.begin(), aidl.channelMasks.end(), legacy.channel_masks,
                    [isInput](const AudioChannelLayout& l) {
                        return aidl2legacy_AudioChannelLayout_audio_channel_mask_t(l, isInput);
                    }));
    legacy.num_channel_masks = aidl.channelMasks.size();

    legacy.encapsulation_type = VALUE_OR_RETURN(
            aidl2legacy_AudioEncapsulationType_audio_encapsulation_type_t(aidl.encapsulationType));
    return legacy;
}

ConversionResult<AudioProfile>
legacy2aidl_audio_profile_AudioProfile(const audio_profile& legacy, bool isInput) {
    AudioProfile aidl;
    aidl.format = VALUE_OR_RETURN(legacy2aidl_audio_format_t_AudioFormatDescription(legacy.format));

    if (legacy.num_sample_rates > std::size(legacy.sample_rates)) {
        return unexpected(BAD_VALUE);
    }
    RETURN_IF_ERROR(
            convertRange(legacy.sample_rates, legacy.sample_rates + legacy.num_sample_rates,
                         std::back_inserter(aidl.sampleRates),
                         convertIntegral<unsigned int, int32_t>));

    if (legacy.num_channel_masks > std::size(legacy.channel_masks)) {
        return unexpected(BAD_VALUE);
    }
    RETURN_IF_ERROR(
            convertRange(legacy.channel_masks, legacy.channel_masks + legacy.num_channel_masks,
                         std::back_inserter(aidl.channelMasks),
                    [isInput](audio_channel_mask_t m) {
                        return legacy2aidl_audio_channel_mask_t_AudioChannelLayout(m, isInput);
                    }));

    aidl.encapsulationType = VALUE_OR_RETURN(
            legacy2aidl_audio_encapsulation_type_t_AudioEncapsulationType(
                    legacy.encapsulation_type));
    return aidl;
}

ConversionResult<audio_gain>
aidl2legacy_AudioGain_audio_gain(const AudioGain& aidl, bool isInput) {
    audio_gain legacy;
    legacy.mode = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_gain_mode_t_mask(aidl.mode));
    legacy.channel_mask = VALUE_OR_RETURN(aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
                    aidl.channelMask, isInput));
    legacy.min_value = VALUE_OR_RETURN(convertIntegral<int>(aidl.minValue));
    legacy.max_value = VALUE_OR_RETURN(convertIntegral<int>(aidl.maxValue));
    legacy.default_value = VALUE_OR_RETURN(convertIntegral<int>(aidl.defaultValue));
    legacy.step_value = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.stepValue));
    legacy.min_ramp_ms = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.minRampMs));
    legacy.max_ramp_ms = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.maxRampMs));
    return legacy;
}

ConversionResult<AudioGain>
legacy2aidl_audio_gain_AudioGain(const audio_gain& legacy, bool isInput) {
    AudioGain aidl;
    aidl.mode = VALUE_OR_RETURN(legacy2aidl_audio_gain_mode_t_int32_t_mask(legacy.mode));
    aidl.channelMask = VALUE_OR_RETURN(
            legacy2aidl_audio_channel_mask_t_AudioChannelLayout(legacy.channel_mask, isInput));
    aidl.minValue = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.min_value));
    aidl.maxValue = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.max_value));
    aidl.defaultValue = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.default_value));
    aidl.stepValue = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.step_value));
    aidl.minRampMs = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.min_ramp_ms));
    aidl.maxRampMs = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.max_ramp_ms));
    return aidl;
}

ConversionResult<audio_port_v7>
aidl2legacy_AudioPort_audio_port_v7(const media::AudioPort& aidl) {
    audio_port_v7 legacy;
    legacy.id = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_port_handle_t(aidl.hal.id));
    legacy.role = VALUE_OR_RETURN(aidl2legacy_AudioPortRole_audio_port_role_t(aidl.sys.role));
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioPortType_audio_port_type_t(aidl.sys.type));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.hal.name, legacy.name, sizeof(legacy.name)));

    if (aidl.hal.profiles.size() > std::size(legacy.audio_profiles)) {
        return unexpected(BAD_VALUE);
    }
    const bool isInput =
            VALUE_OR_RETURN(direction(aidl.sys.role, aidl.sys.type)) == Direction::INPUT;
    RETURN_IF_ERROR(convertRange(
                    aidl.hal.profiles.begin(), aidl.hal.profiles.end(), legacy.audio_profiles,
                    [isInput](const AudioProfile& p) {
                        return aidl2legacy_AudioProfile_audio_profile(p, isInput);
                    }));
    legacy.num_audio_profiles = aidl.hal.profiles.size();

    if (aidl.hal.extraAudioDescriptors.size() > std::size(legacy.extra_audio_descriptors)) {
        return unexpected(BAD_VALUE);
    }
    RETURN_IF_ERROR(
            convertRange(
                    aidl.hal.extraAudioDescriptors.begin(), aidl.hal.extraAudioDescriptors.end(),
                    legacy.extra_audio_descriptors,
                    aidl2legacy_ExtraAudioDescriptor_audio_extra_audio_descriptor));
    legacy.num_extra_audio_descriptors = aidl.hal.extraAudioDescriptors.size();

    if (aidl.hal.gains.size() > std::size(legacy.gains)) {
        return unexpected(BAD_VALUE);
    }
    RETURN_IF_ERROR(convertRange(aidl.hal.gains.begin(), aidl.hal.gains.end(), legacy.gains,
                                 [isInput](const AudioGain& g) {
                                     return aidl2legacy_AudioGain_audio_gain(g, isInput);
                                 }));
    legacy.num_gains = aidl.hal.gains.size();

    legacy.active_config = VALUE_OR_RETURN(
            aidl2legacy_AudioPortConfig_audio_port_config(aidl.sys.activeConfig));
    legacy.ext = VALUE_OR_RETURN(
            aidl2legacy_AudioPortExt_audio_port_v7_ext(aidl.hal.ext, aidl.sys.type, aidl.sys.ext));
    return legacy;
}

ConversionResult<media::AudioPort>
legacy2aidl_audio_port_v7_AudioPort(const audio_port_v7& legacy) {
    media::AudioPort aidl;
    aidl.hal.id = VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(legacy.id));
    aidl.sys.role = VALUE_OR_RETURN(legacy2aidl_audio_port_role_t_AudioPortRole(legacy.role));
    aidl.sys.type = VALUE_OR_RETURN(legacy2aidl_audio_port_type_t_AudioPortType(legacy.type));
    aidl.hal.name = VALUE_OR_RETURN(legacy2aidl_string(legacy.name, sizeof(legacy.name)));

    if (legacy.num_audio_profiles > std::size(legacy.audio_profiles)) {
        return unexpected(BAD_VALUE);
    }
    const bool isInput = VALUE_OR_RETURN(direction(legacy.role, legacy.type)) == Direction::INPUT;
    RETURN_IF_ERROR(
            convertRange(legacy.audio_profiles, legacy.audio_profiles + legacy.num_audio_profiles,
                         std::back_inserter(aidl.hal.profiles),
                         [isInput](const audio_profile& p) {
                             return legacy2aidl_audio_profile_AudioProfile(p, isInput);
                         }));

    if (legacy.num_extra_audio_descriptors > std::size(legacy.extra_audio_descriptors)) {
        return unexpected(BAD_VALUE);
    }
    aidl.sys.profiles.resize(legacy.num_audio_profiles);
    RETURN_IF_ERROR(
            convertRange(legacy.extra_audio_descriptors,
                    legacy.extra_audio_descriptors + legacy.num_extra_audio_descriptors,
                    std::back_inserter(aidl.hal.extraAudioDescriptors),
                    legacy2aidl_audio_extra_audio_descriptor_ExtraAudioDescriptor));

    if (legacy.num_gains > std::size(legacy.gains)) {
        return unexpected(BAD_VALUE);
    }
    RETURN_IF_ERROR(
            convertRange(legacy.gains, legacy.gains + legacy.num_gains,
                         std::back_inserter(aidl.hal.gains),
                         [isInput](const audio_gain& g) {
                             return legacy2aidl_audio_gain_AudioGain(g, isInput);
                         }));
    aidl.sys.gains.resize(legacy.num_gains);

    aidl.sys.activeConfig = VALUE_OR_RETURN(
            legacy2aidl_audio_port_config_AudioPortConfig(legacy.active_config));
    aidl.sys.activeConfig.hal.portId = aidl.hal.id;
    RETURN_IF_ERROR(
            legacy2aidl_AudioPortExt(legacy.ext, legacy.type, &aidl.hal.ext, &aidl.sys.ext));
    return aidl;
}

ConversionResult<audio_mode_t>
aidl2legacy_AudioMode_audio_mode_t(AudioMode aidl) {
    switch (aidl) {
        case AudioMode::SYS_RESERVED_INVALID:
            return AUDIO_MODE_INVALID;
        case AudioMode::SYS_RESERVED_CURRENT:
            return AUDIO_MODE_CURRENT;
        case AudioMode::NORMAL:
            return AUDIO_MODE_NORMAL;
        case AudioMode::RINGTONE:
            return AUDIO_MODE_RINGTONE;
        case AudioMode::IN_CALL:
            return AUDIO_MODE_IN_CALL;
        case AudioMode::IN_COMMUNICATION:
            return AUDIO_MODE_IN_COMMUNICATION;
        case AudioMode::CALL_SCREEN:
            return AUDIO_MODE_CALL_SCREEN;
        case AudioMode::SYS_RESERVED_CALL_REDIRECT:
            return AUDIO_MODE_CALL_REDIRECT;
        case AudioMode::SYS_RESERVED_COMMUNICATION_REDIRECT:
            return AUDIO_MODE_COMMUNICATION_REDIRECT;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioMode>
legacy2aidl_audio_mode_t_AudioMode(audio_mode_t legacy) {
    switch (legacy) {
        case AUDIO_MODE_INVALID:
            return AudioMode::SYS_RESERVED_INVALID;
        case AUDIO_MODE_CURRENT:
            return AudioMode::SYS_RESERVED_CURRENT;
        case AUDIO_MODE_NORMAL:
            return AudioMode::NORMAL;
        case AUDIO_MODE_RINGTONE:
            return AudioMode::RINGTONE;
        case AUDIO_MODE_IN_CALL:
            return AudioMode::IN_CALL;
        case AUDIO_MODE_IN_COMMUNICATION:
            return AudioMode::IN_COMMUNICATION;
        case AUDIO_MODE_CALL_SCREEN:
            return AudioMode::CALL_SCREEN;
        case AUDIO_MODE_CALL_REDIRECT:
            return AudioMode::SYS_RESERVED_CALL_REDIRECT;
        case AUDIO_MODE_COMMUNICATION_REDIRECT:
            return AudioMode::SYS_RESERVED_COMMUNICATION_REDIRECT;
        case AUDIO_MODE_CNT:
            break;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_unique_id_use_t>
aidl2legacy_AudioUniqueIdUse_audio_unique_id_use_t(media::AudioUniqueIdUse aidl) {
    switch (aidl) {
        case media::AudioUniqueIdUse::UNSPECIFIED:
            return AUDIO_UNIQUE_ID_USE_UNSPECIFIED;
        case media::AudioUniqueIdUse::SESSION:
            return AUDIO_UNIQUE_ID_USE_SESSION;
        case media::AudioUniqueIdUse::MODULE:
            return AUDIO_UNIQUE_ID_USE_MODULE;
        case media::AudioUniqueIdUse::EFFECT:
            return AUDIO_UNIQUE_ID_USE_EFFECT;
        case media::AudioUniqueIdUse::PATCH:
            return AUDIO_UNIQUE_ID_USE_PATCH;
        case media::AudioUniqueIdUse::OUTPUT:
            return AUDIO_UNIQUE_ID_USE_OUTPUT;
        case media::AudioUniqueIdUse::INPUT:
            return AUDIO_UNIQUE_ID_USE_INPUT;
        case media::AudioUniqueIdUse::CLIENT:
            return AUDIO_UNIQUE_ID_USE_CLIENT;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioUniqueIdUse>
legacy2aidl_audio_unique_id_use_t_AudioUniqueIdUse(audio_unique_id_use_t legacy) {
    switch (legacy) {
        case AUDIO_UNIQUE_ID_USE_UNSPECIFIED:
            return media::AudioUniqueIdUse::UNSPECIFIED;
        case AUDIO_UNIQUE_ID_USE_SESSION:
            return media::AudioUniqueIdUse::SESSION;
        case AUDIO_UNIQUE_ID_USE_MODULE:
            return media::AudioUniqueIdUse::MODULE;
        case AUDIO_UNIQUE_ID_USE_EFFECT:
            return media::AudioUniqueIdUse::EFFECT;
        case AUDIO_UNIQUE_ID_USE_PATCH:
            return media::AudioUniqueIdUse::PATCH;
        case AUDIO_UNIQUE_ID_USE_OUTPUT:
            return media::AudioUniqueIdUse::OUTPUT;
        case AUDIO_UNIQUE_ID_USE_INPUT:
            return media::AudioUniqueIdUse::INPUT;
        case AUDIO_UNIQUE_ID_USE_CLIENT:
            return media::AudioUniqueIdUse::CLIENT;
        case AUDIO_UNIQUE_ID_USE_MAX:
            break;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<volume_group_t>
aidl2legacy_int32_t_volume_group_t(int32_t aidl) {
    return convertReinterpret<volume_group_t>(aidl);
}

ConversionResult<int32_t>
legacy2aidl_volume_group_t_int32_t(volume_group_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<product_strategy_t>
aidl2legacy_int32_t_product_strategy_t(int32_t aidl) {
    return convertReinterpret<product_strategy_t>(aidl);
}

ConversionResult<int32_t>
legacy2aidl_product_strategy_t_int32_t(product_strategy_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_dual_mono_mode_t>
aidl2legacy_AudioDualMonoMode_audio_dual_mono_mode_t(media::AudioDualMonoMode aidl) {
    switch (aidl) {
        case media::AudioDualMonoMode::OFF:
            return AUDIO_DUAL_MONO_MODE_OFF;
        case media::AudioDualMonoMode::LR:
            return AUDIO_DUAL_MONO_MODE_LR;
        case media::AudioDualMonoMode::LL:
            return AUDIO_DUAL_MONO_MODE_LL;
        case media::AudioDualMonoMode::RR:
            return AUDIO_DUAL_MONO_MODE_RR;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioDualMonoMode>
legacy2aidl_audio_dual_mono_mode_t_AudioDualMonoMode(audio_dual_mono_mode_t legacy) {
    switch (legacy) {
        case AUDIO_DUAL_MONO_MODE_OFF:
            return media::AudioDualMonoMode::OFF;
        case AUDIO_DUAL_MONO_MODE_LR:
            return media::AudioDualMonoMode::LR;
        case AUDIO_DUAL_MONO_MODE_LL:
            return media::AudioDualMonoMode::LL;
        case AUDIO_DUAL_MONO_MODE_RR:
            return media::AudioDualMonoMode::RR;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_timestretch_fallback_mode_t>
aidl2legacy_int32_t_audio_timestretch_fallback_mode_t(int32_t aidl) {
    return convertReinterpret<audio_timestretch_fallback_mode_t>(aidl);
}

ConversionResult<int32_t>
legacy2aidl_audio_timestretch_fallback_mode_t_int32_t(audio_timestretch_fallback_mode_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_timestretch_stretch_mode_t>
aidl2legacy_int32_t_audio_timestretch_stretch_mode_t(int32_t aidl) {
    return convertReinterpret<audio_timestretch_stretch_mode_t>(aidl);
}

ConversionResult<int32_t>
legacy2aidl_audio_timestretch_stretch_mode_t_int32_t(audio_timestretch_stretch_mode_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<audio_playback_rate_t>
aidl2legacy_AudioPlaybackRate_audio_playback_rate_t(const media::AudioPlaybackRate& aidl) {
    audio_playback_rate_t legacy;
    legacy.mSpeed = aidl.speed;
    legacy.mPitch = aidl.pitch;
    legacy.mFallbackMode = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_timestretch_fallback_mode_t(aidl.fallbackMode));
    legacy.mStretchMode = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_timestretch_stretch_mode_t(aidl.stretchMode));
    return legacy;
}

ConversionResult<media::AudioPlaybackRate>
legacy2aidl_audio_playback_rate_t_AudioPlaybackRate(const audio_playback_rate_t& legacy) {
    media::AudioPlaybackRate aidl;
    aidl.speed = legacy.mSpeed;
    aidl.pitch = legacy.mPitch;
    aidl.fallbackMode = VALUE_OR_RETURN(
            legacy2aidl_audio_timestretch_fallback_mode_t_int32_t(legacy.mFallbackMode));
    aidl.stretchMode = VALUE_OR_RETURN(
            legacy2aidl_audio_timestretch_stretch_mode_t_int32_t(legacy.mStretchMode));
    return aidl;
}

ConversionResult<audio_standard_t>
aidl2legacy_AudioStandard_audio_standard_t(AudioStandard aidl) {
    switch (aidl) {
        case AudioStandard::NONE:
            return AUDIO_STANDARD_NONE;
        case AudioStandard::EDID:
            return AUDIO_STANDARD_EDID;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioStandard>
legacy2aidl_audio_standard_t_AudioStandard(audio_standard_t legacy) {
    switch (legacy) {
        case AUDIO_STANDARD_NONE:
            return AudioStandard::NONE;
        case AUDIO_STANDARD_EDID:
            return AudioStandard::EDID;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_extra_audio_descriptor>
aidl2legacy_ExtraAudioDescriptor_audio_extra_audio_descriptor(
        const ExtraAudioDescriptor& aidl) {
    audio_extra_audio_descriptor legacy;
    legacy.standard = VALUE_OR_RETURN(aidl2legacy_AudioStandard_audio_standard_t(aidl.standard));
    if (aidl.audioDescriptor.size() > EXTRA_AUDIO_DESCRIPTOR_SIZE) {
        return unexpected(BAD_VALUE);
    }
    legacy.descriptor_length = aidl.audioDescriptor.size();
    std::copy(aidl.audioDescriptor.begin(), aidl.audioDescriptor.end(),
              std::begin(legacy.descriptor));
    legacy.encapsulation_type =
            VALUE_OR_RETURN(aidl2legacy_AudioEncapsulationType_audio_encapsulation_type_t(
                    aidl.encapsulationType));
    return legacy;
}

ConversionResult<ExtraAudioDescriptor>
legacy2aidl_audio_extra_audio_descriptor_ExtraAudioDescriptor(
        const audio_extra_audio_descriptor& legacy) {
    ExtraAudioDescriptor aidl;
    aidl.standard = VALUE_OR_RETURN(legacy2aidl_audio_standard_t_AudioStandard(legacy.standard));
    if (legacy.descriptor_length > EXTRA_AUDIO_DESCRIPTOR_SIZE) {
        return unexpected(BAD_VALUE);
    }
    aidl.audioDescriptor.resize(legacy.descriptor_length);
    std::copy(legacy.descriptor, legacy.descriptor + legacy.descriptor_length,
              aidl.audioDescriptor.begin());
    aidl.encapsulationType =
            VALUE_OR_RETURN(legacy2aidl_audio_encapsulation_type_t_AudioEncapsulationType(
                    legacy.encapsulation_type));
    return aidl;
}

ConversionResult<audio_encapsulation_type_t>
aidl2legacy_AudioEncapsulationType_audio_encapsulation_type_t(
        const AudioEncapsulationType& aidl) {
    switch (aidl) {
        case AudioEncapsulationType::NONE:
            return AUDIO_ENCAPSULATION_TYPE_NONE;
        case AudioEncapsulationType::IEC61937:
            return AUDIO_ENCAPSULATION_TYPE_IEC61937;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioEncapsulationType>
legacy2aidl_audio_encapsulation_type_t_AudioEncapsulationType(
        const audio_encapsulation_type_t & legacy) {
    switch (legacy) {
        case AUDIO_ENCAPSULATION_TYPE_NONE:
            return AudioEncapsulationType::NONE;
        case AUDIO_ENCAPSULATION_TYPE_IEC61937:
            return AudioEncapsulationType::IEC61937;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<TrackSecondaryOutputInfoPair>
aidl2legacy_TrackSecondaryOutputInfo_TrackSecondaryOutputInfoPair(
        const media::TrackSecondaryOutputInfo& aidl) {
    TrackSecondaryOutputInfoPair trackSecondaryOutputInfoPair;
    trackSecondaryOutputInfoPair.first =
            VALUE_OR_RETURN(aidl2legacy_int32_t_audio_port_handle_t(aidl.portId));
    trackSecondaryOutputInfoPair.second =
            VALUE_OR_RETURN(convertContainer<std::vector<audio_port_handle_t>>(
                    aidl.secondaryOutputIds, aidl2legacy_int32_t_audio_io_handle_t));
    return trackSecondaryOutputInfoPair;
}

ConversionResult<media::TrackSecondaryOutputInfo>
legacy2aidl_TrackSecondaryOutputInfoPair_TrackSecondaryOutputInfo(
        const TrackSecondaryOutputInfoPair& legacy) {
    media::TrackSecondaryOutputInfo trackSecondaryOutputInfo;
    trackSecondaryOutputInfo.portId =
            VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(legacy.first));
    trackSecondaryOutputInfo.secondaryOutputIds =
            VALUE_OR_RETURN(convertContainer<std::vector<int32_t>>(
                    legacy.second, legacy2aidl_audio_io_handle_t_int32_t));
    return trackSecondaryOutputInfo;
}

ConversionResult<audio_direct_mode_t>
aidl2legacy_AudioDirectMode_audio_direct_mode_t(media::AudioDirectMode aidl) {
    switch (aidl) {
        case media::AudioDirectMode::NONE:
            return AUDIO_DIRECT_NOT_SUPPORTED;
        case media::AudioDirectMode::OFFLOAD:
            return AUDIO_DIRECT_OFFLOAD_SUPPORTED;
        case media::AudioDirectMode::OFFLOAD_GAPLESS:
            return AUDIO_DIRECT_OFFLOAD_GAPLESS_SUPPORTED;
        case media::AudioDirectMode::BITSTREAM:
            return AUDIO_DIRECT_BITSTREAM_SUPPORTED;
    }
    return unexpected(BAD_VALUE);
}
ConversionResult<media::AudioDirectMode>
legacy2aidl_audio_direct_mode_t_AudioDirectMode(audio_direct_mode_t legacy) {
    switch (legacy) {
        case AUDIO_DIRECT_NOT_SUPPORTED:
            return media::AudioDirectMode::NONE;
        case AUDIO_DIRECT_OFFLOAD_SUPPORTED:
            return media::AudioDirectMode::OFFLOAD;
        case AUDIO_DIRECT_OFFLOAD_GAPLESS_SUPPORTED:
            return media::AudioDirectMode::OFFLOAD_GAPLESS;
        case AUDIO_DIRECT_BITSTREAM_SUPPORTED:
            return media::AudioDirectMode::BITSTREAM;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_direct_mode_t> aidl2legacy_int32_t_audio_direct_mode_t_mask(int32_t aidl) {
    using LegacyMask = std::underlying_type_t<audio_direct_mode_t>;

    LegacyMask converted = VALUE_OR_RETURN(
            (convertBitmask<LegacyMask, int32_t, audio_direct_mode_t, media::AudioDirectMode>(
                    aidl, aidl2legacy_AudioDirectMode_audio_direct_mode_t,
                    indexToEnum_index<media::AudioDirectMode>,
                    enumToMask_bitmask<LegacyMask, audio_direct_mode_t>)));
    return static_cast<audio_direct_mode_t>(converted);
}
ConversionResult<int32_t> legacy2aidl_audio_direct_mode_t_int32_t_mask(audio_direct_mode_t legacy) {
    using LegacyMask = std::underlying_type_t<audio_direct_mode_t>;

    LegacyMask legacyMask = static_cast<LegacyMask>(legacy);
    return convertBitmask<int32_t, LegacyMask, media::AudioDirectMode, audio_direct_mode_t>(
            legacyMask, legacy2aidl_audio_direct_mode_t_AudioDirectMode,
            indexToEnum_bitmask<audio_direct_mode_t>,
            enumToMask_index<int32_t, media::AudioDirectMode>);
}

ConversionResult<audio_latency_mode_t>
aidl2legacy_LatencyMode_audio_latency_mode_t(media::LatencyMode aidl) {
    switch (aidl) {
        case media::LatencyMode::FREE:
            return AUDIO_LATENCY_MODE_FREE;
        case media::LatencyMode::LOW:
            return AUDIO_LATENCY_MODE_LOW;
    }
    return unexpected(BAD_VALUE);
}
ConversionResult<media::LatencyMode>
legacy2aidl_audio_latency_mode_t_LatencyMode(audio_latency_mode_t legacy) {
    switch (legacy) {
        case AUDIO_LATENCY_MODE_FREE:
            return media::LatencyMode::FREE;
        case AUDIO_LATENCY_MODE_LOW:
            return media::LatencyMode::LOW;
    }
    return unexpected(BAD_VALUE);
}
}  // namespace android
