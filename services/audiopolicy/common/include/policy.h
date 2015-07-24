/*
 * Copyright (C) 2015 The Android Open Source Project
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
#include <vector>

#include <media/AudioContainers.h>

namespace android {

using StreamTypeVector = std::vector<audio_stream_type_t>;

static const audio_attributes_t defaultAttr = AUDIO_ATTRIBUTES_INITIALIZER;

} // namespace android

static const audio_format_t gDynamicFormat = AUDIO_FORMAT_DEFAULT;

static const uint32_t SONIFICATION_RESPECTFUL_AFTER_MUSIC_DELAY = 5000;

// For mixed output and inputs, the policy will use max mixer sampling rates.
// Do not limit sampling rate otherwise
#define SAMPLE_RATE_HZ_MAX 384000

// Used when a client opens a capture stream, without specifying a desired sample rate.
#define SAMPLE_RATE_HZ_DEFAULT 48000

// For mixed output and inputs, the policy will use max mixer channel count.
// Do not limit channel count otherwise
#define MAX_MIXER_CHANNEL_COUNT FCC_8

/**
 * Alias to AUDIO_DEVICE_OUT_DEFAULT defined for clarification when this value is used by volume
 * control APIs (e.g setStreamVolumeIndex().
 */
#define AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME AUDIO_DEVICE_OUT_DEFAULT


/**
 * Check if the state given correspond to an in call state.
 * @TODO find a better name for widely call state
 *
 * @param[in] state to consider
 *
 * @return true if given state represents a device in a telephony or VoIP call
 */
static inline bool is_state_in_call(int state)
{
    return (state == AUDIO_MODE_IN_CALL) || (state == AUDIO_MODE_IN_COMMUNICATION);
}

/**
 * Check whether the output device type is one
 * where addresses are used to distinguish between one connected device and another
 *
 * @param[in] device to consider
 *
 * @return true if the device needs distinguish on address, false otherwise..
 */
static inline bool apm_audio_out_device_distinguishes_on_address(audio_devices_t device)
{
    return device == AUDIO_DEVICE_OUT_REMOTE_SUBMIX ||
           device == AUDIO_DEVICE_OUT_BUS;
}

/**
 * Check whether the input device type is one
 * where addresses are used to distinguish between one connected device and another
 *
 * @param[in] device to consider
 *
 * @return true if the device needs distinguish on address, false otherwise..
 */
static inline bool apm_audio_in_device_distinguishes_on_address(audio_devices_t device)
{
    return device == AUDIO_DEVICE_IN_REMOTE_SUBMIX ||
           device == AUDIO_DEVICE_IN_BUS;
}

/**
 * Check whether the device type is one
 * where addresses are used to distinguish between one connected device and another
 *
 * @param[in] device to consider
 *
 * @return true if the device needs distinguish on address, false otherwise..
 */
static inline bool device_distinguishes_on_address(audio_devices_t device)
{
    return apm_audio_in_device_distinguishes_on_address(device) ||
           apm_audio_out_device_distinguishes_on_address(device);
}

/**
 * Check whether audio device has encoding capability.
 *
 * @param[in] device to consider
 *
 * @return true if device has encoding capability, false otherwise..
 */
static inline bool device_has_encoding_capability(audio_devices_t device)
{
    return audio_is_a2dp_out_device(device);
}

/**
 * Returns the priority of a given audio source for capture. The priority is used when more than one
 * capture session is active on a given input stream to determine which session drives routing and
 * effect configuration.
 *
 * @param[in] inputSource to consider. Valid sources are:
 * - AUDIO_SOURCE_VOICE_COMMUNICATION
 * - AUDIO_SOURCE_CAMCORDER
 * - AUDIO_SOURCE_VOICE_PERFORMANCE
 * - AUDIO_SOURCE_UNPROCESSED
 * - AUDIO_SOURCE_MIC
 * - AUDIO_SOURCE_ECHO_REFERENCE
 * - AUDIO_SOURCE_FM_TUNER
 * - AUDIO_SOURCE_VOICE_RECOGNITION
 * - AUDIO_SOURCE_HOTWORD
 *
 * @return the corresponding input source priority or 0 if priority is irrelevant for this source.
 *      This happens when the specified source cannot share a given input stream (e.g remote submix)
 *      The higher the value, the higher the priority.
 */
static inline int32_t source_priority(audio_source_t inputSource)
{
    switch (inputSource) {
    case AUDIO_SOURCE_VOICE_COMMUNICATION:
        return 9;
    case AUDIO_SOURCE_CAMCORDER:
        return 8;
    case AUDIO_SOURCE_VOICE_PERFORMANCE:
        return 7;
    case AUDIO_SOURCE_UNPROCESSED:
        return 6;
    case AUDIO_SOURCE_MIC:
        return 5;
    case AUDIO_SOURCE_ECHO_REFERENCE:
        return 4;
    case AUDIO_SOURCE_FM_TUNER:
        return 3;
    case AUDIO_SOURCE_VOICE_RECOGNITION:
        return 2;
    case AUDIO_SOURCE_HOTWORD:
        return 1;
    default:
        break;
    }
    return 0;
}

/* Indicates if audio formats are equivalent when considering a match between
 * audio HAL supported formats and client requested formats
 */
static inline bool audio_formats_match(audio_format_t format1,
                                       audio_format_t format2)
{
    if (audio_is_linear_pcm(format1) &&
            (audio_bytes_per_sample(format1) > 2) &&
            audio_is_linear_pcm(format2) &&
            (audio_bytes_per_sample(format2) > 2)) {
        return true;
    }
    return format1 == format2;
}

/**
 * @brief hasStream checks if a given stream type is found in the list of streams
 * @param streams collection of stream types to consider.
 * @param streamType to consider
 * @return true if voice stream is found in the given streams, false otherwise
 */
static inline bool hasStream(const android::StreamTypeVector &streams,
                             audio_stream_type_t streamType)
{
    return std::find(begin(streams), end(streams), streamType) != end(streams);
}

/**
 * @brief hasVoiceStream checks if a voice stream is found in the list of streams
 * @param streams collection to consider.
 * @return true if voice stream is found in the given streams, false otherwise
 */
static inline bool hasVoiceStream(const android::StreamTypeVector &streams)
{
    return hasStream(streams, AUDIO_STREAM_VOICE_CALL);
}

/**
 * @brief extract one device relevant from multiple device selection
 * @param deviceTypes collection of audio device type
 * @return the device type that is selected
 */
static inline audio_devices_t apm_extract_one_audio_device(
        const android::DeviceTypeSet& deviceTypes) {
    if (deviceTypes.empty()) {
        return AUDIO_DEVICE_NONE;
    } else if (deviceTypes.size() == 1) {
        return *(deviceTypes.begin());
    } else {
        // Multiple device selection is either:
        //  - speaker + one other device: give priority to speaker in this case.
        //  - one A2DP device + another device: happens with duplicated output. In this case
        // retain the device on the A2DP output as the other must not correspond to an active
        // selection if not the speaker.
        //  - HDMI-CEC system audio mode only output: give priority to available item in order.
        if (deviceTypes.count(AUDIO_DEVICE_OUT_SPEAKER) != 0) {
            return AUDIO_DEVICE_OUT_SPEAKER;
        } else if (deviceTypes.count(AUDIO_DEVICE_OUT_SPEAKER_SAFE) != 0) {
            return AUDIO_DEVICE_OUT_SPEAKER_SAFE;
        } else if (deviceTypes.count(AUDIO_DEVICE_OUT_HDMI_ARC) != 0) {
            return AUDIO_DEVICE_OUT_HDMI_ARC;
        } else if (deviceTypes.count(AUDIO_DEVICE_OUT_AUX_LINE) != 0) {
            return AUDIO_DEVICE_OUT_AUX_LINE;
        } else if (deviceTypes.count(AUDIO_DEVICE_OUT_SPDIF) != 0) {
            return AUDIO_DEVICE_OUT_SPDIF;
        } else {
            std::vector<audio_devices_t> a2dpDevices = android::Intersection(
                    deviceTypes, android::getAudioDeviceOutAllA2dpSet());
            if (a2dpDevices.empty() || a2dpDevices.size() > 1) {
                ALOGW("%s invalid device combination: %s",
                      __func__, android::dumpDeviceTypes(deviceTypes).c_str());
            }
            return a2dpDevices.empty() ? AUDIO_DEVICE_NONE : a2dpDevices[0];
        }
    }
}