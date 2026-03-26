/*
 * Copyright 2016 The Android Open Source Project
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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0

#include "AAudioUtilities.h"

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>
#include <android/media/audio/common/AudioMMapPolicy.h>
#include <cutils/properties.h>
#include <sys/types.h>
#include <system/audio.h>
#include <utils/Errors.h>
#include <utils/Log.h>
// go/keep-sorted end

// go/keep-sorted start
#include <assert.h>
#include <math.h>
#include <stdint.h>
// go/keep-sorted end

#include "AudioGlobal.h"

using namespace android;

using android::media::audio::common::AudioMMapPolicy;
using android::media::audio::common::AudioMMapPolicyInfo;
using android::media::audio::common::FlushFromFrameAccuracy;

status_t AAudioConvert_aaudioToAndroidStatus(
        aaudio_result_t result,
        const std::map<aaudio_result_t, android::status_t>& customizedMap) {
    // First check if `result` is in the customized map.
    if (const auto it = customizedMap.find(result); it != customizedMap.end()) {
        return it->second;
    }

    // This covers the case for AAUDIO_OK and for positive results.
    if (result >= 0) {
        return result;
    }
    status_t status;
    switch (result) {
    case AAUDIO_ERROR_DISCONNECTED:
    case AAUDIO_ERROR_NO_SERVICE:
        status = DEAD_OBJECT;
        break;
    case AAUDIO_ERROR_INVALID_HANDLE:
        status = BAD_TYPE;
        break;
    case AAUDIO_ERROR_INVALID_STATE:
        status = INVALID_OPERATION;
        break;
    case AAUDIO_ERROR_INVALID_RATE:
    case AAUDIO_ERROR_INVALID_FORMAT:
    case AAUDIO_ERROR_ILLEGAL_ARGUMENT:
    case AAUDIO_ERROR_OUT_OF_RANGE:
        status = BAD_VALUE;
        break;
    case AAUDIO_ERROR_WOULD_BLOCK:
        status = WOULD_BLOCK;
        break;
    case AAUDIO_ERROR_NULL:
        status = UNEXPECTED_NULL;
        break;
    case AAUDIO_ERROR_UNAVAILABLE:
        status = NOT_ENOUGH_DATA;
        break;

    // TODO translate these result codes
    case AAUDIO_ERROR_INTERNAL:
    case AAUDIO_ERROR_UNIMPLEMENTED:
    case AAUDIO_ERROR_NO_FREE_HANDLES:
    case AAUDIO_ERROR_NO_MEMORY:
    case AAUDIO_ERROR_TIMEOUT:
    default:
        status = UNKNOWN_ERROR;
        break;
    }
    return status;
}

aaudio_result_t AAudioConvert_androidToAAudioResult(
        status_t status,
        const std::map<android::status_t, aaudio_result_t>& customizedMap) {
    // First check if `status` is in the customized map.
    if (const auto it = customizedMap.find(status); it != customizedMap.end()) {
        return it->second;
    }

    // This covers the case for OK and for positive result.
    if (status >= 0) {
        return status;
    }
    aaudio_result_t result;
    switch (status) {
    case BAD_TYPE:
        result = AAUDIO_ERROR_INVALID_HANDLE;
        break;
    case DEAD_OBJECT:
        result = AAUDIO_ERROR_NO_SERVICE;
        break;
    case INVALID_OPERATION:
        result = AAUDIO_ERROR_INVALID_STATE;
        break;
    case UNEXPECTED_NULL:
        result = AAUDIO_ERROR_NULL;
        break;
    case BAD_VALUE:
        result = AAUDIO_ERROR_ILLEGAL_ARGUMENT;
        break;
    case WOULD_BLOCK:
        result = AAUDIO_ERROR_WOULD_BLOCK;
        break;
    case NOT_ENOUGH_DATA:
        result = AAUDIO_ERROR_UNAVAILABLE;
        break;
    default:
        result = AAUDIO_ERROR_INTERNAL;
        break;
    }
    return result;
}

audio_session_t AAudioConvert_aaudioToAndroidSessionId(aaudio_session_id_t sessionId) {
    // If not a regular sessionId then convert to a safe value of AUDIO_SESSION_ALLOCATE.
    return (sessionId == AAUDIO_SESSION_ID_ALLOCATE || sessionId == AAUDIO_SESSION_ID_NONE)
           ? AUDIO_SESSION_ALLOCATE
           : (audio_session_t) sessionId;
}

audio_format_t AAudioConvert_aaudioToAndroidDataFormat(aaudio_format_t aaudioFormat) {
    audio_format_t androidFormat;
    switch (aaudioFormat) {
    case AAUDIO_FORMAT_UNSPECIFIED:
        androidFormat = AUDIO_FORMAT_DEFAULT;
        break;
    case AAUDIO_FORMAT_PCM_I16:
        androidFormat = AUDIO_FORMAT_PCM_16_BIT;
        break;
    case AAUDIO_FORMAT_PCM_FLOAT:
        androidFormat = AUDIO_FORMAT_PCM_FLOAT;
        break;
    case AAUDIO_FORMAT_PCM_I24_PACKED:
        androidFormat = AUDIO_FORMAT_PCM_24_BIT_PACKED;
        break;
    case AAUDIO_FORMAT_PCM_I32:
        androidFormat = AUDIO_FORMAT_PCM_32_BIT;
        break;
    case AAUDIO_FORMAT_IEC61937:
        androidFormat = AUDIO_FORMAT_IEC61937;
        break;
    case AAUDIO_FORMAT_MP3:
        androidFormat = AUDIO_FORMAT_MP3;
        break;
    case AAUDIO_FORMAT_AAC_LC:
        androidFormat = AUDIO_FORMAT_AAC_LC;
        break;
    case AAUDIO_FORMAT_AAC_HE_V1:
        androidFormat = AUDIO_FORMAT_AAC_HE_V1;
        break;
    case AAUDIO_FORMAT_AAC_HE_V2:
        androidFormat = AUDIO_FORMAT_AAC_HE_V2;
        break;
    case AAUDIO_FORMAT_AAC_ELD:
        androidFormat = AUDIO_FORMAT_AAC_ELD;
        break;
    case AAUDIO_FORMAT_AAC_XHE:
        androidFormat = AUDIO_FORMAT_AAC_XHE;
        break;
    case AAUDIO_FORMAT_OPUS:
        androidFormat = AUDIO_FORMAT_OPUS;
        break;
    default:
        androidFormat = AUDIO_FORMAT_INVALID;
        ALOGE("%s() 0x%08X unrecognized", __func__, aaudioFormat);
        break;
    }
    return androidFormat;
}

aaudio_format_t AAudioConvert_androidToAAudioDataFormat(audio_format_t androidFormat) {
    aaudio_format_t aaudioFormat;
    switch (androidFormat) {
    case AUDIO_FORMAT_DEFAULT:
        aaudioFormat = AAUDIO_FORMAT_UNSPECIFIED;
        break;
    case AUDIO_FORMAT_PCM_16_BIT:
        aaudioFormat = AAUDIO_FORMAT_PCM_I16;
        break;
    case AUDIO_FORMAT_PCM_FLOAT:
        aaudioFormat = AAUDIO_FORMAT_PCM_FLOAT;
        break;
    case AUDIO_FORMAT_PCM_24_BIT_PACKED:
        aaudioFormat = AAUDIO_FORMAT_PCM_I24_PACKED;
        break;
    case AUDIO_FORMAT_PCM_32_BIT:
        aaudioFormat = AAUDIO_FORMAT_PCM_I32;
        break;
    case AUDIO_FORMAT_IEC61937:
        aaudioFormat = AAUDIO_FORMAT_IEC61937;
        break;
    case AUDIO_FORMAT_MP3:
        aaudioFormat = AAUDIO_FORMAT_MP3;
        break;
    case AUDIO_FORMAT_AAC_LC:
        aaudioFormat = AAUDIO_FORMAT_AAC_LC;
        break;
    case AUDIO_FORMAT_AAC_HE_V1:
        aaudioFormat = AAUDIO_FORMAT_AAC_HE_V1;
        break;
    case AUDIO_FORMAT_AAC_HE_V2:
        aaudioFormat = AAUDIO_FORMAT_AAC_HE_V2;
        break;
    case AUDIO_FORMAT_AAC_ELD:
        aaudioFormat = AAUDIO_FORMAT_AAC_ELD;
        break;
    case AUDIO_FORMAT_AAC_XHE:
        aaudioFormat = AAUDIO_FORMAT_AAC_XHE;
        break;
    case AUDIO_FORMAT_OPUS:
        aaudioFormat = AAUDIO_FORMAT_OPUS;
        break;
    default:
        aaudioFormat = AAUDIO_FORMAT_INVALID;
        ALOGE("%s() 0x%08X unrecognized", __func__, androidFormat);
        break;
    }
    return aaudioFormat;
}

aaudio_format_t AAudioConvert_androidToNearestAAudioDataFormat(audio_format_t androidFormat) {
    // Special case AUDIO_FORMAT_PCM_8_24_BIT because this function should be used to find the
    // resolution of the data format. Setting AUDIO_FORMAT_PCM_8_24_BIT directly is not available
    // from AAudio but hardware may use AUDIO_FORMAT_PCM_8_24_BIT under the hood.
    if (androidFormat == AUDIO_FORMAT_PCM_8_24_BIT) {
        ALOGD("%s() converting 8.24 to 24 bit packed", __func__);
        return AAUDIO_FORMAT_PCM_I24_PACKED;
    }
    return AAudioConvert_androidToAAudioDataFormat(androidFormat);
}

// Make a message string from the condition.
#define STATIC_ASSERT(condition) static_assert(condition, #condition)

audio_usage_t AAudioConvert_usageToInternal(aaudio_usage_t usage) {
    // The public aaudio_content_type_t constants are supposed to have the same
    // values as the internal audio_content_type_t values.
    STATIC_ASSERT(AAUDIO_USAGE_MEDIA == AUDIO_USAGE_MEDIA);
    STATIC_ASSERT(AAUDIO_USAGE_VOICE_COMMUNICATION == AUDIO_USAGE_VOICE_COMMUNICATION);
    STATIC_ASSERT(AAUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING
                  == AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING);
    STATIC_ASSERT(AAUDIO_USAGE_ALARM == AUDIO_USAGE_ALARM);
    STATIC_ASSERT(AAUDIO_USAGE_NOTIFICATION == AUDIO_USAGE_NOTIFICATION);
    STATIC_ASSERT(AAUDIO_USAGE_NOTIFICATION_RINGTONE
                  == AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE);
    STATIC_ASSERT(AAUDIO_USAGE_NOTIFICATION_EVENT == AUDIO_USAGE_NOTIFICATION_EVENT);
    STATIC_ASSERT(AAUDIO_USAGE_ASSISTANCE_ACCESSIBILITY == AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY);
    STATIC_ASSERT(AAUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE
                  == AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE);
    STATIC_ASSERT(AAUDIO_USAGE_ASSISTANCE_SONIFICATION == AUDIO_USAGE_ASSISTANCE_SONIFICATION);
    STATIC_ASSERT(AAUDIO_USAGE_GAME == AUDIO_USAGE_GAME);
    STATIC_ASSERT(AAUDIO_USAGE_ASSISTANT == AUDIO_USAGE_ASSISTANT);
    STATIC_ASSERT(AAUDIO_SYSTEM_USAGE_EMERGENCY == AUDIO_USAGE_EMERGENCY);
    STATIC_ASSERT(AAUDIO_SYSTEM_USAGE_SAFETY == AUDIO_USAGE_SAFETY);
    STATIC_ASSERT(AAUDIO_SYSTEM_USAGE_VEHICLE_STATUS == AUDIO_USAGE_VEHICLE_STATUS);
    STATIC_ASSERT(AAUDIO_SYSTEM_USAGE_ANNOUNCEMENT == AUDIO_USAGE_ANNOUNCEMENT);
    if (usage == AAUDIO_UNSPECIFIED) {
        usage = AAUDIO_USAGE_MEDIA;
    }
    return (audio_usage_t) usage; // same value
}

audio_content_type_t AAudioConvert_contentTypeToInternal(aaudio_content_type_t contentType) {
    // The public aaudio_content_type_t constants are supposed to have the same
    // values as the internal audio_content_type_t values.
    STATIC_ASSERT(AAUDIO_CONTENT_TYPE_MUSIC == AUDIO_CONTENT_TYPE_MUSIC);
    STATIC_ASSERT(AAUDIO_CONTENT_TYPE_SPEECH == AUDIO_CONTENT_TYPE_SPEECH);
    STATIC_ASSERT(AAUDIO_CONTENT_TYPE_SONIFICATION == AUDIO_CONTENT_TYPE_SONIFICATION);
    STATIC_ASSERT(AAUDIO_CONTENT_TYPE_MOVIE == AUDIO_CONTENT_TYPE_MOVIE);
    if (contentType == AAUDIO_UNSPECIFIED) {
        contentType = AAUDIO_CONTENT_TYPE_MUSIC;
    }
    return (audio_content_type_t) contentType; // same value
}

audio_source_t AAudioConvert_inputPresetToAudioSource(aaudio_input_preset_t preset) {
    // The public aaudio_input_preset_t constants are supposed to have the same
    // values as the internal audio_source_t values.
    STATIC_ASSERT(AAUDIO_UNSPECIFIED == AUDIO_SOURCE_DEFAULT);
    STATIC_ASSERT(AAUDIO_INPUT_PRESET_GENERIC == AUDIO_SOURCE_MIC);
    STATIC_ASSERT(AAUDIO_INPUT_PRESET_CAMCORDER == AUDIO_SOURCE_CAMCORDER);
    STATIC_ASSERT(AAUDIO_INPUT_PRESET_VOICE_RECOGNITION == AUDIO_SOURCE_VOICE_RECOGNITION);
    STATIC_ASSERT(AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION == AUDIO_SOURCE_VOICE_COMMUNICATION);
    STATIC_ASSERT(AAUDIO_INPUT_PRESET_UNPROCESSED == AUDIO_SOURCE_UNPROCESSED);
    STATIC_ASSERT(AAUDIO_INPUT_PRESET_VOICE_PERFORMANCE == AUDIO_SOURCE_VOICE_PERFORMANCE);
    if (preset == AAUDIO_UNSPECIFIED) {
        preset = AAUDIO_INPUT_PRESET_VOICE_RECOGNITION;
    }
    return (audio_source_t) preset; // same value
}

audio_flags_mask_t AAudio_computeAudioFlagsMask(
        aaudio_allowed_capture_policy_t policy,
        aaudio_spatialization_behavior_t spatializationBehavior,
        bool isContentSpatialized,
        audio_output_flags_t outputFlags) {
    audio_flags_mask_t flagsMask = AUDIO_FLAG_NONE;
    switch (policy) {
        case AAUDIO_UNSPECIFIED:
        case AAUDIO_ALLOW_CAPTURE_BY_ALL:
            // flagsMask is not modified
            break;
        case AAUDIO_ALLOW_CAPTURE_BY_SYSTEM:
            flagsMask = static_cast<audio_flags_mask_t>(flagsMask | AUDIO_FLAG_NO_MEDIA_PROJECTION);
            break;
        case AAUDIO_ALLOW_CAPTURE_BY_NONE:
            flagsMask = static_cast<audio_flags_mask_t>(flagsMask |
                    AUDIO_FLAG_NO_MEDIA_PROJECTION | AUDIO_FLAG_NO_SYSTEM_CAPTURE);
            break;
        default:
            ALOGE("%s() 0x%08X unrecognized capture policy", __func__, policy);
            // flagsMask is not modified
    }

    switch (spatializationBehavior) {
        case AAUDIO_UNSPECIFIED:
        case AAUDIO_SPATIALIZATION_BEHAVIOR_AUTO:
            // flagsMask is not modified
            break;
        case AAUDIO_SPATIALIZATION_BEHAVIOR_NEVER:
            flagsMask = static_cast<audio_flags_mask_t>(flagsMask | AUDIO_FLAG_NEVER_SPATIALIZE);
            break;
        default:
            ALOGE("%s() 0x%08X unrecognized spatialization behavior",
                  __func__, spatializationBehavior);
            // flagsMask is not modified
    }

    if (isContentSpatialized) {
        flagsMask = static_cast<audio_flags_mask_t>(flagsMask | AUDIO_FLAG_CONTENT_SPATIALIZED);
    }

    if ((outputFlags & AUDIO_OUTPUT_FLAG_HW_AV_SYNC) != 0) {
        flagsMask = static_cast<audio_flags_mask_t>(flagsMask | AUDIO_FLAG_HW_AV_SYNC);
    }
    if ((outputFlags & AUDIO_OUTPUT_FLAG_FAST) != 0) {
        flagsMask = static_cast<audio_flags_mask_t>(flagsMask | AUDIO_FLAG_LOW_LATENCY);
    } else if ((outputFlags & AUDIO_OUTPUT_FLAG_DEEP_BUFFER) != 0) {
        flagsMask = static_cast<audio_flags_mask_t>(flagsMask | AUDIO_FLAG_DEEP_BUFFER);
    }

    return flagsMask;
}

audio_flags_mask_t AAudioConvert_privacySensitiveToAudioFlagsMask(
        bool privacySensitive) {
    return privacySensitive ? AUDIO_FLAG_CAPTURE_PRIVATE : AUDIO_FLAG_NONE;
}

audio_channel_mask_t AAudioConvert_aaudioToAndroidChannelLayoutMask(
        aaudio_channel_mask_t channelMask, bool isInput) {
    if (isInput) {
        switch (channelMask) {
            case AAUDIO_CHANNEL_MONO:
                return AUDIO_CHANNEL_IN_MONO;
            case AAUDIO_CHANNEL_STEREO:
                return AUDIO_CHANNEL_IN_STEREO;
            case AAUDIO_CHANNEL_FRONT_BACK:
                return AUDIO_CHANNEL_IN_FRONT_BACK;
            case AAUDIO_CHANNEL_2POINT0POINT2:
                return AUDIO_CHANNEL_IN_2POINT0POINT2;
            case AAUDIO_CHANNEL_2POINT1POINT2:
                return AUDIO_CHANNEL_IN_2POINT1POINT2;
            case AAUDIO_CHANNEL_3POINT0POINT2:
                return AUDIO_CHANNEL_IN_3POINT0POINT2;
            case AAUDIO_CHANNEL_3POINT1POINT2:
                return AUDIO_CHANNEL_IN_3POINT1POINT2;
            case AAUDIO_CHANNEL_5POINT1:
                return AUDIO_CHANNEL_IN_5POINT1;
            default:
                ALOGE("%s() %#x unrecognized", __func__, channelMask);
                return AUDIO_CHANNEL_INVALID;
        }
    } else {
        switch (channelMask) {
            case AAUDIO_CHANNEL_MONO:
                return AUDIO_CHANNEL_OUT_MONO;
            case AAUDIO_CHANNEL_STEREO:
                return AUDIO_CHANNEL_OUT_STEREO;
            case AAUDIO_CHANNEL_2POINT1:
                return AUDIO_CHANNEL_OUT_2POINT1;
            case AAUDIO_CHANNEL_TRI:
                return AUDIO_CHANNEL_OUT_TRI;
            case AAUDIO_CHANNEL_TRI_BACK:
                return AUDIO_CHANNEL_OUT_TRI_BACK;
            case AAUDIO_CHANNEL_3POINT1:
                return AUDIO_CHANNEL_OUT_3POINT1;
            case AAUDIO_CHANNEL_2POINT0POINT2:
                return AUDIO_CHANNEL_OUT_2POINT0POINT2;
            case AAUDIO_CHANNEL_2POINT1POINT2:
                return AUDIO_CHANNEL_OUT_2POINT1POINT2;
            case AAUDIO_CHANNEL_3POINT0POINT2:
                return AUDIO_CHANNEL_OUT_3POINT0POINT2;
            case AAUDIO_CHANNEL_3POINT1POINT2:
                return AUDIO_CHANNEL_OUT_3POINT1POINT2;
            case AAUDIO_CHANNEL_QUAD:
                return AUDIO_CHANNEL_OUT_QUAD;
            case AAUDIO_CHANNEL_QUAD_SIDE:
                return AUDIO_CHANNEL_OUT_QUAD_SIDE;
            case AAUDIO_CHANNEL_SURROUND:
                return AUDIO_CHANNEL_OUT_SURROUND;
            case AAUDIO_CHANNEL_PENTA:
                return AUDIO_CHANNEL_OUT_PENTA;
            case AAUDIO_CHANNEL_5POINT1:
                return AUDIO_CHANNEL_OUT_5POINT1;
            case AAUDIO_CHANNEL_5POINT1_SIDE:
                return AUDIO_CHANNEL_OUT_5POINT1_SIDE;
            case AAUDIO_CHANNEL_5POINT1POINT2:
                return AUDIO_CHANNEL_OUT_5POINT1POINT2;
            case AAUDIO_CHANNEL_5POINT1POINT4:
                return AUDIO_CHANNEL_OUT_5POINT1POINT4;
            case AAUDIO_CHANNEL_6POINT1:
                return AUDIO_CHANNEL_OUT_6POINT1;
            case AAUDIO_CHANNEL_7POINT1:
                return AUDIO_CHANNEL_OUT_7POINT1;
            case AAUDIO_CHANNEL_7POINT1POINT2:
                return AUDIO_CHANNEL_OUT_7POINT1POINT2;
            case AAUDIO_CHANNEL_7POINT1POINT4:
                return AUDIO_CHANNEL_OUT_7POINT1POINT4;
            case AAUDIO_CHANNEL_13POINT0:
                return AUDIO_CHANNEL_OUT_13POINT0;
            case AAUDIO_CHANNEL_9POINT1POINT4:
                return AUDIO_CHANNEL_OUT_9POINT1POINT4;
            case AAUDIO_CHANNEL_9POINT1POINT6:
                return AUDIO_CHANNEL_OUT_9POINT1POINT6;
            default:
                ALOGE("%s() %#x unrecognized", __func__, channelMask);
                return AUDIO_CHANNEL_INVALID;
        }
    }
}

aaudio_channel_mask_t AAudioConvert_androidToAAudioChannelLayoutMask(
        audio_channel_mask_t channelMask, bool isInput) {
    if (isInput) {
        switch (channelMask) {
            case AUDIO_CHANNEL_IN_MONO:
                return AAUDIO_CHANNEL_MONO;
            case AUDIO_CHANNEL_IN_STEREO:
                return AAUDIO_CHANNEL_STEREO;
            case AUDIO_CHANNEL_IN_FRONT_BACK:
                return AAUDIO_CHANNEL_FRONT_BACK;
            case AUDIO_CHANNEL_IN_2POINT0POINT2:
                return AAUDIO_CHANNEL_2POINT0POINT2;
            case AUDIO_CHANNEL_IN_2POINT1POINT2:
                return AAUDIO_CHANNEL_2POINT1POINT2;
            case AUDIO_CHANNEL_IN_3POINT0POINT2:
                return AAUDIO_CHANNEL_3POINT0POINT2;
            case AUDIO_CHANNEL_IN_3POINT1POINT2:
                return AAUDIO_CHANNEL_3POINT1POINT2;
            case AUDIO_CHANNEL_IN_5POINT1:
                return AAUDIO_CHANNEL_5POINT1;
            default:
                ALOGE("%s() %#x unrecognized", __func__, channelMask);
                return AAUDIO_CHANNEL_INVALID;
        }
    } else {
        switch (channelMask) {
            case AUDIO_CHANNEL_OUT_MONO:
                return AAUDIO_CHANNEL_MONO;
            case AUDIO_CHANNEL_OUT_STEREO:
                return AAUDIO_CHANNEL_STEREO;
            case AUDIO_CHANNEL_OUT_2POINT1:
                return AAUDIO_CHANNEL_2POINT1;
            case AUDIO_CHANNEL_OUT_TRI:
                return AAUDIO_CHANNEL_TRI;
            case AUDIO_CHANNEL_OUT_TRI_BACK:
                return AAUDIO_CHANNEL_TRI_BACK;
            case AUDIO_CHANNEL_OUT_3POINT1:
                return AAUDIO_CHANNEL_3POINT1;
            case AUDIO_CHANNEL_OUT_2POINT0POINT2:
                return AAUDIO_CHANNEL_2POINT0POINT2;
            case AUDIO_CHANNEL_OUT_2POINT1POINT2:
                return AAUDIO_CHANNEL_2POINT1POINT2;
            case AUDIO_CHANNEL_OUT_3POINT0POINT2:
                return AAUDIO_CHANNEL_3POINT0POINT2;
            case AUDIO_CHANNEL_OUT_3POINT1POINT2:
                return AAUDIO_CHANNEL_3POINT1POINT2;
            case AUDIO_CHANNEL_OUT_QUAD:
                return AAUDIO_CHANNEL_QUAD;
            case AUDIO_CHANNEL_OUT_QUAD_SIDE:
                return AAUDIO_CHANNEL_QUAD_SIDE;
            case AUDIO_CHANNEL_OUT_SURROUND:
                return AAUDIO_CHANNEL_SURROUND;
            case AUDIO_CHANNEL_OUT_PENTA:
                return AAUDIO_CHANNEL_PENTA;
            case AUDIO_CHANNEL_OUT_5POINT1:
                return AAUDIO_CHANNEL_5POINT1;
            case AUDIO_CHANNEL_OUT_5POINT1_SIDE:
                return AAUDIO_CHANNEL_5POINT1_SIDE;
            case AUDIO_CHANNEL_OUT_5POINT1POINT2:
                return AAUDIO_CHANNEL_5POINT1POINT2;
            case AUDIO_CHANNEL_OUT_5POINT1POINT4:
                return AAUDIO_CHANNEL_5POINT1POINT4;
            case AUDIO_CHANNEL_OUT_6POINT1:
                return AAUDIO_CHANNEL_6POINT1;
            case AUDIO_CHANNEL_OUT_7POINT1:
                return AAUDIO_CHANNEL_7POINT1;
            case AUDIO_CHANNEL_OUT_7POINT1POINT2:
                return AAUDIO_CHANNEL_7POINT1POINT2;
            case AUDIO_CHANNEL_OUT_7POINT1POINT4:
                return AAUDIO_CHANNEL_7POINT1POINT4;
            case AUDIO_CHANNEL_OUT_13POINT0:
                return AAUDIO_CHANNEL_13POINT0;
            case AUDIO_CHANNEL_OUT_9POINT1POINT4:
                return AAUDIO_CHANNEL_9POINT1POINT4;
            case AUDIO_CHANNEL_OUT_9POINT1POINT6:
                return AAUDIO_CHANNEL_9POINT1POINT6;
            default:
                ALOGE("%s() %#x unrecognized", __func__, channelMask);
                return AAUDIO_CHANNEL_INVALID;
        }
    }
}

int32_t AAudioConvert_channelMaskToCount(aaudio_channel_mask_t channelMask) {
    return __builtin_popcount(channelMask & ~AAUDIO_CHANNEL_BIT_INDEX);
}

aaudio_channel_mask_t AAudioConvert_channelCountToMask(int32_t channelCount) {
    if (channelCount < 0 || channelCount > AUDIO_CHANNEL_COUNT_MAX) {
        return AAUDIO_CHANNEL_INVALID;
    }

    if (channelCount == 0) {
        return AAUDIO_UNSPECIFIED;
    }

    // Return index mask if the channel count is greater than 2.
    return AAUDIO_CHANNEL_BIT_INDEX | ((1 << channelCount) - 1);
}

aaudio_channel_mask_t AAudioConvert_androidToAAudioChannelIndexMask(
        audio_channel_mask_t channelMask) {
    if (audio_channel_mask_get_representation(channelMask) != AUDIO_CHANNEL_REPRESENTATION_INDEX) {
        ALOGE("%s() %#x not an index mask", __func__, channelMask);
        return AAUDIO_CHANNEL_INVALID;
    }
    return (channelMask & ~AUDIO_CHANNEL_INDEX_HDR) | AAUDIO_CHANNEL_BIT_INDEX;
}

audio_channel_mask_t AAudioConvert_aaudioToAndroidChannelIndexMask(
        aaudio_channel_mask_t channelMask) {
    if (!AAudio_isChannelIndexMask(channelMask)) {
        ALOGE("%s() %#x not an index mask", __func__, channelMask);
        return AUDIO_CHANNEL_INVALID;
    }
    return audio_channel_mask_for_index_assignment_from_count(
            AAudioConvert_channelMaskToCount(channelMask));
}

aaudio_channel_mask_t AAudioConvert_androidToAAudioChannelMask(
        audio_channel_mask_t channelMask, bool isInput, bool indexMaskRequired) {
    if (audio_channel_mask_get_representation(channelMask) == AUDIO_CHANNEL_REPRESENTATION_INDEX) {
        return AAudioConvert_androidToAAudioChannelIndexMask(channelMask);
    }
    if (indexMaskRequired) {
        // Require index mask, `channelMask` here is a position mask.
        const int channelCount = isInput ? audio_channel_count_from_in_mask(channelMask)
                                         : audio_channel_count_from_out_mask(channelMask);
        return AAudioConvert_channelCountToMask(channelCount);
    }
    return AAudioConvert_androidToAAudioChannelLayoutMask(channelMask, isInput);
}

audio_channel_mask_t AAudioConvert_aaudioToAndroidChannelMask(
        aaudio_channel_mask_t channelMask, bool isInput) {
    return AAudio_isChannelIndexMask(channelMask)
            ? AAudioConvert_aaudioToAndroidChannelIndexMask(channelMask)
            : AAudioConvert_aaudioToAndroidChannelLayoutMask(channelMask, isInput);
}

bool AAudio_isChannelIndexMask(aaudio_channel_mask_t channelMask) {
    return (channelMask & AAUDIO_CHANNEL_BIT_INDEX) == AAUDIO_CHANNEL_BIT_INDEX;
}

audio_channel_mask_t AAudio_getChannelMaskForOpen(
        aaudio_channel_mask_t channelMask, int32_t samplesPerFrame, bool isInput) {
    if (channelMask != AAUDIO_UNSPECIFIED) {
        if (AAudio_isChannelIndexMask(channelMask) && samplesPerFrame <= 2) {
            // When it is index mask and the count is less than 3, use position mask
            // instead of index mask for opening a stream. This may need to be revisited
            // when making channel index mask public.
            return isInput ? audio_channel_in_mask_from_count(samplesPerFrame)
                           : audio_channel_out_mask_from_count(samplesPerFrame);
        }
        return AAudioConvert_aaudioToAndroidChannelMask(channelMask, isInput);
    }

    // Return stereo when unspecified.
    return isInput ? AUDIO_CHANNEL_IN_STEREO : AUDIO_CHANNEL_OUT_STEREO;
}

int32_t AAudioConvert_framesToBytes(int32_t numFrames,
                                    int32_t bytesPerFrame,
                                    int32_t *sizeInBytes) {
    *sizeInBytes = 0;

    if (numFrames < 0 || bytesPerFrame < 0) {
        ALOGE("negative size, numFrames = %d, frameSize = %d", numFrames, bytesPerFrame);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    // Prevent numeric overflow.
    if (numFrames > (INT32_MAX / bytesPerFrame)) {
        ALOGE("size overflow, numFrames = %d, frameSize = %d", numFrames, bytesPerFrame);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    *sizeInBytes = numFrames * bytesPerFrame;
    return AAUDIO_OK;
}

int32_t AAudioProperty_getWakeupDelayMicros() {
    const int32_t minMicros = 0; // arbitrary
    const int32_t defaultMicros = 200; // arbitrary, based on some observed jitter
    const int32_t maxMicros = 5000; // arbitrary, probably don't want more than 500
    int32_t prop = property_get_int32(AAUDIO_PROP_WAKEUP_DELAY_USEC, defaultMicros);
    if (prop < minMicros) {
        ALOGW("AAudioProperty_getWakeupDelayMicros: clipped %d to %d", prop, minMicros);
        prop = minMicros;
    } else if (prop > maxMicros) {
        ALOGW("AAudioProperty_getWakeupDelayMicros: clipped %d to %d", prop, maxMicros);
        prop = maxMicros;
    }
    return prop;
}

int32_t AAudioProperty_getMinimumSleepMicros() {
    const int32_t minMicros = 1; // arbitrary
    // Higher values can increase latency for moderate workloads.
    // Short values can cause the CPU to short cycle if there is a bug in
    // calculating the wakeup times.
    const int32_t defaultMicros = 100; // arbitrary
    const int32_t maxMicros = 200; // arbitrary
    int32_t prop = property_get_int32(AAUDIO_PROP_MINIMUM_SLEEP_USEC, defaultMicros);
    if (prop < minMicros) {
        ALOGW("AAudioProperty_getMinimumSleepMicros: clipped %d to %d", prop, minMicros);
        prop = minMicros;
    } else if (prop > maxMicros) {
        ALOGW("AAudioProperty_getMinimumSleepMicros: clipped %d to %d", prop, maxMicros);
        prop = maxMicros;
    }
    return prop;
}

static int32_t AAudioProperty_getMMapOffsetMicros(const char *functionName,
        const char *propertyName) {
    const int32_t minMicros = -20000; // arbitrary
    const int32_t defaultMicros = 0;  // arbitrary
    const int32_t maxMicros =  20000; // arbitrary
    int32_t prop = property_get_int32(propertyName, defaultMicros);
    if (prop < minMicros) {
        ALOGW("%s: clipped %d to %d", functionName, prop, minMicros);
        prop = minMicros;
    } else if (prop > maxMicros) {
        ALOGW("%s: clipped %d to %d", functionName, prop, minMicros);
        prop = maxMicros;
    }
    return prop;
}

int32_t AAudioProperty_getInputMMapOffsetMicros() {
    return AAudioProperty_getMMapOffsetMicros(__func__, AAUDIO_PROP_INPUT_MMAP_OFFSET_USEC);
}

int32_t AAudioProperty_getOutputMMapOffsetMicros() {
    return AAudioProperty_getMMapOffsetMicros(__func__, AAUDIO_PROP_OUTPUT_MMAP_OFFSET_USEC);
}

int32_t AAudioProperty_getLogMask() {
    return property_get_int32(AAUDIO_PROP_LOG_MASK, 0);
}

aaudio_result_t AAudio_isFlushAllowed(aaudio_stream_state_t state) {
    aaudio_result_t result = AAUDIO_OK;
    switch (state) {
// Proceed with flushing.
        case AAUDIO_STREAM_STATE_OPEN:
        case AAUDIO_STREAM_STATE_PAUSED:
        case AAUDIO_STREAM_STATE_STOPPED:
        case AAUDIO_STREAM_STATE_FLUSHED:
            break;

// Transition from one inactive state to another.
        case AAUDIO_STREAM_STATE_STARTING:
        case AAUDIO_STREAM_STATE_STARTED:
        case AAUDIO_STREAM_STATE_STOPPING:
        case AAUDIO_STREAM_STATE_PAUSING:
        case AAUDIO_STREAM_STATE_FLUSHING:
        case AAUDIO_STREAM_STATE_CLOSING:
        case AAUDIO_STREAM_STATE_CLOSED:
        case AAUDIO_STREAM_STATE_DISCONNECTED:
        default:
            ALOGE("can only flush stream when PAUSED, OPEN or STOPPED, state = %s",
                  aaudio::AudioGlobal_convertStreamStateToText(state));
            result =  AAUDIO_ERROR_INVALID_STATE;
            break;
    }
    return result;
}

namespace {

aaudio_policy_t aidl2legacy_aaudio_policy(AudioMMapPolicy aidl) {
    switch (aidl) {
        case AudioMMapPolicy::NEVER:
            return AAUDIO_POLICY_NEVER;
        case AudioMMapPolicy::AUTO:
            return AAUDIO_POLICY_AUTO;
        case AudioMMapPolicy::ALWAYS:
            return AAUDIO_POLICY_ALWAYS;
        case AudioMMapPolicy::UNSPECIFIED:
        default:
            return AAUDIO_UNSPECIFIED;
    }
}

} // namespace

aaudio_policy_t AAudio_getAAudioPolicy(const std::vector<AudioMMapPolicyInfo>& policyInfos,
                                       AudioMMapPolicy defaultPolicy) {
    AudioMMapPolicy policy = defaultPolicy;
    for (const auto& policyInfo : policyInfos) {
        if (policyInfo.mmapPolicy == AudioMMapPolicy::NEVER) {
            policy = policyInfo.mmapPolicy;
        } else if (policyInfo.mmapPolicy == AudioMMapPolicy::AUTO ||
                   policyInfo.mmapPolicy == AudioMMapPolicy::ALWAYS) {
            return AAUDIO_POLICY_AUTO;
        }
    }
    return aidl2legacy_aaudio_policy(policy);
}

audio_devices_t AAudioConvert_aaudioToAndroidDeviceType(AAudio_DeviceType device,
                                                        aaudio_direction_t direction) {
    if (direction == AAUDIO_DIRECTION_INPUT) {
        switch (device) {
            case AAUDIO_DEVICE_BUILTIN_MIC:
                return AUDIO_DEVICE_IN_BUILTIN_MIC;
            case AAUDIO_DEVICE_BLUETOOTH_SCO:
                return AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET;
            case AAUDIO_DEVICE_WIRED_HEADSET:
                return AUDIO_DEVICE_IN_WIRED_HEADSET;
            case AAUDIO_DEVICE_HDMI:
                return AUDIO_DEVICE_IN_HDMI;
            case AAUDIO_DEVICE_TELEPHONY:
                return AUDIO_DEVICE_IN_TELEPHONY_RX;
            case AAUDIO_DEVICE_DOCK:
                return AUDIO_DEVICE_IN_DGTL_DOCK_HEADSET;
            case AAUDIO_DEVICE_DOCK_ANALOG:
                return AUDIO_DEVICE_IN_ANLG_DOCK_HEADSET;
            case AAUDIO_DEVICE_USB_ACCESSORY:
                return AUDIO_DEVICE_IN_USB_ACCESSORY;
            case AAUDIO_DEVICE_USB_DEVICE:
                return AUDIO_DEVICE_IN_USB_DEVICE;
            case AAUDIO_DEVICE_USB_HEADSET:
                return AUDIO_DEVICE_IN_USB_HEADSET;
            case AAUDIO_DEVICE_FM_TUNER:
                return AUDIO_DEVICE_IN_FM_TUNER;
            case AAUDIO_DEVICE_TV_TUNER:
                return AUDIO_DEVICE_IN_TV_TUNER;
            case AAUDIO_DEVICE_LINE_ANALOG:
                return AUDIO_DEVICE_IN_LINE;
            case AAUDIO_DEVICE_LINE_DIGITAL:
                return AUDIO_DEVICE_IN_SPDIF;
            case AAUDIO_DEVICE_BLUETOOTH_A2DP:
                return AUDIO_DEVICE_IN_BLUETOOTH_A2DP;
            case AAUDIO_DEVICE_IP:
                return AUDIO_DEVICE_IN_IP;
            case AAUDIO_DEVICE_BUS:
                return AUDIO_DEVICE_IN_BUS;
            case AAUDIO_DEVICE_REMOTE_SUBMIX:
                return AUDIO_DEVICE_IN_REMOTE_SUBMIX;
            case AAUDIO_DEVICE_BLE_HEADSET:
                return AUDIO_DEVICE_IN_BLE_HEADSET;
            case AAUDIO_DEVICE_HDMI_ARC:
                return AUDIO_DEVICE_IN_HDMI_ARC;
            case AAUDIO_DEVICE_HDMI_EARC:
                return AUDIO_DEVICE_IN_HDMI_EARC;
            case AAUDIO_DEVICE_BLE_HEARING_AID:
                return AUDIO_DEVICE_IN_BLE_HEARING_AID;
            case AAUDIO_DEVICE_BLE_CENTRAL:
                return AUDIO_DEVICE_IN_BLE_CENTRAL;
            case AAUDIO_DEVICE_BLE_CENTRAL_BROADCAST:
                return AUDIO_DEVICE_IN_BLE_CENTRAL_BROADCAST;
            default:
                break;
        }
    } else {
        switch (device) {
            case AAUDIO_DEVICE_BUILTIN_EARPIECE:
                return AUDIO_DEVICE_OUT_EARPIECE;
            case AAUDIO_DEVICE_BUILTIN_SPEAKER:
                return AUDIO_DEVICE_OUT_SPEAKER;
            case AAUDIO_DEVICE_WIRED_HEADSET:
                return AUDIO_DEVICE_OUT_WIRED_HEADSET;
            case AAUDIO_DEVICE_WIRED_HEADPHONES:
                return AUDIO_DEVICE_OUT_WIRED_HEADPHONE;
            case AAUDIO_DEVICE_LINE_ANALOG:
                return AUDIO_DEVICE_OUT_LINE;
            case AAUDIO_DEVICE_LINE_DIGITAL:
                return AUDIO_DEVICE_OUT_SPDIF;
            case AAUDIO_DEVICE_BLUETOOTH_SCO:
                return AUDIO_DEVICE_OUT_BLUETOOTH_SCO;
            case AAUDIO_DEVICE_BLUETOOTH_A2DP:
                return AUDIO_DEVICE_OUT_BLUETOOTH_A2DP;
            case AAUDIO_DEVICE_HDMI:
                return AUDIO_DEVICE_OUT_HDMI;
            case AAUDIO_DEVICE_HDMI_ARC:
                return AUDIO_DEVICE_OUT_HDMI_ARC;
            case AAUDIO_DEVICE_HDMI_EARC:
                return AUDIO_DEVICE_OUT_HDMI_EARC;
            case AAUDIO_DEVICE_USB_DEVICE:
                return AUDIO_DEVICE_OUT_USB_DEVICE;
            case AAUDIO_DEVICE_USB_HEADSET:
                return AUDIO_DEVICE_OUT_USB_HEADSET;
            case AAUDIO_DEVICE_USB_ACCESSORY:
                return AUDIO_DEVICE_OUT_USB_ACCESSORY;
            case AAUDIO_DEVICE_DOCK:
                return AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET;
            case AAUDIO_DEVICE_DOCK_ANALOG:
                return AUDIO_DEVICE_OUT_ANLG_DOCK_HEADSET;
            case AAUDIO_DEVICE_FM:
                return AUDIO_DEVICE_OUT_FM;
            case AAUDIO_DEVICE_TELEPHONY:
                return AUDIO_DEVICE_OUT_TELEPHONY_TX;
            case AAUDIO_DEVICE_AUX_LINE:
                return AUDIO_DEVICE_OUT_AUX_LINE;
            case AAUDIO_DEVICE_IP:
                return AUDIO_DEVICE_OUT_IP;
            case AAUDIO_DEVICE_BUS:
                return AUDIO_DEVICE_OUT_BUS;
            case AAUDIO_DEVICE_HEARING_AID:
                return AUDIO_DEVICE_OUT_HEARING_AID;
            case AAUDIO_DEVICE_BUILTIN_SPEAKER_SAFE:
                return AUDIO_DEVICE_OUT_SPEAKER_SAFE;
            case AAUDIO_DEVICE_REMOTE_SUBMIX:
                return AUDIO_DEVICE_OUT_REMOTE_SUBMIX;
            case AAUDIO_DEVICE_BLE_HEADSET:
                return AUDIO_DEVICE_OUT_BLE_HEADSET;
            case AAUDIO_DEVICE_BLE_SPEAKER:
                return AUDIO_DEVICE_OUT_BLE_SPEAKER;
            case AAUDIO_DEVICE_BLE_BROADCAST:
                return AUDIO_DEVICE_OUT_BLE_BROADCAST;
            case AAUDIO_DEVICE_BLE_HEARING_AID:
                return AUDIO_DEVICE_OUT_BLE_HEARING_AID;
            case AAUDIO_DEVICE_BLE_CENTRAL:
                return AUDIO_DEVICE_OUT_BLE_CENTRAL;
            default:
                break;
        }
    }
    return AUDIO_DEVICE_NONE;
}

aaudio_policy_t AAudioConvert_androidToAAudioMMapPolicy(AudioMMapPolicy policy) {
    switch (policy) {
        case AudioMMapPolicy::AUTO:
            return AAUDIO_POLICY_AUTO;
        case AudioMMapPolicy::ALWAYS:
            return AAUDIO_POLICY_ALWAYS;
        case AudioMMapPolicy::NEVER:
        case AudioMMapPolicy::UNSPECIFIED:
        default:
            return AAUDIO_POLICY_NEVER;
    }
}

AAudio_FlushFromAccuracy AAudioConvert_androidToAAudioFlushFromAccuracy(
        FlushFromFrameAccuracy accuracy) {
    switch (accuracy) {
        case FlushFromFrameAccuracy::BEST_EFFORT:
            return AAUDIO_FLUSH_FROM_ACCURACY_UNDEFINED;
        case FlushFromFrameAccuracy::EXACT:
            return AAUDIO_FLUSH_FROM_FRAME_ACCURATE;
        default:
            ALOGW("%s unrecognized accuracy: %d, convert it to undefined",
                  __func__, static_cast<int>(accuracy));
            return AAUDIO_FLUSH_FROM_ACCURACY_UNDEFINED;
    }
}

// If AUDIO_NO_SYSTEM_DECLARATIONS is defined, AUDIO_TIMESTRETCH_FALLBACK_DEFAULT is not
// defined in system/media/audio/include/system/audio.h
#ifdef AUDIO_NO_SYSTEM_DECLARATIONS
// Keep this value the same as the one in system/media/audio/include/system/audio.h
#define AUDIO_TIMESTRETCH_FALLBACK_DEFAULT 0
#endif

aaudio_result_t AAudioConvert_aaudioToAndroidPlaybackParameters(
        const AAudioPlaybackParameters& parameters, android::AudioPlaybackRate* rate) {
    switch (parameters.fallbackMode) {
        case AAUDIO_FALLBACK_MODE_DEFAULT:
            rate->mFallbackMode = AUDIO_TIMESTRETCH_FALLBACK_DEFAULT;
            break;
        case AAUDIO_FALLBACK_MODE_MUTE:
            rate->mFallbackMode = AUDIO_TIMESTRETCH_FALLBACK_MUTE;
            break;
        case AAUDIO_FALLBACK_MODE_FAIL:
            rate->mFallbackMode = AUDIO_TIMESTRETCH_FALLBACK_FAIL;
            break;
        default:
            return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    switch (parameters.stretchMode) {
        case AAUDIO_STRETCH_MODE_DEFAULT:
            rate->mStretchMode = AUDIO_TIMESTRETCH_STRETCH_DEFAULT;
            break;
        case AAUDIO_STRETCH_MODE_VOICE:
            rate->mStretchMode = AUDIO_TIMESTRETCH_STRETCH_VOICE;
            break;
        default:
            return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    rate->mSpeed = parameters.speed;
    rate->mPitch = parameters.pitch;
    return android::isAudioPlaybackRateValid(*rate) ? AAUDIO_OK : AAUDIO_ERROR_ILLEGAL_ARGUMENT;
}

aaudio_result_t AAudioConvert_androidToAAudioPlaybackParameters(
        const android::AudioPlaybackRate& rate, AAudioPlaybackParameters* parameters) {
    if (!android::isAudioPlaybackRateValid(rate)) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    switch (rate.mFallbackMode) {
        case AUDIO_TIMESTRETCH_FALLBACK_MUTE:
            parameters->fallbackMode = AAUDIO_FALLBACK_MODE_MUTE;
            break;
        case AUDIO_TIMESTRETCH_FALLBACK_FAIL:
            parameters->fallbackMode = AAUDIO_FALLBACK_MODE_FAIL;
            break;
        case AUDIO_TIMESTRETCH_FALLBACK_DEFAULT:
            parameters->fallbackMode = AAUDIO_FALLBACK_MODE_DEFAULT;
            break;
        default:
            ALOGW("%s unrecognized fallback mode: %d, convert it to default",
                  __func__, rate.mFallbackMode);
            parameters->fallbackMode = AAUDIO_FALLBACK_MODE_DEFAULT;
            break;
    }

    switch (rate.mStretchMode) {
        case AUDIO_TIMESTRETCH_STRETCH_VOICE:
            parameters->stretchMode = AAUDIO_STRETCH_MODE_VOICE;
            break;
        case AUDIO_TIMESTRETCH_STRETCH_DEFAULT:
            parameters->stretchMode = AAUDIO_STRETCH_MODE_DEFAULT;
            break;
        default:
            ALOGW("%s unrecognized stretch mode: %d, convert it to default",
                  __func__, rate.mFallbackMode);
            parameters->stretchMode = AAUDIO_STRETCH_MODE_DEFAULT;
            break;
    }

    parameters->speed = rate.mSpeed;
    parameters->pitch = rate.mPitch;
    return AAUDIO_OK;
}
