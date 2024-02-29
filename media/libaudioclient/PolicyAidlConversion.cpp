/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "PolicyAidlConversion"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "media/PolicyAidlConversion.h"

#include "media/AidlConversion.h"

namespace android {

using base::unexpected;
using media::audio::common::AudioDeviceAddress;

ConversionResult<uint32_t>
aidl2legacy_AudioMixType_uint32_t(media::AudioMixType aidl) {
    switch (aidl) {
        case media::AudioMixType::PLAYERS:
            return MIX_TYPE_PLAYERS;
        case media::AudioMixType::RECORDERS:
            return MIX_TYPE_RECORDERS;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioMixType>
legacy2aidl_uint32_t_AudioMixType(uint32_t legacy) {
    switch (legacy) {
        case MIX_TYPE_PLAYERS:
            return media::AudioMixType::PLAYERS;
        case MIX_TYPE_RECORDERS:
            return media::AudioMixType::RECORDERS;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<uint32_t>
aidl2legacy_AudioMixCallbackFlag_uint32_t(media::AudioMixCallbackFlag aidl) {
    switch (aidl) {
        case media::AudioMixCallbackFlag::NOTIFY_ACTIVITY:
            return AudioMix::kCbFlagNotifyActivity;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioMixCallbackFlag>
legacy2aidl_uint32_t_AudioMixCallbackFlag(uint32_t legacy) {
    switch (legacy) {
        case AudioMix::kCbFlagNotifyActivity:
            return media::AudioMixCallbackFlag::NOTIFY_ACTIVITY;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<uint32_t>
aidl2legacy_AudioMixCallbackFlag_uint32_t_mask(int32_t aidl) {
    return convertBitmask<uint32_t, int32_t, uint32_t, media::AudioMixCallbackFlag>(
            aidl,
            aidl2legacy_AudioMixCallbackFlag_uint32_t,
            indexToEnum_index<media::AudioMixCallbackFlag>,
            enumToMask_bitmask<uint32_t, uint32_t>);
}

ConversionResult<int32_t>
legacy2aidl_uint32_t_AudioMixCallbackFlag_mask(uint32_t legacy) {
    return convertBitmask<int32_t, uint32_t, media::AudioMixCallbackFlag, uint32_t>(
            legacy,
            legacy2aidl_uint32_t_AudioMixCallbackFlag,
            indexToEnum_bitmask<uint32_t>,
            enumToMask_index<int32_t, media::AudioMixCallbackFlag>);
}

ConversionResult<uint32_t>
aidl2legacy_AudioMixRouteFlag_uint32_t(media::AudioMixRouteFlag aidl) {
    switch (aidl) {
        case media::AudioMixRouteFlag::RENDER:
            return MIX_ROUTE_FLAG_RENDER;
        case media::AudioMixRouteFlag::LOOP_BACK:
            return MIX_ROUTE_FLAG_LOOP_BACK;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioMixRouteFlag>
legacy2aidl_uint32_t_AudioMixRouteFlag(uint32_t legacy) {
    switch (legacy) {
        case MIX_ROUTE_FLAG_RENDER:
            return media::AudioMixRouteFlag::RENDER;
        case MIX_ROUTE_FLAG_LOOP_BACK:
            return media::AudioMixRouteFlag::LOOP_BACK;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<uint32_t>
aidl2legacy_AudioMixRouteFlag_uint32_t_mask(int32_t aidl) {
    return convertBitmask<uint32_t, int32_t, uint32_t, media::AudioMixRouteFlag>(
            aidl,
            aidl2legacy_AudioMixRouteFlag_uint32_t,
            indexToEnum_index<media::AudioMixRouteFlag>,
            enumToMask_bitmask<uint32_t, uint32_t>);
}

ConversionResult<int32_t>
legacy2aidl_uint32_t_AudioMixRouteFlag_mask(uint32_t legacy) {
    return convertBitmask<int32_t, uint32_t, media::AudioMixRouteFlag, uint32_t>(
            legacy,
            legacy2aidl_uint32_t_AudioMixRouteFlag,
            indexToEnum_bitmask<uint32_t>,
            enumToMask_index<int32_t, media::AudioMixRouteFlag>);
}

// This type is unnamed in the original definition, thus we name it here.
using AudioMixMatchCriterionValue = decltype(AudioMixMatchCriterion::mValue);

ConversionResult<AudioMixMatchCriterionValue>
aidl2legacy_AudioMixMatchCriterionValue(
        const media::AudioMixMatchCriterionValue& aidl,
        uint32_t* rule) {
    AudioMixMatchCriterionValue legacy;
    *rule = 0;
    switch (aidl.getTag()) {
        case media::AudioMixMatchCriterionValue::usage:
            legacy.mUsage = VALUE_OR_RETURN(
                    aidl2legacy_AudioUsage_audio_usage_t(UNION_GET(aidl, usage).value()));
            *rule |= RULE_MATCH_ATTRIBUTE_USAGE;
            return legacy;

        case media::AudioMixMatchCriterionValue::source:
            legacy.mSource = VALUE_OR_RETURN(
                    aidl2legacy_AudioSource_audio_source_t(UNION_GET(aidl, source).value()));
            *rule |= RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET;
            return legacy;

        case media::AudioMixMatchCriterionValue::uid:
            legacy.mUid = VALUE_OR_RETURN(
                    aidl2legacy_int32_t_uid_t(UNION_GET(aidl, uid).value()));
            *rule |= RULE_MATCH_UID;
            return legacy;

        case media::AudioMixMatchCriterionValue::userId:
            legacy.mUserId = VALUE_OR_RETURN(
                    convertIntegral<int>(UNION_GET(aidl, userId).value()));
            *rule |= RULE_MATCH_USERID;
            return legacy;
        case media::AudioMixMatchCriterionValue::audioSessionId:
            legacy.mAudioSessionId = VALUE_OR_RETURN(
                    aidl2legacy_int32_t_audio_session_t(UNION_GET(aidl, audioSessionId).value()));
            *rule |= RULE_MATCH_AUDIO_SESSION_ID;
            return legacy;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioMixMatchCriterionValue>
legacy2aidl_AudioMixMatchCriterionValue(
        const AudioMixMatchCriterionValue& legacy,
        uint32_t rule) {
    media::AudioMixMatchCriterionValue aidl;
    switch (rule) {
        case RULE_MATCH_ATTRIBUTE_USAGE:
            UNION_SET(aidl, usage,
                      VALUE_OR_RETURN(legacy2aidl_audio_usage_t_AudioUsage(legacy.mUsage)));
            break;

        case RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET:
            UNION_SET(aidl, source,
                      VALUE_OR_RETURN(legacy2aidl_audio_source_t_AudioSource(legacy.mSource)));
            break;

        case RULE_MATCH_UID:
            UNION_SET(aidl, uid, VALUE_OR_RETURN(legacy2aidl_uid_t_int32_t(legacy.mUid)));
            break;

        case RULE_MATCH_USERID:
            UNION_SET(aidl, userId, VALUE_OR_RETURN(convertReinterpret<uint32_t>(legacy.mUserId)));
            break;
        case RULE_MATCH_AUDIO_SESSION_ID:
            UNION_SET(aidl, audioSessionId,
                VALUE_OR_RETURN(legacy2aidl_audio_session_t_int32_t(legacy.mAudioSessionId)));
            break;
        default:
            return unexpected(BAD_VALUE);
    }
    return aidl;
}


ConversionResult<AudioMixMatchCriterion>
aidl2legacy_AudioMixMatchCriterion(const media::AudioMixMatchCriterion& aidl) {
    AudioMixMatchCriterion legacy;
    legacy.mValue = VALUE_OR_RETURN(
            aidl2legacy_AudioMixMatchCriterionValue(aidl.value, &legacy.mRule));
    if (aidl.invert) {
        legacy.mRule |= RULE_EXCLUSION_MASK;
    }
    return legacy;
}

ConversionResult<media::AudioMixMatchCriterion>
legacy2aidl_AudioMixMatchCriterion(const AudioMixMatchCriterion& legacy) {
    media::AudioMixMatchCriterion aidl;
    uint32_t rule = legacy.mRule;
    if (rule & RULE_EXCLUSION_MASK) {
        aidl.invert = true;
        rule &= ~RULE_EXCLUSION_MASK;
    }
    aidl.value = VALUE_OR_RETURN(legacy2aidl_AudioMixMatchCriterionValue(legacy.mValue, rule));
    return aidl;
}

ConversionResult<AudioMix>
aidl2legacy_AudioMix(const media::AudioMix& aidl) {
    AudioMix legacy;
    RETURN_IF_ERROR(convertRange(aidl.criteria.begin(), aidl.criteria.end(),
                                 std::back_inserter(legacy.mCriteria),
                                 aidl2legacy_AudioMixMatchCriterion));
    legacy.mMixType = VALUE_OR_RETURN(aidl2legacy_AudioMixType_uint32_t(aidl.mixType));
    // See 'convertAudioMixToNative' in 'android_media_AudioSystem.cpp' -- only
    // an output mask is expected here.
    legacy.mFormat = VALUE_OR_RETURN(aidl2legacy_AudioConfig_audio_config_t(
                    aidl.format, false /*isInput*/));
    legacy.mRouteFlags = VALUE_OR_RETURN(
            aidl2legacy_AudioMixRouteFlag_uint32_t_mask(aidl.routeFlags));
    RETURN_IF_ERROR(aidl2legacy_AudioDevice_audio_device(
                    aidl.device, &legacy.mDeviceType, &legacy.mDeviceAddress));
    legacy.mCbFlags = VALUE_OR_RETURN(aidl2legacy_AudioMixCallbackFlag_uint32_t_mask(aidl.cbFlags));
    legacy.mAllowPrivilegedMediaPlaybackCapture = aidl.allowPrivilegedMediaPlaybackCapture;
    legacy.mVoiceCommunicationCaptureAllowed = aidl.voiceCommunicationCaptureAllowed;
    legacy.mToken = aidl.mToken;
    return legacy;
}

ConversionResult<media::AudioMix>
legacy2aidl_AudioMix(const AudioMix& legacy) {
    media::AudioMix aidl;
    aidl.criteria = VALUE_OR_RETURN(
            convertContainer<std::vector<media::AudioMixMatchCriterion>>(
                    legacy.mCriteria,
                    legacy2aidl_AudioMixMatchCriterion));
    aidl.mixType = VALUE_OR_RETURN(legacy2aidl_uint32_t_AudioMixType(legacy.mMixType));
    // See 'convertAudioMixToNative' in 'android_media_AudioSystem.cpp' -- only
    // an output mask is expected here.
    aidl.format = VALUE_OR_RETURN(legacy2aidl_audio_config_t_AudioConfig(
                    legacy.mFormat, false /*isInput*/));
    aidl.routeFlags = VALUE_OR_RETURN(
            legacy2aidl_uint32_t_AudioMixRouteFlag_mask(legacy.mRouteFlags));
    aidl.device = VALUE_OR_RETURN(
            legacy2aidl_audio_device_AudioDevice(
                    legacy.mDeviceType, legacy.mDeviceAddress));
    aidl.cbFlags = VALUE_OR_RETURN(legacy2aidl_uint32_t_AudioMixCallbackFlag_mask(legacy.mCbFlags));
    aidl.allowPrivilegedMediaPlaybackCapture = legacy.mAllowPrivilegedMediaPlaybackCapture;
    aidl.voiceCommunicationCaptureAllowed = legacy.mVoiceCommunicationCaptureAllowed;
    aidl.mToken = legacy.mToken;
    return aidl;
}

ConversionResult<audio_policy_dev_state_t>
aidl2legacy_AudioPolicyDeviceState_audio_policy_dev_state_t(media::AudioPolicyDeviceState aidl) {
    switch (aidl) {
        case media::AudioPolicyDeviceState::UNAVAILABLE:
            return AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE;
        case media::AudioPolicyDeviceState::AVAILABLE:
            return AUDIO_POLICY_DEVICE_STATE_AVAILABLE;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioPolicyDeviceState>
legacy2aidl_audio_policy_dev_state_t_AudioPolicyDeviceState(audio_policy_dev_state_t legacy) {
    switch (legacy) {
        case AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE:
            return media::AudioPolicyDeviceState::UNAVAILABLE;
        case AUDIO_POLICY_DEVICE_STATE_AVAILABLE:
            return media::AudioPolicyDeviceState::AVAILABLE;
        case AUDIO_POLICY_DEVICE_STATE_CNT:
            break;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_policy_force_use_t>
aidl2legacy_AudioPolicyForceUse_audio_policy_force_use_t(media::AudioPolicyForceUse aidl) {
    switch (aidl) {
        case media::AudioPolicyForceUse::COMMUNICATION:
            return AUDIO_POLICY_FORCE_FOR_COMMUNICATION;
        case media::AudioPolicyForceUse::MEDIA:
            return AUDIO_POLICY_FORCE_FOR_MEDIA;
        case media::AudioPolicyForceUse::RECORD:
            return AUDIO_POLICY_FORCE_FOR_RECORD;
        case media::AudioPolicyForceUse::DOCK:
            return AUDIO_POLICY_FORCE_FOR_DOCK;
        case media::AudioPolicyForceUse::SYSTEM:
            return AUDIO_POLICY_FORCE_FOR_SYSTEM;
        case media::AudioPolicyForceUse::HDMI_SYSTEM_AUDIO:
            return AUDIO_POLICY_FORCE_FOR_HDMI_SYSTEM_AUDIO;
        case media::AudioPolicyForceUse::ENCODED_SURROUND:
            return AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND;
        case media::AudioPolicyForceUse::VIBRATE_RINGING:
            return AUDIO_POLICY_FORCE_FOR_VIBRATE_RINGING;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioPolicyForceUse>
legacy2aidl_audio_policy_force_use_t_AudioPolicyForceUse(audio_policy_force_use_t legacy) {
    switch (legacy) {
        case AUDIO_POLICY_FORCE_FOR_COMMUNICATION:
            return media::AudioPolicyForceUse::COMMUNICATION;
        case AUDIO_POLICY_FORCE_FOR_MEDIA:
            return media::AudioPolicyForceUse::MEDIA;
        case AUDIO_POLICY_FORCE_FOR_RECORD:
            return media::AudioPolicyForceUse::RECORD;
        case AUDIO_POLICY_FORCE_FOR_DOCK:
            return media::AudioPolicyForceUse::DOCK;
        case AUDIO_POLICY_FORCE_FOR_SYSTEM:
            return media::AudioPolicyForceUse::SYSTEM;
        case AUDIO_POLICY_FORCE_FOR_HDMI_SYSTEM_AUDIO:
            return media::AudioPolicyForceUse::HDMI_SYSTEM_AUDIO;
        case AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND:
            return media::AudioPolicyForceUse::ENCODED_SURROUND;
        case AUDIO_POLICY_FORCE_FOR_VIBRATE_RINGING:
            return media::AudioPolicyForceUse::VIBRATE_RINGING;
        case AUDIO_POLICY_FORCE_USE_CNT:
            break;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_policy_forced_cfg_t>
aidl2legacy_AudioPolicyForcedConfig_audio_policy_forced_cfg_t(media::AudioPolicyForcedConfig aidl) {
    switch (aidl) {
        case media::AudioPolicyForcedConfig::NONE:
            return AUDIO_POLICY_FORCE_NONE;
        case media::AudioPolicyForcedConfig::SPEAKER:
            return AUDIO_POLICY_FORCE_SPEAKER;
        case media::AudioPolicyForcedConfig::HEADPHONES:
            return AUDIO_POLICY_FORCE_HEADPHONES;
        case media::AudioPolicyForcedConfig::BT_SCO:
            return AUDIO_POLICY_FORCE_BT_SCO;
        case media::AudioPolicyForcedConfig::BT_A2DP:
            return AUDIO_POLICY_FORCE_BT_A2DP;
        case media::AudioPolicyForcedConfig::WIRED_ACCESSORY:
            return AUDIO_POLICY_FORCE_WIRED_ACCESSORY;
        case media::AudioPolicyForcedConfig::BT_CAR_DOCK:
            return AUDIO_POLICY_FORCE_BT_CAR_DOCK;
        case media::AudioPolicyForcedConfig::BT_DESK_DOCK:
            return AUDIO_POLICY_FORCE_BT_DESK_DOCK;
        case media::AudioPolicyForcedConfig::ANALOG_DOCK:
            return AUDIO_POLICY_FORCE_ANALOG_DOCK;
        case media::AudioPolicyForcedConfig::DIGITAL_DOCK:
            return AUDIO_POLICY_FORCE_DIGITAL_DOCK;
        case media::AudioPolicyForcedConfig::NO_BT_A2DP:
            return AUDIO_POLICY_FORCE_NO_BT_A2DP;
        case media::AudioPolicyForcedConfig::SYSTEM_ENFORCED:
            return AUDIO_POLICY_FORCE_SYSTEM_ENFORCED;
        case media::AudioPolicyForcedConfig::HDMI_SYSTEM_AUDIO_ENFORCED:
            return AUDIO_POLICY_FORCE_HDMI_SYSTEM_AUDIO_ENFORCED;
        case media::AudioPolicyForcedConfig::ENCODED_SURROUND_NEVER:
            return AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER;
        case media::AudioPolicyForcedConfig::ENCODED_SURROUND_ALWAYS:
            return AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS;
        case media::AudioPolicyForcedConfig::ENCODED_SURROUND_MANUAL:
            return AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioPolicyForcedConfig>
legacy2aidl_audio_policy_forced_cfg_t_AudioPolicyForcedConfig(audio_policy_forced_cfg_t legacy) {
    switch (legacy) {
        case AUDIO_POLICY_FORCE_NONE:
            return media::AudioPolicyForcedConfig::NONE;
        case AUDIO_POLICY_FORCE_SPEAKER:
            return media::AudioPolicyForcedConfig::SPEAKER;
        case AUDIO_POLICY_FORCE_HEADPHONES:
            return media::AudioPolicyForcedConfig::HEADPHONES;
        case AUDIO_POLICY_FORCE_BT_SCO:
            return media::AudioPolicyForcedConfig::BT_SCO;
        case AUDIO_POLICY_FORCE_BT_A2DP:
            return media::AudioPolicyForcedConfig::BT_A2DP;
        case AUDIO_POLICY_FORCE_WIRED_ACCESSORY:
            return media::AudioPolicyForcedConfig::WIRED_ACCESSORY;
        case AUDIO_POLICY_FORCE_BT_CAR_DOCK:
            return media::AudioPolicyForcedConfig::BT_CAR_DOCK;
        case AUDIO_POLICY_FORCE_BT_DESK_DOCK:
            return media::AudioPolicyForcedConfig::BT_DESK_DOCK;
        case AUDIO_POLICY_FORCE_ANALOG_DOCK:
            return media::AudioPolicyForcedConfig::ANALOG_DOCK;
        case AUDIO_POLICY_FORCE_DIGITAL_DOCK:
            return media::AudioPolicyForcedConfig::DIGITAL_DOCK;
        case AUDIO_POLICY_FORCE_NO_BT_A2DP:
            return media::AudioPolicyForcedConfig::NO_BT_A2DP;
        case AUDIO_POLICY_FORCE_SYSTEM_ENFORCED:
            return media::AudioPolicyForcedConfig::SYSTEM_ENFORCED;
        case AUDIO_POLICY_FORCE_HDMI_SYSTEM_AUDIO_ENFORCED:
            return media::AudioPolicyForcedConfig::HDMI_SYSTEM_AUDIO_ENFORCED;
        case AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER:
            return media::AudioPolicyForcedConfig::ENCODED_SURROUND_NEVER;
        case AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS:
            return media::AudioPolicyForcedConfig::ENCODED_SURROUND_ALWAYS;
        case AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL:
            return media::AudioPolicyForcedConfig::ENCODED_SURROUND_MANUAL;
        case AUDIO_POLICY_FORCE_CFG_CNT:
            break;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<device_role_t>
aidl2legacy_DeviceRole_device_role_t(media::DeviceRole aidl) {
    switch (aidl) {
        case media::DeviceRole::NONE:
            return DEVICE_ROLE_NONE;
        case media::DeviceRole::PREFERRED:
            return DEVICE_ROLE_PREFERRED;
        case media::DeviceRole::DISABLED:
            return DEVICE_ROLE_DISABLED;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::DeviceRole>
legacy2aidl_device_role_t_DeviceRole(device_role_t legacy) {
    switch (legacy) {
        case DEVICE_ROLE_NONE:
            return media::DeviceRole::NONE;
        case DEVICE_ROLE_PREFERRED:
            return media::DeviceRole::PREFERRED;
        case DEVICE_ROLE_DISABLED:
            return media::DeviceRole::DISABLED;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_offload_mode_t>
aidl2legacy_AudioOffloadMode_audio_offload_mode_t(media::AudioOffloadMode aidl) {
    switch (aidl) {
        case media::AudioOffloadMode::NOT_SUPPORTED:
            return AUDIO_OFFLOAD_NOT_SUPPORTED;
        case media::AudioOffloadMode::SUPPORTED:
            return AUDIO_OFFLOAD_SUPPORTED;
        case media::AudioOffloadMode::GAPLESS_SUPPORTED:
            return AUDIO_OFFLOAD_GAPLESS_SUPPORTED;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioOffloadMode>
legacy2aidl_audio_offload_mode_t_AudioOffloadMode(audio_offload_mode_t legacy) {
    switch (legacy) {
        case AUDIO_OFFLOAD_NOT_SUPPORTED:
            return media::AudioOffloadMode::NOT_SUPPORTED;
        case AUDIO_OFFLOAD_SUPPORTED:
            return media::AudioOffloadMode::SUPPORTED;
        case AUDIO_OFFLOAD_GAPLESS_SUPPORTED:
            return media::AudioOffloadMode::GAPLESS_SUPPORTED;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_mixer_behavior_t>
aidl2legacy_AudioMixerBehavior_audio_mixer_behavior_t(media::AudioMixerBehavior aidl) {
    switch (aidl) {
        case media::AudioMixerBehavior::DEFAULT:
            return AUDIO_MIXER_BEHAVIOR_DEFAULT;
        case media::AudioMixerBehavior::BIT_PERFECT:
            return AUDIO_MIXER_BEHAVIOR_BIT_PERFECT;
        case media::AudioMixerBehavior::INVALID:
            return AUDIO_MIXER_BEHAVIOR_INVALID;
    }
    return unexpected(BAD_VALUE);
}
ConversionResult<media::AudioMixerBehavior>
legacy2aidl_audio_mixer_behavior_t_AudioMixerBehavior(audio_mixer_behavior_t legacy) {
    switch (legacy) {
        case AUDIO_MIXER_BEHAVIOR_DEFAULT:
            return media::AudioMixerBehavior::DEFAULT;
        case AUDIO_MIXER_BEHAVIOR_BIT_PERFECT:
            return media::AudioMixerBehavior::BIT_PERFECT;
        case AUDIO_MIXER_BEHAVIOR_INVALID:
            return media::AudioMixerBehavior::INVALID;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_mixer_attributes_t>
aidl2legacy_AudioMixerAttributesInternal_audio_mixer_attributes_t(
        const media::AudioMixerAttributesInternal& aidl) {
    audio_mixer_attributes_t legacy = AUDIO_MIXER_ATTRIBUTES_INITIALIZER;
    legacy.config = VALUE_OR_RETURN(
            aidl2legacy_AudioConfigBase_audio_config_base_t(aidl.config, false /*isInput*/));
    legacy.mixer_behavior = VALUE_OR_RETURN(
            aidl2legacy_AudioMixerBehavior_audio_mixer_behavior_t(aidl.mixerBehavior));
    return legacy;
}
ConversionResult<media::AudioMixerAttributesInternal>
legacy2aidl_audio_mixer_attributes_t_AudioMixerAttributesInternal(
        const audio_mixer_attributes& legacy) {
    media::AudioMixerAttributesInternal aidl;
    aidl.config = VALUE_OR_RETURN(
            legacy2aidl_audio_config_base_t_AudioConfigBase(legacy.config, false /*isInput*/));
    aidl.mixerBehavior = VALUE_OR_RETURN(
            legacy2aidl_audio_mixer_behavior_t_AudioMixerBehavior(legacy.mixer_behavior));
    return aidl;
}


}  // namespace android
