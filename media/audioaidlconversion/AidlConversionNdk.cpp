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

#include <utility>

#define LOG_TAG "AidlConversionNdk"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// AIDL NDK backend to legacy audio data structure conversion utilities.

namespace aidl {
namespace android {

using ::aidl::android::hardware::audio::effect::AcousticEchoCanceler;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Flags;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::media::audio::common::AudioDeviceDescription;

using ::android::BAD_VALUE;
using ::android::base::unexpected;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Utils

ConversionResult<AcousticEchoCanceler> getParameterSpecificAec(const Parameter& aidl) {
    const auto& specific = VALUE_OR_RETURN(UNION_GET(aidl, specific));
    return VALUE_OR_RETURN(UNION_GET(specific, acousticEchoCanceler));
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Converters

ConversionResult<uint32_t> aidl2legacy_Flags_Type_uint32(Flags::Type type) {
    switch (type) {
        case Flags::Type::INSERT:
            return EFFECT_FLAG_TYPE_INSERT;
        case Flags::Type::AUXILIARY:
            return EFFECT_FLAG_TYPE_AUXILIARY;
        case Flags::Type::REPLACE:
            return EFFECT_FLAG_TYPE_REPLACE;
        case Flags::Type::PRE_PROC:
            return EFFECT_FLAG_TYPE_PRE_PROC;
        case Flags::Type::POST_PROC:
            return EFFECT_FLAG_TYPE_POST_PROC;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<uint32_t> aidl2legacy_Flags_Insert_uint32(Flags::Insert insert) {
    switch (insert) {
        case Flags::Insert::ANY:
            return EFFECT_FLAG_INSERT_ANY;
        case Flags::Insert::FIRST:
            return EFFECT_FLAG_INSERT_FIRST;
        case Flags::Insert::LAST:
            return EFFECT_FLAG_INSERT_LAST;
        case Flags::Insert::EXCLUSIVE:
            return EFFECT_FLAG_INSERT_EXCLUSIVE;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<uint32_t> aidl2legacy_Flags_Volume_uint32(Flags::Volume volume) {
    switch (volume) {
        case Flags::Volume::NONE:
            return 0;
        case Flags::Volume::CTRL:
            return EFFECT_FLAG_VOLUME_CTRL;
        case Flags::Volume::IND:
            return EFFECT_FLAG_VOLUME_IND;
        case Flags::Volume::MONITOR:
            return EFFECT_FLAG_VOLUME_MONITOR;
    }
    return unexpected(BAD_VALUE);
}
ConversionResult<uint32_t> aidl2legacy_Flags_HardwareAccelerator_uint32(
        Flags::HardwareAccelerator hwAcceleratorMode) {
    switch (hwAcceleratorMode) {
        case Flags::HardwareAccelerator::NONE:
            return 0;
        case Flags::HardwareAccelerator::SIMPLE:
            return EFFECT_FLAG_HW_ACC_SIMPLE;
        case Flags::HardwareAccelerator::TUNNEL:
            return EFFECT_FLAG_HW_ACC_TUNNEL;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<uint32_t> aidl2legacy_Flags_uint32(Flags aidl) {
    uint32_t legacy = 0;
    legacy |= VALUE_OR_RETURN(aidl2legacy_Flags_Type_uint32(aidl.type));
    legacy |= VALUE_OR_RETURN(aidl2legacy_Flags_Insert_uint32(aidl.insert));
    legacy |= VALUE_OR_RETURN(aidl2legacy_Flags_Volume_uint32(aidl.volume));
    legacy |= VALUE_OR_RETURN(aidl2legacy_Flags_HardwareAccelerator_uint32(aidl.hwAcceleratorMode));

    if (aidl.offloadIndication) {
        legacy |= EFFECT_FLAG_OFFLOAD_SUPPORTED;
    }
    if (aidl.deviceIndication) {
        legacy |= EFFECT_FLAG_DEVICE_IND;
    }
    if (aidl.audioModeIndication) {
        legacy |= EFFECT_FLAG_AUDIO_MODE_IND;
    }
    if (aidl.audioSourceIndication) {
        legacy |= EFFECT_FLAG_AUDIO_SOURCE_IND;
    }
    if (aidl.noProcessing) {
        legacy |= EFFECT_FLAG_NO_PROCESS;
    }
    return legacy;
}

ConversionResult<Flags::Type> legacy2aidl_uint32_Flags_Type(uint32_t legacy) {
    switch (legacy & EFFECT_FLAG_TYPE_MASK) {
        case EFFECT_FLAG_TYPE_INSERT:
            return Flags::Type::INSERT;
        case EFFECT_FLAG_TYPE_AUXILIARY:
            return Flags::Type::AUXILIARY;
        case EFFECT_FLAG_TYPE_REPLACE:
            return Flags::Type::REPLACE;
        case EFFECT_FLAG_TYPE_PRE_PROC:
            return Flags::Type::PRE_PROC;
        case EFFECT_FLAG_TYPE_POST_PROC:
            return Flags::Type::POST_PROC;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<Flags::Insert> legacy2aidl_uint32_Flags_Insert(uint32_t legacy) {
    switch (legacy & EFFECT_FLAG_INSERT_MASK) {
        case EFFECT_FLAG_INSERT_ANY:
            return Flags::Insert::ANY;
        case EFFECT_FLAG_INSERT_FIRST:
            return Flags::Insert::FIRST;
        case EFFECT_FLAG_INSERT_LAST:
            return Flags::Insert::LAST;
        case EFFECT_FLAG_INSERT_EXCLUSIVE:
            return Flags::Insert::EXCLUSIVE;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<Flags::Volume> legacy2aidl_uint32_Flags_Volume(uint32_t legacy) {
    switch (legacy & EFFECT_FLAG_VOLUME_MASK) {
        case EFFECT_FLAG_VOLUME_IND:
            return Flags::Volume::IND;
        case EFFECT_FLAG_VOLUME_MONITOR:
            return Flags::Volume::MONITOR;
        case EFFECT_FLAG_VOLUME_NONE:
            return Flags::Volume::NONE;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<Flags::HardwareAccelerator> legacy2aidl_uint32_Flags_HardwareAccelerator(
        uint32_t legacy) {
    switch (legacy & EFFECT_FLAG_HW_ACC_MASK) {
        case EFFECT_FLAG_HW_ACC_SIMPLE:
            return Flags::HardwareAccelerator::SIMPLE;
        case EFFECT_FLAG_HW_ACC_TUNNEL:
            return Flags::HardwareAccelerator::TUNNEL;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<Flags> legacy2aidl_uint32_Flags(uint32_t legacy) {
    Flags aidl;

    aidl.type = VALUE_OR_RETURN(legacy2aidl_uint32_Flags_Type(legacy));
    aidl.insert = VALUE_OR_RETURN(legacy2aidl_uint32_Flags_Insert(legacy));
    aidl.volume = VALUE_OR_RETURN(legacy2aidl_uint32_Flags_Volume(legacy));
    aidl.hwAcceleratorMode = VALUE_OR_RETURN(legacy2aidl_uint32_Flags_HardwareAccelerator(legacy));
    aidl.offloadIndication = (legacy & EFFECT_FLAG_OFFLOAD_SUPPORTED);
    aidl.deviceIndication = (legacy & EFFECT_FLAG_DEVICE_IND);
    aidl.audioModeIndication = (legacy & EFFECT_FLAG_AUDIO_MODE_IND);
    aidl.audioSourceIndication = (legacy & EFFECT_FLAG_AUDIO_SOURCE_IND);
    aidl.noProcessing = (legacy & EFFECT_FLAG_NO_PROCESS);
    return aidl;
}

ConversionResult<effect_descriptor_t>
aidl2legacy_Descriptor_effect_descriptor(const Descriptor& aidl) {
    effect_descriptor_t legacy;
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.common.id.type));
    legacy.uuid = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.common.id.uuid));
    // legacy descriptor doesn't have proxy information
    // proxy = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.proxy));
    legacy.apiVersion = EFFECT_CONTROL_API_VERSION;
    legacy.flags = VALUE_OR_RETURN(aidl2legacy_Flags_uint32(aidl.common.flags));
    legacy.cpuLoad = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.common.cpuLoad));
    legacy.memoryUsage = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.common.memoryUsage));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.common.name, legacy.name, sizeof(legacy.name)));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.common.implementor, legacy.implementor,
                                        sizeof(legacy.implementor)));
    return legacy;
}

ConversionResult<Descriptor>
legacy2aidl_effect_descriptor_Descriptor(const effect_descriptor_t& legacy) {
    Descriptor aidl;
    aidl.common.id.type = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.type));
    aidl.common.id.uuid = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.uuid));
    // legacy descriptor doesn't have proxy information
    // aidl.common.id.proxy
    aidl.common.flags = VALUE_OR_RETURN(legacy2aidl_uint32_Flags(legacy.flags));
    aidl.common.cpuLoad = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.cpuLoad));
    aidl.common.memoryUsage = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.memoryUsage));
    aidl.common.name = VALUE_OR_RETURN(legacy2aidl_string(legacy.name, sizeof(legacy.name)));
    aidl.common.implementor =
            VALUE_OR_RETURN(legacy2aidl_string(legacy.implementor, sizeof(legacy.implementor)));
    return aidl;
}

ConversionResult<buffer_config_t> aidl2legacy_AudioConfigBase_buffer_config_t(
        const media::audio::common::AudioConfigBase& aidl, bool isInput) {
    buffer_config_t legacy;

    legacy.samplingRate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.sampleRate));
    legacy.mask |= EFFECT_CONFIG_SMP_RATE;

    legacy.channels = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.channelMask, isInput));
    legacy.mask |= EFFECT_CONFIG_CHANNELS;

    legacy.format = VALUE_OR_RETURN(aidl2legacy_AudioFormatDescription_audio_format_t(aidl.format));
    legacy.mask |= EFFECT_CONFIG_FORMAT;

    return legacy;
}

ConversionResult<media::audio::common::AudioConfigBase>
legacy2aidl_buffer_config_t_AudioConfigBase(const buffer_config_t& legacy, bool isInput) {
    media::audio::common::AudioConfigBase aidl;

    if (legacy.mask & EFFECT_CONFIG_SMP_RATE) {
        aidl.sampleRate = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.samplingRate));
    }
    if (legacy.mask & EFFECT_CONFIG_CHANNELS) {
        aidl.channelMask = VALUE_OR_RETURN(legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                static_cast<audio_channel_mask_t>(legacy.channels), isInput));
    }
    if (legacy.mask & EFFECT_CONFIG_FORMAT) {
        aidl.format = VALUE_OR_RETURN(legacy2aidl_audio_format_t_AudioFormatDescription(
                static_cast<audio_format_t>(legacy.format)));
    }
    return aidl;
}

ConversionResult<uint32_t> aidl2legacy_Parameter_uint32_echoDelay(const Parameter& aidl) {
    const auto& aec = VALUE_OR_RETURN(getParameterSpecificAec(aidl));
    const auto& echoDelay = VALUE_OR_RETURN(UNION_GET(aec, echoDelayUs));
    return VALUE_OR_RETURN(convertIntegral<uint32_t>(echoDelay));
}

ConversionResult<Parameter> legacy2aidl_uint32_echoDelay_Parameter(const uint32_t& legacy) {
    int delay = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy));
    AcousticEchoCanceler aec = AcousticEchoCanceler::make<AcousticEchoCanceler::echoDelayUs>(delay);
    Parameter::Specific specific =
            Parameter::Specific::make<Parameter::Specific::acousticEchoCanceler>(aec);

    return Parameter::make<Parameter::specific>(specific);
}

ConversionResult<uint32_t> aidl2legacy_Parameter_uint32_mobileMode(const Parameter& aidl) {
    const auto& aec = VALUE_OR_RETURN(getParameterSpecificAec(aidl));
    const auto& mobileMode = VALUE_OR_RETURN(UNION_GET(aec, mobileMode));
    return VALUE_OR_RETURN(convertIntegral<uint32_t>(mobileMode));
}

ConversionResult<Parameter> legacy2aidl_uint32_mobileMode_Parameter(const uint32_t& legacy) {
    bool mode = VALUE_OR_RETURN(convertIntegral<bool>(legacy));
    AcousticEchoCanceler aec = AcousticEchoCanceler::make<AcousticEchoCanceler::mobileMode>(mode);
    Parameter::Specific specific =
            Parameter::Specific::make<Parameter::Specific::acousticEchoCanceler>(aec);

    return Parameter::make<Parameter::specific>(specific);
}

}  // namespace android
}  // aidl
