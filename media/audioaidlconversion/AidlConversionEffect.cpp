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

#include <cstdint>
#include <inttypes.h>
#include <utility>

#define LOG_TAG "AidlConversionEffect"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <aidl/android/hardware/audio/effect/DefaultExtension.h>
#include <aidl/android/hardware/audio/effect/VendorExtension.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionEffect.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// AIDL NDK backend to legacy audio data structure conversion utilities.

namespace aidl {
namespace android {

using ::aidl::android::hardware::audio::effect::AcousticEchoCanceler;
using ::aidl::android::hardware::audio::effect::AutomaticGainControlV2;
using ::aidl::android::hardware::audio::effect::BassBoost;
using ::aidl::android::hardware::audio::effect::DefaultExtension;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Downmix;
using ::aidl::android::hardware::audio::effect::DynamicsProcessing;
using ::aidl::android::hardware::audio::effect::Flags;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::PresetReverb;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::aidl::android::hardware::audio::effect::Visualizer;
using ::aidl::android::media::audio::common::AudioDeviceDescription;

using ::android::BAD_VALUE;
using ::android::OK;
using ::android::status_t;
using ::android::base::unexpected;
using ::android::effect::utils::EffectParamReader;
using ::android::effect::utils::EffectParamWrapper;
using ::android::effect::utils::EffectParamWriter;

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

ConversionResult<Flags::Volume> legacy2aidl_uint32_Flags_Volume(uint32_t legacy) {
    switch (legacy & EFFECT_FLAG_VOLUME_MASK) {
        case EFFECT_FLAG_VOLUME_CTRL:
            return Flags::Volume::CTRL;
        case EFFECT_FLAG_VOLUME_IND:
            return Flags::Volume::IND;
        case EFFECT_FLAG_VOLUME_MONITOR:
            return Flags::Volume::MONITOR;
        case EFFECT_FLAG_VOLUME_NONE:
            return Flags::Volume::NONE;
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
    if (aidl.bypass) {
        legacy |= EFFECT_FLAG_NO_PROCESS;
    }
    return legacy;
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
    aidl.bypass = (legacy & EFFECT_FLAG_NO_PROCESS);
    return aidl;
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

ConversionResult<Flags::HardwareAccelerator> legacy2aidl_uint32_Flags_HardwareAccelerator(
        uint32_t legacy) {
    switch (legacy & EFFECT_FLAG_HW_ACC_MASK) {
        case EFFECT_FLAG_HW_ACC_SIMPLE:
            return Flags::HardwareAccelerator::SIMPLE;
        case EFFECT_FLAG_HW_ACC_TUNNEL:
            return Flags::HardwareAccelerator::TUNNEL;
        case 0:
            return Flags::HardwareAccelerator::NONE;
    }
    return unexpected(BAD_VALUE);
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

ConversionResult<uint32_t> aidl2legacy_Parameter_aec_uint32_echoDelay(const Parameter& aidl) {
    int echoDelay = VALUE_OR_RETURN(
            GET_PARAMETER_SPECIFIC_FIELD(aidl, AcousticEchoCanceler, acousticEchoCanceler,
                                         AcousticEchoCanceler::echoDelayUs, int));
    return VALUE_OR_RETURN(convertReinterpret<uint32_t>(echoDelay));
}

ConversionResult<Parameter> legacy2aidl_uint32_echoDelay_Parameter_aec(uint32_t legacy) {
    int delay = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy));
    return MAKE_SPECIFIC_PARAMETER(AcousticEchoCanceler, acousticEchoCanceler, echoDelayUs, delay);
}

ConversionResult<uint32_t> aidl2legacy_Parameter_aec_uint32_mobileMode(const Parameter& aidl) {
    bool mobileMode = VALUE_OR_RETURN(
            GET_PARAMETER_SPECIFIC_FIELD(aidl, AcousticEchoCanceler, acousticEchoCanceler,
                                         AcousticEchoCanceler::mobileMode, bool));
    return VALUE_OR_RETURN(convertIntegral<uint32_t>(mobileMode));
}

ConversionResult<Parameter> legacy2aidl_uint32_mobileMode_Parameter_aec(uint32_t legacy) {
    bool mode = VALUE_OR_RETURN(convertIntegral<bool>(legacy));
    return MAKE_SPECIFIC_PARAMETER(AcousticEchoCanceler, acousticEchoCanceler, mobileMode, mode);
}

ConversionResult<uint32_t> aidl2legacy_Parameter_agc_uint32_fixedDigitalGain(
        const Parameter& aidl) {
    int gain = VALUE_OR_RETURN(
            GET_PARAMETER_SPECIFIC_FIELD(aidl, AutomaticGainControlV2, automaticGainControlV2,
                                         AutomaticGainControlV2::fixedDigitalGainMb, int));
    return VALUE_OR_RETURN(convertReinterpret<uint32_t>(gain));
}

ConversionResult<Parameter> legacy2aidl_uint32_fixedDigitalGain_Parameter_agc(uint32_t legacy) {
    int gain = VALUE_OR_RETURN(convertReinterpret<int>(legacy));
    return MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV2, automaticGainControlV2,
                                   fixedDigitalGainMb, gain);
}

ConversionResult<uint32_t> aidl2legacy_Parameter_agc_uint32_levelEstimator(
        const Parameter& aidl) {
    const auto& le = VALUE_OR_RETURN(GET_PARAMETER_SPECIFIC_FIELD(
            aidl, AutomaticGainControlV2, automaticGainControlV2,
            AutomaticGainControlV2::levelEstimator, AutomaticGainControlV2::LevelEstimator));
    return static_cast<uint32_t>(le);
}

ConversionResult<Parameter> legacy2aidl_uint32_levelEstimator_Parameter_agc(uint32_t legacy) {
    if (legacy > (uint32_t)AutomaticGainControlV2::LevelEstimator::PEAK) {
        return unexpected(BAD_VALUE);
    }
    AutomaticGainControlV2::LevelEstimator le =
            static_cast<AutomaticGainControlV2::LevelEstimator>(legacy);
    return MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV2, automaticGainControlV2, levelEstimator,
                                   le);
}

ConversionResult<uint32_t> aidl2legacy_Parameter_agc_uint32_saturationMargin(
        const Parameter& aidl) {
    int saturationMargin = VALUE_OR_RETURN(
            GET_PARAMETER_SPECIFIC_FIELD(aidl, AutomaticGainControlV2, automaticGainControlV2,
                                         AutomaticGainControlV2::saturationMarginMb, int));
    return VALUE_OR_RETURN(convertIntegral<uint32_t>(saturationMargin));
}

ConversionResult<Parameter> legacy2aidl_uint32_saturationMargin_Parameter_agc(uint32_t legacy) {
    int saturationMargin = VALUE_OR_RETURN(convertIntegral<int>(legacy));
    return MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV2, automaticGainControlV2,
                                   saturationMarginMb, saturationMargin);
}

ConversionResult<uint16_t> aidl2legacy_Parameter_BassBoost_uint16_strengthPm(
        const Parameter& aidl) {
    int strength = VALUE_OR_RETURN(
            GET_PARAMETER_SPECIFIC_FIELD(aidl, BassBoost, bassBoost, BassBoost::strengthPm, int));
    return VALUE_OR_RETURN(convertIntegral<uint16_t>(strength));
}

ConversionResult<Parameter> legacy2aidl_uint16_strengthPm_Parameter_BassBoost(uint16_t legacy) {
    int strength = VALUE_OR_RETURN(convertIntegral<int>(legacy));
    return MAKE_SPECIFIC_PARAMETER(BassBoost, bassBoost, strengthPm, strength);
}

ConversionResult<int16_t> aidl2legacy_Parameter_Downmix_int16_type(const Parameter& aidl) {
    Downmix::Type aidlType = VALUE_OR_RETURN(
            GET_PARAMETER_SPECIFIC_FIELD(aidl, Downmix, downmix, Downmix::type, Downmix::Type));
    return VALUE_OR_RETURN(convertIntegral<int16_t>(static_cast<uint32_t>(aidlType)));
}

ConversionResult<Parameter> legacy2aidl_int16_type_Parameter_Downmix(int16_t legacy) {
    if (legacy > (uint32_t) Downmix::Type::FOLD) {
        return unexpected(BAD_VALUE);
    }
    Downmix::Type aidlType = static_cast<Downmix::Type>(legacy);
    return MAKE_SPECIFIC_PARAMETER(Downmix, downmix, type, aidlType);
}

ConversionResult<int16_t> aidl2legacy_DynamicsProcessing_ResolutionPreference_uint32_(
        const Parameter& aidl) {
    Downmix::Type aidlType = VALUE_OR_RETURN(
            GET_PARAMETER_SPECIFIC_FIELD(aidl, Downmix, downmix, Downmix::type, Downmix::Type));
    return VALUE_OR_RETURN(convertIntegral<int16_t>(static_cast<uint32_t>(aidlType)));
}

ConversionResult<DynamicsProcessing::ResolutionPreference>
legacy2aidl_int32_DynamicsProcessing_ResolutionPreference(int32_t legacy) {
    if (legacy > (int32_t)DynamicsProcessing::ResolutionPreference::FAVOR_TIME_RESOLUTION) {
        return unexpected(BAD_VALUE);
    }
    return static_cast<DynamicsProcessing::ResolutionPreference>(legacy);
}

ConversionResult<int32_t> aidl2legacy_DynamicsProcessing_ResolutionPreference_int32(
        DynamicsProcessing::ResolutionPreference aidl) {
    return static_cast<int32_t>(aidl);
}

ConversionResult<uint32_t> aidl2legacy_Parameter_Visualizer_ScalingMode_uint32(
        Visualizer::ScalingMode aidl) {
    switch (aidl) {
        case Visualizer::ScalingMode::NORMALIZED: {
            return 0;
        }
        case Visualizer::ScalingMode::AS_PLAYED: {
            return 1;
        }
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<Visualizer::ScalingMode> legacy2aidl_Parameter_Visualizer_uint32_ScalingMode(
        uint32_t legacy) {
    if (legacy == 0) {
        return Visualizer::ScalingMode::NORMALIZED;
    } else if (legacy == 1) {
        return Visualizer::ScalingMode::AS_PLAYED;
    } else {
        return unexpected(BAD_VALUE);
    }
}

ConversionResult<uint32_t> aidl2legacy_Parameter_Visualizer_MeasurementMode_uint32(
        Visualizer::MeasurementMode aidl) {
    switch (aidl) {
        case Visualizer::MeasurementMode::NONE: {
            return 0;
        }
        case Visualizer::MeasurementMode::PEAK_RMS: {
            return 1;
        }
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<Visualizer::MeasurementMode>
legacy2aidl_Parameter_Visualizer_uint32_MeasurementMode(uint32_t legacy) {
    if (legacy == 0) {
        return Visualizer::MeasurementMode::NONE;
    } else if (legacy == 1) {
        return Visualizer::MeasurementMode::PEAK_RMS;
    } else {
        return unexpected(BAD_VALUE);
    }
}

ConversionResult<status_t> aidl2legacy_VendorExtension_EffectParameterWriter(
        EffectParamWriter& param, VendorExtension ext) {
    std::optional<DefaultExtension> defaultExt;
    RETURN_IF_ERROR(ext.extension.getParcelable(&defaultExt));
    if (!defaultExt.has_value()) {
        return unexpected(BAD_VALUE);
    }

    // DefaultExtension defaultValue = defaultExt->get();
    if (defaultExt->bytes.size() < sizeof(effect_param_t)) {
        return unexpected(BAD_VALUE);
    }
    // verify data length with EffectParamWrapper, DefaultExtension array size should not smaller
    // than (sizeof(effect_param_t) + paddedPSize + vSize)
    EffectParamWrapper wrapper(*(effect_param_t*)defaultExt->bytes.data());
    if (sizeof(effect_param_t) + wrapper.getPaddedParameterSize() + wrapper.getValueSize() >
        defaultExt->bytes.size()) {
        return unexpected(BAD_VALUE);
    }

    RETURN_IF_ERROR(param.overwrite(wrapper.getEffectParam()));
    return OK;
}

ConversionResult<VendorExtension> legacy2aidl_EffectParameterReader_VendorExtension(
        EffectParamReader& param) {
    size_t len = param.getTotalSize();
    DefaultExtension defaultExt;
    defaultExt.bytes.resize(len);

    std::memcpy(defaultExt.bytes.data(), (void *)&param.getEffectParam(), len);

    VendorExtension ext;
    ext.extension.setParcelable(defaultExt);
    return ext;
}

ConversionResult<::android::status_t> aidl2legacy_Parameter_EffectParameterWriter(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl,
        EffectParamWriter& legacy) {
    VendorExtension ext = VALUE_OR_RETURN(
            (::aidl::android::getParameterSpecific<Parameter, VendorExtension,
                                                   Parameter::Specific::vendorEffect>(aidl)));
    return VALUE_OR_RETURN_STATUS(aidl2legacy_VendorExtension_EffectParameterWriter(legacy, ext));
}

ConversionResult<Parameter> legacy2aidl_EffectParameterReader_Parameter(EffectParamReader& param) {
    VendorExtension ext = VALUE_OR_RETURN(legacy2aidl_EffectParameterReader_VendorExtension(param));
    return UNION_MAKE(Parameter, specific, UNION_MAKE(Parameter::Specific, vendorEffect, ext));
}

}  // namespace android
}  // aidl
