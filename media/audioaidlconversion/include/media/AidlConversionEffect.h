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

#pragma once

#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

/**
 * Can only handle conversion between AIDL (NDK backend) and legacy type.
 */
#include <hardware/audio_effect.h>
#include <media/AidlConversionUtil.h>
#include <system/audio_effect.h>
#include <system/audio_effects/audio_effects_utils.h>

#include <aidl/android/hardware/audio/effect/IEffect.h>

namespace aidl {
namespace android {

template <typename P, typename T, typename P::Specific::Tag tag>
ConversionResult<T> getParameterSpecific(const P& u) {
    const auto& spec = VALUE_OR_RETURN(UNION_GET(u, specific));
    return unionGetField<typename P::Specific, tag>(spec);
}

template <typename P, typename T, typename P::Specific::Tag tag, typename T::Tag field, typename F>
ConversionResult<F> getParameterSpecificField(const P& u) {
    const auto& spec =
            VALUE_OR_RETURN((getParameterSpecific<std::decay_t<decltype(u)>, T, tag>(u)));
    return VALUE_OR_RETURN((unionGetField<T, field>(spec)));
}

#define GET_PARAMETER_SPECIFIC_FIELD(_u, _effect, _tag, _field, _fieldType)                      \
    getParameterSpecificField<std::decay_t<decltype(_u)>, _effect,                               \
                              aidl::android::hardware::audio::effect::Parameter::Specific::_tag, \
                              _effect::_field, _fieldType>(_u)

#define MAKE_SPECIFIC_PARAMETER(_spec, _tag, _field, _value)                                 \
    UNION_MAKE(aidl::android::hardware::audio::effect::Parameter, specific,                  \
               UNION_MAKE(aidl::android::hardware::audio::effect::Parameter::Specific, _tag, \
                          UNION_MAKE(_spec, _field, _value)))

#define MAKE_SPECIFIC_PARAMETER_ID(_spec, _tag, _field)                     \
    UNION_MAKE(aidl::android::hardware::audio::effect::Parameter::Id, _tag, \
               UNION_MAKE(_spec::Id, commonTag, _field))

#define MAKE_EXTENSION_PARAMETER_ID(_effect, _tag, _field)                  \
    UNION_MAKE(aidl::android::hardware::audio::effect::Parameter::Id, _tag, \
               UNION_MAKE(_effect::Id, vendorExtensionTag, _field))

#define VENDOR_EXTENSION_GET_AND_RETURN(_effect, _tag, _param)                                    \
    {                                                                                             \
        aidl::android::hardware::audio::effect::VendorExtension _extId = VALUE_OR_RETURN_STATUS(  \
                aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(_param));        \
        aidl::android::hardware::audio::effect::Parameter::Id _id =                               \
                MAKE_EXTENSION_PARAMETER_ID(_effect, _tag##Tag, _extId);                          \
        aidl::android::hardware::audio::effect::Parameter _aidlParam;                             \
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(_id, &_aidlParam))); \
        aidl::android::hardware::audio::effect::VendorExtension _ext =                            \
                VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(                              \
                        _aidlParam, _effect, _tag, _effect::vendor, VendorExtension));            \
        return VALUE_OR_RETURN_STATUS(                                                            \
                aidl::android::aidl2legacy_Parameter_EffectParameterWriter(_aidlParam, _param));  \
    }

ConversionResult<uint32_t> aidl2legacy_Flags_Type_uint32(
        ::aidl::android::hardware::audio::effect::Flags::Type type);
ConversionResult<uint32_t> aidl2legacy_Flags_Insert_uint32(
        ::aidl::android::hardware::audio::effect::Flags::Insert insert);
ConversionResult<uint32_t> aidl2legacy_Flags_Volume_uint32(
        ::aidl::android::hardware::audio::effect::Flags::Volume volume);
ConversionResult<uint32_t> aidl2legacy_Flags_HardwareAccelerator_uint32(
        ::aidl::android::hardware::audio::effect::Flags::HardwareAccelerator hwAcceleratorMode);
ConversionResult<uint32_t> aidl2legacy_Flags_uint32(
        const ::aidl::android::hardware::audio::effect::Flags aidl);

ConversionResult<::aidl::android::hardware::audio::effect::Flags::Type>
legacy2aidl_uint32_Flags_Type(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags::Insert>
legacy2aidl_uint32_Flags_Insert(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags::Volume>
legacy2aidl_uint32_Flags_Volume(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags::HardwareAccelerator>
legacy2aidl_uint32_Flags_HardwareAccelerator(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags> legacy2aidl_uint32_Flags(
        uint32_t hal);

ConversionResult<effect_descriptor_t> aidl2legacy_Descriptor_effect_descriptor(
        const ::aidl::android::hardware::audio::effect::Descriptor& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Descriptor>
legacy2aidl_effect_descriptor_Descriptor(const effect_descriptor_t& hal);

ConversionResult<uint32_t> aidl2legacy_Parameter_aec_uint32_echoDelay(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_uint32_echoDelay_Parameter_aec(uint32_t legacy);

ConversionResult<uint32_t> aidl2legacy_Parameter_aec_uint32_mobileMode(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_uint32_mobileMode_Parameter_aec(uint32_t legacy);

ConversionResult<uint32_t> aidl2legacy_Parameter_agc_uint32_fixedDigitalGain(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_uint32_fixedDigitalGain_Parameter_agc(uint32_t legacy);

ConversionResult<uint32_t> aidl2legacy_Parameter_agc_uint32_levelEstimator(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_uint32_levelEstimator_Parameter_agc(uint32_t legacy);

ConversionResult<uint32_t> aidl2legacy_Parameter_agc_uint32_saturationMargin(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_uint32_saturationMargin_Parameter_agc(uint32_t legacy);

ConversionResult<uint16_t> aidl2legacy_Parameter_BassBoost_uint16_strengthPm(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_uint16_strengthPm_Parameter_BassBoost(uint16_t legacy);

ConversionResult<int16_t> aidl2legacy_Parameter_Downmix_int16_type(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_int16_type_Parameter_Downmix(int16_t legacy);

ConversionResult<::aidl::android::hardware::audio::effect::DynamicsProcessing::ResolutionPreference>
legacy2aidl_int32_DynamicsProcessing_ResolutionPreference(int32_t legacy);
ConversionResult<int32_t> aidl2legacy_DynamicsProcessing_ResolutionPreference_int32(
        ::aidl::android::hardware::audio::effect::DynamicsProcessing::ResolutionPreference aidl);

ConversionResult<uint32_t> aidl2legacy_Parameter_Visualizer_ScalingMode_uint32(
        ::aidl::android::hardware::audio::effect::Visualizer::ScalingMode aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Visualizer::ScalingMode>
legacy2aidl_Parameter_Visualizer_uint32_ScalingMode(uint32_t legacy);

ConversionResult<uint32_t> aidl2legacy_Parameter_Visualizer_MeasurementMode_uint32(
        ::aidl::android::hardware::audio::effect::Visualizer::MeasurementMode aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Visualizer::MeasurementMode>
legacy2aidl_Parameter_Visualizer_uint32_MeasurementMode(uint32_t legacy);

/**
 * Read DefaultExtension from VendorExtension, and overwrite to the entire effect_param_t (both
 * parameter and data area) with EffectParamWriter::overwrite.
 */
ConversionResult<::android::status_t> aidl2legacy_VendorExtension_EffectParameterWriter_Data(
        ::android::effect::utils::EffectParamWriter& param,
        ::aidl::android::hardware::audio::effect::VendorExtension ext);
/**
 * Copy the entire effect_param_t (both parameter and data area) to DefaultExtension::bytes, and
 * write into VendorExtension.
 */
ConversionResult<::aidl::android::hardware::audio::effect::VendorExtension>
legacy2aidl_EffectParameterReader_VendorExtension(
        ::android::effect::utils::EffectParamReader& param);

ConversionResult<::android::status_t> aidl2legacy_Parameter_EffectParameterWriter(
        const ::aidl::android::hardware::audio::effect::Parameter& aidl,
        ::android::effect::utils::EffectParamWriter& legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Parameter>
legacy2aidl_EffectParameterReader_Parameter(
        ::android::effect::utils::EffectParamReader& param);
}  // namespace android
}  // namespace aidl
