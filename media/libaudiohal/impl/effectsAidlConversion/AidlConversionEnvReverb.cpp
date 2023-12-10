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
#include <cstring>
#include <optional>
#define LOG_TAG "AidlConversionEnvReverb"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_environmentalreverb.h>

#include <utils/Log.h>

#include "AidlConversionEnvReverb.h"

namespace android {
namespace effect {

using ::aidl::android::convertIntegral;
using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::EnvironmentalReverb;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

/**
 * Macro to get a parameter from effect_param_t wrapper and set it to AIDL effect.
 *
 * Return if there is any error, otherwise continue execution.
 *
 * @param param EffectParamReader, a reader wrapper of effect_param_t.
 * @param aidlType Type of the AIDL parameter field, used to construct AIDL Parameter union.
 * @param valueType Type of the value get from effect_param_t.
 * @param tag The AIDL parameter union field tag.
 */
#define SET_AIDL_PARAMETER(param, aidlType, valueType, tag)                                \
    {                                                                                      \
        Parameter aidlParam;                                                               \
        valueType value;                                                                   \
        if (status_t status = param.readFromValue(&value); status != OK) {                 \
            ALOGE("%s  %s read from parameter failed, ret %d", __func__, #tag, status);    \
            return status;                                                                 \
        }                                                                                  \
        aidlParam = MAKE_SPECIFIC_PARAMETER(                                               \
                EnvironmentalReverb, environmentalReverb, tag,                             \
                VALUE_OR_RETURN_STATUS(aidl::android::convertIntegral<aidlType>(value)));  \
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->setParameter(aidlParam))); \
    }

/**
 * Macro to get a parameter from AIDL effect and write the value to effect_param_t with wrapper.
 *
 * Return if there is any error, otherwise continue execution.
 *
 * @param param EffectParamWriter, a writer wrapper of effect_param_t.
 * @param aidlType Type of the AIDL parameter field, used to construct AIDL Parameter union.
 * @param valueType  Type of the value get from effect_param_t.
 * @param tag The AIDL parameter union field tag.
 */
#define GET_AIDL_PARAMETER(param, aidltype, valueType, tag)                                        \
    {                                                                                              \
        aidltype value;                                                                            \
        Parameter aidlParam;                                                                       \
        Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(EnvironmentalReverb, environmentalReverbTag, \
                                                      EnvironmentalReverb::tag);                   \
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));    \
        value = VALUE_OR_RETURN_STATUS(                                                            \
                GET_PARAMETER_SPECIFIC_FIELD(aidlParam, EnvironmentalReverb, environmentalReverb,  \
                                             EnvironmentalReverb::tag, std::decay_t<aidltype>));   \
        if (status_t status = param.writeToValue((valueType*)&value); status != OK) {              \
            param.setStatus(status);                                                               \
            ALOGE("%s %s write to parameter failed %d, ret %d", __func__, #tag, value, status);    \
            return status;                                                                         \
        }                                                                                          \
    }

status_t AidlConversionEnvReverb::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (status_t status = param.readFromParameter(&type); status != OK) {
        ALOGE("%s failed to read type from %s, ret %d", __func__, param.toString().c_str(), status);
        return BAD_VALUE;
    }

    switch (type) {
        case REVERB_PARAM_ROOM_LEVEL: {
            SET_AIDL_PARAMETER(param, int32_t, int16_t, roomLevelMb);
            break;
        }
        case REVERB_PARAM_ROOM_HF_LEVEL: {
            SET_AIDL_PARAMETER(param, int32_t, int16_t, roomHfLevelMb);
            break;
        }
        case REVERB_PARAM_DECAY_TIME: {
            SET_AIDL_PARAMETER(param, int32_t, uint32_t, decayTimeMs);
            break;
        }
        case REVERB_PARAM_DECAY_HF_RATIO: {
            SET_AIDL_PARAMETER(param, int32_t, int16_t, decayHfRatioPm);
            break;
        }
        case REVERB_PARAM_REFLECTIONS_LEVEL: {
            SET_AIDL_PARAMETER(param, int32_t, int16_t, reflectionsLevelMb);
            break;
        }
        case REVERB_PARAM_REFLECTIONS_DELAY: {
            SET_AIDL_PARAMETER(param, int32_t, uint32_t, reflectionsDelayMs);
            break;
        }
        case REVERB_PARAM_REVERB_LEVEL: {
            SET_AIDL_PARAMETER(param, int32_t, int16_t, levelMb);
            break;
        }
        case REVERB_PARAM_REVERB_DELAY: {
            SET_AIDL_PARAMETER(param, int32_t, uint32_t, delayMs);
            break;
        }
        case REVERB_PARAM_DIFFUSION: {
            SET_AIDL_PARAMETER(param, int32_t, int16_t, diffusionPm);
            break;
        }
        case REVERB_PARAM_DENSITY: {
            SET_AIDL_PARAMETER(param, int32_t, int16_t, densityPm);
            break;
        }
        case REVERB_PARAM_BYPASS: {
            SET_AIDL_PARAMETER(param, bool, int32_t, bypass);
            break;
        }
        case REVERB_PARAM_PROPERTIES: {
            if (sizeof(t_reverb_settings) > param.getValueSize()) {
                ALOGE("%s vsize %zu less than t_reverb_settings size %zu", __func__,
                      param.getValueSize(), sizeof(t_reverb_settings));
                return BAD_VALUE;
            }
            // this sequency needs to be aligned with t_reverb_settings
            SET_AIDL_PARAMETER(param, int32_t, int16_t, roomLevelMb);
            SET_AIDL_PARAMETER(param, int32_t, int16_t, roomHfLevelMb);
            SET_AIDL_PARAMETER(param, int32_t, uint32_t, decayTimeMs);
            SET_AIDL_PARAMETER(param, int32_t, int16_t, decayHfRatioPm);
            SET_AIDL_PARAMETER(param, int32_t, int16_t, reflectionsLevelMb);
            SET_AIDL_PARAMETER(param, int32_t, uint32_t, reflectionsDelayMs);
            SET_AIDL_PARAMETER(param, int32_t, int16_t, levelMb);
            SET_AIDL_PARAMETER(param, int32_t, uint32_t, delayMs);
            SET_AIDL_PARAMETER(param, int32_t, int16_t, diffusionPm);
            SET_AIDL_PARAMETER(param, int32_t, int16_t, densityPm);
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            Parameter aidlParam = MAKE_SPECIFIC_PARAMETER(EnvironmentalReverb,
                                                          environmentalReverb, vendor, ext);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->setParameter(aidlParam)));
            break;
        }
    }
    return OK;
}

status_t AidlConversionEnvReverb::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (status_t status = param.readFromParameter(&type); status != OK) {
        ALOGE("%s failed to read type from %s", __func__, param.toString().c_str());
        param.setStatus(status);
        return status;
    }

    switch (type) {
        case REVERB_PARAM_ROOM_LEVEL: {
            GET_AIDL_PARAMETER(param, int32_t, int16_t, roomLevelMb);
            break;
        }
        case REVERB_PARAM_ROOM_HF_LEVEL: {
            GET_AIDL_PARAMETER(param, int32_t, int16_t, roomHfLevelMb);
            break;
        }
        case REVERB_PARAM_DECAY_TIME: {
            GET_AIDL_PARAMETER(param, int32_t, uint32_t, decayTimeMs);
            break;
        }
        case REVERB_PARAM_DECAY_HF_RATIO: {
            GET_AIDL_PARAMETER(param, int32_t, int16_t, decayHfRatioPm);
            break;
        }
        case REVERB_PARAM_REFLECTIONS_LEVEL: {
            GET_AIDL_PARAMETER(param, int32_t, int16_t, reflectionsLevelMb);
            break;
        }
        case REVERB_PARAM_REFLECTIONS_DELAY: {
            GET_AIDL_PARAMETER(param, int32_t, uint32_t, reflectionsDelayMs);
            break;
        }
        case REVERB_PARAM_REVERB_LEVEL: {
            GET_AIDL_PARAMETER(param, int32_t, int16_t, levelMb);
            break;
        }
        case REVERB_PARAM_REVERB_DELAY: {
            GET_AIDL_PARAMETER(param, int32_t, uint32_t, delayMs);
            break;
        }
        case REVERB_PARAM_DIFFUSION: {
            GET_AIDL_PARAMETER(param, int32_t, int16_t, diffusionPm);
            break;
        }
        case REVERB_PARAM_DENSITY: {
            GET_AIDL_PARAMETER(param, int32_t, int16_t, densityPm);
            break;
        }
        case REVERB_PARAM_BYPASS: {
            GET_AIDL_PARAMETER(param, bool, int32_t, bypass);
            break;
        }
        case REVERB_PARAM_PROPERTIES: {
            // this sequency needs to be aligned with t_reverb_settings
            GET_AIDL_PARAMETER(param, int32_t, int16_t, roomLevelMb);
            GET_AIDL_PARAMETER(param, int32_t, int16_t, roomHfLevelMb);
            GET_AIDL_PARAMETER(param, int32_t, uint32_t, decayTimeMs);
            GET_AIDL_PARAMETER(param, int32_t, int16_t, decayHfRatioPm);
            GET_AIDL_PARAMETER(param, int32_t, int16_t, reflectionsLevelMb);
            GET_AIDL_PARAMETER(param, int32_t, uint32_t, reflectionsDelayMs);
            GET_AIDL_PARAMETER(param, int32_t, int16_t, levelMb);
            GET_AIDL_PARAMETER(param, int32_t, uint32_t, delayMs);
            GET_AIDL_PARAMETER(param, int32_t, int16_t, diffusionPm);
            GET_AIDL_PARAMETER(param, int32_t, int16_t, densityPm);
            break;
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(EnvironmentalReverb, environmentalReverb, param);
        }
    }
    return OK;
}

} // namespace effect
} // namespace android
