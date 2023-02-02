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
#include <media/audiohal/AudioEffectUuid.h>
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
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

#define MAKE_AIDL_PARAMETER(aidlParam, param, value, tag)                            \
    {                                                                                \
        if (OK != param.readFromValue(&value)) {                                     \
            ALOGE("%s invalid parameter %s %d", __func__, #tag, value);              \
            return BAD_VALUE;                                                        \
        }                                                                            \
        aidlParam = MAKE_SPECIFIC_PARAMETER(                                         \
                EnvironmentalReverb, environmentalReverb, tag,                       \
                VALUE_OR_RETURN_STATUS(aidl::android::convertIntegral<int>(value))); \
    }

#define GET_AIDL_PARAMETER(tag, value, param)                                                      \
    {                                                                                              \
        Parameter aidlParam;                                                                       \
        Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(EnvironmentalReverb, environmentalReverbTag, \
                                                      EnvironmentalReverb::tag);                   \
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));    \
        value = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(                               \
                aidlParam, EnvironmentalReverb, environmentalReverb, EnvironmentalReverb::tag,     \
                std::decay_t<decltype(value)>));                                                   \
        return param.writeToValue(&value);                                                         \
    }

status_t AidlConversionEnvReverb::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    uint16_t value16;
    uint32_t value32;
    switch (type) {
        case REVERB_PARAM_ROOM_LEVEL: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value16, roomLevelMb);
            break;
        }
        case REVERB_PARAM_ROOM_HF_LEVEL: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value16, roomHfLevelMb);
            break;
        }
        case REVERB_PARAM_DECAY_TIME: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value32, decayTimeMs);
            break;
        }
        case REVERB_PARAM_DECAY_HF_RATIO: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value16, decayHfRatioPm);
            break;
        }
        case REVERB_PARAM_REVERB_LEVEL: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value16, levelMb);
            break;
        }
        case REVERB_PARAM_REVERB_DELAY: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value32, delayMs);
            break;
        }
        case REVERB_PARAM_DIFFUSION: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value16, diffusionPm);
            break;
        }
        case REVERB_PARAM_DENSITY: {
            MAKE_AIDL_PARAMETER(aidlParam, param, value16, densityPm);
            break;
        }
        case REVERB_PARAM_BYPASS: {
            if (OK != param.readFromValue(&value32)) {
                ALOGE("%s invalid bypass parameter %d", __func__, value32);
                return BAD_VALUE;
            }
            bool isByPass = VALUE_OR_RETURN_STATUS(aidl::android::convertIntegral<bool>(value32));
            aidlParam = MAKE_SPECIFIC_PARAMETER(EnvironmentalReverb, environmentalReverb, bypass,
                                                isByPass);
            break;
        }
        case REVERB_PARAM_REFLECTIONS_LEVEL: {
            // TODO
            break;
        }
        case REVERB_PARAM_REFLECTIONS_DELAY: {
            // TODO
            break;
        }
        case REVERB_PARAM_PROPERTIES: {
            // TODO
            break;
        }
        default: {
            // TODO: handle with vendor extension
        }
    }
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionEnvReverb::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    uint16_t value16;
    uint32_t value32;
    switch (type) {
        case REVERB_PARAM_ROOM_LEVEL: {
            GET_AIDL_PARAMETER(roomLevelMb, value16, param);
        }
        case REVERB_PARAM_ROOM_HF_LEVEL: {
            GET_AIDL_PARAMETER(roomHfLevelMb, value16, param);
        }
        case REVERB_PARAM_DECAY_TIME: {
            GET_AIDL_PARAMETER(decayTimeMs, value32, param);
        }
        case REVERB_PARAM_DECAY_HF_RATIO: {
            GET_AIDL_PARAMETER(decayHfRatioPm, value16, param);
        }
        case REVERB_PARAM_REVERB_LEVEL: {
            GET_AIDL_PARAMETER(levelMb, value16, param);
        }
        case REVERB_PARAM_REVERB_DELAY: {
            GET_AIDL_PARAMETER(delayMs, value32, param);
        }
        case REVERB_PARAM_DIFFUSION: {
            GET_AIDL_PARAMETER(diffusionPm, value16, param);
        }
        case REVERB_PARAM_DENSITY: {
            GET_AIDL_PARAMETER(densityPm, value16, param);
        }
        case REVERB_PARAM_BYPASS: {
            bool isByPass;
            GET_AIDL_PARAMETER(bypass, isByPass, param);
        }
        case REVERB_PARAM_REFLECTIONS_LEVEL: {
            // TODO
            break;
        }
        case REVERB_PARAM_REFLECTIONS_DELAY: {
            // TODO
            break;
        }
        case REVERB_PARAM_PROPERTIES: {
            // TODO
            break;
        }
        default: {
            // TODO: handle with vendor extension
        }
    }
    return BAD_VALUE;
}

} // namespace effect
} // namespace android
