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
#define LOG_TAG "AidlConversionAgc1"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_agc.h>

#include <utils/Log.h>

#include "AidlConversionAgc1.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::AutomaticGainControlV1;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionAgc1::setParameterLevel(EffectParamReader& param) {
    int16_t level;
    RETURN_STATUS_IF_ERROR(param.readFromValue(&level));
    Parameter aidlParam = MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV1, automaticGainControlV1,
                                                  targetPeakLevelDbFs, level);
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionAgc1::setParameterGain(EffectParamReader& param) {
    int16_t gain;
    RETURN_STATUS_IF_ERROR(param.readFromValue(&gain));
    Parameter aidlParam = MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV1, automaticGainControlV1,
                                                  maxCompressionGainDb, gain);
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionAgc1::setParameterLimiterEnable(EffectParamReader& param) {
    bool enable;
    RETURN_STATUS_IF_ERROR(param.readFromValue(&enable));
    Parameter aidlParam = MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV1, automaticGainControlV1,
                                                  enableLimiter, enable);
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionAgc1::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    switch (type) {
        case AGC_PARAM_TARGET_LEVEL: {
            return setParameterLevel(param);
        }
        case AGC_PARAM_COMP_GAIN: {
            return setParameterGain(param);
        }
        case AGC_PARAM_LIMITER_ENA: {
            return setParameterLimiterEnable(param);
        }
        case AGC_PARAM_PROPERTIES: {
            RETURN_STATUS_IF_ERROR(setParameterLevel(param));
            RETURN_STATUS_IF_ERROR(setParameterGain(param));
            RETURN_STATUS_IF_ERROR(setParameterLimiterEnable(param));
            return OK;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            Parameter aidlParam = MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV1,
                                                          automaticGainControlV1, vendor, ext);
            return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
        }
    }
}

status_t AidlConversionAgc1::getParameterLevel(EffectParamWriter& param) {
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControlV1, automaticGainControlV1Tag,
                                                  AutomaticGainControlV1::targetPeakLevelDbFs);
    Parameter aidlParam;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    int32_t level = VALUE_OR_RETURN_STATUS(
            GET_PARAMETER_SPECIFIC_FIELD(aidlParam, AutomaticGainControlV1, automaticGainControlV1,
                                         AutomaticGainControlV1::targetPeakLevelDbFs, int32_t));
    return param.writeToValue(&level);
}

status_t AidlConversionAgc1::getParameterGain(EffectParamWriter& param) {
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControlV1, automaticGainControlV1Tag,
                                                  AutomaticGainControlV1::maxCompressionGainDb);
    Parameter aidlParam;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    int32_t gain = VALUE_OR_RETURN_STATUS(
            GET_PARAMETER_SPECIFIC_FIELD(aidlParam, AutomaticGainControlV1, automaticGainControlV1,
                                         AutomaticGainControlV1::maxCompressionGainDb, int32_t));
    return param.writeToValue(&gain);
}

status_t AidlConversionAgc1::getParameterLimiterEnable(EffectParamWriter& param) {
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControlV1, automaticGainControlV1Tag,
                                                  AutomaticGainControlV1::enableLimiter);
    Parameter aidlParam;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    bool enable = VALUE_OR_RETURN_STATUS(
            GET_PARAMETER_SPECIFIC_FIELD(aidlParam, AutomaticGainControlV1, automaticGainControlV1,
                                         AutomaticGainControlV1::enableLimiter, bool));
    return param.writeToValue(&enable);
}

status_t AidlConversionAgc1::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    switch (type) {
        case AGC_PARAM_TARGET_LEVEL: {
            return getParameterLevel(param);
        }
        case AGC_PARAM_COMP_GAIN: {
            return getParameterGain(param);
        }
        case AGC_PARAM_LIMITER_ENA: {
            return getParameterLimiterEnable(param);
        }
        case AGC_PARAM_PROPERTIES: {
            RETURN_STATUS_IF_ERROR(getParameterLevel(param));
            RETURN_STATUS_IF_ERROR(getParameterGain(param));
            RETURN_STATUS_IF_ERROR(getParameterLimiterEnable(param));
            return OK;
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(AutomaticGainControlV1, automaticGainControlV1, param);
        }
    }
}

} // namespace effect
} // namespace android
