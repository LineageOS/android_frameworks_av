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
#define LOG_TAG "AidlConversionAgc2"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_agc2.h>

#include <utils/Log.h>

#include "AidlConversionAgc2.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::AutomaticGainControlV2;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionAgc2::setParameter(EffectParamReader& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_fixedDigitalGain_Parameter_agc(value));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_levelEstimator_Parameter_agc(value));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_saturationMargin_Parameter_agc(value));
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(AutomaticGainControlV2, automaticGainControlV2,
                                                vendor, ext);
            break;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionAgc2::getParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN: {
            Parameter::Id id =
                    MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControlV2, automaticGainControlV2Tag,
                                               AutomaticGainControlV2::fixedDigitalGainMb);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_agc_uint32_fixedDigitalGain(aidlParam));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR: {
            Parameter::Id id =
                    MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControlV2, automaticGainControlV2Tag,
                                               AutomaticGainControlV2::levelEstimator);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_agc_uint32_levelEstimator(aidlParam));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN: {
            Parameter::Id id =
                    MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControlV2, automaticGainControlV2Tag,
                                               AutomaticGainControlV2::saturationMarginMb);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_agc_uint32_saturationMargin(aidlParam));
            break;
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(AutomaticGainControlV2, automaticGainControlV2, param);
        }
    }

    return param.writeToValue(&value);
}

} // namespace effect
} // namespace android
