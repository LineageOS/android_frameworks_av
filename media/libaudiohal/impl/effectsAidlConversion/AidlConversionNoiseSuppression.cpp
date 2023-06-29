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
#define LOG_TAG "AidlConversionNoiseSuppression"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_ns.h>

#include <utils/Log.h>

#include "AidlConversionNoiseSuppression.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::NoiseSuppression;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionNoiseSuppression::setParameter(EffectParamReader& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case NS_PARAM_LEVEL: {
            aidlParam = MAKE_SPECIFIC_PARAMETER(NoiseSuppression, noiseSuppression, level,
                                                static_cast<NoiseSuppression::Level>(value));
            break;
        }
        case NS_PARAM_TYPE: {
            aidlParam = MAKE_SPECIFIC_PARAMETER(NoiseSuppression, noiseSuppression, type,
                                                static_cast<NoiseSuppression::Type>(value));
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(NoiseSuppression, noiseSuppression, vendor, ext);
            break;
        }
    }
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionNoiseSuppression::getParameter(EffectParamWriter& param) {
    uint32_t paramType = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&paramType)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (paramType) {
        case NS_PARAM_LEVEL: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(NoiseSuppression, noiseSuppressionTag,
                                                        NoiseSuppression::level);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            NoiseSuppression::Level level = VALUE_OR_RETURN_STATUS(
                    GET_PARAMETER_SPECIFIC_FIELD(aidlParam, NoiseSuppression, noiseSuppression,
                                                 NoiseSuppression::level, NoiseSuppression::Level));
            value = static_cast<uint32_t>(level);
            break;
        }
        case NS_PARAM_TYPE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(NoiseSuppression, noiseSuppressionTag,
                                                        NoiseSuppression::type);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            NoiseSuppression::Type nsType = VALUE_OR_RETURN_STATUS(
                    GET_PARAMETER_SPECIFIC_FIELD(aidlParam, NoiseSuppression, noiseSuppression,
                                                 NoiseSuppression::type, NoiseSuppression::Type));
            value = static_cast<uint32_t>(nsType);
            break;
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(NoiseSuppression, noiseSuppression, param);
        }
    }
    return param.writeToValue(&value);
}

} // namespace effect
} // namespace android
