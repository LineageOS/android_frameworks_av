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
#define LOG_TAG "AidlConversionAec"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_aec.h>

#include <utils/Log.h>

#include "AidlConversionAec.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::AcousticEchoCanceler;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionAec::setParameter(EffectParamReader& param) {
    uint32_t type, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) ||
        OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

    Parameter aidlParam;
    switch (type) {
        case AEC_PARAM_ECHO_DELAY:
            FALLTHROUGH_INTENDED;
        case AEC_PARAM_PROPERTIES: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_echoDelay_Parameter_aec(value));
            break;
        }
        case AEC_PARAM_MOBILE_MODE: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_mobileMode_Parameter_aec(value));
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(AcousticEchoCanceler, acousticEchoCanceler, vendor,
                                                ext);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->setParameter(aidlParam)));
            break;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionAec::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type)) {
        param.setStatus(BAD_VALUE);
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AEC_PARAM_ECHO_DELAY:
            FALLTHROUGH_INTENDED;
        case AEC_PARAM_PROPERTIES: {
            int32_t delay = 0;
            Parameter::Id id =
                    MAKE_SPECIFIC_PARAMETER_ID(AcousticEchoCanceler, acousticEchoCancelerTag,
                                               AcousticEchoCanceler::echoDelayUs);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            delay = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_aec_uint32_echoDelay(aidlParam));
            return param.writeToValue(&delay);
        }
        case AEC_PARAM_MOBILE_MODE: {
            int32_t mode = 0;
            Parameter::Id id =
                    MAKE_SPECIFIC_PARAMETER_ID(AcousticEchoCanceler, acousticEchoCancelerTag,
                                               AcousticEchoCanceler::mobileMode);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            mode = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_aec_uint32_mobileMode(aidlParam));
            return param.writeToValue(&mode);
        }
        default: {
            // use vendor extension implementation, the first 32bits (param type) won't pass to HAL
            VENDOR_EXTENSION_GET_AND_RETURN(AcousticEchoCanceler, acousticEchoCanceler, param);
        }
    }
}

} // namespace effect
} // namespace android
