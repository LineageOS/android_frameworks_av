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
#define LOG_TAG "AidlConversionDownmix"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_downmix.h>

#include <system/audio_effect.h>
#include <utils/Log.h>

#include "AidlConversionDownmix.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Downmix;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionDownmix::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    int16_t value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(int16_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case DOWNMIX_PARAM_TYPE: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_int16_type_Parameter_Downmix(value));
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(Downmix, downmix, vendor, ext);
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionDownmix::getParameter(EffectParamWriter& param) {
    int16_t value = 0;
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type)) {
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case DOWNMIX_PARAM_TYPE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Downmix, downmixTag, Downmix::type);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_Downmix_int16_type(aidlParam));
            break;
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(Downmix, downmix, param);
        }
    }

    return param.writeToValue(&value);
}

} // namespace effect
} // namespace android
