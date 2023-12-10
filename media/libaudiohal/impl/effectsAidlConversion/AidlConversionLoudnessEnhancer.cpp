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
#define LOG_TAG "AidlConversionLoudnessEnhancer"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_loudnessenhancer.h>

#include <utils/Log.h>

#include "AidlConversionLoudnessEnhancer.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::getParameterSpecificField;
using ::aidl::android::hardware::audio::effect::LoudnessEnhancer;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionLoudnessEnhancer::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    int32_t gain = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&gain)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case LOUDNESS_ENHANCER_PARAM_TARGET_GAIN_MB: {
            aidlParam = MAKE_SPECIFIC_PARAMETER(LoudnessEnhancer, loudnessEnhancer, gainMb, gain);
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(LoudnessEnhancer, loudnessEnhancer, vendor, ext);
            break;
        }
    }
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionLoudnessEnhancer::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    switch (type) {
        case LOUDNESS_ENHANCER_PARAM_TARGET_GAIN_MB: {
            Parameter aidlParam;
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(LoudnessEnhancer, loudnessEnhancerTag,
                                                        LoudnessEnhancer::gainMb);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            int32_t gain = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, LoudnessEnhancer, loudnessEnhancer, LoudnessEnhancer::gainMb,
                    std::decay_t<decltype(gain)>));
            return param.writeToValue(&gain);
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(LoudnessEnhancer, loudnessEnhancer, param);
        }
    }
}

} // namespace effect
} // namespace android
