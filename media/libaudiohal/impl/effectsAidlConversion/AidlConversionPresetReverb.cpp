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
#define LOG_TAG "AidlConversionPresetReverb"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_presetreverb.h>

#include <utils/Log.h>

#include "AidlConversionPresetReverb.h"

namespace android {
namespace effect {

using ::aidl::android::convertIntegral;
using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::PresetReverb;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionPresetReverb::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    if (type == REVERB_PARAM_PRESET) {
        uint16_t value = 0;
        if (OK != param.readFromValue(&value)) {
            ALOGE("%s invalid preset value %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
        aidlParam = MAKE_SPECIFIC_PARAMETER(PresetReverb, presetReverb, preset,
                                            static_cast<PresetReverb::Presets>(value));
    } else {
        // for vendor extension, copy data area to the DefaultExtension, parameter ignored
        VendorExtension ext = VALUE_OR_RETURN_STATUS(
                aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
        aidlParam = MAKE_SPECIFIC_PARAMETER(PresetReverb, presetReverb, vendor, ext);
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionPresetReverb::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    uint16_t value = 0;
    ALOGE("%s enter %s", __func__, param.toString().c_str());
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    if (type == REVERB_PARAM_PRESET) {
        Parameter aidlParam;
        Parameter::Id id =
                MAKE_SPECIFIC_PARAMETER_ID(PresetReverb, presetReverbTag, PresetReverb::preset);
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
        auto aidlPreset = VALUE_OR_RETURN_STATUS(
                GET_PARAMETER_SPECIFIC_FIELD(aidlParam, PresetReverb, presetReverb,
                                             PresetReverb::preset, PresetReverb::Presets));
        value = static_cast<uint16_t>(aidlPreset);
    } else {
        // handle vendor extension
        VENDOR_EXTENSION_GET_AND_RETURN(PresetReverb, presetReverb, param);
    }
    return param.writeToValue(&value);
}

} // namespace effect
} // namespace android
