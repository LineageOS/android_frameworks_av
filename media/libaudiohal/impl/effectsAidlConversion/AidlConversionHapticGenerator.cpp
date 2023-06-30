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
#define LOG_TAG "AidlConversionHapticGenerator"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_hapticgenerator.h>

#include <utils/Log.h>

#include "AidlConversionHapticGenerator.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::HapticGenerator;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionHapticGenerator::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case HG_PARAM_HAPTIC_INTENSITY: {
            int32_t id = 0, scale;
            if (OK != param.readFromValue(&id) || OK != param.readFromValue(&scale)) {
                ALOGE("%s invalid intensity %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            HapticGenerator::HapticScale hpScale(
                    {.id = id, .scale = (HapticGenerator::VibratorScale)(scale)});
            aidlParam = MAKE_SPECIFIC_PARAMETER(HapticGenerator, hapticGenerator, hapticScales,
                                                {hpScale});
            break;
        }
        case HG_PARAM_VIBRATOR_INFO: {
            float resonantFrequencyHz, qFactor, maxAmplitude;
            if (OK != param.readFromValue(&resonantFrequencyHz) ||
                OK != param.readFromValue(&qFactor) || OK != param.readFromValue(&maxAmplitude)) {
                ALOGE("%s invalid vibrator info %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            HapticGenerator::VibratorInformation info({.resonantFrequencyHz = resonantFrequencyHz,
                                                       .qFactor = qFactor,
                                                       .maxAmplitude = maxAmplitude});
            aidlParam =
                    MAKE_SPECIFIC_PARAMETER(HapticGenerator, hapticGenerator, vibratorInfo, info);
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(HapticGenerator, hapticGenerator, vendor, ext);
            break;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

// No parameter to get for HapticGenerator
status_t AidlConversionHapticGenerator::getParameter(EffectParamWriter& param) {
    VENDOR_EXTENSION_GET_AND_RETURN(HapticGenerator, hapticGenerator, param);
}

} // namespace effect
} // namespace android
