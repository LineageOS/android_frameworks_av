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
#define LOG_TAG "AidlConversionEQ"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/audiohal/AudioEffectUuid.h>
#include <system/audio_effects/effect_equalizer.h>

#include <utils/Log.h>

#include "AidlConversionEq.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Equalizer;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionEq::setParameter(EffectParamReader& param) {
    uint32_t type;
    uint16_t value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) ||
        OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

    Parameter aidlParam;
    switch (type) {
        case EQ_PARAM_CUR_PRESET: {
            aidlParam = MAKE_SPECIFIC_PARAMETER(Equalizer, equalizer, preset, (int)value);
            break;
        }
        case EQ_PARAM_BAND_LEVEL: {
            int32_t band;
            uint16_t level;
            if (OK != param.readFromParameter(&band) || OK != param.readFromParameter(&level)) {
                ALOGE("%s invalid bandLevel param %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            std::vector<Equalizer::BandLevel> bandLevels = {{.index = band, .levelMb = level}};
            aidlParam = MAKE_SPECIFIC_PARAMETER(Equalizer, equalizer, bandLevels, bandLevels);
            break;
        }
        case EQ_PARAM_PROPERTIES: {
            // TODO: handle properties setting
            break;
        }
        default: {
            // TODO: implement vendor extension parameters
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

aidl::ConversionResult<Parameter> AidlConversionEq::getAidlParameter(Equalizer::Tag tag) {
    Parameter aidlParam;
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Equalizer, equalizerTag, tag);
    RETURN_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    return aidlParam;
}

status_t AidlConversionEq::getParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type)) {
        param.setStatus(BAD_VALUE);
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case EQ_PARAM_NUM_BANDS: {
            aidlParam = VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::bandLevels));
            auto bandLevels = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Equalizer, equalizer, Equalizer::bandLevels,
                    std::vector<Equalizer::BandLevel>));
            uint32_t num = bandLevels.size();
            return param.writeToValue(&num);
        }
        default:
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
    }
    return param.writeToValue(&value);
}

} // namespace effect
} // namespace android
