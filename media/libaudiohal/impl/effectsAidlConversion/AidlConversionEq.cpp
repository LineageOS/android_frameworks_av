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
#include <system/audio_effects/effect_equalizer.h>

#include <utils/Log.h>

#include "AidlConversionEq.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Equalizer;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::Range;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::base::unexpected;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionEq::setParameter(EffectParamReader& param) {
    uint32_t type;
    if (OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

    Parameter aidlParam;
    switch (type) {
        case EQ_PARAM_CUR_PRESET: {
            uint16_t value = 0;
            if (OK != param.readFromValue(&value)) {
                ALOGE("%s invalid param %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            aidlParam = MAKE_SPECIFIC_PARAMETER(Equalizer, equalizer, preset, (int)value);
            break;
        }
        case EQ_PARAM_BAND_LEVEL: {
            int32_t band;
            int16_t level;
            if (OK != param.readFromParameter(&band) || OK != param.readFromValue(&level)) {
                ALOGE("%s invalid bandLevel param %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            std::vector<Equalizer::BandLevel> bandLevels = {{.index = band, .levelMb = level}};
            aidlParam = MAKE_SPECIFIC_PARAMETER(Equalizer, equalizer, bandLevels, bandLevels);
            break;
        }
        case EQ_PARAM_PROPERTIES: {
            int16_t num;
            if (OK != param.readFromValue(&num)) {
                ALOGE("%s invalid param %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            // set preset if it's valid
            if (num >= 0) {
                aidlParam = MAKE_SPECIFIC_PARAMETER(Equalizer, equalizer, preset, (int)num);
                break;
            }
            // set bandLevel if no preset was set
            if (OK != param.readFromValue(&num)) {
                ALOGE("%s invalid param %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            std::vector<Equalizer::BandLevel> bandLevels;
            for (int i = 0; i < num; i++) {
                Equalizer::BandLevel level({.index = i});
                if (OK != param.readFromValue((uint16_t*)&level.levelMb)) {
                    ALOGE("%s invalid param %s", __func__, param.toString().c_str());
                    return BAD_VALUE;
                }
                bandLevels.push_back(level);
            }
            aidlParam = MAKE_SPECIFIC_PARAMETER(Equalizer, equalizer, bandLevels, bandLevels);
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(Equalizer, equalizer, vendor, ext);
            break;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

ConversionResult<Parameter> AidlConversionEq::getAidlParameter(Equalizer::Tag tag) {
    Parameter aidlParam;
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Equalizer, equalizerTag, tag);
    RETURN_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    return aidlParam;
}

ConversionResult<int32_t> AidlConversionEq::getParameterPreset() {
    Parameter aidlParam = VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::preset));
    return VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(aidlParam, Equalizer, equalizer,
                                                               Equalizer::preset, int32_t));
}

ConversionResult<std::string> AidlConversionEq::getParameterPresetName(
        EffectParamWriter& param) {
    int32_t presetIdx;
    if (OK != param.readFromParameter(&presetIdx)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return unexpected(BAD_VALUE);
    }
    Parameter aidlParam = VALUE_OR_RETURN(getAidlParameter(Equalizer::presets));
    const auto& presets = VALUE_OR_RETURN(GET_PARAMETER_SPECIFIC_FIELD(
            aidlParam, Equalizer, equalizer, Equalizer::presets, std::vector<Equalizer::Preset>));
    for (const auto& preset : presets) {
        if (presetIdx == preset.index) {
            return preset.name;
        }
    }
    return unexpected(BAD_VALUE);
}

status_t AidlConversionEq::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (OK != param.readFromParameter(&type)) {
        param.setStatus(BAD_VALUE);
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

    switch (type) {
        case EQ_PARAM_NUM_BANDS: {
            Parameter aidlParam = VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::bandLevels));
            const auto& bandLevels = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Equalizer, equalizer, Equalizer::bandLevels,
                    std::vector<Equalizer::BandLevel>));
            uint16_t bands = bandLevels.size();
            return param.writeToValue(&bands);
        }
        case EQ_PARAM_LEVEL_RANGE: {
            if (mDesc.capability.range.getTag() != Range::equalizer) {
                return OK;
            }
            const auto& ranges = mDesc.capability.range.get<Range::equalizer>();
            for (const auto& r : ranges) {
                if (r.min.getTag() == Equalizer::bandLevels &&
                    r.max.getTag() == Equalizer::bandLevels) {
                    const auto& aidlMin = r.min.get<Equalizer::bandLevels>();
                    const auto& aidlMax = r.max.get<Equalizer::bandLevels>();
                    int16_t min =
                            std::min_element(aidlMin.begin(), aidlMin.end(), [](auto& a, auto& b) {
                                return a.levelMb < b.levelMb;
                            })->levelMb;
                    int16_t max =
                            std::max_element(aidlMax.begin(), aidlMax.end(), [](auto& a, auto& b) {
                                return a.levelMb < b.levelMb;
                            })->levelMb;
                    return (OK == param.writeToValue(&min) && OK == param.writeToValue(&max))
                                   ? OK
                                   : BAD_VALUE;
                }
            }
            break;
        }
        case EQ_PARAM_BAND_LEVEL: {
            int32_t bandIdx;
            if (OK != param.readFromParameter(&bandIdx)) {
                break;
            }

            Parameter aidlParam = VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::bandLevels));
            const auto& bandLevels = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Equalizer, equalizer, Equalizer::bandLevels,
                    std::vector<Equalizer::BandLevel>));
            for (const auto& band : bandLevels) {
                if (band.index == bandIdx) {
                    return param.writeToValue((uint16_t *)&band.levelMb);
                }
            }
            break;
        }
        case EQ_PARAM_CENTER_FREQ: {
            int32_t index;
            if (OK != param.readFromParameter(&index)) {
                break;
            }

            Parameter aidlParam = VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::centerFreqMh));
            const auto& freqs = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Equalizer, equalizer, Equalizer::centerFreqMh, std::vector<int>));
            if ((size_t)index >= freqs.size()) {
                ALOGE("%s index %d exceed size %zu", __func__, index, freqs.size());
                break;
            }
            return param.writeToValue(&freqs[index]);
        }
        case EQ_PARAM_BAND_FREQ_RANGE: {
            int32_t index;
            if (OK != param.readFromParameter(&index)) {
                break;
            }

            Parameter aidlParam =
                    VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::bandFrequencies));
            const auto& bands = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Equalizer, equalizer, Equalizer::bandFrequencies,
                    std::vector<Equalizer::BandFrequency>));
            for (const auto& band : bands) {
                if (band.index == index) {
                    return (OK == param.writeToValue(&band.minMh) &&
                            OK == param.writeToValue(&band.maxMh))
                                   ? OK
                                   : BAD_VALUE;
                }
            }
            break;
        }
        case EQ_PARAM_GET_BAND: {
            int32_t freq;
            if (OK != param.readFromParameter(&freq)) {
                break;
            }

            Parameter aidlParam =
                    VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::bandFrequencies));
            const auto& bands = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Equalizer, equalizer, Equalizer::bandFrequencies,
                    std::vector<Equalizer::BandFrequency>));
            for (const auto& band : bands) {
                if (freq >= band.minMh && freq <= band.maxMh) {
                    return param.writeToValue((uint16_t*)&band.index);
                }
            }
            break;
        }
        case EQ_PARAM_CUR_PRESET: {
            int32_t preset = VALUE_OR_RETURN_STATUS(getParameterPreset());
            return param.writeToValue((uint16_t*)&preset);
        }
        case EQ_PARAM_GET_NUM_OF_PRESETS: {
            Parameter aidlParam = VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::presets));
            const auto& presets = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Equalizer, equalizer, Equalizer::presets,
                    std::vector<Equalizer::Preset>));
            uint16_t num = presets.size();
            return param.writeToValue(&num);
        }
        case EQ_PARAM_GET_PRESET_NAME: {
            std::string name = VALUE_OR_RETURN_STATUS(getParameterPresetName(param));
            return param.writeToValue(name.c_str(), name.length());
        }
        case EQ_PARAM_PROPERTIES: {
            int32_t preset = VALUE_OR_RETURN_STATUS(getParameterPreset());
            if (OK != param.writeToValue((uint16_t*)&preset)) {
                break;
            }
            Parameter aidlParam = VALUE_OR_RETURN_STATUS(getAidlParameter(Equalizer::bandLevels));
            std::vector<Equalizer::BandLevel> bandLevels =
                    VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                            aidlParam, Equalizer, equalizer, Equalizer::bandLevels,
                            std::vector<Equalizer::BandLevel>));
            uint16_t bands = bandLevels.size();
            if (OK != param.writeToValue(&bands)) {
                break;
            }
            std::sort(bandLevels.begin(), bandLevels.end(),
                      [](const auto& a, const auto& b) { return a.index < b.index; });
            for (const auto& level : bandLevels) {
                if (status_t status = param.writeToValue((uint16_t*)&level.levelMb); status != OK) {
                    return status;
                }
            }
            return OK;
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(Equalizer, equalizer, param);
        }
    }

    param.setStatus(BAD_VALUE);
    ALOGE("%s invalid param %s", __func__, param.toString().c_str());
    return BAD_VALUE;
}

} // namespace effect
} // namespace android
