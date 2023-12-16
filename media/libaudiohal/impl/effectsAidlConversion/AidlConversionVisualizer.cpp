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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#define LOG_TAG "AidlConversionVisualizer"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_visualizer.h>

#include <utils/Log.h>

#include "AidlConversionVisualizer.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::aidl::android::hardware::audio::effect::Visualizer;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionVisualizer::setParameter(EffectParamReader& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case VISUALIZER_PARAM_CAPTURE_SIZE: {
            mCaptureSize = value;
            aidlParam = MAKE_SPECIFIC_PARAMETER(Visualizer, visualizer, captureSamples, value);
            break;
        }
        case VISUALIZER_PARAM_SCALING_MODE: {
            Visualizer::ScalingMode mode = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_Parameter_Visualizer_uint32_ScalingMode(value));
            aidlParam = MAKE_SPECIFIC_PARAMETER(Visualizer, visualizer, scalingMode, mode);
            break;
        }
        case VISUALIZER_PARAM_LATENCY: {
            aidlParam = MAKE_SPECIFIC_PARAMETER(Visualizer, visualizer, latencyMs, value);
            break;
        }
        case VISUALIZER_PARAM_MEASUREMENT_MODE: {
            Visualizer::MeasurementMode mode = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_Parameter_Visualizer_uint32_MeasurementMode(value));
            aidlParam = MAKE_SPECIFIC_PARAMETER(Visualizer, visualizer, measurementMode, mode);
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(Visualizer, visualizer, vendor, ext);
            break;
        }
    }
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionVisualizer::getParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(int32_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case VISUALIZER_PARAM_CAPTURE_SIZE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Visualizer, visualizerTag,
                                                          Visualizer::captureSamples);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Visualizer, visualizer, Visualizer::captureSamples, int32_t));
            mCaptureSize = value;
            return param.writeToValue(&value);
        }
        case VISUALIZER_PARAM_SCALING_MODE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Visualizer, visualizerTag,
                                                          Visualizer::scalingMode);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            Visualizer::ScalingMode mode = VALUE_OR_RETURN_STATUS(
                    GET_PARAMETER_SPECIFIC_FIELD(aidlParam, Visualizer, visualizer,
                                                 Visualizer::scalingMode, Visualizer::ScalingMode));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_Visualizer_ScalingMode_uint32(mode));
            return param.writeToValue(&value);
        }
        case VISUALIZER_PARAM_LATENCY: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Visualizer, visualizerTag,
                                                          Visualizer::latencyMs);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = (int32_t)VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Visualizer, visualizer, Visualizer::latencyMs, int32_t));
            return param.writeToValue(&value);
        }
        case VISUALIZER_PARAM_MEASUREMENT_MODE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Visualizer, visualizerTag,
                                                          Visualizer::measurementMode);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            Visualizer::MeasurementMode mode = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, Visualizer, visualizer, Visualizer::measurementMode,
                    Visualizer::MeasurementMode));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_Visualizer_MeasurementMode_uint32(mode));
            return param.writeToValue(&value);
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(Visualizer, visualizer, param);
        }
    }
}

status_t AidlConversionVisualizer::visualizerCapture(uint32_t* replySize, void* pReplyData) {
    if (!replySize || !pReplyData || *replySize != mCaptureSize) {
        ALOGE("%s illegal param replySize %p pReplyData %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    Parameter aidlParam;
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Visualizer, visualizerTag,
                                                    Visualizer::captureSampleBuffer);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    const auto& samples = VALUE_OR_RETURN_STATUS(
            GET_PARAMETER_SPECIFIC_FIELD(aidlParam, Visualizer, visualizer,
                                         Visualizer::captureSampleBuffer, std::vector<uint8_t>));
    size_t len = std::min((size_t)*replySize, samples.size());
    std::memcpy(pReplyData, samples.data(), *replySize = len);
    return OK;
}

status_t AidlConversionVisualizer::visualizerMeasure(uint32_t* replySize, void* pReplyData) {
    if (!replySize || !pReplyData || *replySize != 2 * sizeof(int32_t)) {
        ALOGE("%s illegal param replySize %p pReplyData %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    Parameter aidlParam;
    Parameter::Id id =
            MAKE_SPECIFIC_PARAMETER_ID(Visualizer, visualizerTag, Visualizer::measurement);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    const auto& measure = VALUE_OR_RETURN_STATUS(GET_PARAMETER_SPECIFIC_FIELD(
            aidlParam, Visualizer, visualizer, Visualizer::measurement, Visualizer::Measurement));
    int32_t* reply = (int32_t *) pReplyData;
    *reply++ = measure.peak;
    *reply = measure.rms;
    return OK;
}

} // namespace effect
} // namespace android
