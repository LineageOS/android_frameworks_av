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
#define LOG_TAG "AidlConversionDp"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effect.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <Utils.h>
#include <utils/Log.h>

#include "AidlConversionDynamicsProcessing.h"

namespace android {
namespace effect {

using ::aidl::android::convertIntegral;
using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Capability;
using ::aidl::android::hardware::audio::effect::DynamicsProcessing;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::toString;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionDp::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&type));
    Parameter aidlParam;
    switch (type) {
        case DP_PARAM_INPUT_GAIN: {
            DynamicsProcessing::InputGain inputGainAidl;
            RETURN_STATUS_IF_ERROR(param.readFromParameter(&inputGainAidl.channel));
            RETURN_STATUS_IF_ERROR(param.readFromValue(&inputGainAidl.gainDb));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, inputGain,
                                                {inputGainAidl});
            break;
        }
        case DP_PARAM_ENGINE_ARCHITECTURE: {
            DynamicsProcessing::EngineArchitecture engine =
                    VALUE_OR_RETURN_STATUS(readEngineArchitectureFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing,
                                                engineArchitecture, engine);
            mEngine = engine;
            break;
        }
        case DP_PARAM_PRE_EQ: {
            DynamicsProcessing::ChannelConfig chConfig =
                    VALUE_OR_RETURN_STATUS(readChannelConfigFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, preEq,
                                                {chConfig});
            break;
        }
        case DP_PARAM_POST_EQ: {
            DynamicsProcessing::ChannelConfig chConfig =
                    VALUE_OR_RETURN_STATUS(readChannelConfigFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, postEq,
                                                {chConfig});
            break;
        }
        case DP_PARAM_MBC: {
            DynamicsProcessing::ChannelConfig chConfig =
                    VALUE_OR_RETURN_STATUS(readChannelConfigFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, mbc,
                                                {chConfig});
            break;
        }
        case DP_PARAM_PRE_EQ_BAND: {
            DynamicsProcessing::EqBandConfig bandConfig =
                    VALUE_OR_RETURN_STATUS(readEqBandConfigFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, preEqBand,
                                                {bandConfig});
            break;
        }
        case DP_PARAM_POST_EQ_BAND: {
            DynamicsProcessing::EqBandConfig bandConfig =
                    VALUE_OR_RETURN_STATUS(readEqBandConfigFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, postEqBand,
                                                {bandConfig});
            break;
        }
        case DP_PARAM_MBC_BAND: {
            DynamicsProcessing::MbcBandConfig bandConfig =
                    VALUE_OR_RETURN_STATUS(readMbcBandConfigFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, mbcBand,
                                                {bandConfig});
            break;
        }
        case DP_PARAM_LIMITER: {
            DynamicsProcessing::LimiterConfig config =
                    VALUE_OR_RETURN_STATUS(readLimiterConfigFromParam(param));
            aidlParam = MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, limiter,
                                                {config});
            break;
        }
        default: {
            // for vendor extension, copy data area to the DefaultExtension, parameter ignored
            VendorExtension ext = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
            aidlParam =
                    MAKE_SPECIFIC_PARAMETER(DynamicsProcessing, dynamicsProcessing, vendor, ext);
            break;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionDp::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&type));
    Parameter aidlParam;
    switch (type) {
        case DP_PARAM_INPUT_GAIN: {
            int32_t channel;
            RETURN_STATUS_IF_ERROR(param.readFromParameter(&channel));
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(DynamicsProcessing, dynamicsProcessingTag,
                                                          DynamicsProcessing::inputGain);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));

            std::vector<DynamicsProcessing::InputGain> gains =
                    VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                            aidlParam, DynamicsProcessing, dynamicsProcessing,
                            DynamicsProcessing::inputGain,
                            std::vector<DynamicsProcessing::InputGain>));
            for (const auto& gain : gains) {
                if (gain.channel == channel) {
                    return param.writeToValue(&gain.gainDb);
                }
            }
            ALOGE("%s not able to find channel %d", __func__, channel);
            return BAD_VALUE;
        }
        case DP_PARAM_ENGINE_ARCHITECTURE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(DynamicsProcessing, dynamicsProcessingTag,
                                                          DynamicsProcessing::engineArchitecture);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));

            DynamicsProcessing::EngineArchitecture engine =
                    VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                            aidlParam, DynamicsProcessing, dynamicsProcessing,
                            DynamicsProcessing::engineArchitecture,
                            DynamicsProcessing::EngineArchitecture));
            int32_t resolution = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_DynamicsProcessing_ResolutionPreference_int32(
                            engine.resolutionPreference));
            int32_t preEqInUse =
                    VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(engine.preEqStage.inUse));
            int32_t mbcInUse =
                    VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(engine.mbcStage.inUse));
            int32_t postEqInUse =
                    VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(engine.postEqStage.inUse));
            int32_t limiterInUse =
                    VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(engine.limiterInUse));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&resolution));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&engine.preferredProcessingDurationMs));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&preEqInUse));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&engine.preEqStage.bandCount));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&mbcInUse));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&engine.mbcStage.bandCount));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&postEqInUse));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&engine.postEqStage.bandCount));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&limiterInUse));
            mEngine = engine;
            return OK;
        }
        case DP_PARAM_PRE_EQ: {
            return getChannelConfig(DynamicsProcessing::preEq, param);
        }
        case DP_PARAM_POST_EQ: {
            return getChannelConfig(DynamicsProcessing::postEq, param);
        }
        case DP_PARAM_MBC: {
            return getChannelConfig(DynamicsProcessing::mbc, param);
        }
        case DP_PARAM_PRE_EQ_BAND: {
            return getEqBandConfig(DynamicsProcessing::preEqBand, param);
        }
        case DP_PARAM_POST_EQ_BAND: {
            return getEqBandConfig(DynamicsProcessing::postEqBand, param);
        }
        case DP_PARAM_MBC_BAND: {
            return getMbcBandConfig(param);
        }
        case DP_PARAM_LIMITER: {
            return getLimiterConfig(param);
        }
        case DP_PARAM_GET_CHANNEL_COUNT: {
            uint32_t channel = ::aidl::android::hardware::audio::common::getChannelCount(
                    mCommon.input.base.channelMask);
            RETURN_STATUS_IF_ERROR(param.writeToValue(&channel));
            return OK;
        }
        default: {
            VENDOR_EXTENSION_GET_AND_RETURN(DynamicsProcessing, dynamicsProcessing, param);
        }
    }
}

ConversionResult<DynamicsProcessing::ChannelConfig>
AidlConversionDp::readChannelConfigFromParam(EffectParamReader& param) {
    int32_t enable, channel;
    RETURN_IF_ERROR(param.readFromParameter(&channel));
    RETURN_IF_ERROR(param.readFromValue(&enable));

    return DynamicsProcessing::ChannelConfig(
            {.channel = channel, .enable = VALUE_OR_RETURN(convertIntegral<bool>(enable))});
}

ConversionResult<DynamicsProcessing::EqBandConfig>
AidlConversionDp::readEqBandConfigFromParam(EffectParamReader& param) {
    DynamicsProcessing::EqBandConfig config;
    int32_t enable;
    RETURN_IF_ERROR(param.readFromParameter(&config.channel));
    RETURN_IF_ERROR(param.readFromParameter(&config.band));
    RETURN_IF_ERROR(param.readFromValue(&enable));
    RETURN_IF_ERROR(param.readFromValue(&config.cutoffFrequencyHz));
    RETURN_IF_ERROR(param.readFromValue(&config.gainDb));

    config.enable = VALUE_OR_RETURN(convertIntegral<bool>(enable));
    return config;
}

ConversionResult<DynamicsProcessing::MbcBandConfig>
AidlConversionDp::readMbcBandConfigFromParam(EffectParamReader& param) {
    DynamicsProcessing::MbcBandConfig config;
    int32_t enable;
    RETURN_IF_ERROR(param.readFromParameter(&config.channel));
    RETURN_IF_ERROR(param.readFromParameter(&config.band));
    RETURN_IF_ERROR(param.readFromValue(&enable));
    RETURN_IF_ERROR(param.readFromValue(&config.cutoffFrequencyHz));
    RETURN_IF_ERROR(param.readFromValue(&config.attackTimeMs));
    RETURN_IF_ERROR(param.readFromValue(&config.releaseTimeMs));
    RETURN_IF_ERROR(param.readFromValue(&config.ratio));
    RETURN_IF_ERROR(param.readFromValue(&config.thresholdDb));
    RETURN_IF_ERROR(param.readFromValue(&config.kneeWidthDb));
    RETURN_IF_ERROR(param.readFromValue(&config.noiseGateThresholdDb));
    RETURN_IF_ERROR(param.readFromValue(&config.expanderRatio));
    RETURN_IF_ERROR(param.readFromValue(&config.preGainDb));
    RETURN_IF_ERROR(param.readFromValue(&config.postGainDb));

    config.enable = VALUE_OR_RETURN(convertIntegral<bool>(enable));
    return config;
}

ConversionResult<DynamicsProcessing::LimiterConfig>
AidlConversionDp::readLimiterConfigFromParam(EffectParamReader& param) {
    DynamicsProcessing::LimiterConfig config;
    int32_t enable, inUse;
    RETURN_IF_ERROR(param.readFromParameter(&config.channel));
    RETURN_IF_ERROR(param.readFromValue(&inUse));
    RETURN_IF_ERROR(param.readFromValue(&enable));
    RETURN_IF_ERROR(param.readFromValue(&config.linkGroup));
    RETURN_IF_ERROR(param.readFromValue(&config.attackTimeMs));
    RETURN_IF_ERROR(param.readFromValue(&config.releaseTimeMs));
    RETURN_IF_ERROR(param.readFromValue(&config.ratio));
    RETURN_IF_ERROR(param.readFromValue(&config.thresholdDb));
    RETURN_IF_ERROR(param.readFromValue(&config.postGainDb));

    config.enable = VALUE_OR_RETURN(convertIntegral<bool>(enable));
    return config;
}

ConversionResult<DynamicsProcessing::EngineArchitecture>
AidlConversionDp::readEngineArchitectureFromParam(EffectParamReader& param) {
    DynamicsProcessing::EngineArchitecture engine;
    int32_t variant, preEqInUse, mbcInUse, postEqInUse, limiterInUse;
    RETURN_IF_ERROR(param.readFromValue(&variant));
    RETURN_IF_ERROR(param.readFromValue(&engine.preferredProcessingDurationMs));
    RETURN_IF_ERROR(param.readFromValue(&preEqInUse));
    RETURN_IF_ERROR(param.readFromValue(&engine.preEqStage.bandCount));
    RETURN_IF_ERROR(param.readFromValue(&mbcInUse));
    RETURN_IF_ERROR(param.readFromValue(&engine.mbcStage.bandCount));
    RETURN_IF_ERROR(param.readFromValue(&postEqInUse));
    RETURN_IF_ERROR(param.readFromValue(&engine.postEqStage.bandCount));
    RETURN_IF_ERROR(param.readFromValue(&limiterInUse));

    engine.resolutionPreference = VALUE_OR_RETURN(
            aidl::android::legacy2aidl_int32_DynamicsProcessing_ResolutionPreference(variant));
    engine.preEqStage.inUse = VALUE_OR_RETURN(convertIntegral<bool>(preEqInUse));
    engine.mbcStage.inUse = VALUE_OR_RETURN(convertIntegral<bool>(mbcInUse));
    engine.postEqStage.inUse = VALUE_OR_RETURN(convertIntegral<bool>(postEqInUse));
    engine.limiterInUse = VALUE_OR_RETURN(convertIntegral<bool>(limiterInUse));
    return engine;
}

status_t AidlConversionDp::getChannelConfig(DynamicsProcessing::Tag tag, EffectParamWriter& param) {
    int32_t channel;
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&channel));

    Parameter aidlParam;
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(DynamicsProcessing, dynamicsProcessingTag, tag);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));

    std::vector<DynamicsProcessing::ChannelConfig> channels;
    int32_t inUse, bandCount;
    switch (tag) {
        case DynamicsProcessing::preEq: {
            inUse = mEngine.preEqStage.inUse;
            bandCount = mEngine.preEqStage.bandCount;
            channels = VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, DynamicsProcessing, dynamicsProcessing, DynamicsProcessing::preEq,
                    std::vector<DynamicsProcessing::ChannelConfig>));
            break;
        }
        case DynamicsProcessing::postEq: {
            inUse = mEngine.postEqStage.inUse;
            bandCount = mEngine.postEqStage.bandCount;
            channels = VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, DynamicsProcessing, dynamicsProcessing, DynamicsProcessing::postEq,
                    std::vector<DynamicsProcessing::ChannelConfig>));
            break;
        }
        case DynamicsProcessing::mbc: {
            inUse = mEngine.mbcStage.inUse;
            bandCount = mEngine.mbcStage.bandCount;
            channels = VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, DynamicsProcessing, dynamicsProcessing, DynamicsProcessing::mbc,
                    std::vector<DynamicsProcessing::ChannelConfig>));
            break;
        }
        default: {
            ALOGE("%s unsupported tag %s", __func__, toString(tag).c_str());
            return BAD_VALUE;
        }
    }

    for (const auto& ch : channels) {
        if (ch.channel == channel) {
            int32_t enable = ch.enable;
            RETURN_STATUS_IF_ERROR(param.writeToValue(&inUse));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&enable));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandCount));
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d", __func__, channel);
    return BAD_VALUE;
}

status_t AidlConversionDp::getEqBandConfig(DynamicsProcessing::Tag tag, EffectParamWriter& param) {
    int32_t channel, band;
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&channel));
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&band));

    Parameter aidlParam;
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(DynamicsProcessing, dynamicsProcessingTag, tag);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));

    std::vector<DynamicsProcessing::EqBandConfig> bands;
    if (tag == DynamicsProcessing::preEqBand) {
        bands = VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                aidlParam, DynamicsProcessing, dynamicsProcessing, preEqBand,
                std::vector<DynamicsProcessing::EqBandConfig>));
    } else if (tag == DynamicsProcessing::postEqBand) {
        bands = VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                aidlParam, DynamicsProcessing, dynamicsProcessing, postEqBand,
                std::vector<DynamicsProcessing::EqBandConfig>));
    } else {
        return BAD_VALUE;
    }

    for (const auto& bandIt : bands) {
        if (bandIt.channel == channel && bandIt.band == band) {
            int32_t enable = bandIt.enable;
            RETURN_STATUS_IF_ERROR(param.writeToValue(&enable));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.cutoffFrequencyHz));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.gainDb));
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d band %d", __func__, channel, band);
    return BAD_VALUE;
}

status_t AidlConversionDp::getMbcBandConfig(EffectParamWriter& param) {
    int32_t channel, band;
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&channel));
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&band));
    Parameter aidlParam;
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(DynamicsProcessing, dynamicsProcessingTag,
                                                  DynamicsProcessing::mbcBand);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));

    std::vector<DynamicsProcessing::MbcBandConfig> bands =
            VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, DynamicsProcessing, dynamicsProcessing, mbcBand,
                    std::vector<DynamicsProcessing::MbcBandConfig>));

    for (const auto& bandIt : bands) {
        if (bandIt.channel == channel && bandIt.band == band) {
            int32_t enable = bandIt.enable;
            RETURN_STATUS_IF_ERROR(param.writeToValue(&enable));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.cutoffFrequencyHz));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.attackTimeMs));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.releaseTimeMs));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.ratio));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.thresholdDb));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.kneeWidthDb));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.noiseGateThresholdDb));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.expanderRatio));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.preGainDb));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&bandIt.postGainDb));
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d band %d", __func__, channel, band);
    return BAD_VALUE;
}

status_t AidlConversionDp::getLimiterConfig(EffectParamWriter& param) {
    int32_t channel;
    RETURN_STATUS_IF_ERROR(param.readFromParameter(&channel));
    Parameter aidlParam;
    Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(DynamicsProcessing, dynamicsProcessingTag,
                                                  DynamicsProcessing::limiter);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));

    std::vector<DynamicsProcessing::LimiterConfig> configs =
            VALUE_OR_RETURN_STATUS(aidl::android::GET_PARAMETER_SPECIFIC_FIELD(
                    aidlParam, DynamicsProcessing, dynamicsProcessing, limiter,
                    std::vector<DynamicsProcessing::LimiterConfig>));

    for (const auto& config : configs) {
        if (config.channel == channel) {
            int32_t inUse = mEngine.limiterInUse;
            int32_t enable = config.enable;
            RETURN_STATUS_IF_ERROR(param.writeToValue(&inUse));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&enable));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&config.linkGroup));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&config.attackTimeMs));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&config.releaseTimeMs));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&config.ratio));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&config.thresholdDb));
            RETURN_STATUS_IF_ERROR(param.writeToValue(&config.postGainDb));
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d", __func__, channel);
    return BAD_VALUE;
}

} // namespace effect
} // namespace android
