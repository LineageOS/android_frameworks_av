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
#include <media/audiohal/AudioEffectUuid.h>
#include <system/audio_effect.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>

#include <utils/Log.h>

#include "AidlConversionDynamicsProcessing.h"

namespace android {
namespace effect {

using ::aidl::android::convertIntegral;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Capability;
using ::aidl::android::hardware::audio::effect::DynamicsProcessing;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::toString;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionDp::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case DP_PARAM_INPUT_GAIN: {
            DynamicsProcessing::InputGain inputGainAidl;
            if (OK != param.readFromParameter(&inputGainAidl.channel) ||
                OK != param.readFromValue(&inputGainAidl.gainDb)) {
                ALOGE("%s invalid inputGain %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
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
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionDp::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
    }
    Parameter aidlParam;
    switch (type) {
        case DP_PARAM_INPUT_GAIN: {
            int32_t channel;
            if (OK != param.readFromParameter(&channel)) {
                ALOGE("%s invalid inputGain %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(DynamicsProcessing, dynamicsProcessingTag,
                                                          DynamicsProcessing::inputGain);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));

            DynamicsProcessing::Capability cap =
                    mDesc.capability.get<Capability::dynamicsProcessing>();
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
            int32_t channel;
            if (OK != param.readFromParameter(&channel)) {
                ALOGE("%s invalid inputGain %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
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
            if (OK != param.writeToValue(&resolution) ||
                OK != param.writeToValue(&engine.preferredProcessingDurationMs) ||
                OK != param.writeToValue(&preEqInUse) ||
                OK != param.writeToValue(&engine.preEqStage.bandCount) ||
                OK != param.writeToValue(&mbcInUse) ||
                OK != param.writeToValue(&engine.mbcStage.bandCount) ||
                OK != param.writeToValue(&postEqInUse) ||
                OK != param.writeToValue(&engine.postEqStage.bandCount) ||
                OK != param.writeToValue(&limiterInUse)) {
                ALOGE("%s invalid engineArchitecture %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
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
            uint32_t channel = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_AudioChannelLayout_audio_channel_mask_t(
                            mCommon.input.base.channelMask, true /* input */));
            if (OK != param.writeToValue(&channel)) {
                ALOGE("%s write channel number %d to param failed %s", __func__, channel,
                      param.toString().c_str());
                return BAD_VALUE;
            }
            return OK;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }
}

aidl::ConversionResult<DynamicsProcessing::ChannelConfig>
AidlConversionDp::readChannelConfigFromParam(EffectParamReader& param) {
    int32_t enable, channel;
    if (OK != param.readFromParameter(&channel) || OK != param.readFromValue(&enable)) {
        ALOGE("%s invalid channel config param %s", __func__, param.toString().c_str());
        return ::android::base::unexpected(::android::BAD_VALUE);
    }
    return DynamicsProcessing::ChannelConfig(
            {.enable = VALUE_OR_RETURN(convertIntegral<bool>(enable)), .channel = channel});
}

aidl::ConversionResult<DynamicsProcessing::EqBandConfig>
AidlConversionDp::readEqBandConfigFromParam(EffectParamReader& param) {
    DynamicsProcessing::EqBandConfig config;
    int32_t enable;
    if (OK != param.readFromParameter(&config.channel) ||
        OK != param.readFromParameter(&config.band) ||
        OK != param.readFromValue(&enable) ||
        OK != param.readFromValue(&config.cutoffFrequencyHz) ||
        OK != param.readFromValue(&config.gainDb)) {
        ALOGE("%s invalid eq band param %s", __func__, param.toString().c_str());
        return ::android::base::unexpected(::android::BAD_VALUE);
    }
    config.enable = VALUE_OR_RETURN(convertIntegral<bool>(enable));
    return config;
}

aidl::ConversionResult<DynamicsProcessing::MbcBandConfig>
AidlConversionDp::readMbcBandConfigFromParam(EffectParamReader& param) {
    DynamicsProcessing::MbcBandConfig config;
    int32_t enable;
    if (OK != param.readFromParameter(&config.channel) ||
        OK != param.readFromParameter(&config.band) ||
        OK != param.readFromValue(&enable) ||
        OK != param.readFromValue(&config.cutoffFrequencyHz) ||
        OK != param.readFromValue(&config.attackTimeMs) ||
        OK != param.readFromValue(&config.releaseTimeMs) ||
        OK != param.readFromValue(&config.ratio) ||
        OK != param.readFromValue(&config.thresholdDb) ||
        OK != param.readFromValue(&config.kneeWidthDb) ||
        OK != param.readFromValue(&config.noiseGateThresholdDb) ||
        OK != param.readFromValue(&config.expanderRatio) ||
        OK != param.readFromValue(&config.preGainDb) ||
        OK != param.readFromValue(&config.postGainDb)) {
        ALOGE("%s invalid mbc band config param %s", __func__, param.toString().c_str());
        return ::android::base::unexpected(::android::BAD_VALUE);
    }
    config.enable = VALUE_OR_RETURN(convertIntegral<bool>(enable));
    return config;
}

aidl::ConversionResult<DynamicsProcessing::LimiterConfig>
AidlConversionDp::readLimiterConfigFromParam(EffectParamReader& param) {
    DynamicsProcessing::LimiterConfig config;
    int32_t enable, inUse;
    if (OK != param.readFromParameter(&config.channel) ||
        OK != param.readFromValue(&inUse) ||
        OK != param.readFromValue(&enable) ||
        OK != param.readFromValue(&config.linkGroup) ||
        OK != param.readFromValue(&config.attackTimeMs) ||
        OK != param.readFromValue(&config.releaseTimeMs) ||
        OK != param.readFromValue(&config.ratio) ||
        OK != param.readFromValue(&config.thresholdDb) ||
        OK != param.readFromValue(&config.postGainDb)) {
        ALOGE("%s invalid limiter config param %s", __func__, param.toString().c_str());
        return ::android::base::unexpected(::android::BAD_VALUE);
    }
    config.enable = VALUE_OR_RETURN(convertIntegral<bool>(enable));
    return config;
}

aidl::ConversionResult<DynamicsProcessing::EngineArchitecture>
AidlConversionDp::readEngineArchitectureFromParam(EffectParamReader& param) {
    DynamicsProcessing::EngineArchitecture engine;
    int32_t variant, preEqInUse, mbcInUse, postEqInUse, limiterInUse;
    if (OK != param.readFromValue(&variant) &&
        OK != param.readFromValue(&engine.preferredProcessingDurationMs) &&
        OK != param.readFromValue(&preEqInUse) &&
        OK != param.readFromValue(&engine.preEqStage.bandCount) &&
        OK != param.readFromValue(&mbcInUse) &&
        OK != param.readFromValue(&engine.mbcStage.bandCount) &&
        OK != param.readFromValue(&postEqInUse) &&
        OK != param.readFromValue(&engine.postEqStage.bandCount) &&
        OK != param.readFromValue(&limiterInUse)) {
        ALOGE("%s invalid engineArchitecture %s", __func__, param.toString().c_str());
        return ::android::base::unexpected(::android::BAD_VALUE);
    }

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
    if (OK != param.readFromParameter(&channel)) {
        ALOGE("%s invalid parameter %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

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
            if (OK != param.writeToValue(&inUse) ||
                OK != param.writeToValue(&enable) ||
                OK != param.writeToValue(&bandCount)) {
                ALOGE("%s failed to write into param value %s", __func__,
                      param.toString().c_str());
                return BAD_VALUE;
            }
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d", __func__, channel);
    return BAD_VALUE;
}

status_t AidlConversionDp::getEqBandConfig(DynamicsProcessing::Tag tag, EffectParamWriter& param) {
    int32_t channel, band;
    if (OK != param.readFromParameter(&channel) || OK != param.readFromParameter(&band)) {
        ALOGE("%s invalid parameter %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

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
            if (OK != param.writeToValue(&enable) ||
                OK != param.writeToValue(&bandIt.cutoffFrequencyHz) ||
                OK != param.writeToValue(&bandIt.gainDb)) {
                ALOGE("%s failed to write into param value %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d band %d", __func__, channel, band);
    return BAD_VALUE;
}

status_t AidlConversionDp::getMbcBandConfig(EffectParamWriter& param) {
    int32_t channel, band;
    if (OK != param.readFromParameter(&channel) || OK != param.readFromParameter(&band)) {
        ALOGE("%s invalid parameter %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
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
            if (OK != param.writeToValue(&enable) ||
                OK != param.writeToValue(&bandIt.cutoffFrequencyHz) ||
                OK != param.writeToValue(&bandIt.attackTimeMs) ||
                OK != param.writeToValue(&bandIt.releaseTimeMs) ||
                OK != param.writeToValue(&bandIt.ratio) ||
                OK != param.writeToValue(&bandIt.thresholdDb) ||
                OK != param.writeToValue(&bandIt.kneeWidthDb) ||
                OK != param.writeToValue(&bandIt.noiseGateThresholdDb) ||
                OK != param.writeToValue(&bandIt.expanderRatio) ||
                OK != param.writeToValue(&bandIt.preGainDb) ||
                OK != param.writeToValue(&bandIt.postGainDb)) {
                ALOGE("%s failed to write into param value %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d band %d", __func__, channel, band);
    return BAD_VALUE;
}

status_t AidlConversionDp::getLimiterConfig(EffectParamWriter& param) {
    int32_t channel;
    if (OK != param.readFromParameter(&channel)) {
        ALOGE("%s invalid parameter %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
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
            if (OK != param.writeToValue(&inUse) ||
                OK != param.writeToValue(&enable) ||
                OK != param.writeToValue(&config.linkGroup) ||
                OK != param.writeToValue(&config.attackTimeMs) ||
                OK != param.writeToValue(&config.releaseTimeMs) ||
                OK != param.writeToValue(&config.ratio) ||
                OK != param.writeToValue(&config.thresholdDb) ||
                OK != param.writeToValue(&config.postGainDb)) {
                ALOGE("%s failed to write into param value %s", __func__, param.toString().c_str());
                return BAD_VALUE;
            }
            return OK;
        }
    }
    ALOGE("%s not able to find channel %d", __func__, channel);
    return BAD_VALUE;
}

} // namespace effect
} // namespace android
