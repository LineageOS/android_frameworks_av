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
#define LOG_TAG "EffectConversionHelperAidl"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/audiohal/AudioEffectUuid.h>
#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_agc2.h>
#include <system/audio_effects/effect_bassboost.h>
#include <system/audio_effects/effect_downmix.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <system/audio_effects/effect_environmentalreverb.h>
#include <system/audio_effects/effect_equalizer.h>
#include <system/audio_effects/effect_hapticgenerator.h>
#include <system/audio_effects/effect_loudnessenhancer.h>
#include <system/audio_effects/effect_ns.h>
#include <system/audio_effects/effect_presetreverb.h>
#include <system/audio_effects/effect_spatializer.h>
#include <system/audio_effects/effect_virtualizer.h>
#include <system/audio_effects/effect_visualizer.h>

#include <utils/Log.h>

#include "EffectConversionHelperAidl.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::AcousticEchoCanceler;
using ::aidl::android::hardware::audio::effect::AutomaticGainControl;
using ::aidl::android::hardware::audio::effect::BassBoost;
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Downmix;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::media::audio::common::AudioDeviceDescription;
using ::aidl::android::media::audio::common::AudioUuid;
using android::effect::utils::EffectParamReader;
using android::effect::utils::EffectParamWriter;

using ::android::status_t;

const std::map<uint32_t /* effect_command_e */, EffectConversionHelperAidl::CommandHandler>
        EffectConversionHelperAidl::mCommandHandlerMap = {
                {EFFECT_CMD_INIT, &EffectConversionHelperAidl::handleInit},
                {EFFECT_CMD_SET_PARAM, &EffectConversionHelperAidl::handleSetParameter},
                {EFFECT_CMD_GET_PARAM, &EffectConversionHelperAidl::handleGetParameter},
                {EFFECT_CMD_SET_CONFIG, &EffectConversionHelperAidl::handleSetConfig},
                {EFFECT_CMD_GET_CONFIG, &EffectConversionHelperAidl::handleGetConfig},
                {EFFECT_CMD_RESET, &EffectConversionHelperAidl::handleReset},
                {EFFECT_CMD_ENABLE, &EffectConversionHelperAidl::handleEnable},
                {EFFECT_CMD_DISABLE, &EffectConversionHelperAidl::handleDisable},
                {EFFECT_CMD_SET_DEVICE, &EffectConversionHelperAidl::handleSetDevice},
                {EFFECT_CMD_SET_INPUT_DEVICE, &EffectConversionHelperAidl::handleSetDevice},
                {EFFECT_CMD_SET_VOLUME, &EffectConversionHelperAidl::handleSetVolume},
                {EFFECT_CMD_OFFLOAD, &EffectConversionHelperAidl::handleSetOffload},
                {EFFECT_CMD_FIRST_PROPRIETARY, &EffectConversionHelperAidl::handleFirstPriority}};

const std::map<AudioUuid /* TypeUUID */, std::pair<EffectConversionHelperAidl::SetParameter,
                                                   EffectConversionHelperAidl::GetParameter>>
        EffectConversionHelperAidl::mParameterHandlerMap = {
                {kAcousticEchoCancelerTypeUUID,
                 {&EffectConversionHelperAidl::setAecParameter,
                  &EffectConversionHelperAidl::getAecParameter}},
                {kAutomaticGainControlTypeUUID,
                 {&EffectConversionHelperAidl::setAgcParameter,
                  &EffectConversionHelperAidl::getAgcParameter}},
                {kBassBoostTypeUUID,
                 {&EffectConversionHelperAidl::setBassBoostParameter,
                  &EffectConversionHelperAidl::getBassBoostParameter}},
                {kDownmixTypeUUID,
                 {&EffectConversionHelperAidl::setDownmixParameter,
                  &EffectConversionHelperAidl::getDownmixParameter}}};

EffectConversionHelperAidl::EffectConversionHelperAidl(
        std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
        int32_t sessionId, int32_t ioId,
        const ::aidl::android::hardware::audio::effect::Descriptor& desc)
    : mSessionId(sessionId), mIoId(ioId), mDesc(desc), mEffect(std::move(effect)) {
    mCommon.session = sessionId;
    mCommon.ioHandle = ioId;
    mCommon.input = mCommon.output = kDefaultAudioConfig;
}

status_t EffectConversionHelperAidl::handleCommand(uint32_t cmdCode, uint32_t cmdSize,
                                                   void* pCmdData, uint32_t* replySize,
                                                   void* pReplyData) {
    const auto& handler = mCommandHandlerMap.find(cmdCode);
    if (handler == mCommandHandlerMap.end() || !handler->second) {
        ALOGE("%s handler for command %u doesn't exist", __func__, cmdCode);
        return BAD_VALUE;
    }
    return (this->*handler->second)(cmdSize, pCmdData, replySize, pReplyData);
}

status_t EffectConversionHelperAidl::handleInit(uint32_t cmdSize __unused,
                                                const void* pCmdData __unused, uint32_t* replySize,
                                                void* pReplyData) {
    if (!replySize || *replySize < sizeof(int) || !pReplyData) {
        return BAD_VALUE;
    }

    return *(status_t*)pReplyData =
                   statusTFromBinderStatus(mEffect->open(mCommon, std::nullopt, &mOpenReturn));
}

status_t EffectConversionHelperAidl::handleSetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_param_t) || !pCmdData || !replySize ||
        *replySize < sizeof(int) || !pReplyData) {
        return BAD_VALUE;
    }

    auto reader = EffectParamReader(*(effect_param_t*)pCmdData);
    if (!reader.validateCmdSize(cmdSize)) {
        ALOGE("%s illegal param %s size %u", __func__, reader.toString().c_str(), cmdSize);
        return BAD_VALUE;
    }

    const auto& handler = mParameterHandlerMap.find(mDesc.common.id.type);
    if (handler == mParameterHandlerMap.end() || !handler->second.first) {
        ALOGE("%s handler for uuid %s not found", __func__,
              mDesc.common.id.type.toString().c_str());
        return BAD_VALUE;
    }
    const SetParameter& functor = handler->second.first;
    return *(status_t*)pReplyData = (this->*functor)(reader);
}

status_t EffectConversionHelperAidl::handleGetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_param_t) || !pCmdData || !replySize || !pReplyData) {
        return BAD_VALUE;
    }

    const auto reader = EffectParamReader(*(effect_param_t*)pCmdData);
    if (!reader.validateCmdSize(cmdSize)) {
        ALOGE("%s illegal param %s, replysize %u", __func__, reader.toString().c_str(),
              *replySize);
        return BAD_VALUE;
    }

    const auto& handler = mParameterHandlerMap.find(mDesc.common.id.type);
    if (handler == mParameterHandlerMap.end() || !handler->second.second) {
        ALOGE("%s handler for uuid %s not found", __func__,
              mDesc.common.id.type.toString().c_str());
        return BAD_VALUE;
    }
    const GetParameter& functor = handler->second.second;
    memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + reader.getParameterSize());
    auto writer = EffectParamWriter(*(effect_param_t *)pReplyData);
    (this->*functor)(writer);
    *replySize = writer.getTotalSize();
    return writer.getStatus();
}

status_t EffectConversionHelperAidl::handleSetConfig(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(int) || !pReplyData ||
        cmdSize != sizeof(effect_config_t)) {
        return BAD_VALUE;
    }

    const auto& legacyConfig = static_cast<const effect_config_t*>(pCmdData);
    // already open, apply latest settings
    mCommon.input.base =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_buffer_config_t_AudioConfigBase(
                    legacyConfig->inputCfg, true /* isInput */));
    mCommon.output.base =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_buffer_config_t_AudioConfigBase(
                    legacyConfig->outputCfg, false /* isInput */));
    mCommon.session = mSessionId;
    mCommon.ioHandle = mIoId;
    // TODO: add access mode support
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::common>(mCommon))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleGetConfig(uint32_t cmdSize __unused,
                                                     const void* pCmdData __unused,
                                                     uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    Parameter param;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(
            Parameter::Id::make<Parameter::Id::commonTag>(Parameter::common), &param)));

    const auto& common = param.get<Parameter::common>();
    effect_config_t* pConfig = (effect_config_t*)pReplyData;
    pConfig->inputCfg = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioConfigBase_buffer_config_t(common.input.base, true));
    pConfig->outputCfg =
            VALUE_OR_RETURN_STATUS(::aidl::android::aidl2legacy_AudioConfigBase_buffer_config_t(
                    common.output.base, false));
    return OK;
}

status_t EffectConversionHelperAidl::handleReset(uint32_t cmdSize __unused,
                                                 const void* pCmdData __unused, uint32_t* replySize,
                                                 void* pReplyData) {
    if (!replySize || *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::RESET));
}

status_t EffectConversionHelperAidl::handleEnable(uint32_t cmdSize __unused,
                                                 const void* pCmdData __unused, uint32_t* replySize,
                                                 void* pReplyData) {
    if (!replySize || *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::START));
}

status_t EffectConversionHelperAidl::handleDisable(uint32_t cmdSize __unused,
                                                   const void* pCmdData __unused,
                                                   uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::STOP));
}

status_t EffectConversionHelperAidl::handleSetDevice(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (cmdSize != sizeof(uint32_t) || !pCmdData || !replySize ||
        *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }
    // TODO: convert from audio_devices_t to std::vector<AudioDeviceDescription>
    // const auto& legacyDevice = *(uint32_t*)(pCmdData);
    std::vector<AudioDeviceDescription> aidlDevices;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::deviceDescription>(aidlDevices))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetVolume(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (cmdSize != 2 * sizeof(uint32_t) || !pCmdData || !replySize ||
        *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }
    Parameter::VolumeStereo volume = {.left = (float)(*(uint32_t*)pCmdData) / (1 << 24),
                                      .right = (float)(*(uint32_t*)pCmdData + 1) / (1 << 24)};
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::volumeStereo>(volume))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetOffload(uint32_t cmdSize, const void* pCmdData,
                                                      uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_offload_param_t) || !pCmdData || !replySize ||
        *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }
    // TODO: handle this after effectproxy implemented in libaudiohal
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleFirstPriority(uint32_t cmdSize __unused,
                                                         const void* pCmdData __unused,
                                                         uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    // TODO to be implemented
    return OK;
}

status_t EffectConversionHelperAidl::setAecParameter(EffectParamReader& param) {
    uint32_t type, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) ||
        OK != param.readFromValue(&value)) {
        ALOGW("%s invalid param %s", __func__, param.toString().c_str());
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
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t EffectConversionHelperAidl::getAecParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        param.setStatus(BAD_VALUE);
        ALOGW("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AEC_PARAM_ECHO_DELAY:
            FALLTHROUGH_INTENDED;
        case AEC_PARAM_PROPERTIES: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(AcousticEchoCanceler,
                                                          acousticEchoCancelerTag, echoDelayUs);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_aec_uint32_echoDelay(aidlParam));
            break;
        }
        case AEC_PARAM_MOBILE_MODE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(AcousticEchoCanceler,
                                                          acousticEchoCancelerTag, mobileMode);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_aec_uint32_mobileMode(aidlParam));
            break;
        }
        default:
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
    }
    param.writeToValue(&value);
    return OK;
}

status_t EffectConversionHelperAidl::setAgcParameter(EffectParamReader& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGW("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_fixedDigitalGain_Parameter_agc(value));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_levelEstimator_Parameter_agc(value));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_saturationMargin_Parameter_agc(value));
            break;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t EffectConversionHelperAidl::getAgcParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGW("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(
                    AutomaticGainControl, automaticGainControlTag, fixedDigitalGainMb);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_agc_uint32_fixedDigitalGain(aidlParam));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControl,
                                                          automaticGainControlTag, levelEstimator);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_agc_uint32_levelEstimator(aidlParam));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(
                    AutomaticGainControl, automaticGainControlTag, saturationMarginMb);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_agc_uint32_saturationMargin(aidlParam));
            break;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    param.writeToValue(&value);
    return OK;
}

status_t EffectConversionHelperAidl::setBassBoostParameter(EffectParamReader& param) {
    uint32_t type = 0;
    uint16_t value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGW("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case BASSBOOST_PARAM_STRENGTH: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint16_strengthPm_Parameter_BassBoost(value));
            break;
        }
        case BASSBOOST_PARAM_STRENGTH_SUPPORTED: {
            ALOGW("%s set BASSBOOST_PARAM_STRENGTH_SUPPORTED not supported", __func__);
            return BAD_VALUE;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t EffectConversionHelperAidl::getBassBoostParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGW("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case BASSBOOST_PARAM_STRENGTH: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(BassBoost, bassBoostTag, strengthPm);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_BassBoost_uint16_strengthPm(aidlParam));
            break;
        }
        case BASSBOOST_PARAM_STRENGTH_SUPPORTED: {
            const auto& cap =
                    VALUE_OR_RETURN_STATUS(aidl::android::UNION_GET(mDesc.capability, bassBoost));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::convertIntegral<uint32_t>(cap.strengthSupported));
            break;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    param.writeToValue(&value);
    return OK;
}

status_t EffectConversionHelperAidl::setDownmixParameter(EffectParamReader& param) {
    uint32_t type = 0;
    int16_t value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(int16_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGW("%s invalid param %s", __func__, param.toString().c_str());
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
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t EffectConversionHelperAidl::getDownmixParameter(EffectParamWriter& param) {
    int16_t value = 0;
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint16_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case DOWNMIX_PARAM_TYPE: {
            Parameter::Id id = MAKE_SPECIFIC_PARAMETER_ID(Downmix, downmixTag, type);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_Downmix_int16_type(aidlParam));
            break;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    param.writeToValue(&value);
    return OK;
}

} // namespace effect
} // namespace android
