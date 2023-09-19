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

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#define LOG_TAG "EffectConversionHelperAidl"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/AudioContainers.h>
#include <system/audio_effects/effect_visualizer.h>

#include <utils/Log.h>

#include "EffectConversionHelperAidl.h"
#include "EffectProxy.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Flags;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::State;
using ::aidl::android::media::audio::common::AudioDeviceDescription;
using ::aidl::android::media::audio::common::AudioMode;
using ::aidl::android::media::audio::common::AudioSource;
using ::android::hardware::EventFlag;
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
                {EFFECT_CMD_SET_AUDIO_MODE, &EffectConversionHelperAidl::handleSetAudioMode},
                {EFFECT_CMD_SET_AUDIO_SOURCE, &EffectConversionHelperAidl::handleSetAudioSource},
                {EFFECT_CMD_SET_DEVICE, &EffectConversionHelperAidl::handleSetDevice},
                {EFFECT_CMD_SET_INPUT_DEVICE, &EffectConversionHelperAidl::handleSetDevice},
                {EFFECT_CMD_SET_VOLUME, &EffectConversionHelperAidl::handleSetVolume},
                {EFFECT_CMD_OFFLOAD, &EffectConversionHelperAidl::handleSetOffload},
                // Only visualizer support these commands, reuse of EFFECT_CMD_FIRST_PROPRIETARY
                {VISUALIZER_CMD_CAPTURE, &EffectConversionHelperAidl::handleVisualizerCapture},
                {VISUALIZER_CMD_MEASURE, &EffectConversionHelperAidl::handleVisualizerMeasure}};

EffectConversionHelperAidl::EffectConversionHelperAidl(
        std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
        int32_t sessionId, int32_t ioId, const Descriptor& desc, bool isProxy)
    : mSessionId(sessionId),
      mIoId(ioId),
      mDesc(desc),
      mEffect(std::move(effect)),
      mIsInputStream(mDesc.common.flags.type == Flags::Type::PRE_PROC),
      mIsProxyEffect(isProxy) {
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
        ALOGE("%s parameter invalid, replySize %s pReplyData %p", __func__,
              numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    // Do nothing for EFFECT_CMD_INIT, call IEffect.open() with EFFECT_CMD_SET_CONFIG
    return *(status_t*)pReplyData = OK;
}

status_t EffectConversionHelperAidl::handleSetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_param_t) || !pCmdData || !replySize || *replySize < sizeof(int) ||
        !pReplyData) {
        ALOGE("%s parameter invalid, cmdSize %u pCmdData %p replySize %s pReplyData %p", __func__,
              cmdSize, pCmdData, numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    auto reader = EffectParamReader(*(effect_param_t*)pCmdData);
    if (!reader.validateCmdSize(cmdSize)) {
        ALOGE("%s illegal param %s size %u", __func__, reader.toString().c_str(), cmdSize);
        return BAD_VALUE;
    }

    status_t ret = setParameter(reader);
    EffectParamWriter writer(*(effect_param_t*)pReplyData);
    writer.setStatus(ret);
    return *(status_t*)pReplyData = ret;
}

status_t EffectConversionHelperAidl::handleGetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_param_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s illegal cmdSize %u pCmdData %p replySize %s replyData %p", __func__, cmdSize,
              pCmdData, numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    const auto reader = EffectParamReader(*(effect_param_t*)pCmdData);
    if (*replySize < sizeof(effect_param_t) + reader.getParameterSize()) {
        ALOGE("%s illegal param %s, replySize %u", __func__, reader.toString().c_str(), *replySize);
        return BAD_VALUE;
    }

    // copy effect_param_t and parameters
    memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + reader.getParameterSize());
    auto writer = EffectParamWriter(*(effect_param_t*)pReplyData);
    status_t ret = getParameter(writer);
    writer.finishValueWrite();
    writer.setStatus(ret);
    *replySize = writer.getTotalSize();
    if (ret != OK) {
        ALOGE("%s error ret %d, %s", __func__, ret, writer.toString().c_str());
    }
    return ret;
}

status_t EffectConversionHelperAidl::handleSetConfig(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(int) || !pReplyData ||
        cmdSize != sizeof(effect_config_t)) {
        ALOGE("%s parameter invalid, cmdSize %u pCmdData %p replySize %s pReplyData %p", __func__,
              cmdSize, pCmdData, numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    effect_config_t* config = (effect_config_t*)pCmdData;
    Parameter::Common common = {
            .session = mCommon.session,
            .ioHandle = mCommon.ioHandle,
            .input =
                    VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_buffer_config_t_AudioConfig(
                            config->inputCfg, mIsInputStream)),
            .output =
                    VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_buffer_config_t_AudioConfig(
                            config->outputCfg, mIsInputStream))};

    State state;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getState(&state)));
    // in case of buffer/ioHandle re-configure for an opened effect, close it and re-open
    if (state != State::INIT && mCommon != common) {
        ALOGI("%s at state %s, closing effect", __func__,
              android::internal::ToString(state).c_str());
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->close()));
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getState(&state)));
        mStatusQ.reset();
        mInputQ.reset();
        mOutputQ.reset();
    }

    if (state == State::INIT) {
        ALOGI("%s at state %s, opening effect with input %s output %s", __func__,
              android::internal::ToString(state).c_str(), common.input.toString().c_str(),
              common.output.toString().c_str());
        IEffect::OpenEffectReturn openReturn;
        RETURN_STATUS_IF_ERROR(
                statusTFromBinderStatus(mEffect->open(common, std::nullopt, &openReturn)));

        if (mIsProxyEffect) {
            mStatusQ = std::static_pointer_cast<EffectProxy>(mEffect)->getStatusMQ();
            mInputQ = std::static_pointer_cast<EffectProxy>(mEffect)->getInputMQ();
            mOutputQ = std::static_pointer_cast<EffectProxy>(mEffect)->getOutputMQ();
        } else {
            mStatusQ = std::make_shared<StatusMQ>(openReturn.statusMQ);
            mInputQ = std::make_shared<DataMQ>(openReturn.inputDataMQ);
            mOutputQ = std::make_shared<DataMQ>(openReturn.outputDataMQ);
        }

        if (status_t status = updateEventFlags(); status != OK) {
            ALOGV("%s closing at status %d", __func__, status);
            mEffect->close();
            return status;
        }
    } else if (mCommon != common) {
        ALOGI("%s at state %s, setParameter", __func__, android::internal::ToString(state).c_str());
        Parameter aidlParam = UNION_MAKE(Parameter, common, common);
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->setParameter(aidlParam)));
    }
    mCommon = common;

    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleGetConfig(uint32_t cmdSize __unused,
                                                     const void* pCmdData __unused,
                                                     uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid, replySize %s pReplyData %p", __func__,
              numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    Parameter param;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(
            Parameter::Id::make<Parameter::Id::commonTag>(Parameter::common), &param)));
    if (param.getTag() != Parameter::common) {
        *replySize = 0;
        ALOGW("%s no valid common tag return from HAL: %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

    const auto& common = param.get<Parameter::common>();
    effect_config_t* pConfig = (effect_config_t*)pReplyData;
    pConfig->inputCfg = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioConfig_buffer_config_t(common.input, true));
    pConfig->outputCfg = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioConfig_buffer_config_t(common.output, false));
    return OK;
}

status_t EffectConversionHelperAidl::handleReset(uint32_t cmdSize __unused,
                                                 const void* pCmdData __unused, uint32_t* replySize,
                                                 void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid, replySize %s pReplyData %p", __func__,
              numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::RESET));
}

status_t EffectConversionHelperAidl::handleEnable(uint32_t cmdSize __unused,
                                                  const void* pCmdData __unused,
                                                  uint32_t* replySize, void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid, replySize %s pReplyData %p", __func__,
              numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::START));
}

status_t EffectConversionHelperAidl::handleDisable(uint32_t cmdSize __unused,
                                                   const void* pCmdData __unused,
                                                   uint32_t* replySize, void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid, replySize %s pReplyData %p", __func__,
              numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::STOP));
}

status_t EffectConversionHelperAidl::handleSetAudioSource(uint32_t cmdSize, const void* pCmdData,
                                                          uint32_t* replySize, void* pReplyData) {
    if (cmdSize != sizeof(uint32_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid, cmdSize %u pCmdData %p replySize %s pReplyData %p", __func__,
              cmdSize, pCmdData, numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }
    if (!getDescriptor().common.flags.audioSourceIndication) {
        ALOGW("%s parameter no audioSourceIndication, skipping", __func__);
        return OK;
    }

    audio_source_t source = *(audio_source_t*)pCmdData;
    AudioSource aidlSource =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_audio_source_t_AudioSource(source));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::source>(aidlSource))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetAudioMode(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize != sizeof(uint32_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid, cmdSize %u pCmdData %p replySize %s pReplyData %p", __func__,
              cmdSize, pCmdData, numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }
    if (!getDescriptor().common.flags.audioModeIndication) {
        ALOGW("%s parameter no audioModeIndication, skipping", __func__);
        return OK;
    }
    audio_mode_t mode = *(audio_mode_t *)pCmdData;
    AudioMode aidlMode =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_audio_mode_t_AudioMode(mode));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::mode>(aidlMode))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetDevice(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (cmdSize != sizeof(uint32_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid, cmdSize %u pCmdData %p replySize %s pReplyData %p", __func__,
              cmdSize, pCmdData, numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }
    if (!getDescriptor().common.flags.deviceIndication) {
        ALOGW("%s parameter no deviceIndication, skipping", __func__);
        return OK;
    }
    // convert from bitmask of audio_devices_t to std::vector<AudioDeviceDescription>
    auto legacyDevices = *(uint32_t*)(pCmdData);
    // extract the input bit and remove it from bitmasks
    const auto inputBit = legacyDevices & AUDIO_DEVICE_BIT_IN;
    legacyDevices &= ~AUDIO_DEVICE_BIT_IN;
    std::vector<AudioDeviceDescription> aidlDevices;
    while (legacyDevices) {
        // get audio_devices_t represented by the last true bit and convert to AIDL
        const auto lowestBitDevice = legacyDevices & -legacyDevices;
        AudioDeviceDescription deviceDesc = VALUE_OR_RETURN_STATUS(
                ::aidl::android::legacy2aidl_audio_devices_t_AudioDeviceDescription(
                        static_cast<audio_devices_t>(lowestBitDevice | inputBit)));
        aidlDevices.emplace_back(deviceDesc);
        legacyDevices -= lowestBitDevice;
    }

    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::deviceDescription>(aidlDevices))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetVolume(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (cmdSize != 2 * sizeof(uint32_t) || !pCmdData) {
        ALOGE("%s parameter invalid %u %p", __func__, cmdSize, pCmdData);
        return BAD_VALUE;
    }

    constexpr uint32_t unityGain = 1 << 24;
    uint32_t vl = *(uint32_t*)pCmdData;
    uint32_t vr = *((uint32_t*)pCmdData + 1);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::volumeStereo>(Parameter::VolumeStereo(
                    {.left = (float)vl / unityGain, .right = (float)vr / unityGain})))));

    // get volume from effect and set if changed, return the volume in command if HAL not return
    // correct parameter.
    Parameter::Id id = Parameter::Id::make<Parameter::Id::commonTag>(Parameter::volumeStereo);
    Parameter volParam;
    const status_t getParamStatus = statusTFromBinderStatus(mEffect->getParameter(id, &volParam));
    if (getParamStatus != OK || volParam.getTag() != Parameter::volumeStereo) {
        ALOGW("%s no valid volume return from HAL, status %d: %s, return volume in command",
              __func__, getParamStatus, volParam.toString().c_str());
    } else {
        Parameter::VolumeStereo appliedVolume = volParam.get<Parameter::volumeStereo>();
        vl = (uint32_t)(appliedVolume.left * unityGain);
        vr = (uint32_t)(appliedVolume.right * unityGain);
    }

    if (replySize && *replySize == 2 * sizeof(uint32_t) && pReplyData) {
        uint32_t vol_ret[2] = {vl, vr};
        memcpy(pReplyData, vol_ret, sizeof(vol_ret));
    }
    return OK;
}

status_t EffectConversionHelperAidl::handleSetOffload(uint32_t cmdSize, const void* pCmdData,
                                                      uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_offload_param_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid, cmdSize %u pCmdData %p replySize %s pReplyData %p", __func__,
              cmdSize, pCmdData, numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }
    effect_offload_param_t* offload = (effect_offload_param_t*)pCmdData;
    // send to proxy to update active sub-effect
    if (mIsProxyEffect) {
        ALOGI("%s offload param offload %s ioHandle %d", __func__,
              offload->isOffload ? "true" : "false", offload->ioHandle);
        const auto& effectProxy = std::static_pointer_cast<EffectProxy>(mEffect);
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(effectProxy->setOffloadParam(offload)));
        if (mCommon.ioHandle != offload->ioHandle) {
            ALOGI("%s ioHandle update [%d to %d]", __func__, mCommon.ioHandle, offload->ioHandle);
            mCommon.ioHandle = offload->ioHandle;
            Parameter aidlParam = UNION_MAKE(Parameter, common, mCommon);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->setParameter(aidlParam)));
        }
        // update FMQs if the effect instance already open
        if (State state; effectProxy->getState(&state).isOk() && state != State::INIT) {
            mStatusQ = effectProxy->getStatusMQ();
            mInputQ = effectProxy->getInputMQ();
            mOutputQ = effectProxy->getOutputMQ();
            updateEventFlags();
        }
    }
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleVisualizerCapture(uint32_t cmdSize __unused,
                                                             const void* pCmdData __unused,
                                                             uint32_t* replySize,
                                                             void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid replySize %s pReplyData %p", __func__,
              numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    const auto& uuid = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioUuid_audio_uuid_t(mDesc.common.id.type));
    if (0 != memcmp(&uuid, SL_IID_VISUALIZATION, sizeof(effect_uuid_t))) {
        ALOGE("%s visualizer command not supported by %s", __func__,
              mDesc.common.id.toString().c_str());
        return BAD_VALUE;
    }

    return visualizerCapture(replySize, pReplyData);
}

status_t EffectConversionHelperAidl::handleVisualizerMeasure(uint32_t cmdSize __unused,
                                                             const void* pCmdData __unused,
                                                             uint32_t* replySize,
                                                             void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid, replySize %s pReplyData %p", __func__,
              numericPointerToString(replySize).c_str(), pReplyData);
        return BAD_VALUE;
    }

    const auto& uuid = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioUuid_audio_uuid_t(mDesc.common.id.type));
    if (0 != memcmp(&uuid, SL_IID_VISUALIZATION, sizeof(effect_uuid_t))) {
        ALOGE("%s visualizer command not supported by %s", __func__,
              mDesc.common.id.toString().c_str());
        return BAD_VALUE;
    }

    return visualizerMeasure(replySize, pReplyData);
}

status_t EffectConversionHelperAidl::updateEventFlags() {
    status_t status = BAD_VALUE;
    EventFlag* efGroup = nullptr;
    if (mStatusQ && mStatusQ->isValid()) {
        status = EventFlag::createEventFlag(mStatusQ->getEventFlagWord(), &efGroup);
        if (status != OK || !efGroup) {
            ALOGE("%s: create EventFlagGroup failed, ret %d, egGroup %p", __func__, status,
                  efGroup);
            status = (status == OK) ? BAD_VALUE : status;
        }
    } else if (isBypassing()) {
        // for effect with bypass (no processing) flag, it's okay to not have statusQ
        return OK;
    }

    mEfGroup.reset(efGroup, EventFlagDeleter());
    return status;
}

bool EffectConversionHelperAidl::isBypassing() const {
    return mEffect &&
           (mDesc.common.flags.bypass ||
            (mIsProxyEffect && std::static_pointer_cast<EffectProxy>(mEffect)->isBypassing()));
}

Descriptor EffectConversionHelperAidl::getDescriptor() const {
    if (!mIsProxyEffect) {
        return mDesc;
    }

    Descriptor desc;
    if (const auto status = mEffect->getDescriptor(&desc); !status.isOk()) {
        ALOGE("%s failed to get proxy descriptor (%d:%s), using default", __func__,
              status.getStatus(), status.getMessage());
        return mDesc;
    }
    return desc;
}

}  // namespace effect
}  // namespace android
