/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "EffectHalAidl"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionUtil.h>
#include <media/EffectsFactoryApi.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>

#include "EffectHalAidl.h"

#include <system/audio.h>

#include <aidl/android/hardware/audio/effect/IEffect.h>

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::State;
using ::aidl::android::hardware::audio::effect::Parameter;

namespace android {
namespace effect {

EffectHalAidl::EffectHalAidl(const std::shared_ptr<IEffect>& effect, uint64_t effectId,
                             int32_t sessionId, int32_t ioId)
    : mEffectId(effectId), mSessionId(sessionId), mIoId(ioId), mEffect(effect) {}

EffectHalAidl::~EffectHalAidl() {}

status_t EffectHalAidl::setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGW("%s not implemented yet", __func__);
    return OK;
}

status_t EffectHalAidl::setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGW("%s not implemented yet", __func__);
    return OK;
}

status_t EffectHalAidl::process() {
    ALOGW("%s not implemented yet", __func__);
    // write to input FMQ here?
    return OK;
}

// TODO: no one using, maybe deprecate this interface
status_t EffectHalAidl::processReverse() {
    ALOGW("%s not implemented yet", __func__);
    return OK;
}

status_t EffectHalAidl::handleSetConfig(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                        uint32_t* replySize, void* pReplyData) {
    if (pCmdData == NULL || cmdSize != sizeof(effect_config_t) || replySize == NULL ||
        *replySize != sizeof(int32_t) || pReplyData == NULL) {
        ALOGE("%s parameter error code %u", __func__, cmdCode);
        return BAD_VALUE;
    }

    *static_cast<int32_t*>(pReplyData) = FAILED_TRANSACTION;
    memcpy(&mConfig, pCmdData, cmdSize);

    State state;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getState(&state)));
    // effect not open yet, save settings locally
    if (state != State::INIT) {
        effect_config_t* legacyConfig = static_cast<effect_config_t*>(pCmdData);
        // already open, apply latest settings
        Parameter aidlParam;
        Parameter::Common aidlCommon;
        aidlCommon.input.base =
                VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_AudioConfigBase_buffer_config_t(
                        legacyConfig->inputCfg, true /* isInput */));
        aidlCommon.output.base =
                VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_AudioConfigBase_buffer_config_t(
                        legacyConfig->outputCfg, false /* isInput */));
        aidlCommon.session = mSessionId;
        aidlCommon.ioHandle = mIoId;
        Parameter::Id id;
        id.set<Parameter::Id::commonTag>(Parameter::common);
        aidlParam.set<Parameter::common>(aidlCommon);
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->setParameter(aidlParam)));
    }
    *(int*)pReplyData = 0;
    *static_cast<int32_t*>(pReplyData) = OK;
    return OK;
}

status_t EffectHalAidl::handleGetConfig(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                        uint32_t* replySize, void* pReplyData) {
    if (pCmdData == NULL || cmdSize == 0 || replySize == NULL ||
        *replySize != sizeof(effect_config_t) || pReplyData == NULL) {
        ALOGE("%s parameter error with cmdCode %d", __func__, cmdCode);
        return BAD_VALUE;
    }

    *(effect_config_t*)pReplyData = mConfig;
    return OK;
}

status_t EffectHalAidl::handleSetParameter(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                           uint32_t* replySize, void* pReplyData) {
    ALOGW("%s not implemented yet", __func__);
    if (pCmdData == NULL || cmdSize == 0 || replySize == NULL ||
        *replySize != sizeof(effect_config_t) || pReplyData == NULL) {
        ALOGE("%s parameter error with cmdCode %d", __func__, cmdCode);
        return BAD_VALUE;
    }
    return OK;
}

status_t EffectHalAidl::handleGetParameter(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                           uint32_t* replySize, void* pReplyData) {
    ALOGW("%s not implemented yet", __func__);
    if (pCmdData == NULL || cmdSize == 0 || replySize == NULL ||
        *replySize != sizeof(effect_config_t) || pReplyData == NULL) {
        ALOGE("%s parameter error with cmdCode %d", __func__, cmdCode);
        return BAD_VALUE;
    }
    return OK;
}

status_t EffectHalAidl::command(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                uint32_t* replySize, void* pReplyData) {
    ALOGW("%s code %d not implemented yet", __func__, cmdCode);
    ::ndk::ScopedAStatus status;
    switch (cmdCode) {
        case EFFECT_CMD_INIT: {
            // open with default effect_config_t (convert to Parameter.Common)
            IEffect::OpenEffectReturn ret;
            Parameter::Common common;
            RETURN_STATUS_IF_ERROR(
                    statusTFromBinderStatus(mEffect->open(common, std::nullopt, &ret)));
            return OK;
        }
        case EFFECT_CMD_SET_CONFIG:
            return handleSetConfig(cmdCode, cmdSize, pCmdData, replySize, pReplyData);
        case EFFECT_CMD_GET_CONFIG:
            return handleGetConfig(cmdCode, cmdSize, pCmdData, replySize, pReplyData);
        case EFFECT_CMD_RESET:
            return mEffect->command(CommandId::RESET).getStatus();
        case EFFECT_CMD_ENABLE:
            return mEffect->command(CommandId::START).getStatus();
        case EFFECT_CMD_DISABLE:
            return mEffect->command(CommandId::STOP).getStatus();
        case EFFECT_CMD_SET_PARAM:
            return handleSetParameter(cmdCode, cmdSize, pCmdData, replySize, pReplyData);
        case EFFECT_CMD_SET_PARAM_DEFERRED:
        case EFFECT_CMD_SET_PARAM_COMMIT:
            // TODO
            return OK;
        case EFFECT_CMD_GET_PARAM:
            return handleGetParameter(cmdCode, cmdSize, pCmdData, replySize, pReplyData);
        case EFFECT_CMD_SET_DEVICE:
            return OK;
        case EFFECT_CMD_SET_VOLUME:
            return OK;
        case EFFECT_CMD_SET_AUDIO_MODE:
            return OK;
        case EFFECT_CMD_SET_CONFIG_REVERSE:
            return OK;
        case EFFECT_CMD_SET_INPUT_DEVICE:
            return OK;
        case EFFECT_CMD_GET_CONFIG_REVERSE:
            return OK;
        case EFFECT_CMD_GET_FEATURE_SUPPORTED_CONFIGS:
            return OK;
        case EFFECT_CMD_GET_FEATURE_CONFIG:
            return OK;
        case EFFECT_CMD_SET_FEATURE_CONFIG:
            return OK;
        case EFFECT_CMD_SET_AUDIO_SOURCE:
            return OK;
        case EFFECT_CMD_OFFLOAD:
            return OK;
        case EFFECT_CMD_DUMP:
            return OK;
        case EFFECT_CMD_FIRST_PROPRIETARY:
            return OK;
        default:
            return INVALID_OPERATION;
    }
    return INVALID_OPERATION;
}

status_t EffectHalAidl::getDescriptor(effect_descriptor_t* pDescriptor) {
    ALOGW("%s %p", __func__, pDescriptor);
    if (pDescriptor == nullptr) {
        return BAD_VALUE;
    }
    Descriptor aidlDesc;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getDescriptor(&aidlDesc)));

    *pDescriptor = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(aidlDesc));
    return OK;
}

status_t EffectHalAidl::close() {
    auto ret = mEffect->close();
    ALOGI("%s %s", __func__, ret.getMessage());
    return ret.getStatus();
}

status_t EffectHalAidl::dump(int fd) {
    ALOGW("%s not implemented yet, fd %d", __func__, fd);
    return OK;
}

} // namespace effect
} // namespace android
