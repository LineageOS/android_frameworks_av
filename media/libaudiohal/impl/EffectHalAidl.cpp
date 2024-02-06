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

#include <cstddef>
#define LOG_TAG "EffectHalAidl"
//#define LOG_NDEBUG 0

#include <memory>

#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/AidlConversionUtil.h>
#include <media/EffectsFactoryApi.h>
#include <mediautils/TimeCheck.h>
#include <system/audio.h>
#include <system/audio_effects/effect_uuid.h>
#include <utils/Log.h>

#include "EffectHalAidl.h"
#include "EffectProxy.h"

#include <aidl/android/hardware/audio/effect/IEffect.h>

#include "effectsAidlConversion/AidlConversionAec.h"
#include "effectsAidlConversion/AidlConversionAgc1.h"
#include "effectsAidlConversion/AidlConversionAgc2.h"
#include "effectsAidlConversion/AidlConversionBassBoost.h"
#include "effectsAidlConversion/AidlConversionDownmix.h"
#include "effectsAidlConversion/AidlConversionDynamicsProcessing.h"
#include "effectsAidlConversion/AidlConversionEnvReverb.h"
#include "effectsAidlConversion/AidlConversionEq.h"
#include "effectsAidlConversion/AidlConversionHapticGenerator.h"
#include "effectsAidlConversion/AidlConversionLoudnessEnhancer.h"
#include "effectsAidlConversion/AidlConversionNoiseSuppression.h"
#include "effectsAidlConversion/AidlConversionPresetReverb.h"
#include "effectsAidlConversion/AidlConversionSpatializer.h"
#include "effectsAidlConversion/AidlConversionVendorExtension.h"
#include "effectsAidlConversion/AidlConversionVirtualizer.h"
#include "effectsAidlConversion/AidlConversionVisualizer.h"

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::IFactory;
using ::aidl::android::hardware::audio::effect::kEventFlagDataMqUpdate;
using ::aidl::android::hardware::audio::effect::kReopenSupportedVersion;
using ::aidl::android::hardware::audio::effect::State;

namespace android {
namespace effect {

EffectHalAidl::EffectHalAidl(const std::shared_ptr<IFactory>& factory,
                             const std::shared_ptr<IEffect>& effect, int32_t sessionId,
                             int32_t ioId, const Descriptor& desc, bool isProxyEffect)
    : mFactory(factory),
      mEffect(effect),
      mSessionId(sessionId),
      mIoId(ioId),
      mIsProxyEffect(isProxyEffect) {
    assert(mFactory != nullptr);
    assert(mEffect != nullptr);
    createAidlConversion(effect, sessionId, ioId, desc);
}

EffectHalAidl::~EffectHalAidl() {
    if (mEffect) {
        if (mIsProxyEffect) {
            std::static_pointer_cast<EffectProxy>(mEffect)->destroy();
        } else if (mFactory) {
            mFactory->destroyEffect(mEffect);
        }
    }
}

status_t EffectHalAidl::createAidlConversion(
        std::shared_ptr<IEffect> effect,
        int32_t sessionId, int32_t ioId,
        const Descriptor& desc) {
    const auto& typeUuid = desc.common.id.type;
    ALOGI("%s create UUID %s", __func__, typeUuid.toString().c_str());
    if (typeUuid ==
        ::aidl::android::hardware::audio::effect::getEffectTypeUuidAcousticEchoCanceler()) {
        mConversion = std::make_unique<android::effect::AidlConversionAec>(effect, sessionId, ioId,
                                                                           desc, mIsProxyEffect);
    } else if (typeUuid == ::aidl::android::hardware::audio::effect::
                                   getEffectTypeUuidAutomaticGainControlV1()) {
        mConversion = std::make_unique<android::effect::AidlConversionAgc1>(effect, sessionId, ioId,
                                                                            desc, mIsProxyEffect);
    } else if (typeUuid == ::aidl::android::hardware::audio::effect::
                                   getEffectTypeUuidAutomaticGainControlV2()) {
        mConversion = std::make_unique<android::effect::AidlConversionAgc2>(effect, sessionId, ioId,
                                                                            desc, mIsProxyEffect);
    } else if (typeUuid == ::aidl::android::hardware::audio::effect::getEffectTypeUuidBassBoost()) {
        mConversion = std::make_unique<android::effect::AidlConversionBassBoost>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid == ::aidl::android::hardware::audio::effect::getEffectTypeUuidDownmix()) {
        mConversion = std::make_unique<android::effect::AidlConversionDownmix>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidDynamicsProcessing()) {
        mConversion = std::make_unique<android::effect::AidlConversionDp>(effect, sessionId, ioId,
                                                                          desc, mIsProxyEffect);
    } else if (typeUuid == ::aidl::android::hardware::audio::effect::getEffectTypeUuidEnvReverb()) {
        mConversion = std::make_unique<android::effect::AidlConversionEnvReverb>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid == ::aidl::android::hardware::audio::effect::getEffectTypeUuidEqualizer()) {
        mConversion = std::make_unique<android::effect::AidlConversionEq>(effect, sessionId, ioId,
                                                                          desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidHapticGenerator()) {
        mConversion = std::make_unique<android::effect::AidlConversionHapticGenerator>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidLoudnessEnhancer()) {
        mConversion = std::make_unique<android::effect::AidlConversionLoudnessEnhancer>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidNoiseSuppression()) {
        mConversion = std::make_unique<android::effect::AidlConversionNoiseSuppression>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidPresetReverb()) {
        mConversion = std::make_unique<android::effect::AidlConversionPresetReverb>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidSpatializer()) {
        mConversion = std::make_unique<android::effect::AidlConversionSpatializer>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidVirtualizer()) {
        mConversion = std::make_unique<android::effect::AidlConversionVirtualizer>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else if (typeUuid ==
               ::aidl::android::hardware::audio::effect::getEffectTypeUuidVisualizer()) {
        mConversion = std::make_unique<android::effect::AidlConversionVisualizer>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    } else {
        // For unknown UUID, use vendor extension implementation
        mConversion = std::make_unique<android::effect::AidlConversionVendorExtension>(
                effect, sessionId, ioId, desc, mIsProxyEffect);
    }
    return OK;
}

status_t EffectHalAidl::setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
    mInBuffer = buffer;
    return OK;
}

status_t EffectHalAidl::setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
    mOutBuffer = buffer;
    return OK;
}

// write to input FMQ here, wait for statusMQ STATUS_OK, and read from output FMQ
status_t EffectHalAidl::process() {
    const std::string effectName = mConversion->getDescriptor().common.name;
    State state = State::INIT;
    if (mConversion->isBypassing() || !mEffect->getState(&state).isOk() ||
        state != State::PROCESSING) {
        ALOGI("%s skipping %s process because it's %s", __func__, effectName.c_str(),
              mConversion->isBypassing()
                      ? "bypassing"
                      : aidl::android::hardware::audio::effect::toString(state).c_str());
        return -ENODATA;
    }

    // check if the DataMq needs any update, timeout at 1ns to avoid being blocked
    auto efGroup = mConversion->getEventFlagGroup();
    if (!efGroup) {
        ALOGE("%s invalid efGroup", __func__);
        return INVALID_OPERATION;
    }

    // use IFactory HAL version because IEffect can be an EffectProxy instance
    static const int halVersion = [&]() {
        int version = 0;
        return mFactory->getInterfaceVersion(&version).isOk() ? version : 0;
    }();

    if (uint32_t efState = 0; halVersion >= kReopenSupportedVersion &&
                              ::android::OK == efGroup->wait(kEventFlagDataMqUpdate, &efState,
                                                             1 /* ns */, true /* retry */) &&
                              efState & kEventFlagDataMqUpdate) {
        ALOGI("%s %s V%d receive dataMQUpdate eventFlag from HAL", __func__, effectName.c_str(),
              halVersion);
        mConversion->reopen();
    }
    auto statusQ = mConversion->getStatusMQ();
    auto inputQ = mConversion->getInputMQ();
    auto outputQ = mConversion->getOutputMQ();
    if (!statusQ || !statusQ->isValid() || !inputQ || !inputQ->isValid() || !outputQ ||
        !outputQ->isValid()) {
        ALOGE("%s invalid FMQ [Status %d I %d O %d]", __func__, statusQ ? statusQ->isValid() : 0,
              inputQ ? inputQ->isValid() : 0, outputQ ? outputQ->isValid() : 0);
        return INVALID_OPERATION;
    }

    size_t available = inputQ->availableToWrite();
    size_t floatsToWrite = std::min(available, mInBuffer->getSize() / sizeof(float));
    if (floatsToWrite == 0) {
        ALOGE("%s not able to write, floats in buffer %zu, space in FMQ %zu", __func__,
              mInBuffer->getSize() / sizeof(float), available);
        return INVALID_OPERATION;
    }
    if (!mInBuffer->audioBuffer() ||
        !inputQ->write((float*)mInBuffer->audioBuffer()->f32, floatsToWrite)) {
        ALOGE("%s failed to write %zu floats from audiobuffer %p to inputQ [avail %zu]", __func__,
              floatsToWrite, mInBuffer->audioBuffer(), inputQ->availableToWrite());
        return INVALID_OPERATION;
    }
    efGroup->wake(aidl::android::hardware::audio::effect::kEventFlagNotEmpty);

    IEffect::Status retStatus{};
    if (!statusQ->readBlocking(&retStatus, 1) || retStatus.status != OK ||
        (size_t)retStatus.fmqConsumed != floatsToWrite || retStatus.fmqProduced == 0) {
        ALOGE("%s read status failed: %s", __func__, retStatus.toString().c_str());
        return INVALID_OPERATION;
    }

    available = outputQ->availableToRead();
    size_t floatsToRead = std::min(available, mOutBuffer->getSize() / sizeof(float));
    if (floatsToRead == 0) {
        ALOGE("%s not able to read, buffer space %zu, floats in FMQ %zu", __func__,
              mOutBuffer->getSize() / sizeof(float), available);
        return INVALID_OPERATION;
    }
    // always read floating point data for AIDL
    if (!mOutBuffer->audioBuffer() ||
        !outputQ->read(mOutBuffer->audioBuffer()->f32, floatsToRead)) {
        ALOGE("%s failed to read %zu from outputQ to audioBuffer %p", __func__, floatsToRead,
              mOutBuffer->audioBuffer());
        return INVALID_OPERATION;
    }

    ALOGD("%s %s consumed %zu produced %zu", __func__, effectName.c_str(), floatsToWrite,
          floatsToRead);
    return OK;
}

// TODO: no one using, maybe deprecate this interface
status_t EffectHalAidl::processReverse() {
    ALOGW("%s not implemented yet", __func__);
    return OK;
}

status_t EffectHalAidl::command(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                uint32_t* replySize, void* pReplyData) {
    TIME_CHECK();
    if (!mConversion) {
        ALOGE("%s can not handle command %d when conversion not exist", __func__, cmdCode);
        return INVALID_OPERATION;
    }

    return mConversion->handleCommand(cmdCode, cmdSize, pCmdData, replySize, pReplyData);
}

status_t EffectHalAidl::getDescriptor(effect_descriptor_t* pDescriptor) {
    TIME_CHECK();
    if (pDescriptor == nullptr) {
        ALOGE("%s null descriptor pointer", __func__);
        return BAD_VALUE;
    }
    Descriptor aidlDesc;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getDescriptor(&aidlDesc)));

    *pDescriptor = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(aidlDesc));
    return OK;
}

status_t EffectHalAidl::close() {
    TIME_CHECK();
    return statusTFromBinderStatus(mEffect->close());
}

status_t EffectHalAidl::dump(int fd) {
    TIME_CHECK();
    return mEffect->dump(fd, nullptr, 0);
}

} // namespace effect
} // namespace android
