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
#include <media/audiohal/AudioEffectUuid.h>
#include <media/EffectsFactoryApi.h>
#include <mediautils/TimeCheck.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "EffectHalAidl.h"

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
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::IFactory;
using ::aidl::android::hardware::audio::effect::Parameter;

namespace android {
namespace effect {

EffectHalAidl::EffectHalAidl(
        const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory>& factory,
        const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>& effect,
        uint64_t effectId, int32_t sessionId, int32_t ioId,
        const ::aidl::android::hardware::audio::effect::Descriptor& desc)
    : mFactory(factory),
      mEffect(effect),
      mEffectId(effectId),
      mSessionId(sessionId),
      mIoId(ioId),
      mDesc(desc) {
    createAidlConversion(effect, sessionId, ioId, desc);
}

EffectHalAidl::~EffectHalAidl() {
    if (mFactory) {
        mFactory->destroyEffect(mEffect);
    }
}

status_t EffectHalAidl::createAidlConversion(
        std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
        int32_t sessionId, int32_t ioId,
        const ::aidl::android::hardware::audio::effect::Descriptor& desc) {
    const auto& typeUuid = desc.common.id.type;
    ALOGI("%s create UUID %s", __func__, typeUuid.toString().c_str());
    if (typeUuid == kAcousticEchoCancelerTypeUUID) {
        mConversion =
                std::make_unique<android::effect::AidlConversionAec>(effect, sessionId, ioId, desc);
    } else if (typeUuid == kAutomaticGainControl1TypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionAgc1>(effect, sessionId, ioId,
                                                                            desc);
    } else if (typeUuid == kAutomaticGainControl2TypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionAgc2>(effect, sessionId, ioId,
                                                                            desc);
    } else if (typeUuid == kBassBoostTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionBassBoost>(effect, sessionId,
                                                                                 ioId, desc);
    } else if (typeUuid == kDownmixTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionDownmix>(effect, sessionId,
                                                                               ioId, desc);
    } else if (typeUuid == kDynamicsProcessingTypeUUID) {
        mConversion =
                std::make_unique<android::effect::AidlConversionDp>(effect, sessionId, ioId, desc);
    } else if (typeUuid == kEnvReverbTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionEnvReverb>(effect, sessionId,
                                                                                 ioId, desc);
    } else if (typeUuid == kEqualizerTypeUUID) {
        mConversion =
                std::make_unique<android::effect::AidlConversionEq>(effect, sessionId, ioId, desc);
    } else if (typeUuid == kHapticGeneratorTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionHapticGenerator>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kLoudnessEnhancerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionLoudnessEnhancer>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kNoiseSuppressionTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionNoiseSuppression>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kPresetReverbTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionPresetReverb>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kSpatializerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionSpatializer>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kVirtualizerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionVirtualizer>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kVisualizerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionVisualizer>(effect, sessionId,
                                                                                  ioId, desc);
    } else {
        // For unknown UUID, use vendor extension implementation
        mConversion = std::make_unique<android::effect::AidlConversionVendorExtension>(
                effect, sessionId, ioId, desc);
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
    size_t available = mInputQ->availableToWrite();
    size_t floatsToWrite = std::min(available, mInBuffer->getSize() / sizeof(float));
    if (floatsToWrite == 0) {
        ALOGW("%s not able to write, floats in buffer %zu, space in FMQ %zu", __func__,
              mInBuffer->getSize() / sizeof(float), available);
        return INVALID_OPERATION;
    }
    if (!mInputQ->write((float*)mInBuffer->ptr(), floatsToWrite)) {
        ALOGW("%s failed to write %zu into inputQ", __func__, floatsToWrite);
        return INVALID_OPERATION;
    }

    IEffect::Status retStatus{};
    if (!mStatusQ->readBlocking(&retStatus, 1) || retStatus.status != OK ||
        (size_t)retStatus.fmqConsumed != floatsToWrite || retStatus.fmqProduced == 0) {
        ALOGW("%s read status failed: %s", __func__, retStatus.toString().c_str());
        return INVALID_OPERATION;
    }

    available = mOutputQ->availableToRead();
    size_t floatsToRead = std::min(available, mOutBuffer->getSize() / sizeof(float));
    if (floatsToRead == 0) {
        ALOGW("%s not able to read, buffer space %zu, floats in FMQ %zu", __func__,
              mOutBuffer->getSize() / sizeof(float), available);
        return INVALID_OPERATION;
    }
    if (!mOutputQ->read((float*)mOutBuffer->ptr(), floatsToRead)) {
        ALOGW("%s failed to read %zu from outputQ", __func__, floatsToRead);
        return INVALID_OPERATION;
    }

    ALOGD("%s %s consumed %zu produced %zu", __func__, mDesc.common.name.c_str(), floatsToWrite,
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

    status_t ret = mConversion->handleCommand(cmdCode, cmdSize, pCmdData, replySize, pReplyData);
    // update FMQs when effect open successfully
    if (ret == OK && cmdCode == EFFECT_CMD_INIT) {
        const auto& retParam = mConversion->getEffectReturnParam();
        mStatusQ = std::make_unique<StatusMQ>(retParam.statusMQ);
        mInputQ = std::make_unique<DataMQ>(retParam.inputDataMQ);
        mOutputQ = std::make_unique<DataMQ>(retParam.outputDataMQ);
        if (!mStatusQ->isValid() || !mInputQ->isValid() || !mOutputQ->isValid()) {
            ALOGE("%s return with invalid FMQ", __func__);
            return NO_INIT;
        }
    }

    return ret;
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
