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

#define LOG_TAG "AHAL_HapticGeneratorImpl"

#include <android-base/logging.h>
#include <audio_effects/effect_hapticgenerator.h>
#include <system/audio_effects/effect_uuid.h>

#include "EffectHapticGenerator.h"

using aidl::android::hardware::audio::effect::Descriptor;
using aidl::android::hardware::audio::effect::getEffectImplUuidHapticGenerator;
using aidl::android::hardware::audio::effect::getEffectTypeUuidHapticGenerator;
using aidl::android::hardware::audio::effect::HapticGeneratorImpl;
using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::media::audio::common::AudioUuid;

extern "C" binder_exception_t createEffect(const AudioUuid* in_impl_uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (!in_impl_uuid || *in_impl_uuid != getEffectImplUuidHapticGenerator()) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (instanceSpp) {
        *instanceSpp = ndk::SharedRefBase::make<HapticGeneratorImpl>();
        LOG(DEBUG) << __func__ << " instance " << instanceSpp->get() << " created";
        return EX_NONE;
    } else {
        LOG(ERROR) << __func__ << " invalid input parameter!";
        return EX_ILLEGAL_ARGUMENT;
    }
}

extern "C" binder_exception_t queryEffect(const AudioUuid* in_impl_uuid, Descriptor* _aidl_return) {
    if (!in_impl_uuid || *in_impl_uuid != getEffectImplUuidHapticGenerator()) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    *_aidl_return = HapticGeneratorImpl::kDescriptor;
    return EX_NONE;
}

namespace aidl::android::hardware::audio::effect {

const std::string HapticGeneratorImpl::kEffectName = "Haptic Generator";
const Descriptor HapticGeneratorImpl::kDescriptor = {
        .common = {.id = {.type = getEffectTypeUuidHapticGenerator(),
                          .uuid = getEffectImplUuidHapticGenerator(),
                          .proxy = std::nullopt},
                   .flags = {.type = Flags::Type::INSERT, .insert = Flags::Insert::FIRST},
                   .name = HapticGeneratorImpl::kEffectName,
                   .implementor = "The Android Open Source Project"}};

ndk::ScopedAStatus HapticGeneratorImpl::getDescriptor(Descriptor* _aidl_return) {
    RETURN_IF(!_aidl_return, EX_ILLEGAL_ARGUMENT, "Parameter:nullptr");
    LOG(DEBUG) << __func__ << kDescriptor.toString();
    *_aidl_return = kDescriptor;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus HapticGeneratorImpl::commandImpl(CommandId command) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    switch (command) {
        case CommandId::START:
            mContext->enable();
            break;
        case CommandId::STOP:
            mContext->disable();
            break;
        case CommandId::RESET:
            mContext->reset();
            break;
        default:
            LOG(ERROR) << __func__ << " commandId " << toString(command) << " not supported";
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "commandIdNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus HapticGeneratorImpl::setParameterSpecific(const Parameter::Specific& specific) {
    RETURN_IF(Parameter::Specific::hapticGenerator != specific.getTag(), EX_ILLEGAL_ARGUMENT,
              "EffectNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto& hgParam = specific.get<Parameter::Specific::hapticGenerator>();
    auto tag = hgParam.getTag();

    switch (tag) {
        case HapticGenerator::hapticScales: {
            RETURN_IF(mContext->setHgHapticScales(hgParam.get<HapticGenerator::hapticScales>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setHapticScaleFailed");
            return ndk::ScopedAStatus::ok();
        }
        case HapticGenerator::vibratorInfo: {
            RETURN_IF(mContext->setHgVibratorInformation(
                              hgParam.get<HapticGenerator::vibratorInfo>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setVibratorInfoFailed");
            return ndk::ScopedAStatus::ok();
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "HapticGeneratorTagNotSupported");
        }
    }
}

ndk::ScopedAStatus HapticGeneratorImpl::getParameterSpecific(const Parameter::Id& id,
                                                             Parameter::Specific* specific) {
    RETURN_IF(!specific, EX_NULL_POINTER, "nullPtr");
    auto tag = id.getTag();
    RETURN_IF(Parameter::Id::hapticGeneratorTag != tag, EX_ILLEGAL_ARGUMENT, "wrongIdTag");
    auto hgId = id.get<Parameter::Id::hapticGeneratorTag>();
    auto hgIdTag = hgId.getTag();
    switch (hgIdTag) {
        case HapticGenerator::Id::commonTag:
            return getParameterHapticGenerator(hgId.get<HapticGenerator::Id::commonTag>(),
                                               specific);
        default:
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(hgIdTag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "HapticGeneratorTagNotSupported");
    }
}

ndk::ScopedAStatus HapticGeneratorImpl::getParameterHapticGenerator(const HapticGenerator::Tag& tag,
                                                                    Parameter::Specific* specific) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    HapticGenerator hgParam;
    switch (tag) {
        case HapticGenerator::hapticScales: {
            hgParam.set<HapticGenerator::hapticScales>(mContext->getHgHapticScales());
            break;
        }
        case HapticGenerator::vibratorInfo: {
            hgParam.set<HapticGenerator::vibratorInfo>(mContext->getHgVibratorInformation());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "HapticGeneratorTagNotSupported");
        }
    }

    specific->set<Parameter::Specific::hapticGenerator>(hgParam);
    return ndk::ScopedAStatus::ok();
}

std::shared_ptr<EffectContext> HapticGeneratorImpl::createContext(const Parameter::Common& common) {
    if (mContext) {
        LOG(DEBUG) << __func__ << " context already exist";
        return mContext;
    }

    mContext = std::make_shared<HapticGeneratorContext>(1 /* statusFmqDepth */, common);
    return mContext;
}

RetCode HapticGeneratorImpl::releaseContext() {
    if (mContext) {
        mContext->reset();
    }
    return RetCode::SUCCESS;
}

// Processing method running in EffectWorker thread.
IEffect::Status HapticGeneratorImpl::effectProcessImpl(float* in, float* out, int samples) {
    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!mContext, status, "nullContext");
    return mContext->process(in, out, samples);
}

}  // namespace aidl::android::hardware::audio::effect
