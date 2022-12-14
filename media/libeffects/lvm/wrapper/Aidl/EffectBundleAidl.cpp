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

#define LOG_TAG "EffectBundleAidl"
#include <Utils.h>
#include <algorithm>
#include <unordered_set>

#include <android-base/logging.h>
#include <fmq/AidlMessageQueue.h>
#include <audio_effects/effect_bassboost.h>
#include <audio_effects/effect_equalizer.h>
#include <audio_effects/effect_virtualizer.h>

#include "EffectBundleAidl.h"
#include <LVM.h>
#include <limits.h>

using aidl::android::hardware::audio::effect::Descriptor;
using aidl::android::hardware::audio::effect::EffectBundleAidl;
using aidl::android::hardware::audio::effect::kEqualizerBundleImplUUID;
using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::hardware::audio::effect::State;
using aidl::android::media::audio::common::AudioUuid;

extern "C" binder_exception_t createEffect(const AudioUuid* uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (uuid == nullptr || *uuid != kEqualizerBundleImplUUID) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (instanceSpp) {
        *instanceSpp = ndk::SharedRefBase::make<EffectBundleAidl>(*uuid);
        LOG(DEBUG) << __func__ << " instance " << instanceSpp->get() << " created";
        return EX_NONE;
    } else {
        LOG(ERROR) << __func__ << " invalid input parameter!";
        return EX_ILLEGAL_ARGUMENT;
    }
}

extern "C" binder_exception_t queryEffect(const AudioUuid* in_impl_uuid, Descriptor* _aidl_return) {
    if (!in_impl_uuid || *in_impl_uuid != kEqualizerBundleImplUUID) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    *_aidl_return = aidl::android::hardware::audio::effect::lvm::kEqualizerDesc;
    return EX_NONE;
}

namespace aidl::android::hardware::audio::effect {

EffectBundleAidl::EffectBundleAidl(const AudioUuid& uuid) {
    LOG(DEBUG) << __func__ << uuid.toString();
    if (uuid == kEqualizerBundleImplUUID) {
        mType = lvm::BundleEffectType::EQUALIZER;
        mDescriptor = &lvm::kEqualizerDesc;
    } else {
        // TODO: add other bundle effect types here.
        LOG(ERROR) << __func__ << uuid.toString() << " not supported yet!";
    }
}

EffectBundleAidl::~EffectBundleAidl() {
    cleanUp();
    LOG(DEBUG) << __func__;
}

ndk::ScopedAStatus EffectBundleAidl::getDescriptor(Descriptor* _aidl_return) {
    RETURN_IF(!_aidl_return, EX_ILLEGAL_ARGUMENT, "Parameter:nullptr");
    LOG(DEBUG) << _aidl_return->toString();
    *_aidl_return = *mDescriptor;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::setParameterCommon(const Parameter& param) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto tag = param.getTag();
    switch (tag) {
        case Parameter::common:
            RETURN_IF(mContext->setCommon(param.get<Parameter::common>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setCommFailed");
            break;
        case Parameter::deviceDescription:
            RETURN_IF(mContext->setOutputDevice(param.get<Parameter::deviceDescription>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setDeviceFailed");
            break;
        case Parameter::mode:
            RETURN_IF(mContext->setAudioMode(param.get<Parameter::mode>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setModeFailed");
            break;
        case Parameter::source:
            RETURN_IF(mContext->setAudioSource(param.get<Parameter::source>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setSourceFailed");
            break;
        case Parameter::volumeStereo:
            RETURN_IF(mContext->setVolumeStereo(param.get<Parameter::volumeStereo>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setVolumeStereoFailed");
            break;
        default: {
            LOG(ERROR) << __func__ << " unsupportedParameterTag " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "commonParamNotSupported");
        }
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::setParameterSpecific(const Parameter::Specific& specific) {
    LOG(DEBUG) << __func__ << " specific " << specific.toString();
    auto tag = specific.getTag();
    RETURN_IF(tag != Parameter::Specific::equalizer, EX_ILLEGAL_ARGUMENT,
              "specificParamNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto& eq = specific.get<Parameter::Specific::equalizer>();
    auto eqTag = eq.getTag();
    switch (eqTag) {
        case Equalizer::preset:
            RETURN_IF(mContext->setEqualizerPreset(eq.get<Equalizer::preset>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setBandLevelsFailed");
            break;
        case Equalizer::bandLevels:
            RETURN_IF(mContext->setEqualizerBandLevels(eq.get<Equalizer::bandLevels>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setBandLevelsFailed");
            break;
        default:
            LOG(ERROR) << __func__ << " unsupported parameter " << specific.toString();
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "eqTagNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::getParameterSpecific(const Parameter::Id& id,
                                                          Parameter::Specific* specific) {
    RETURN_IF(!specific, EX_NULL_POINTER, "nullPtr");
    auto tag = id.getTag();
    RETURN_IF(Parameter::Id::equalizerTag != tag, EX_ILLEGAL_ARGUMENT, "wrongIdTag");
    auto eqId = id.get<Parameter::Id::equalizerTag>();
    auto eqIdTag = eqId.getTag();
    switch (eqIdTag) {
        case Equalizer::Id::commonTag:
            return getParameterEqualizer(eqId.get<Equalizer::Id::commonTag>(), specific);
        default:
            LOG(ERROR) << __func__ << " tag " << toString(eqIdTag) << " not supported";
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "EqualizerTagNotSupported");
    }
}

ndk::ScopedAStatus EffectBundleAidl::getParameterEqualizer(const Equalizer::Tag& tag,
                                                           Parameter::Specific* specific) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    Equalizer eqParam;
    switch (tag) {
        case Equalizer::bandLevels: {
            eqParam.set<Equalizer::bandLevels>(mContext->getEqualizerBandLevels());
            break;
        }
        case Equalizer::preset: {
            eqParam.set<Equalizer::preset>(mContext->getEqualizerPreset());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " not handled tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "unsupportedTag");
        }
    }

    specific->set<Parameter::Specific::equalizer>(eqParam);
    return ndk::ScopedAStatus::ok();
}

std::shared_ptr<EffectContext> EffectBundleAidl::createContext(const Parameter::Common& common) {
    if (mContext) {
        LOG(DEBUG) << __func__ << " context already exist";
    } else {
        // GlobalSession is a singleton
        mContext = GlobalSession::getGlobalSession().createSession(mType, 1 /* statusFmqDepth */,
                                                                   common);
    }

    return mContext;
}

std::shared_ptr<EffectContext> EffectBundleAidl::getContext() {
    return mContext;
}

RetCode EffectBundleAidl::releaseContext() {
    if (mContext) {
        GlobalSession::getGlobalSession().releaseSession(mType, mContext->getSessionId());
        mContext.reset();
    }
    return RetCode::SUCCESS;
}

ndk::ScopedAStatus EffectBundleAidl::commandImpl(CommandId command) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    switch (command) {
        case CommandId::START:
            mContext->enable();
            break;
        case CommandId::STOP:
            mContext->disable();
            break;
        case CommandId::RESET:
            mContext->disable();
            mContext->resetBuffer();
            break;
        default:
            LOG(ERROR) << __func__ << " commandId " << toString(command) << " not supported";
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "commandIdNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

// Processing method running in EffectWorker thread.
IEffect::Status EffectBundleAidl::effectProcessImpl(float* in, float* out, int sampleToProcess) {
    return mContext->lvmProcess(in, out, sampleToProcess);
}

}  // namespace aidl::android::hardware::audio::effect
