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
using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::hardware::audio::effect::kBassBoostBundleImplUUID;
using aidl::android::hardware::audio::effect::kEqualizerBundleImplUUID;
using aidl::android::hardware::audio::effect::State;
using aidl::android::media::audio::common::AudioUuid;

bool isUuidSupported(const AudioUuid* uuid) {
    return (*uuid == kEqualizerBundleImplUUID || *uuid == kBassBoostBundleImplUUID);
}

extern "C" binder_exception_t createEffect(const AudioUuid* uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (uuid == nullptr || !isUuidSupported(uuid)) {
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
    if (!in_impl_uuid || !isUuidSupported(in_impl_uuid)) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (*in_impl_uuid == kEqualizerBundleImplUUID) {
        *_aidl_return = aidl::android::hardware::audio::effect::lvm::kEqualizerDesc;
    } else if (*in_impl_uuid == kBassBoostBundleImplUUID) {
        *_aidl_return = aidl::android::hardware::audio::effect::lvm:: kBassBoostDesc;
    }
    return EX_NONE;
}

namespace aidl::android::hardware::audio::effect {

EffectBundleAidl::EffectBundleAidl(const AudioUuid& uuid) {
    LOG(DEBUG) << __func__ << uuid.toString();
    if (uuid == kEqualizerBundleImplUUID) {
        mType = lvm::BundleEffectType::EQUALIZER;
        mDescriptor = &lvm::kEqualizerDesc;
        mEffectName = &lvm::kEqualizerEffectName;
    } else if (uuid == kBassBoostBundleImplUUID) {
        mType = lvm::BundleEffectType::BASS_BOOST;
        mDescriptor = &lvm::kBassBoostDesc;
        mEffectName = &lvm::kBassBoostEffectName;
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
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto tag = specific.getTag();
    switch (tag) {
        case Parameter::Specific::equalizer:
            return setParameterEqualizer(specific);
        case Parameter::Specific::bassBoost:
            return setParameterBassBoost(specific);
        default:
            LOG(ERROR) << __func__ << " unsupported tag " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "specificParamNotSupported");
    }
}

ndk::ScopedAStatus EffectBundleAidl::setParameterEqualizer(const Parameter::Specific& specific) {
    auto& eq = specific.get<Parameter::Specific::equalizer>();
    auto eqTag = eq.getTag();
    switch (eqTag) {
        case Equalizer::preset:
            RETURN_IF(mContext->setEqualizerPreset(eq.get<Equalizer::preset>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setBandLevelsFailed");
            return ndk::ScopedAStatus::ok();
        case Equalizer::bandLevels:
            RETURN_IF(mContext->setEqualizerBandLevels(eq.get<Equalizer::bandLevels>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setBandLevelsFailed");
            return ndk::ScopedAStatus::ok();
        default:
            LOG(ERROR) << __func__ << " unsupported parameter " << specific.toString();
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "eqTagNotSupported");
    }
}

ndk::ScopedAStatus EffectBundleAidl::setParameterBassBoost(const Parameter::Specific& specific) {
    auto& bb = specific.get<Parameter::Specific::bassBoost>();
    auto bbTag = bb.getTag();
    switch (bbTag) {
        case BassBoost::strengthPm: {
            RETURN_IF(mContext->setBassBoostStrength(bb.get<BassBoost::strengthPm>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setStrengthFailed");
            return ndk::ScopedAStatus::ok();
        }
        default:
            LOG(ERROR) << __func__ << " unsupported parameter " << specific.toString();
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "bbTagNotSupported");
    }
}

ndk::ScopedAStatus EffectBundleAidl::getParameterSpecific(const Parameter::Id& id,
                                                          Parameter::Specific* specific) {
    RETURN_IF(!specific, EX_NULL_POINTER, "nullPtr");
    auto tag = id.getTag();

    switch (tag) {
        case Parameter::Id::equalizerTag:
            return getParameterEqualizer(id.get<Parameter::Id::equalizerTag>(), specific);
        case Parameter::Id::bassBoostTag:
            return getParameterBassBoost(id.get<Parameter::Id::bassBoostTag>(), specific);
        default:
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "wrongIdTag");
    }
}

ndk::ScopedAStatus EffectBundleAidl::getParameterEqualizer(const Equalizer::Id& id,
                                                           Parameter::Specific* specific) {
    RETURN_IF(id.getTag() != Equalizer::Id::commonTag, EX_ILLEGAL_ARGUMENT,
              "EqualizerTagNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    Equalizer eqParam;

    auto tag = id.get<Equalizer::Id::commonTag>();
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

ndk::ScopedAStatus EffectBundleAidl::getParameterBassBoost(const BassBoost::Id& id,
                                                           Parameter::Specific* specific) {
    RETURN_IF(id.getTag() != BassBoost::Id::commonTag, EX_ILLEGAL_ARGUMENT,
              "BassBoostTagNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    BassBoost bbParam;

    auto tag = id.get<BassBoost::Id::commonTag>();
    switch (tag) {
        case BassBoost::strengthPm: {
            bbParam.set<BassBoost::strengthPm>(mContext->getBassBoostStrength());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " not handled tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "BassBoostTagNotSupported");
        }
    }

    specific->set<Parameter::Specific::bassBoost>(bbParam);
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
    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!mContext, status, "nullContext");
    return mContext->lvmProcess(in, out, sampleToProcess);
}

}  // namespace aidl::android::hardware::audio::effect
