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

#define LOG_TAG "AHAL_VisualizerLibEffects"

#include <android-base/logging.h>
#include "Visualizer.h"

using aidl::android::hardware::audio::effect::Descriptor;
using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::hardware::audio::effect::VisualizerImpl;
using aidl::android::hardware::audio::effect::kVisualizerImplUUID;
using aidl::android::hardware::audio::effect::State;
using aidl::android::media::audio::common::AudioUuid;

extern "C" binder_exception_t createEffect(const AudioUuid* in_impl_uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (!in_impl_uuid || *in_impl_uuid != kVisualizerImplUUID) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (instanceSpp) {
        *instanceSpp = ndk::SharedRefBase::make<VisualizerImpl>();
        LOG(DEBUG) << __func__ << " instance " << instanceSpp->get() << " created";
        return EX_NONE;
    } else {
        LOG(ERROR) << __func__ << " invalid input parameter!";
        return EX_ILLEGAL_ARGUMENT;
    }
}

extern "C" binder_exception_t queryEffect(const AudioUuid* in_impl_uuid, Descriptor* _aidl_return) {
    if (!in_impl_uuid || *in_impl_uuid != kVisualizerImplUUID) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    *_aidl_return = VisualizerImpl::kDescriptor;
    return EX_NONE;
}

namespace aidl::android::hardware::audio::effect {

const std::string VisualizerImpl::kEffectName = "Visualizer";
const Visualizer::Capability VisualizerImpl::kCapability = {
        .maxLatencyMs = VisualizerContext::kMaxLatencyMs,
        .captureSampleRange = {.min = 0, .max = VisualizerContext::kMaxCaptureBufSize}};
const Descriptor VisualizerImpl::kDescriptor = {
        .common = {.id = {.type = kVisualizerTypeUUID,
                          .uuid = kVisualizerImplUUID,
                          .proxy = std::nullopt},
                   .flags = {.type = Flags::Type::INSERT,
                             .insert = Flags::Insert::LAST,
                             .volume = Flags::Volume::CTRL},
                   .name = VisualizerImpl::kEffectName,
                   .implementor = "The Android Open Source Project"},
        .capability = Capability::make<Capability::visualizer>(VisualizerImpl::kCapability)};

ndk::ScopedAStatus VisualizerImpl::getDescriptor(Descriptor* _aidl_return) {
    RETURN_IF(!_aidl_return, EX_ILLEGAL_ARGUMENT, "Parameter:nullptr");
    LOG(DEBUG) << __func__ << kDescriptor.toString();
    *_aidl_return = kDescriptor;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VisualizerImpl::commandImpl(CommandId command) {
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

ndk::ScopedAStatus VisualizerImpl::setOnlyParameter(
        const Visualizer::SetOnlyParameters& param) {
    auto tag = param.getTag();
    switch (tag) {
        case Visualizer::SetOnlyParameters::latencyMs: {
            mContext->setDownstreamLatency(param.get<Visualizer::SetOnlyParameters::latencyMs>());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "setOnlyParameterTagNotSupported");
        }
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VisualizerImpl::setParameterSpecific(const Parameter::Specific& specific) {
    RETURN_IF(Parameter::Specific::visualizer != specific.getTag(), EX_ILLEGAL_ARGUMENT,
              "EffectNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto& param = specific.get<Parameter::Specific::visualizer>();
    const auto tag = param.getTag();
    switch (tag) {
        case Visualizer::captureSamples: {
            RETURN_IF(mContext->setCaptureSamples(param.get<Visualizer::captureSamples>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setCaptureSizeFailed");
            return ndk::ScopedAStatus::ok();
        }
        case Visualizer::scalingMode: {
            RETURN_IF(mContext->setScalingMode(param.get<Visualizer::scalingMode>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setScalingModeFailed");
            return ndk::ScopedAStatus::ok();
        }
        case Visualizer::measurementMode: {
            RETURN_IF(mContext->setMeasurementMode(param.get<Visualizer::measurementMode>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setMeasurementModeFailed");
            return ndk::ScopedAStatus::ok();
        }
        case Visualizer::setOnlyParameters: {
            return setOnlyParameter(param.get<Visualizer::setOnlyParameters>());
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "VisualizerTagNotSupported");
        }
    }
}

ndk::ScopedAStatus VisualizerImpl::getOnlyParameter(const Visualizer::GetOnlyParameters::Tag tag,
                                                    Parameter::Specific* specific) {
    Visualizer visualizer;
    Visualizer::GetOnlyParameters param;
    switch (tag) {
        case Visualizer::GetOnlyParameters::measurement: {
            param.set<Visualizer::GetOnlyParameters::measurement>(mContext->getMeasure());
            break;
        }
        case Visualizer::GetOnlyParameters::captureSampleBuffer: {
            param.set<Visualizer::GetOnlyParameters::captureSampleBuffer>(mContext->capture());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "setOnlyParameterTagNotSupported");
        }
    }
    visualizer.set<Visualizer::getOnlyParameters>(param);
    specific->set<Parameter::Specific::visualizer>(visualizer);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VisualizerImpl::getParameterSpecific(const Parameter::Id& id,
                                                        Parameter::Specific* specific) {
    RETURN_IF(!specific, EX_NULL_POINTER, "nullPtr");
    auto tag = id.getTag();
    RETURN_IF(Parameter::Id::visualizerTag != tag, EX_ILLEGAL_ARGUMENT, "wrongIdTag");
    auto specificId = id.get<Parameter::Id::visualizerTag>();
    auto specificTag = specificId.getTag();
    switch (specificTag) {
        case Visualizer::Id::commonTag: {
            return getParameterVisualizer(specificId.get<Visualizer::Id::commonTag>(), specific);
        }
        case Visualizer::Id::getOnlyParamTag: {
            return getOnlyParameter(specificId.get<Visualizer::Id::getOnlyParamTag>(), specific);
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(specificTag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "VisualizerTagNotSupported");
        }
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VisualizerImpl::getParameterVisualizer(const Visualizer::Tag& tag,
                                                          Parameter::Specific* specific) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    Visualizer param;
    switch (tag) {
        case Visualizer::captureSamples: {
            param.set<Visualizer::captureSamples>(mContext->getCaptureSamples());
            break;
        }
        case Visualizer::scalingMode: {
            param.set<Visualizer::scalingMode>(mContext->getScalingMode());
            break;
        }
        case Visualizer::measurementMode: {
            param.set<Visualizer::measurementMode>(mContext->getMeasurementMode());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "VisualizerTagNotSupported");
        }
    }

    specific->set<Parameter::Specific::visualizer>(param);
    return ndk::ScopedAStatus::ok();
}

std::shared_ptr<EffectContext> VisualizerImpl::createContext(const Parameter::Common& common) {
    if (mContext) {
        LOG(DEBUG) << __func__ << " context already exist";
        return mContext;
    }

    mContext = std::make_shared<VisualizerContext>(1 /* statusFmqDepth */, common);
    mContext->initParams(common);
    return mContext;
}

RetCode VisualizerImpl::releaseContext() {
    if (mContext) {
        mContext->disable();
        mContext->resetBuffer();
    }
    return RetCode::SUCCESS;
}

// Processing method running in EffectWorker thread.
IEffect::Status VisualizerImpl::effectProcessImpl(float* in, float* out, int samples) {
    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!mContext, status, "nullContext");
    return mContext->process(in, out, samples);
}

}  // namespace aidl::android::hardware::audio::effect
