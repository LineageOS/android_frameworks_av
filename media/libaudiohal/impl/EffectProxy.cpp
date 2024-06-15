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

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <memory>
#define LOG_TAG "EffectProxy"
// #define LOG_NDEBUG 0

#include <fmq/AidlMessageQueue.h>
#include <system/audio_aidl_utils.h>
#include <utils/Log.h>

#include "EffectProxy.h"

using ::aidl::android::hardware::audio::effect::Capability;
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Flags;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::IFactory;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::State;
using ::aidl::android::media::audio::common::AudioUuid;

namespace android::effect {

EffectProxy::EffectProxy(const AudioUuid& uuid, const std::vector<Descriptor>& descriptors,
                         const std::shared_ptr<IFactory>& factory)
    : mDescriptorCommon(buildDescriptorCommon(uuid, descriptors)),
      mSubEffects(
              [](const std::vector<Descriptor>& descs, const std::shared_ptr<IFactory>& factory) {
                  std::vector<SubEffect> subEffects;
                  ALOG_ASSERT(factory, "invalid EffectFactory handle");
                  ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();
                  for (const auto& desc : descs) {
                      SubEffect sub({.descriptor = desc});
                      status = factory->createEffect(desc.common.id.uuid, &sub.handle);
                      if (!status.isOk() || !sub.handle) {
                          sub.handle = nullptr;
                          ALOGW("%s create sub-effect %s failed", __func__,
                                ::android::audio::utils::toString(desc.common.id.uuid).c_str());
                      }
                      subEffects.emplace_back(sub);
                  }
                  return subEffects;
              }(descriptors, factory)),
      mFactory(factory) {}

EffectProxy::~EffectProxy() {
    close();
    destroy();
    mSubEffects.clear();
}

ndk::ScopedAStatus EffectProxy::destroy() {
    ALOGV("%s: %s", __func__,
          ::android::audio::utils::toString(mDescriptorCommon.id.type).c_str());
    return runWithAllSubEffects([&](std::shared_ptr<IEffect>& effect) {
        ndk::ScopedAStatus status = mFactory->destroyEffect(effect);
        if (status.isOk()) {
            effect.reset();
        }
        return status;
    });
}

ndk::ScopedAStatus EffectProxy::setOffloadParam(const effect_offload_param_t* offload) {
    const auto& itor = std::find_if(mSubEffects.begin(), mSubEffects.end(), [&](const auto& sub) {
        const auto& desc = sub.descriptor;
        return offload->isOffload ==
               (desc.common.flags.hwAcceleratorMode == Flags::HardwareAccelerator::TUNNEL);
    });
    if (itor == mSubEffects.end()) {
        ALOGE("%s no %soffload sub-effect found", __func__, offload->isOffload ? "" : "non-");
        mActiveSubIdx = 0;
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "noActiveEffctFound");
    }

    mActiveSubIdx = std::distance(mSubEffects.begin(), itor);
    ALOGI("%s: active %soffload sub-effect %zu descriptor: %s", __func__,
          offload->isOffload ? "" : "non-", mActiveSubIdx,
          ::android::audio::utils::toString(mSubEffects[mActiveSubIdx].descriptor.common.id.uuid)
                  .c_str());
    return runWithAllSubEffects([&](std::shared_ptr<IEffect>& effect) {
        return effect->setParameter(Parameter::make<Parameter::offload>(offload->isOffload));
    });
}

// EffectProxy go over sub-effects and call IEffect interfaces
ndk::ScopedAStatus EffectProxy::open(const Parameter::Common& common,
                                     const std::optional<Parameter::Specific>& specific,
                                     IEffect::OpenEffectReturn* ret __unused) {
    ndk::ScopedAStatus status =
            ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_STATE, "nullEffectHandle");
    for (auto& sub : mSubEffects) {
        IEffect::OpenEffectReturn openReturn;
        if (!sub.handle || !(status = sub.handle->open(common, specific, &openReturn)).isOk()) {
            ALOGE("%s: failed to open %p UUID %s", __func__, sub.handle.get(),
                  ::android::audio::utils::toString(sub.descriptor.common.id.uuid).c_str());
            break;
        }
        sub.effectMq.statusQ = std::make_shared<StatusMQ>(openReturn.statusMQ);
        sub.effectMq.inputQ = std::make_shared<DataMQ>(openReturn.inputDataMQ);
        sub.effectMq.outputQ = std::make_shared<DataMQ>(openReturn.outputDataMQ);
    }

    // close all opened effects if failure
    if (!status.isOk()) {
        ALOGE("%s: closing all sub-effects with error %s", __func__,
              status.getDescription().c_str());
        close();
    }

    return status;
}

ndk::ScopedAStatus EffectProxy::reopen(OpenEffectReturn* ret __unused) {
    ndk::ScopedAStatus status =
            ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_STATE, "nullEffectHandle");
    for (auto& sub : mSubEffects) {
        IEffect::OpenEffectReturn openReturn;
        if (!sub.handle || !(status = sub.handle->reopen(&openReturn)).isOk()) {
            ALOGE("%s: failed to open %p UUID %s", __func__, sub.handle.get(),
                  ::android::audio::utils::toString(sub.descriptor.common.id.uuid).c_str());
            break;
        }
        sub.effectMq.statusQ = std::make_shared<StatusMQ>(openReturn.statusMQ);
        sub.effectMq.inputQ = std::make_shared<DataMQ>(openReturn.inputDataMQ);
        sub.effectMq.outputQ = std::make_shared<DataMQ>(openReturn.outputDataMQ);
    }

    // close all opened effects if failure
    if (!status.isOk()) {
        ALOGE("%s: closing all sub-effects with error %s", __func__,
              status.getDescription().c_str());
        close();
    }

    return status;
}

ndk::ScopedAStatus EffectProxy::close() {
    command(CommandId::STOP);
    return runWithAllSubEffects([&](std::shared_ptr<IEffect>& effect) {
        return effect->close();
    });
}

ndk::ScopedAStatus EffectProxy::getDescriptor(Descriptor* desc) {
    *desc = mSubEffects[mActiveSubIdx].descriptor;
    desc->common.id.uuid = desc->common.id.proxy.value();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectProxy::buildDescriptor(const AudioUuid& uuid,
                                                const std::vector<Descriptor>& subEffectDescs,
                                                Descriptor* desc) {
    if (!desc) {
        ALOGE("%s: null descriptor pointer", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER, "nullptr");
    }

    if (subEffectDescs.size() < 2) {
        ALOGE("%s: proxy need at least 2 sub-effects, got %zu", __func__, subEffectDescs.size());
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                "needMoreSubEffects");
    }

    desc->common = buildDescriptorCommon(uuid, subEffectDescs);
    return ndk::ScopedAStatus::ok();
}

Descriptor::Common EffectProxy::buildDescriptorCommon(
        const AudioUuid& uuid, const std::vector<Descriptor>& subEffectDescs) {
    // initial flag values before we know which sub-effect to active (with setOffloadParam)
    // align to HIDL EffectProxy flags
    Descriptor::Common common = {.flags = {.type = Flags::Type::INSERT,
                                           .insert = Flags::Insert::LAST,
                                           .volume = Flags::Volume::CTRL}};

    for (const auto& desc : subEffectDescs) {
        if (desc.common.flags.hwAcceleratorMode == Flags::HardwareAccelerator::TUNNEL) {
            common.flags.hwAcceleratorMode = Flags::HardwareAccelerator::TUNNEL;
        }

        // set indication if any sub-effect indication was set
        common.flags.offloadIndication |= desc.common.flags.offloadIndication;
        common.flags.deviceIndication |= desc.common.flags.deviceIndication;
        common.flags.audioModeIndication |= desc.common.flags.audioModeIndication;
        common.flags.audioSourceIndication |= desc.common.flags.audioSourceIndication;
        // Set to NONE if any sub-effect not supporting any Volume command
        if (desc.common.flags.volume == Flags::Volume::NONE) {
            common.flags.volume = Flags::Volume::NONE;
        }
    }

    // copy type UUID from any of sub-effects, all sub-effects should have same type
    common.id.type = subEffectDescs[0].common.id.type;
    // replace implementation UUID with proxy UUID.
    common.id.uuid = uuid;
    common.id.proxy = std::nullopt;
    common.name = "Proxy";
    common.implementor = "AOSP";
    return common;
}

// Handle with active sub-effect first, only send to other sub-effects when success
ndk::ScopedAStatus EffectProxy::command(CommandId id) {
    return runWithActiveSubEffectThenOthers(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->command(id);
            });
}

// Return the active sub-effect state
ndk::ScopedAStatus EffectProxy::getState(State* state) {
    return runWithActiveSubEffect(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->getState(state);
            });
}

// Handle with active sub-effect first, only send to other sub-effects when success
ndk::ScopedAStatus EffectProxy::setParameter(const Parameter& param) {
    return runWithActiveSubEffectThenOthers(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->setParameter(param);
            });
}

// Return the active sub-effect parameter
ndk::ScopedAStatus EffectProxy::getParameter(const Parameter::Id& id, Parameter* param) {
    return runWithActiveSubEffect(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->getParameter(id, param);
            });
}

ndk::ScopedAStatus EffectProxy::runWithActiveSubEffectThenOthers(
        std::function<ndk::ScopedAStatus(const std::shared_ptr<IEffect>&)> const& func) {
    ndk::ScopedAStatus status = runWithActiveSubEffect(func);
    if (!status.isOk()) {
        ALOGE("%s active sub-effect return error %s", __func__, status.getDescription().c_str());
    }

    // proceed with others
    for (size_t i = 0; i < mSubEffects.size(); i++) {
        if (i == mActiveSubIdx) {
            continue;
        }
        if (!mSubEffects[i].handle) {
            ALOGE("%s null sub-effect interface for %s", __func__,
                  mSubEffects[i].descriptor.common.id.uuid.toString().c_str());
            continue;
        }
        func(mSubEffects[i].handle);
    }
    return status;
}

ndk::ScopedAStatus EffectProxy::runWithActiveSubEffect(
        std::function<ndk::ScopedAStatus(const std::shared_ptr<IEffect>&)> const& func) {
    if (!mSubEffects[mActiveSubIdx].handle) {
        ALOGE("%s null active sub-effect interface, active %s", __func__,
              mSubEffects[mActiveSubIdx].descriptor.toString().c_str());
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "activeSubEffectNull");
    }
    return func(mSubEffects[mActiveSubIdx].handle);
}

ndk::ScopedAStatus EffectProxy::runWithAllSubEffects(
        std::function<ndk::ScopedAStatus(std::shared_ptr<IEffect>&)> const& func) {
    ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();
    // proceed with others if active sub-effect success
    for (auto& sub : mSubEffects) {
        if (!sub.handle) {
            ALOGW("%s null sub-effect interface %s", __func__, sub.descriptor.toString().c_str());
            continue;
        }
        ndk::ScopedAStatus temp = func(sub.handle);
        if (!temp.isOk()) {
            status = ndk::ScopedAStatus::fromStatus(temp.getStatus());
        }
    }
    return status;
}

bool EffectProxy::isBypassing() const {
    return mSubEffects[mActiveSubIdx].descriptor.common.flags.bypass;
}

bool EffectProxy::isTunnel() const {
    return mSubEffects[mActiveSubIdx].descriptor.common.flags.hwAcceleratorMode ==
           Flags::HardwareAccelerator::TUNNEL;
}

binder_status_t EffectProxy::dump(int fd, const char** args, uint32_t numArgs) {
    const std::string dumpString = toString();
    write(fd, dumpString.c_str(), dumpString.size());

    return runWithAllSubEffects([&](std::shared_ptr<IEffect>& effect) {
               return ndk::ScopedAStatus::fromStatus(effect->dump(fd, args, numArgs));
           })
            .getStatus();
}

std::string EffectProxy::toString(size_t level) const {
    std::string prefixSpace(level, ' ');
    std::string ss = prefixSpace + "EffectProxy:\n";
    prefixSpace += " ";
    base::StringAppendF(&ss, "%sDescriptorCommon: %s\n", prefixSpace.c_str(),
                        mDescriptorCommon.toString().c_str());
    base::StringAppendF(&ss, "%sActiveSubIdx: %zu\n", prefixSpace.c_str(), mActiveSubIdx);
    base::StringAppendF(&ss, "%sAllSubEffects:\n", prefixSpace.c_str());
    for (size_t i = 0; i < mSubEffects.size(); i++) {
        base::StringAppendF(&ss, "%s[%zu] - Handle: %p, %s\n", prefixSpace.c_str(), i,
                            mSubEffects[i].handle.get(),
                            mSubEffects[i].descriptor.toString().c_str());
    }
    return ss;
}

} // namespace android::effect
