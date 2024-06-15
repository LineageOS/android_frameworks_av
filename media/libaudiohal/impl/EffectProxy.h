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

#pragma once

#include <map>
#include <memory>

#include <aidl/android/hardware/audio/effect/BnEffect.h>
#include <aidl/android/hardware/audio/effect/BnFactory.h>
#include <fmq/AidlMessageQueue.h>
#include <system/audio_effect.h>

namespace android {
namespace effect {

/**
 * EffectProxy is the proxy for one or more effect AIDL implementations (sub effect) of same type.
 * The audio framework use EffectProxy as a composite implementation of all sub effect
 * implementations.
 *
 * At any given time, there is only one active effect which consuming and producing data for each
 * proxy. All setter commands (except the legacy EFFECT_CMD_OFFLOAD, it will be handled by the audio
 * framework directly) and parameters will be pass through to all sub effects, the getter commands
 * and parameters will only passthrough to the active sub-effect.
 *
 */
class EffectProxy final : public ::aidl::android::hardware::audio::effect::BnEffect {
  public:
    EffectProxy(
            const ::aidl::android::media::audio::common::AudioUuid& uuid,
            const std::vector<::aidl::android::hardware::audio::effect::Descriptor>& descriptors,
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory>& factory);

    /**
     * Handle offload parameter setting from framework.
     */
    ndk::ScopedAStatus setOffloadParam(const effect_offload_param_t* offload);

    /**
     * Destroy all sub-effects via AIDL IFactory.
     */
    ndk::ScopedAStatus destroy();

    // IEffect interfaces override
    ndk::ScopedAStatus open(
            const ::aidl::android::hardware::audio::effect::Parameter::Common& common,
            const std::optional<::aidl::android::hardware::audio::effect::Parameter::Specific>&
                    specific,
            ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn* ret) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus reopen(
            ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn* ret) override;
    ndk::ScopedAStatus getDescriptor(
            ::aidl::android::hardware::audio::effect::Descriptor* desc) override;
    ndk::ScopedAStatus command(::aidl::android::hardware::audio::effect::CommandId id) override;
    ndk::ScopedAStatus getState(::aidl::android::hardware::audio::effect::State* state) override;
    ndk::ScopedAStatus setParameter(
            const ::aidl::android::hardware::audio::effect::Parameter& param) override;
    ndk::ScopedAStatus getParameter(
            const ::aidl::android::hardware::audio::effect::Parameter::Id& id,
            ::aidl::android::hardware::audio::effect::Parameter* param) override;

    static ndk::ScopedAStatus buildDescriptor(
            const ::aidl::android::media::audio::common::AudioUuid& uuid,
            const std::vector<::aidl::android::hardware::audio::effect::Descriptor>& subEffectDescs,
            ::aidl::android::hardware::audio::effect::Descriptor* desc);

    /**
     * Get the const reference of the active sub-effect return parameters.
     * Always use this interface to get the effect open return parameters (FMQs) after a success
     * setOffloadParam() call.
     */
    using StatusMQ = ::android::AidlMessageQueue<
            ::aidl::android::hardware::audio::effect::IEffect::Status,
            ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>;
    using DataMQ = ::android::AidlMessageQueue<
            float, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>;
    const std::shared_ptr<StatusMQ>& getStatusMQ() const {
        return mSubEffects[mActiveSubIdx].effectMq.statusQ;
    }
    const std::shared_ptr<DataMQ>& getInputMQ() const {
        return mSubEffects[mActiveSubIdx].effectMq.inputQ;
    }
    const std::shared_ptr<DataMQ>& getOutputMQ() const {
        return mSubEffects[mActiveSubIdx].effectMq.outputQ;
    }

    bool isBypassing() const;
    bool isTunnel() const;

    // call dump for all sub-effects
    binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;

    std::string toString(size_t indent = 0) const;

  private:
    // Proxy descriptor common part, copy from one sub-effect, and update the implementation UUID to
    // proxy UUID, proxy descriptor capability part comes from the active sub-effect capability
    const ::aidl::android::hardware::audio::effect::Descriptor::Common mDescriptorCommon;

    struct EffectMQ {
        std::shared_ptr<StatusMQ> statusQ;
        std::shared_ptr<DataMQ> inputQ, outputQ;
    };
    struct SubEffect {
        const ::aidl::android::hardware::audio::effect::Descriptor descriptor;
        std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> handle;
        EffectMQ effectMq;
    };
    std::vector<SubEffect> mSubEffects;

    const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory> mFactory;

    // index of the active sub-effects, by default use the first one (index 0)
    // It's safe to assume there will always at least two SubEffects in mSubEffects
    size_t mActiveSubIdx = 0;

    ndk::ScopedAStatus runWithActiveSubEffectThenOthers(
            std::function<ndk::ScopedAStatus(
                    const std::shared_ptr<
                            ::aidl::android::hardware::audio::effect::IEffect>&)> const& func);

    ndk::ScopedAStatus runWithActiveSubEffect(
            std::function<ndk::ScopedAStatus(const std::shared_ptr<IEffect>&)> const& func);

    ndk::ScopedAStatus runWithAllSubEffects(
            std::function<ndk::ScopedAStatus(std::shared_ptr<IEffect>&)> const& func);

    // build Descriptor.Common with all sub-effect descriptors
    static ::aidl::android::hardware::audio::effect::Descriptor::Common buildDescriptorCommon(
            const ::aidl::android::media::audio::common::AudioUuid& uuid,
            const std::vector<::aidl::android::hardware::audio::effect::Descriptor>&
                    subEffectDescs);

    // close and release all sub-effects
    ~EffectProxy();
};

} // namespace effect
} // namespace android
