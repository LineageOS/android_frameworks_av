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
    EffectProxy(const ::aidl::android::hardware::audio::effect::Descriptor::Identity& id,
                const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory>& factory);

    /**
     * Add a sub effect into the proxy, the descriptor of candidate sub-effect need to have same
     * proxy UUID as mUuid.
     */
    ndk::ScopedAStatus addSubEffect(
            const ::aidl::android::hardware::audio::effect::Descriptor& sub);

    /**
     * Create all sub-effects via AIDL IFactory, always call create() after all sub-effects added
     * successfully with addSubEffect.
     */
    ndk::ScopedAStatus create();

    /**
     * Destroy all sub-effects via AIDL IFactory, always call create() after all sub-effects added
     * successfully with addSubEffect.
     */
    ndk::ScopedAStatus destroy();

    /**
     * Handle offload parameter setting from framework.
     */
    ndk::ScopedAStatus setOffloadParam(const effect_offload_param_t* offload);

    /**
     * Get the const reference of the active sub-effect return parameters.
     * Always use this interface to get the effect open return parameters (FMQs) after a success
     * setOffloadParam() call.
     */
    const IEffect::OpenEffectReturn* getEffectReturnParam();

    // IEffect interfaces override
    ndk::ScopedAStatus open(
            const ::aidl::android::hardware::audio::effect::Parameter::Common& common,
            const std::optional<::aidl::android::hardware::audio::effect::Parameter::Specific>&
                    specific,
            ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn* ret) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus getDescriptor(
            ::aidl::android::hardware::audio::effect::Descriptor* desc) override;
    ndk::ScopedAStatus command(::aidl::android::hardware::audio::effect::CommandId id) override;
    ndk::ScopedAStatus getState(::aidl::android::hardware::audio::effect::State* state) override;
    ndk::ScopedAStatus setParameter(
            const ::aidl::android::hardware::audio::effect::Parameter& param) override;
    ndk::ScopedAStatus getParameter(
            const ::aidl::android::hardware::audio::effect::Parameter::Id& id,
            ::aidl::android::hardware::audio::effect::Parameter* param) override;

  private:
    // Proxy identity, copy from one sub-effect, and update the implementation UUID to proxy UUID
    const ::aidl::android::hardware::audio::effect::Descriptor::Identity mIdentity;
    const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory> mFactory;

    // A map of sub effects descriptor to the IEffect handle and return FMQ
    enum SubEffectTupleIndex { HANDLE, DESCRIPTOR, RETURN };
    using EffectProxySub =
            std::tuple<std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>,
                       ::aidl::android::hardware::audio::effect::Descriptor,
                       ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn>;
    std::map<const ::aidl::android::hardware::audio::effect::Descriptor::Identity, EffectProxySub>
            mSubEffects;

    // Descriptor of the only active effect in the mSubEffects map
    ::aidl::android::hardware::audio::effect::Descriptor::Identity mActiveSub;

    // keep the flag of sub-effects
    ::aidl::android::hardware::audio::effect::Flags mSubFlags;

    ndk::ScopedAStatus runWithActiveSubEffectThenOthers(
            std::function<ndk::ScopedAStatus(
                    const std::shared_ptr<
                            ::aidl::android::hardware::audio::effect::IEffect>&)> const& func);

    ndk::ScopedAStatus runWithActiveSubEffect(
            std::function<ndk::ScopedAStatus(const std::shared_ptr<IEffect>&)> const& func);

    ndk::ScopedAStatus runWithAllSubEffects(
            std::function<ndk::ScopedAStatus(std::shared_ptr<IEffect>&)> const& func);

    // close and release all sub-effects
    ~EffectProxy();
};

} // namespace effect
} // namespace android
