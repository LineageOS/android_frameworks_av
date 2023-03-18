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

#pragma once

#include <aidl/android/hardware/audio/effect/BnEffect.h>
#include <audio_effects/effect_downmix.h>

#include "DownmixContext.h"
#include "effect-impl/EffectImpl.h"

namespace aidl::android::hardware::audio::effect {

class DownmixImpl final : public EffectImpl {
  public:
    static const std::string kEffectName;
    static const Descriptor kDescriptor;
    DownmixImpl() { LOG(DEBUG) << __func__; }
    ~DownmixImpl() {
        cleanUp();
        LOG(DEBUG) << __func__;
    }

    ndk::ScopedAStatus commandImpl(CommandId command) override;
    ndk::ScopedAStatus getDescriptor(Descriptor* _aidl_return) override;
    ndk::ScopedAStatus setParameterCommon(const Parameter& param) override;
    ndk::ScopedAStatus setParameterSpecific(const Parameter::Specific& specific) override;
    ndk::ScopedAStatus getParameterSpecific(const Parameter::Id& id,
                                            Parameter::Specific* specific) override;
    IEffect::Status effectProcessImpl(float* in, float* out, int process) override;
    std::shared_ptr<EffectContext> createContext(const Parameter::Common& common) override;
    RetCode releaseContext() override;

    std::shared_ptr<EffectContext> getContext() override { return mContext; }
    std::string getEffectName() override { return kEffectName; }

  private:
    std::shared_ptr<DownmixContext> mContext;
    ndk::ScopedAStatus getParameterDownmix(const Downmix::Tag& tag, Parameter::Specific* specific);
};
}  // namespace aidl::android::hardware::audio::effect
