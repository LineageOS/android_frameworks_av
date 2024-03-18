/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <aidl/android/hardware/audio/effect/BnEffect.h>

using namespace aidl::android::hardware::audio::effect;

namespace aidl::android::hardware::audio::effect {

class EffectMock : public BnEffect {
  public:
    ndk::ScopedAStatus open(const Parameter::Common&, const std::optional<Parameter::Specific>&,
                            IEffect::OpenEffectReturn*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus close() override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus command(CommandId) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getState(State*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getDescriptor(Descriptor*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus reopen(IEffect::OpenEffectReturn*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setParameter(const Parameter&) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getParameter(const Parameter::Id&, Parameter*) override {
        return ndk::ScopedAStatus::ok();
    }
};

}  // namespace aidl::android::hardware::audio::effect
