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
#include <aidl/android/hardware/audio/effect/BnFactory.h>

using namespace aidl::android::media::audio::common;
using namespace aidl::android::hardware::audio::effect;

namespace aidl::android::hardware::audio::effect {

class FactoryMock : public BnFactory {
    ndk::ScopedAStatus queryEffects(const std::optional<AudioUuid>&,
                                    const std::optional<AudioUuid>&,
                                    const std::optional<AudioUuid>&,
                                    std::vector<Descriptor>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus queryProcessing(const std::optional<Processing::Type>&,
                                       std::vector<Processing>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus destroyEffect(const std::shared_ptr<IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus createEffect(const AudioUuid&, std::shared_ptr<IEffect>*) override;
};

}  // namespace aidl::android::hardware::audio::effect
