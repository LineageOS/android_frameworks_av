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

#include <media/audiohal/EffectsFactoryHalInterface.h>

namespace android::audioflinger {

/**
 * Effect Configuration abstraction and helper class.
 */
class EffectConfiguration {
public:
    static bool isHidl() {
        static const bool isHidl = getAudioHalVersionInfo().isHidl();
        return isHidl;
    }

    static const sp<EffectsFactoryHalInterface>& getEffectsFactoryHal() {
        static const auto effectsFactoryHal = EffectsFactoryHalInterface::create();
        return effectsFactoryHal;
    }

    static const detail::AudioHalVersionInfo& getAudioHalVersionInfo() {
        static const auto audioHalVersionInfo = getEffectsFactoryHal() ?
                getEffectsFactoryHal()->getHalVersion() : detail::AudioHalVersionInfo{
                        detail::AudioHalVersionInfo::Type::HIDL, 0 /* major */, 0 /* minor */ };
        return audioHalVersionInfo;
    }
};

} // namespace android::audioflinger
