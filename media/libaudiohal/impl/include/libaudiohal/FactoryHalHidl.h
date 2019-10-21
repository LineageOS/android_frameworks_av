/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_FACTORY_HAL_HIDL_H
#define ANDROID_HARDWARE_FACTORY_HAL_HIDL_H

/** @file Library entry points to create the HAL factories. */

#include <media/audiohal/DevicesFactoryHalInterface.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <utils/StrongPointer.h>

#include <array>
#include <utility>

namespace android {

/** Supported HAL versions, in order of preference.
 * Implementation should use specialize the `create*FactoryHal` for their version.
 * Client should use `createPreferedImpl<*FactoryHal>()` to instantiate
 * the preferred available impl.
 */
enum class AudioHALVersion {
    V6_0,
    V5_0,
    V4_0,
    V2_0,
    end, // used for iterating over supported versions
};

/** Template function to fully specialized for each version and each Interface. */
template <AudioHALVersion, class Interface>
sp<Interface> createFactoryHal();

/** @Return the preferred available implementation or nullptr if none are available. */
template <class Interface, AudioHALVersion version = AudioHALVersion{}>
static sp<Interface> createPreferedImpl() {
    if constexpr (version == AudioHALVersion::end) {
        return nullptr; // tried all version, all returned nullptr
    } else {
        if (auto created = createFactoryHal<version, Interface>(); created != nullptr) {
           return created;
        }

        using Raw = std::underlying_type_t<AudioHALVersion>; // cast as enum class do not support ++
        return createPreferedImpl<Interface, AudioHALVersion(Raw(version) + 1)>();
    }
}


} // namespace android

#endif // ANDROID_HARDWARE_FACTORY_HAL_HIDL_H
