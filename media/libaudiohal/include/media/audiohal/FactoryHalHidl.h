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

#include <string>
#include <utility>

#include <utils/StrongPointer.h>

namespace android {

// The pair of the interface's package name and the interface name,
// e.g. <"android.hardware.audio", "IDevicesFactory">.
// Splitting is used for easier construction of versioned names (FQNs).
using InterfaceName = std::pair<std::string, std::string>;

namespace detail {

void* createPreferredImpl(const InterfaceName& iface, const InterfaceName& siblingIface);

}  // namespace detail

/**
 * Create a client for the "preferred" (most recent) implementation of an interface.
 * by loading the appropriate version of the shared library containing the implementation.
 *
 * In the audio HAL, there are two families of interfaces: core and effects. Both are
 * packed into the same shared library for memory efficiency. Since the core and the effects
 * interface can have different minor versions on the device, in order to avoid loading multiple
 * shared libraries the loader function considers which interface among two has the most
 * recent version. Thus, a pair of interface names must be passed in.
 *
 * @param iface the interface that needs to be created.
 * @param siblingIface the interface which occupies the same shared library.
 * @return the preferred available implementation or nullptr if none are available.
 */
template <class Interface>
static sp<Interface> createPreferredImpl(
        const InterfaceName& iface, const InterfaceName& siblingIface) {
    return sp<Interface>{
        static_cast<Interface*>(detail::createPreferredImpl(iface, siblingIface))};
}

} // namespace android

#endif // ANDROID_HARDWARE_FACTORY_HAL_HIDL_H
