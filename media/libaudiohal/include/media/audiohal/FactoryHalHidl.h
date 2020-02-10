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

#include <utils/StrongPointer.h>

namespace android {

namespace detail {

void* createPreferredImpl(const std::string& package, const std::string& interface);

}  // namespace detail

/** @Return the preferred available implementation or nullptr if none are available. */
template <class Interface>
static sp<Interface> createPreferredImpl(const std::string& package, const std::string& interface) {
    return sp<Interface>{static_cast<Interface*>(detail::createPreferredImpl(package, interface))};
}

} // namespace android

#endif // ANDROID_HARDWARE_FACTORY_HAL_HIDL_H
