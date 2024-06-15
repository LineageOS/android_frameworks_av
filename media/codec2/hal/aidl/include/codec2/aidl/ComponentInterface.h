/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef CODEC2_AIDL_UTILS_COMPONENT_INTERFACE_H
#define CODEC2_AIDL_UTILS_COMPONENT_INTERFACE_H

#include <codec2/aidl/Configurable.h>
#include <codec2/aidl/ParamTypes.h>

#include <aidl/android/hardware/media/c2/BnComponentInterface.h>

#include <codec2/common/MultiAccessUnitHelper.h>

#include <C2Component.h>
#include <C2Buffer.h>
#include <C2.h>

#include <memory>
#include <set>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

using ::android::MultiAccessUnitInterface;

struct ComponentInterface : public BnComponentInterface {
    ComponentInterface(
            const std::shared_ptr<C2ComponentInterface>& interface,
            const std::shared_ptr<ParameterCache>& cache);
    ComponentInterface(
        const std::shared_ptr<C2ComponentInterface>& interface,
        const std::shared_ptr<MultiAccessUnitInterface>& largeBufferIntf,
        const std::shared_ptr<ParameterCache>& cache);
    c2_status_t status() const;
    ::ndk::ScopedAStatus getConfigurable(
            std::shared_ptr<IConfigurable> *intf) override;

protected:
    std::shared_ptr<C2ComponentInterface> mInterface;
    std::shared_ptr<CachedConfigurable> mConfigurable;
    c2_status_t mInit;
};

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // namespace aidl

#endif  // CODEC2_AIDL_UTILS_COMPONENT_INTERFACE_H
