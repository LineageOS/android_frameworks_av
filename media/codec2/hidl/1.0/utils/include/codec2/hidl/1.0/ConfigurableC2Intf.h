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

#ifndef HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_CONFIGURABLEC2INTF_H
#define HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_CONFIGURABLEC2INTF_H

#include <C2Work.h>
#include <C2Component.h>
#include <C2Param.h>
#include <C2.h>

#include <hidl/HidlSupport.h>
#include <utils/StrongPointer.h>
#include <vector>
#include <memory>

namespace hardware {
namespace google {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using ::android::sp;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;

/**
 * Common Codec 2.0 interface wrapper.
 */
struct ConfigurableC2Intf {
    C2String getName() const { return mName; }
    /** C2ComponentInterface::query_vb sans stack params */
    virtual c2_status_t query(
            const std::vector<C2Param::Index> &indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params) const = 0;
    /** C2ComponentInterface::config_vb */
    virtual c2_status_t config(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) = 0;
    /** C2ComponentInterface::querySupportedParams_nb */
    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params) const = 0;
    /** C2ComponentInterface::querySupportedParams_nb */
    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields, c2_blocking_t mayBlock) const = 0;

    virtual ~ConfigurableC2Intf() = default;

    ConfigurableC2Intf(const C2String& name) : mName(name) {}

protected:
    C2String mName; /* cache component name */
};

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace google
}  // namespace hardware

#endif  // HARDWARE_GOOGLE_MEDIA_C2_V1_0_UTILS_CONFIGURABLEC2INTF_H
