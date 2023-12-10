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

#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>
#define LOG_TAG "AidlConversionVendorExtension"
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/effect/DefaultExtension.h>
#include <aidl/android/hardware/audio/effect/VendorExtension.h>
#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>

#include <utils/Log.h>

#include "AidlConversionVendorExtension.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::DefaultExtension;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

/**
 * For all effect types we currently don't support, add a default extension implementation to use
 * std::vector<uint8_t> to pass through all data in the format of effect_param_t (the data we got
 * from libaudioclient for now).
 * This logic will be removed after we adopt to same AIDL parameter union AIDL in libaudioclient,
 * after that framework doesn't need to do any AIDL conversion, and the vendor extension can be
 * pass down in Parameter as is.
 */
status_t AidlConversionVendorExtension::setParameter(EffectParamReader& param) {
    Parameter aidlParam = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_EffectParameterReader_Parameter(param));
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionVendorExtension::getParameter(EffectParamWriter& param) {
    VendorExtension extId = VALUE_OR_RETURN_STATUS(
            aidl::android::legacy2aidl_EffectParameterReader_VendorExtension(param));
    Parameter::Id id = UNION_MAKE(Parameter::Id, vendorEffectTag, extId);
    Parameter aidlParam;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    // copy the AIDL extension data back to effect_param_t
    return VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Parameter_EffectParameterWriter(aidlParam, param));
}

} // namespace effect
} // namespace android
