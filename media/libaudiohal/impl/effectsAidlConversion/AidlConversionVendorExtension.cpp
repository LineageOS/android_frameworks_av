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
    size_t len = param.getValueSize();
    DefaultExtension ext;
    ext.bytes.resize(len);
    if (OK != param.readFromValue(ext.bytes.data(), len)) {
        ALOGE("%s read value from param %s failed", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    VendorExtension effectParam;
    effectParam.extension.setParcelable(ext);
    Parameter aidlParam = UNION_MAKE(Parameter, specific,
                                     UNION_MAKE(Parameter::Specific, vendorEffect, effectParam));
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionVendorExtension::getParameter(EffectParamWriter& param) {
    int32_t tag;
    if (OK != param.readFromParameter(&tag)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }

    Parameter aidlParam;
    Parameter::Id id = UNION_MAKE(Parameter::Id, vendorEffectTag, tag /* parameter tag */);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    VendorExtension effectParam = VALUE_OR_RETURN_STATUS(
            (::aidl::android::getParameterSpecific<Parameter, VendorExtension,
                                                   Parameter::Specific::vendorEffect>(aidlParam)));
    std::optional<DefaultExtension> ext;
    if (STATUS_OK != effectParam.extension.getParcelable(&ext) || !ext.has_value()) {
        ALOGE("%s get extension parcelable failed", __func__);
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    const auto& extBytes = ext.value().bytes;
    if (param.getValueSize() < extBytes.size()) {
        ALOGE("%s extension return data %zu exceed vsize %zu", __func__, extBytes.size(),
              param.getValueSize());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    return param.writeToValue(extBytes.data(), extBytes.size());
}

} // namespace effect
} // namespace android
