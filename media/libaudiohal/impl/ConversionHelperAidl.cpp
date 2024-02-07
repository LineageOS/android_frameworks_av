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

#define LOG_TAG "ConversionHelperAidl"

#include <memory>

#include <media/AidlConversionUtil.h>
#include <utils/Log.h>

#include "ConversionHelperAidl.h"

using aidl::android::aidl_utils::statusTFromBinderStatus;
using aidl::android::hardware::audio::core::VendorParameter;
using aidl::android::media::audio::IHalAdapterVendorExtension;

namespace android {

status_t parseAndGetVendorParameters(
        std::shared_ptr<IHalAdapterVendorExtension> vendorExt,
        const VendorParametersRecipient& recipient,
        const AudioParameter& parameterKeys,
        String8* values) {
    using ParameterScope = IHalAdapterVendorExtension::ParameterScope;
    if (parameterKeys.size() == 0) return OK;
    const String8 rawKeys = parameterKeys.keysToString();

    std::vector<std::string> parameterIds;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(vendorExt->parseVendorParameterIds(
                            ParameterScope(recipient.index()),
                            std::string(rawKeys.c_str()), &parameterIds)));
    if (parameterIds.empty()) return OK;

    std::vector<VendorParameter> parameters;
    if (recipient.index() == static_cast<int>(ParameterScope::MODULE)) {
        auto module = std::get<static_cast<int>(ParameterScope::MODULE)>(recipient);
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(module->getVendorParameters(
                                parameterIds, &parameters)));
    } else if (recipient.index() == static_cast<int>(ParameterScope::STREAM)) {
        auto stream = std::get<static_cast<int>(ParameterScope::STREAM)>(recipient);
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(stream->getVendorParameters(
                                parameterIds, &parameters)));
    } else {
        LOG_ALWAYS_FATAL("%s: unexpected recipient variant index: %zu",
                __func__, recipient.index());
    }
    if (!parameters.empty()) {
        std::string vendorParameters;
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(vendorExt->processVendorParameters(
                                ParameterScope(recipient.index()),
                                parameters, &vendorParameters)));
        // Re-parse the vendor-provided string to ensure that it is correct.
        AudioParameter reparse(String8(vendorParameters.c_str()));
        if (reparse.size() != 0) {
            if (values->length() > 0) {
                values->append(";");
            }
            values->append(reparse.toString().c_str());
        }
    }
    return OK;
}

status_t parseAndSetVendorParameters(
        std::shared_ptr<IHalAdapterVendorExtension> vendorExt,
        const VendorParametersRecipient& recipient,
        const AudioParameter& parameters) {
    using ParameterScope = IHalAdapterVendorExtension::ParameterScope;
    if (parameters.size() == 0) return OK;
    const String8 rawKeysAndValues = parameters.toString();

    std::vector<VendorParameter> syncParameters, asyncParameters;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(vendorExt->parseVendorParameters(
                            ParameterScope(recipient.index()),
                            std::string(rawKeysAndValues.c_str()),
                            &syncParameters, &asyncParameters)));
    if (recipient.index() == static_cast<int>(ParameterScope::MODULE)) {
        auto module = std::get<static_cast<int>(ParameterScope::MODULE)>(recipient);
        if (!syncParameters.empty()) {
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(module->setVendorParameters(
                                    syncParameters, false /*async*/)));
        }
        if (!asyncParameters.empty()) {
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(module->setVendorParameters(
                                    asyncParameters, true /*async*/)));
        }
    } else if (recipient.index() == static_cast<int>(ParameterScope::STREAM)) {
        auto stream = std::get<static_cast<int>(ParameterScope::STREAM)>(recipient);
        if (!syncParameters.empty()) {
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(stream->setVendorParameters(
                                    syncParameters, false /*async*/)));
        }
        if (!asyncParameters.empty()) {
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(stream->setVendorParameters(
                                    asyncParameters, true /*async*/)));
        }
    } else {
        LOG_ALWAYS_FATAL("%s: unexpected recipient variant index: %zu",
                __func__, recipient.index());
    }
    return OK;
}

} // namespace android
