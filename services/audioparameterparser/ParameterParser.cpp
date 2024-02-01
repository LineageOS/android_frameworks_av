/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "ParameterParser.h"

#define LOG_TAG "Audio_ParameterParser"
#include <android-base/logging.h>

namespace vendor::audio::parserservice {

using ::aidl::android::hardware::audio::core::VendorParameter;
using ParameterScope = ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope;

::ndk::ScopedAStatus ParameterParser::parseVendorParameterIds(ParameterScope in_scope,
                                                              const std::string& in_rawKeys,
                                                              std::vector<std::string>*) {
    LOG(DEBUG) << __func__ << ": scope: " << toString(in_scope) << ", keys: " << in_rawKeys;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus ParameterParser::parseVendorParameters(ParameterScope in_scope,
                                                            const std::string& in_rawKeysAndValues,
                                                            std::vector<VendorParameter>*,
                                                            std::vector<VendorParameter>*) {
    LOG(DEBUG) << __func__ << ": scope: " << toString(in_scope)
               << ", keys/values: " << in_rawKeysAndValues;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus ParameterParser::parseBluetoothA2dpReconfigureOffload(
        const std::string& in_rawValue, std::vector<VendorParameter>*) {
    LOG(DEBUG) << __func__ << ": value: " << in_rawValue;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus ParameterParser::parseBluetoothLeReconfigureOffload(
        const std::string& in_rawValue, std::vector<VendorParameter>*) {
    LOG(DEBUG) << __func__ << ": value: " << in_rawValue;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus ParameterParser::processVendorParameters(
        ParameterScope in_scope, const std::vector<VendorParameter>& in_parameters, std::string*) {
    LOG(DEBUG) << __func__ << ": scope: " << toString(in_scope)
               << ", parameters: " << ::android::internal::ToString(in_parameters);
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace vendor::audio::parserservice
