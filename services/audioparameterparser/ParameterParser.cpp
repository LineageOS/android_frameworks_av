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

#define LOG_TAG "Audio_ParameterParser"

#include "ParameterParser.h"

#include <android-base/logging.h>
#include <media/AudioParameter.h>

namespace vendor::audio::parserservice {

using ::aidl::android::hardware::audio::core::VendorParameter;
using ParameterScope = ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope;
using ScopeType = ::aidl::android::media::audio::IHalAdapterVendorExtension::ScopeType;

::ndk::ScopedAStatus ParameterParser::parseVendorParameterIds(
        const ParameterScope& in_scope, const std::string& in_rawKeys,
        std::vector<std::string>* _aidl_return) {
    LOG(DEBUG) << __func__ << ": scope: " << in_scope.toString() << ", keys: " << in_rawKeys;
    if (in_scope.scope == ScopeType::MODULE) {
        ::android::AudioParameter params(::android::String8(in_rawKeys.c_str()));
        if (params.containsKey(
                    ::android::String8(::android::AudioParameter::keyClipTransitionSupport))) {
            _aidl_return->emplace_back(::android::AudioParameter::keyClipTransitionSupport);
        }
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus ParameterParser::parseVendorParameters(const ParameterScope& in_scope,
                                                            const std::string& in_rawKeysAndValues,
                                                            std::vector<VendorParameter>*,
                                                            std::vector<VendorParameter>*) {
    LOG(DEBUG) << __func__ << ": scope: " << in_scope.toString()
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
        const ParameterScope& in_scope, const std::vector<VendorParameter>& in_parameters,
        std::string* _aidl_return) {
    LOG(DEBUG) << __func__ << ": scope: " << in_scope.toString()
               << ", parameters: " << ::android::internal::ToString(in_parameters);
    if (in_scope.scope == ScopeType::MODULE) {
        ::android::AudioParameter result;
        for (const auto& param : in_parameters) {
            if (param.id == ::android::AudioParameter::keyClipTransitionSupport) {
                result.addInt(
                        ::android::String8(::android::AudioParameter::keyClipTransitionSupport),
                        true);
            }
        }
        *_aidl_return = result.toString().c_str();
    }
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace vendor::audio::parserservice
