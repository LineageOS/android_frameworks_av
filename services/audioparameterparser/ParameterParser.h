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

#pragma once

#include <aidl/android/media/audio/BnHalAdapterVendorExtension.h>

namespace vendor::audio::parserservice {

class ParameterParser : public ::aidl::android::media::audio::BnHalAdapterVendorExtension {
  public:
    ParameterParser() = default;

  private:
    ::ndk::ScopedAStatus parseVendorParameterIds(
            ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope in_scope,
            const std::string& in_rawKeys, std::vector<std::string>* _aidl_return) override;

    ::ndk::ScopedAStatus parseVendorParameters(
            ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope in_scope,
            const std::string& in_rawKeysAndValues,
            std::vector<::aidl::android::hardware::audio::core::VendorParameter>*
                    out_syncParameters,
            std::vector<::aidl::android::hardware::audio::core::VendorParameter>*
                    out_asyncParameters) override;

    ::ndk::ScopedAStatus parseBluetoothA2dpReconfigureOffload(
            const std::string& in_rawValue,
            std::vector<::aidl::android::hardware::audio::core::VendorParameter>* _aidl_return)
            override;

    ::ndk::ScopedAStatus parseBluetoothLeReconfigureOffload(
            const std::string& in_rawValue,
            std::vector<::aidl::android::hardware::audio::core::VendorParameter>* _aidl_return)
            override;

    ::ndk::ScopedAStatus processVendorParameters(
            ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope in_scope,
            const std::vector<::aidl::android::hardware::audio::core::VendorParameter>&
                    in_parameters,
            std::string* _aidl_return) override;
};

}  // namespace vendor::audio::parserservice
