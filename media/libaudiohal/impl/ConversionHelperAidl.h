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

#pragma once

#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <aidl/android/hardware/audio/core/IModule.h>
#include <aidl/android/hardware/audio/core/IStreamCommon.h>
#include <aidl/android/media/audio/IHalAdapterVendorExtension.h>
#include <android-base/expected.h>
#include <error/Result.h>
#include <media/AudioParameter.h>
#include <utils/String16.h>
#include <utils/Vector.h>

namespace android {

/*
 * Helper macro to add instance name, function name in logs
 * classes should provide getInstanceName API to use these macros.
 * print function names along with instance name.
 *
 * Usage:
 *  AUGMENT_LOG(D);
 *  AUGMENT_LOG(I, "hello!");
 *  AUGMENT_LOG(W, "value: %d", value);
 *
 *  AUGMENT_LOG_IF(D, value < 0, "negative");
 *  AUGMENT_LOG_IF(E, value < 0, "bad value: %d", value);
 */

#define AUGMENT_LOG(level, ...)                                                  \
    ALOG##level("[%s] %s" __VA_OPT__(": " __android_second(0, __VA_ARGS__, "")), \
                getInstanceName().c_str(), __func__ __VA_OPT__(__android_rest(__VA_ARGS__)))

#define AUGMENT_LOG_IF(level, cond, ...)                                                    \
    ALOG##level##_IF(cond, "[%s] %s" __VA_OPT__(": " __android_second(0, __VA_ARGS__, "")), \
                     getInstanceName().c_str(), __func__ __VA_OPT__(__android_rest(__VA_ARGS__)))

class Args {
  public:
    explicit Args(const Vector<String16>& args)
            : mValues(args.size()), mPtrs(args.size()) {
        for (size_t i = 0; i < args.size(); ++i) {
            mValues[i] = std::string(String8(args[i]));
            mPtrs[i] = mValues[i].c_str();
        }
    }
    const char** args() { return mPtrs.data(); }
  private:
    std::vector<std::string> mValues;
    std::vector<const char*> mPtrs;
};

class ConversionHelperAidl {
  protected:
    ConversionHelperAidl(std::string_view className, std::string_view instanceName)
        : mClassName(className), mInstanceName(instanceName) {}

    const std::string& getClassName() const { return mClassName; }

    const std::string& getInstanceName() const { return mInstanceName; }

    const std::string mClassName;
    const std::string mInstanceName;
};

// 'action' must accept a value of type 'T' and return 'status_t'.
// The function returns 'true' if the parameter was found, and the action has succeeded.
// The function returns 'false' if the parameter was not found.
// Any errors get propagated, if there are errors it means the parameter was found.
template<typename T, typename F>
error::Result<bool> filterOutAndProcessParameter(
        AudioParameter& parameters, const String8& key, const F& action) {
    if (parameters.containsKey(key)) {
        T value;
        status_t status = parameters.get(key, value);
        if (status == OK) {
            parameters.remove(key);
            status = action(value);
            if (status == OK) return true;
        }
        return base::unexpected(status);
    }
    return false;
}

// Must use the same order of elements as IHalAdapterVendorExtension::ScopeType.
using VendorParametersRecipient = std::variant<
        std::shared_ptr<::aidl::android::hardware::audio::core::IModule>,
        std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon>>;
status_t fillVendorParameterIds(
        std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> vendorExt,
        ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope scope,
        const AudioParameter& parameterKeys, std::vector<std::string>& vendorParametersIds);
status_t fillKeyValuePairsFromVendorParameters(
        std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> vendorExt,
        ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope scope,
        const std::vector<::aidl::android::hardware::audio::core::VendorParameter>&
                vendorParameters,
        String8* values);
status_t fillVendorParameters(
        std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> vendorExt,
        ::aidl::android::media::audio::IHalAdapterVendorExtension::ParameterScope scope,
        const AudioParameter& parameters,
        std::vector<::aidl::android::hardware::audio::core::VendorParameter>& syncParameters,
        std::vector<::aidl::android::hardware::audio::core::VendorParameter>& asyncParameters);

}  // namespace android
