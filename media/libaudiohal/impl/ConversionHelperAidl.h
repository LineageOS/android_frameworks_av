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
    ConversionHelperAidl(std::string_view className) : mClassName(className) {}

    const std::string& getClassName() const {
        return mClassName;
    }

    const std::string mClassName;
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

// Must use the same order of elements as IHalAdapterVendorExtension::ParameterScope.
using VendorParametersRecipient = std::variant<
        std::shared_ptr<::aidl::android::hardware::audio::core::IModule>,
        std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon>>;
status_t parseAndGetVendorParameters(
        std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> vendorExt,
        const VendorParametersRecipient& recipient,
        const AudioParameter& parameterKeys,
        String8* values);
status_t parseAndSetVendorParameters(
        std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> vendorExt,
        const VendorParametersRecipient& recipient,
        const AudioParameter& parameters);

}  // namespace android
