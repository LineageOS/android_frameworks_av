/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef ANDROID_HARDWARE_CORE_CONVERSION_HELPER_HIDL_H
#define ANDROID_HARDWARE_CORE_CONVERSION_HELPER_HIDL_H

#include "ConversionHelperHidl.h"

#include PATH(android/hardware/audio/CORE_TYPES_FILE_VERSION/types.h)
#include <utils/String8.h>
#include <utils/String16.h>
#include <utils/Vector.h>

using ::android::hardware::audio::CORE_TYPES_CPP_VERSION::ParameterValue;
using CoreResult = ::android::hardware::audio::CORE_TYPES_CPP_VERSION::Result;

using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;

namespace android {

class CoreConversionHelperHidl : public ConversionHelperHidl<CoreResult> {
  protected:
    static status_t keysFromHal(const String8& keys, hidl_vec<hidl_string> *hidlKeys);
    static status_t parametersFromHal(const String8& kvPairs, hidl_vec<ParameterValue> *hidlParams);
    static void parametersToHal(const hidl_vec<ParameterValue>& parameters, String8 *values);
    static void argsFromHal(const Vector<String16>& args, hidl_vec<hidl_string> *hidlArgs);

    CoreConversionHelperHidl(std::string_view className);

  private:
    static status_t analyzeResult(const CoreResult& result);
};

}  // namespace android

#endif // ANDROID_HARDWARE_CORE_CONVERSION_HELPER_HIDL_H
