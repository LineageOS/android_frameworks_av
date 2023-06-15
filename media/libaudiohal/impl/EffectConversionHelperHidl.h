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

#ifndef ANDROID_HARDWARE_EFFECT_CONVERSION_HELPER_HIDL_H
#define ANDROID_HARDWARE_EFFECT_CONVERSION_HELPER_HIDL_H

#include "ConversionHelperHidl.h"

#include PATH(android/hardware/audio/effect/COMMON_TYPES_FILE_VERSION/types.h)

using EffectResult = ::android::hardware::audio::effect::COMMON_TYPES_CPP_VERSION::Result;

namespace android {

class EffectConversionHelperHidl : public ConversionHelperHidl<EffectResult> {
  protected:
    static status_t analyzeResult(const EffectResult& result);

    EffectConversionHelperHidl(std::string_view className);
};

}  // namespace android

#endif // ANDROID_HARDWARE_EFFECT_CONVERSION_HELPER_HIDL_H
