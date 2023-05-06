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

/**
 * Conversions between the NDK and CPP backends for common types.
 */
#include <aidl/android/media/audio/common/AudioFormatDescription.h>
#include <aidl/android/media/audio/common/AudioHalEngineConfig.h>
#include <aidl/android/media/audio/common/AudioMMapPolicyInfo.h>
#include <aidl/android/media/audio/common/AudioMMapPolicyType.h>
#include <aidl/android/media/audio/common/AudioMode.h>
#include <aidl/android/media/audio/common/AudioPort.h>
#include <android/media/audio/common/AudioFormatDescription.h>
#include <android/media/audio/common/AudioHalEngineConfig.h>
#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include <android/media/audio/common/AudioMode.h>
#include <android/media/audio/common/AudioPort.h>
#include <media/AidlConversionUtil.h>

namespace android {

#define DECLARE_CONVERTERS(packageName, className)                       \
    ConversionResult<::aidl::packageName::className>                    \
    cpp2ndk_##className(const ::packageName::className& cpp);           \
    ConversionResult<::packageName::className>                          \
    ndk2cpp_##className(const ::aidl::packageName::className& ndk);

DECLARE_CONVERTERS(android::media::audio::common, AudioFormatDescription);
DECLARE_CONVERTERS(android::media::audio::common, AudioHalEngineConfig);
DECLARE_CONVERTERS(android::media::audio::common, AudioMMapPolicyInfo);
DECLARE_CONVERTERS(android::media::audio::common, AudioMMapPolicyType);
DECLARE_CONVERTERS(android::media::audio::common, AudioMode);
DECLARE_CONVERTERS(android::media::audio::common, AudioPort);

#undef DECLARE_CONVERTERS

}  // namespace android
