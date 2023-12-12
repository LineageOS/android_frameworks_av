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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_UTIL_H
#define ANDROID_COMPANION_VIRTUALCAMERA_UTIL_H

#include <cstdint>

#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "android/binder_auto_utils.h"
#include "ui/Fence.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Converts camera AIDL status to ndk::ScopedAStatus
inline ndk::ScopedAStatus cameraStatus(
    const ::aidl::android::hardware::camera::common::Status status) {
  return ndk::ScopedAStatus::fromServiceSpecificError(
      static_cast<int32_t>(status));
}

// Import Fence from AIDL NativeHandle.
//
// If the handle can't be used to construct Fence (is empty or doesn't contain
// only single fd) this function will return Fence instance in invalid state.
sp<Fence> importFence(
    const ::aidl::android::hardware::common::NativeHandle& handle);

// Returns true if specified pixel format is supported for virtual camera input.
bool isPixelFormatSupportedForInput(
    ::aidl::android::companion::virtualcamera::Format format);

// Returns true if specified format is supported for virtual camera input.
bool isFormatSupportedForInput(
    int width, int height,
    ::aidl::android::companion::virtualcamera::Format format);

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_UTIL_H
