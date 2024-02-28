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

#include <cmath>
#include <cstdint>
#include <memory>

#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "android/binder_auto_utils.h"
#include "android/hardware_buffer.h"
#include "system/graphics.h"
#include "ui/Fence.h"

namespace android {
namespace companion {
namespace virtualcamera {

// RAII utility class to safely lock AHardwareBuffer and obtain android_ycbcr
// structure describing YUV plane layout.
//
// Access to the buffer is locked immediatelly afer construction.
class YCbCrLockGuard {
 public:
  YCbCrLockGuard(std::shared_ptr<AHardwareBuffer> hwBuffer, uint32_t usageFlags);
  YCbCrLockGuard(YCbCrLockGuard&& other) = default;
  ~YCbCrLockGuard();

  // Returns OK if the buffer is successfully locked.
  status_t getStatus() const;

  // Dereferencing instance of this guard returns android_ycbcr structure
  // describing the layout.
  // Caller needs to check whether the buffer was successfully locked
  // before dereferencing.
  const android_ycbcr& operator*() const;

  // Disable copy.
  YCbCrLockGuard(const YCbCrLockGuard&) = delete;
  YCbCrLockGuard& operator=(const YCbCrLockGuard&) = delete;

 private:
  std::shared_ptr<AHardwareBuffer> mHwBuffer;
  android_ycbcr mYCbCr = {};
  status_t mLockStatus = DEAD_OBJECT;
};

// RAII utility class to safely lock AHardwareBuffer and obtain
// AHardwareBuffer_Planes (Suitable for interacting with RGBA / BLOB buffers.
//
// Access to the buffer is locked immediatelly afer construction.
class PlanesLockGuard {
 public:
  PlanesLockGuard(std::shared_ptr<AHardwareBuffer> hwBuffer,
                  uint64_t usageFlags, sp<Fence> fence = nullptr);
  PlanesLockGuard(PlanesLockGuard&& other) = default;
  ~PlanesLockGuard();

  // Returns OK if the buffer is successfully locked.
  status_t getStatus() const;

  // Dereferencing instance of this guard returns AHardwareBuffer_Planes
  // structure describing the layout.
  //
  // Caller needs to check whether the buffer was successfully locked
  // before dereferencing.
  const AHardwareBuffer_Planes& operator*() const;

  // Disable copy.
  PlanesLockGuard(const PlanesLockGuard&) = delete;
  PlanesLockGuard& operator=(const YCbCrLockGuard&) = delete;

 private:
  std::shared_ptr<AHardwareBuffer> mHwBuffer;
  AHardwareBuffer_Planes mPlanes;
  status_t mLockStatus = DEAD_OBJECT;
};

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
    ::aidl::android::companion::virtualcamera::Format format, int maxFps);

// Representation of resolution / size.
struct Resolution {
  Resolution() = default;
  Resolution(const int w, const int h) : width(w), height(h) {
  }

  // Order by increasing pixel count, and by width for same pixel count.
  bool operator<(const Resolution& other) const {
    const int pixCount = width * height;
    const int otherPixCount = other.width * other.height;
    return pixCount == otherPixCount ? width < other.width
                                     : pixCount < otherPixCount;
  }

  bool operator<=(const Resolution& other) const {
    return *this == other || *this < other;
  }

  bool operator==(const Resolution& other) const {
    return width == other.width && height == other.height;
  }

  int width = 0;
  int height = 0;
};

inline bool isApproximatellySameAspectRatio(const Resolution r1,
                                            const Resolution r2) {
  static constexpr float kAspectRatioEpsilon = 0.05;
  float aspectRatio1 =
      static_cast<float>(r1.width) / static_cast<float>(r1.height);
  float aspectRatio2 =
      static_cast<float>(r2.width) / static_cast<float>(r2.height);

  return std::abs(aspectRatio1 - aspectRatio2) < kAspectRatioEpsilon;
}

std::ostream& operator<<(std::ostream& os, const Resolution& resolution);

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_UTIL_H
