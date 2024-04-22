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

#include "Util.h"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>

#include "EglUtil.h"
#include "android/hardware_buffer.h"
#include "jpeglib.h"
#include "ui/GraphicBuffer.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::hardware::common::NativeHandle;

constexpr int kMaxFpsUpperLimit = 60;

constexpr std::array<Format, 2> kSupportedFormats{Format::YUV_420_888,
                                                  Format::RGBA_8888};

YCbCrLockGuard::YCbCrLockGuard(std::shared_ptr<AHardwareBuffer> hwBuffer,
                               const uint32_t usageFlags)
    : mHwBuffer(hwBuffer) {
  GraphicBuffer* gBuffer = GraphicBuffer::fromAHardwareBuffer(mHwBuffer.get());
  if (gBuffer == nullptr) {
    ALOGE("%s: Attempting to lock nullptr buffer.", __func__);
    return;
  }
  mLockStatus = gBuffer->lockYCbCr(usageFlags, &mYCbCr);
  if (mLockStatus != OK) {
    ALOGE("%s: Failed to lock graphic buffer: %s", __func__,
          statusToString(mLockStatus).c_str());
  }
}

YCbCrLockGuard::~YCbCrLockGuard() {
  if (getStatus() != OK) {
    return;
  }

  GraphicBuffer* gBuffer = GraphicBuffer::fromAHardwareBuffer(mHwBuffer.get());
  if (gBuffer == nullptr) {
    return;
  }
  gBuffer->unlock();
  status_t status = gBuffer->unlock();
  if (status != NO_ERROR) {
    ALOGE("Failed to unlock graphic buffer: %s", statusToString(status).c_str());
  }
}

status_t YCbCrLockGuard::getStatus() const {
  return mLockStatus;
}

const android_ycbcr& YCbCrLockGuard::operator*() const {
  LOG_ALWAYS_FATAL_IF(getStatus() != OK,
                      "Dereferencing unlocked YCbCrLockGuard, status is %s",
                      statusToString(mLockStatus).c_str());
  return mYCbCr;
}

PlanesLockGuard::PlanesLockGuard(std::shared_ptr<AHardwareBuffer> hwBuffer,
                                 const uint64_t usageFlags, sp<Fence> fence) {
  if (hwBuffer == nullptr) {
    ALOGE("%s: Attempting to lock nullptr buffer.", __func__);
    return;
  }

  const int32_t rawFence = fence != nullptr ? fence->get() : -1;
  mLockStatus = static_cast<status_t>(AHardwareBuffer_lockPlanes(
      hwBuffer.get(), usageFlags, rawFence, nullptr, &mPlanes));
  if (mLockStatus != OK) {
    ALOGE("%s: Failed to lock graphic buffer: %s", __func__,
          statusToString(mLockStatus).c_str());
  }
}

PlanesLockGuard::~PlanesLockGuard() {
  if (getStatus() != OK || mHwBuffer == nullptr) {
    return;
  }
  AHardwareBuffer_unlock(mHwBuffer.get(), /*fence=*/nullptr);
}

int PlanesLockGuard::getStatus() const {
  return mLockStatus;
}

const AHardwareBuffer_Planes& PlanesLockGuard::operator*() const {
  LOG_ALWAYS_FATAL_IF(getStatus() != OK,
                      "Dereferencing unlocked PlanesLockGuard, status is %s",
                      statusToString(mLockStatus).c_str());
  return mPlanes;
}

sp<Fence> importFence(const NativeHandle& aidlHandle) {
  if (aidlHandle.fds.size() != 1) {
    return sp<Fence>::make();
  }

  return sp<Fence>::make(::dup(aidlHandle.fds[0].get()));
}

bool isPixelFormatSupportedForInput(const Format format) {
  return std::find(kSupportedFormats.begin(), kSupportedFormats.end(),
                   format) != kSupportedFormats.end();
}

// Returns true if specified format is supported for virtual camera input.
bool isFormatSupportedForInput(const int width, const int height,
                               const Format format, const int maxFps) {
  if (!isPixelFormatSupportedForInput(format)) {
    return false;
  }

  int maxTextureSize = getMaximumTextureSize();
  if (width <= 0 || height <= 0 || width > maxTextureSize ||
      height > maxTextureSize) {
    return false;
  }

  if (maxFps <= 0 || maxFps > kMaxFpsUpperLimit) {
    return false;
  }

  return true;
}

std::ostream& operator<<(std::ostream& os, const Resolution& resolution) {
  return os << resolution.width << "x" << resolution.height;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
