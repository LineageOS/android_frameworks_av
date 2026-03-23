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

#include <android_companion_virtualdevice_flags.h>
#include <unistd.h>

#include <cstdint>
#include <memory>

#include "EglUtil.h"
#include "android/hardware_buffer.h"
#include "ui/GraphicBuffer.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

namespace flags = ::android::companion::virtualdevice::flags;

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::common::NativeHandle;
using ::aidl::android::hardware::graphics::common::Dataspace;
using ::aidl::android::hardware::graphics::common::PixelFormat;

constexpr int kMaxFpsUpperLimit = 60;

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

  const int32_t rawFence = fence != nullptr ? dup(fence->get()) : -1;
  mLockStatus = static_cast<status_t>(AHardwareBuffer_lockPlanes(
      hwBuffer.get(), usageFlags, rawFence, nullptr, &mPlanes));
  if (mLockStatus != OK) {
    ALOGE("%s: Failed to lock graphic buffer: %s", __func__,
          statusToString(mLockStatus).c_str());
  }
  if (rawFence >= 0) {
    close(rawFence);
  }
  mHwBuffer = hwBuffer;
}

PlanesLockGuard::~PlanesLockGuard() {
  if (getStatus() != OK || mHwBuffer == nullptr) {
    return;
  }
  AHardwareBuffer_unlock(mHwBuffer.get(), /*fence=*/nullptr);
}

status_t PlanesLockGuard::getStatus() const {
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

bool isImageFormatSupportedForInput(const Format format) {
  switch (format) {
    case Format::JPEG:
      [[fallthrough]];
    case Format::HEIC:
      if (!flags::virtual_camera_direct_blob_transfer()) {
        ALOGV(
            "%s: Rejecting blob type 0x%x since direct transfer feature is "
            "disabled",
            __func__, static_cast<int>(format));
        return false;
      }
      [[fallthrough]];
    case Format::YUV_420_888:
      [[fallthrough]];
    case Format::RGBA_8888:
      return true;
    case Format::UNKNOWN:
      return false;
  }
}

bool isFormatSupportedForInput(const int width, const int height,
                               const Format format, const int maxFps) {
  if (!isImageFormatSupportedForInput(format)) {
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

bool isBlobFormat(Format format) {
  return format == Format::HEIC || format == Format::JPEG;
}

bool isHeicStreamConfig(
    const ::aidl::android::hardware::camera::device::Stream& stream) {
  return stream.format == PixelFormat::BLOB &&
         stream.dataSpace == Dataspace::HEIF;
}

bool isBlobStreamConfig(const Stream& stream) {
  return stream.format == PixelFormat::BLOB &&
         (stream.dataSpace == Dataspace::HEIF ||
          stream.dataSpace == Dataspace::JFIF);
}

bool areMatchingBlobTypes(
    const Stream& halStream,
    const SupportedStreamConfiguration& internalStreamConfig) {
  return (halStream.format == PixelFormat::BLOB) &&
         ((halStream.dataSpace == Dataspace::HEIF &&
           internalStreamConfig.imageFormat == Format::HEIC) ||
          (halStream.dataSpace == Dataspace::JFIF &&
           internalStreamConfig.imageFormat == Format::JPEG));
}

bool areMatchingBlobTypes(
    const ::aidl::android::hardware::camera::device::Stream& a,
    const ::aidl::android::hardware::camera::device::Stream& b) {
  return a.dataSpace == b.dataSpace && isBlobStreamConfig(a) &&
         isBlobStreamConfig(b);
}

bool areMatchingBlobTypes(Format a, Format b) {
  return isBlobFormat(a) && isBlobFormat(b) && a == b;
}

bool areDifferentBlobTypes(Format a, Format b) {
  return isBlobFormat(a) && isBlobFormat(b) && a != b;
}

std::ostream& operator<<(std::ostream& os, const Resolution& resolution) {
  return os << resolution.width << "x" << resolution.height;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
