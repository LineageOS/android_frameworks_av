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

// #define LOG_NDEBUG 0
#define LOG_TAG "VirtualCameraStream"
#include "VirtualCameraStream.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <tuple>
#include <utility>

#include "EGL/egl.h"
#include "aidl/android/hardware/camera/device/Stream.h"
#include "aidlcommonsupport/NativeHandle.h"
#include "android/hardware_buffer.h"
#include "cutils/native_handle.h"
#include "ui/GraphicBuffer.h"
#include "ui/GraphicBufferMapper.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::common::NativeHandle;

namespace {

sp<GraphicBuffer> createGraphicBuffer(GraphicBufferMapper& mapper,
                                      const buffer_handle_t bufferHandle) {
  uint64_t width;
  uint64_t height;
  uint64_t usage;
  uint64_t layerCount;
  ui::PixelFormat pixelFormat;
  if (mapper.getWidth(bufferHandle, &width) != NO_ERROR ||
      mapper.getHeight(bufferHandle, &height) != NO_ERROR ||
      mapper.getUsage(bufferHandle, &usage) != NO_ERROR ||
      mapper.getLayerCount(bufferHandle, &layerCount) != NO_ERROR ||
      mapper.getPixelFormatRequested(bufferHandle, &pixelFormat) != NO_ERROR) {
    ALOGE("Error fetching metadata for the imported YCbCr420 buffer handle.");
    return nullptr;
  }

  return sp<GraphicBuffer>::make(
      bufferHandle, GraphicBuffer::HandleWrapMethod::TAKE_HANDLE, width, height,
      static_cast<int>(pixelFormat), layerCount, usage, width);
}

std::shared_ptr<AHardwareBuffer> importBufferInternal(
    const NativeHandle& aidlHandle) {
  if (aidlHandle.fds.empty()) {
    ALOGE("Empty handle - nothing to import");
    return nullptr;
  }
  std::unique_ptr<native_handle_t, int (*)(native_handle_t*)> nativeHandle(
      ::android::makeFromAidl(aidlHandle), native_handle_delete);

  GraphicBufferMapper& mapper = GraphicBufferMapper::get();

  buffer_handle_t bufferHandle;
  // Use importBufferNoValidate to rely on ground-truth metadata passed along
  // the buffer.
  int ret = mapper.importBufferNoValidate(nativeHandle.get(), &bufferHandle);
  if (ret != NO_ERROR) {
    ALOGE("Failed to import buffer handle: %d", ret);
    return nullptr;
  }

  sp<GraphicBuffer> buf = createGraphicBuffer(mapper, bufferHandle);

  if (buf == nullptr || buf->initCheck() != NO_ERROR) {
    ALOGE("Imported graphic buffer is not correcly initialized.");
    return nullptr;
  }

  AHardwareBuffer* rawPtr = buf->toAHardwareBuffer();
  AHardwareBuffer_acquire(rawPtr);

  return std::shared_ptr<AHardwareBuffer>(buf->toAHardwareBuffer(),
                                          AHardwareBuffer_release);
}

}  // namespace

VirtualCameraStream::VirtualCameraStream(const Stream& stream)
    : mStreamConfig(stream) {
}

std::shared_ptr<AHardwareBuffer> VirtualCameraStream::importBuffer(
    const ::aidl::android::hardware::camera::device::StreamBuffer& buffer) {
  auto hwBufferPtr = importBufferInternal(buffer.buffer);
  if (hwBufferPtr != nullptr) {
    std::lock_guard<std::mutex> lock(mLock);
    mBuffers.emplace(std::piecewise_construct,
                     std::forward_as_tuple(buffer.bufferId),
                     std::forward_as_tuple(hwBufferPtr));
  }
  return hwBufferPtr;
}

std::shared_ptr<AHardwareBuffer> VirtualCameraStream::getHardwareBuffer(
    const int bufferId) {
  std::lock_guard<std::mutex> lock(mLock);
  return getHardwareBufferLocked(bufferId);
}

std::shared_ptr<EglFrameBuffer> VirtualCameraStream::getEglFrameBuffer(
    const EGLDisplay eglDisplay, const int bufferId) {
  const FramebufferMapKey key(bufferId, eglDisplay);

  std::lock_guard<std::mutex> lock(mLock);

  auto it = mEglFramebuffers.find(key);
  if (it != mEglFramebuffers.end()) {
    return it->second;
  }

  std::shared_ptr<AHardwareBuffer> hwBufferPtr =
      getHardwareBufferLocked(bufferId);
  if (hwBufferPtr == nullptr) {
    return nullptr;
  }
  std::shared_ptr<EglFrameBuffer> framebufferPtr =
      std::make_shared<EglFrameBuffer>(eglDisplay, hwBufferPtr);
  mEglFramebuffers.emplace(std::piecewise_construct, std::forward_as_tuple(key),
                           std::forward_as_tuple(framebufferPtr));

  return framebufferPtr;
}

std::shared_ptr<AHardwareBuffer> VirtualCameraStream::getHardwareBufferLocked(
    const int bufferId) {
  auto it = mBuffers.find(bufferId);
  return it != mBuffers.end() ? it->second : nullptr;
}

bool VirtualCameraStream::removeBuffer(int bufferId) {
  std::lock_guard<std::mutex> lock(mLock);

  return mBuffers.erase(bufferId) == 1;
}

Stream VirtualCameraStream::getStreamConfig() const {
  return mStreamConfig;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
