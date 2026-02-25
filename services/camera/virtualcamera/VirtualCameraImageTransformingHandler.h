/*
 * Copyright (C) 2025 The Android Open Source Project
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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGETRANSFORMINGHANDLER_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGETRANSFORMINGHANDLER_H

#include <gui/Surface.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "Exif.h"
#include "GLES/gl.h"
#include "VirtualCameraCaptureRequest.h"
#include "VirtualCameraImageHandler.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/CaptureResult.h"
#include "aidl/android/hardware/camera/device/Stream.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "android/binder_auto_utils.h"
#include "util/EglDisplayContext.h"
#include "util/EglFramebuffer.h"
#include "util/EglProgram.h"
#include "util/EglSurfaceTexture.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

/**
 * VirtualCameraImageTransformingHandler
 *
 * Represents a frame consumer that can modify the contents of the image frames
 * it receives before transferring to the Camera2 client, e.g. scale, compress
 * to JPEG.
 */
class VirtualCameraImageTransformingHandler : public VirtualCameraImageHandler {
 public:
  VirtualCameraImageTransformingHandler(
      VirtualCameraSessionContext& sessionContext, Resolution inputSurfaceSize,
      std::function<void(void)> frameReadyCallback);
  virtual ~VirtualCameraImageTransformingHandler();

  virtual bool waitForInputFrame(const std::chrono::nanoseconds timeout) override;
  virtual void interruptWait() override;
  virtual void updateTexture() override;
  virtual std::chrono::nanoseconds getTimestamp() override;
  virtual bool isFirstFrameDrawn() override;
  virtual sp<Surface> getInputSurface() override;
  virtual ndk::ScopedAStatus fillOutputBuffer(
      const RequestSettings& requestSettings,
      const CaptureRequestBuffer& requestBuffer,
      const ::aidl::android::hardware::camera::device::Stream& halStreamConfig,
      ::aidl::android::hardware::camera::device::CaptureResult& captureResult)
      override;

 private:
  /**
   * createThumbnail()
   *
   * Create thumbnail with specified size for current image.
   * The compressed image size is limited by 32KiB.
   * Returns vector with compressed thumbnail if successful,
   * empty vector otherwise.
   *
   * TODO(b/301023410) - Refactor the actual rendering logic off this class for
   * easier testability.
   */
  std::vector<uint8_t> createThumbnail(Resolution resolution, int quality);

  /**
   * renderIntoBlobStreamBuffer()
   *
   * Render current image to the BLOB buffer.
   * If fence is specified, this function will block until the fence is cleared
   * before writing to the buffer.
   * Always called on render thread.
   */
  ndk::ScopedAStatus renderIntoBlobStreamBuffer(
      const RequestSettings& requestSettings,
      const CaptureRequestBuffer& requestBuffer,
      ::aidl::android::hardware::camera::device::CaptureResult& captureResult);

  /**
   * renderIntoImageStreamBuffer()
   *
   * Render current image to the YCbCr buffer.
   * If fence is specified, this function will block until the fence is cleared
   * before writing to the buffer.
   * Always called on render thread.
   */
  ndk::ScopedAStatus renderIntoImageStreamBuffer(
      const CaptureRequestBuffer& requestBuffer);

  /**
   * renderIntoEglFramebuffer()
   *
   * Render current image into provided EglFramebuffer.
   * If fence is specified, this function will block until the fence is cleared
   * before writing to the buffer.
   * Always called on the render thread.
   */
  ndk::ScopedAStatus renderIntoEglFramebuffer(
      EglFrameBuffer& framebuffer, sp<Fence> fence = nullptr,
      std::optional<Rect> viewport = std::nullopt);

  VirtualCameraSessionContext& mSessionContext;

  // EGL helpers - constructed and accessed only from capture thread.
  std::unique_ptr<EglDisplayContext> mEglDisplayContext;
  std::unique_ptr<EglTextureProgram> mEglTextureYuvProgram;
  std::unique_ptr<EglTextureProgram> mEglTextureRgbProgram;
  std::unique_ptr<EglSurfaceTexture> mEglSurfaceTexture;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGETRANSFORMINGHANDLER_H
