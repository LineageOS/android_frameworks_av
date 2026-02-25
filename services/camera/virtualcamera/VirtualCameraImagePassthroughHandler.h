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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGEPASSTHROUGHHANDLER_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGEPASSTHROUGHHANDLER_H

#include <android/hardware_buffer.h>
#include <gui/Surface.h>
#include <media/NdkImage.h>
#include <media/NdkImageReader.h>
#include <media/NdkMediaError.h>

#include <chrono>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <mutex>

#include "VirtualCameraCaptureRequest.h"
#include "VirtualCameraImageHandler.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/hardware/camera/device/CaptureResult.h"
#include "aidl/android/hardware/camera/device/Stream.h"
#include "android/binder_auto_utils.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

/**
 * VirtualCameraImagePassthroughHandler
 *
 * Represents a frame consumer that does not modify the contents of the image frames
 * it receives before transferring to the Camera2 client. It simply propagates
 * the buffers unmodified from the Virtual Camera Owner to the calling client.
 */
class VirtualCameraImagePassthroughHandler : public VirtualCameraImageHandler {
 public:
  static std::unique_ptr<VirtualCameraImagePassthroughHandler> create(
      VirtualCameraSessionContext& sessionContext,
      ::aidl::android::companion::virtualcamera::Format imageFormat,
      std::function<void(void)> frameReadyCallback);

  VirtualCameraImagePassthroughHandler(
      VirtualCameraSessionContext& sessionContext,
      ::aidl::android::companion::virtualcamera::Format imageFormat,
      std::function<void(void)> frameReadyCallback, sp<Surface> inputSurface,
      std::unique_ptr<AImageReader,
                      CustomDeleter<AImageReader, AImageReader_delete>>
          imageReader);
  virtual ~VirtualCameraImagePassthroughHandler();
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

  // Trigger registered "on frame available" callback
  void onFrameAvailable();

 private:
  void resetFrameAvailableSignalingMechanism();

  VirtualCameraSessionContext& mSessionContext;
  ::aidl::android::companion::virtualcamera::Format mImageFormat;
  std::function<void(void)> mOnFrameAvailable;

  std::mutex mFrameAvailableCallbackMutex;
  bool mFrameAvailablePromiseSignalled;
  std::unique_ptr<std::promise<bool>> mFrameAvailablePromise;
  std::unique_ptr<std::future<bool>> mFrameAvailableFuture;

  bool mIsFirstFrameDrawn;

  sp<Surface> mInputSurface;
  std::unique_ptr<AImageReader, CustomDeleter<AImageReader, AImageReader_delete>>
      mImageReader;
  std::unique_ptr<AImage, CustomDeleter<AImage, AImage_delete>> mCurrentImage;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGEPASSTHROUGHHANDLER_H
