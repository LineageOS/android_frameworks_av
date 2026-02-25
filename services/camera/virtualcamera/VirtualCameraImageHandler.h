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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGEHANDLER_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGEHANDLER_H

#include <gui/Surface.h>

#include <chrono>

#include "VirtualCameraCaptureRequest.h"
#include "aidl/android/hardware/camera/device/CaptureResult.h"
#include "aidl/android/hardware/camera/device/Stream.h"

namespace android {
namespace companion {
namespace virtualcamera {

/**
 * VirtualCameraImageHandler
 *
 * Pure virtual interface representing a consumer of the data produced by the
 * Virtual Camera Owner. This data can take different forms, e.g. structured
 * YUV/RGBA, unstructured BLOBs, etc. The derived classes of this interface
 * contain the logic for consuming these different data.
 */
class VirtualCameraImageHandler {
 public:
  virtual ~VirtualCameraImageHandler() {
  }

  /**
   * waitForInputFrame()
   *
   * Block until an input frame is produced by the Virtual Camera Owner. Return
   * immediately if the input surface already has a frame in its BufferQueue.
   *
   * Returns true if an input frame arrived before |timeout| expires. False
   * otherwise.
   */
  virtual bool waitForInputFrame(const std::chrono::nanoseconds timeout) = 0;

  /**
   * interruptWait()
   *
   * Interrupt any ongoing wait for an input frame.
   */
  virtual void interruptWait() = 0;

  /**
   * updateTexture()
   *
   * Request input surface to fast-forward to most recent input frame.
   * Currently queued buffers in the input surface will be released and only
   * the most recent buffer in the queue will be acquired.
   */
  virtual void updateTexture() = 0;

  /**
   * getTimestamp()
   *
   * Returns timestamp of latest frame. Returns 0 if the producer has not yet
   * associated a timestamp with this producer.
   */
  virtual std::chrono::nanoseconds getTimestamp() = 0;

  /**
   * isFirstFrameDrawn()
   *
   * Returns true if the input surface has received at least one frame.
   */
  virtual bool isFirstFrameDrawn() = 0;

  /**
   * getInputSurface()
   *
   * Returns input surface for this frame consumer.
   */
  virtual sp<Surface> getInputSurface() = 0;

  /**
   * fillOutputBuffer()
   *
   * Transfer data from most recent input frame to output buffers.
   */
  virtual ndk::ScopedAStatus fillOutputBuffer(
      const RequestSettings& requestSettings,
      const CaptureRequestBuffer& requestBuffer,
      const ::aidl::android::hardware::camera::device::Stream& halStreamConfig,
      ::aidl::android::hardware::camera::device::CaptureResult& captureResult) = 0;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAIMAGEHANDLER_H
