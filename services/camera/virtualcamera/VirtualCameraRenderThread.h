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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERARENDERTHREAD_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERARENDERTHREAD_H

#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "VirtualCameraDevice.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/ICameraDeviceCallback.h"
#include "android/binder_auto_utils.h"
#include "util/EglDisplayContext.h"
#include "util/EglFramebuffer.h"
#include "util/EglProgram.h"
#include "util/EglSurfaceTexture.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Represents single output buffer of capture request.
class CaptureRequestBuffer {
 public:
  CaptureRequestBuffer(int streamId, int bufferId, sp<Fence> fence = nullptr);

  int getStreamId() const;
  int getBufferId() const;
  sp<Fence> getFence() const;

 private:
  const int mStreamId;
  const int mBufferId;
  const sp<Fence> mFence;
};

struct RequestSettings {
  int jpegQuality = VirtualCameraDevice::kDefaultJpegQuality;
  Resolution thumbnailResolution = Resolution(0, 0);
  int thumbnailJpegQuality = VirtualCameraDevice::kDefaultJpegQuality;
};

// Represents single capture request to fill set of buffers.
class ProcessCaptureRequestTask {
 public:
  ProcessCaptureRequestTask(
      int frameNumber, const std::vector<CaptureRequestBuffer>& requestBuffers,
      const RequestSettings& RequestSettings = {});

  // Returns frame number corresponding to the request.
  int getFrameNumber() const;

  // Get reference to vector describing output buffers corresponding
  // to this request.
  //
  // Note that the vector is owned by the ProcessCaptureRequestTask instance,
  // so it cannot be access outside of its lifetime.
  const std::vector<CaptureRequestBuffer>& getBuffers() const;

  const RequestSettings& getRequestSettings() const;

 private:
  const int mFrameNumber;
  const std::vector<CaptureRequestBuffer> mBuffers;
  const RequestSettings mRequestSettings;
};

// Wraps dedicated rendering thread and rendering business with corresponding
// input surface.
class VirtualCameraRenderThread {
 public:
  // Create VirtualCameraRenderThread instance:
  // * sessionContext - VirtualCameraSessionContext reference for shared access
  // to mapped buffers.
  // * inputSurfaceSize - requested size of input surface.
  // * reportedSensorSize - reported static sensor size of virtual camera.
  // * cameraDeviceCallback - callback for corresponding camera instance
  // * testMode - when set to true, test pattern is rendered to input surface
  // before each capture request is processed to simulate client input.
  VirtualCameraRenderThread(
      VirtualCameraSessionContext& sessionContext, Resolution inputSurfaceSize,
      Resolution reportedSensorSize,
      std::shared_ptr<
          ::aidl::android::hardware::camera::device::ICameraDeviceCallback>
          cameraDeviceCallback,
      bool testMode = false);

  ~VirtualCameraRenderThread();

  // Start rendering thread.
  void start();
  // Stop rendering thread.
  void stop();

  // Equeue capture task for processing on render thread.
  void enqueueTask(std::unique_ptr<ProcessCaptureRequestTask> task)
      EXCLUDES(mLock);

  // Flush all in-flight requests.
  void flush() EXCLUDES(mLock);

  // Returns input surface corresponding to "virtual camera sensor".
  sp<Surface> getInputSurface();

 private:
  std::unique_ptr<ProcessCaptureRequestTask> dequeueTask() EXCLUDES(mLock);

  // Rendering thread entry point.
  void threadLoop();

  // Process single capture request task (always called on render thread).
  void processCaptureRequest(const ProcessCaptureRequestTask& captureRequestTask);

  // Flush single capture request task returning the error status immediately.
  void flushCaptureRequest(const ProcessCaptureRequestTask& captureRequestTask);

  // TODO(b/301023410) - Refactor the actual rendering logic off this class for
  // easier testability.

  // Create thumbnail with specified size for current image.
  // The compressed image size is limited by 32KiB.
  // Returns vector with compressed thumbnail if successful,
  // empty vector otherwise.
  std::vector<uint8_t> createThumbnail(Resolution resolution, int quality);

  // Render current image to the BLOB buffer.
  // If fence is specified, this function will block until the fence is cleared
  // before writing to the buffer.
  // Always called on render thread.
  ndk::ScopedAStatus renderIntoBlobStreamBuffer(
      const int streamId, const int bufferId,
      const RequestSettings& requestSettings, sp<Fence> fence = nullptr);

  // Render current image to the YCbCr buffer.
  // If fence is specified, this function will block until the fence is cleared
  // before writing to the buffer.
  // Always called on render thread.
  ndk::ScopedAStatus renderIntoImageStreamBuffer(int streamId, int bufferId,
                                                 sp<Fence> fence = nullptr);

  // Render current image into provided EglFramebuffer.
  // If fence is specified, this function will block until the fence is cleared
  // before writing to the buffer.
  // Always called on the render thread.
  ndk::ScopedAStatus renderIntoEglFramebuffer(EglFrameBuffer& framebuffer,
                                              sp<Fence> fence = nullptr);

  // Camera callback
  const std::shared_ptr<
      ::aidl::android::hardware::camera::device::ICameraDeviceCallback>
      mCameraDeviceCallback;

  const Resolution mInputSurfaceSize;
  const Resolution mReportedSensorSize;
  const int mTestMode;

  VirtualCameraSessionContext& mSessionContext;

  std::thread mThread;

  // Blocking queue implementation.
  std::mutex mLock;
  std::deque<std::unique_ptr<ProcessCaptureRequestTask>> mQueue GUARDED_BY(mLock);
  std::condition_variable mCondVar;
  volatile bool mPendingExit GUARDED_BY(mLock);

  // EGL helpers - constructed and accessed only from rendering thread.
  std::unique_ptr<EglDisplayContext> mEglDisplayContext;
  std::unique_ptr<EglTextureProgram> mEglTextureYuvProgram;
  std::unique_ptr<EglTextureProgram> mEglTextureRgbProgram;
  std::unique_ptr<EglSurfaceTexture> mEglSurfaceTexture;

  std::promise<sp<Surface>> mInputSurfacePromise;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERARENDERTHREAD_H
