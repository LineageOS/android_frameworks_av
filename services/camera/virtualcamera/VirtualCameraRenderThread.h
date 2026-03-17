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

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <thread>
#include <variant>
#include <vector>

#include "VirtualCameraCaptureRequest.h"
#include "VirtualCameraImageHandler.h"
#include "VirtualCameraSessionContext.h"
#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/ICameraDeviceCallback.h"
#include "gui/Surface.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

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

struct UpdateTextureTask {};

// Variant holding either a ProcessCaptureRequestTask or UpdateTextureTask
// used to mix both type of task in the rendering queue
struct RenderThreadTask
    : public std::variant<std::unique_ptr<ProcessCaptureRequestTask>,
                          UpdateTextureTask> {
  // Allow implicit conversion to bool.
  //
  // Returns false, if the RenderThreadTask consists of a null
  // ProcessCaptureRequestTask, which signals that the thread should terminate.
  operator bool() const {
    const bool isExitSignal =
        std::holds_alternative<std::unique_ptr<ProcessCaptureRequestTask>>(
            *this) &&
        std::get<std::unique_ptr<ProcessCaptureRequestTask>>(*this) == nullptr;
    return !isExitSignal;
  }
};

// Wraps dedicated rendering thread and rendering business with corresponding
// input surface.
class VirtualCameraRenderThread {
 public:
  // Create VirtualCameraRenderThread instance:
  // * sessionContext - VirtualCameraSessionContext reference for shared access
  // to mapped buffers.
  // * inputSurfaceIndex - index of the input surface.
  // * imageFormat - image format of the input surface
  // * inputSurfaceSize - requested size of input surface.
  // * reportedSensorSize - reported static sensor size of virtual camera.
  // * cameraDeviceCallback - callback for corresponding camera instance
  // before each capture request is processed to simulate client input.
  VirtualCameraRenderThread(
      VirtualCameraSessionContext& sessionContext, int inputSurfaceIndex,
      ::aidl::android::companion::virtualcamera::Format imageFormat,
      Resolution inputSurfaceSize, Resolution reportedSensorSize,
      std::shared_ptr<
          ::aidl::android::hardware::camera::device::ICameraDeviceCallback>
          cameraDeviceCallback);

  ~VirtualCameraRenderThread();

  // Start rendering thread.
  bool start();
  // Stop rendering thread.
  void stop();

  // Send request to render thread to update the texture.
  // Currently queued buffers in the input surface will be consumed and the most
  // recent buffer in the input surface will be attached to the texture), all
  // other buffers will be returned to the buffer queue.
  void requestTextureUpdate() EXCLUDES(mLock);

  // Enqueue capture task for processing on render thread.
  void enqueueTask(std::unique_ptr<ProcessCaptureRequestTask> task)
      EXCLUDES(mLock);

  // Flush all in-flight requests up to frameNumber (inclusive).
  void flush(int frameNumber = -1) EXCLUDES(mLock);

  // Returns input surface corresponding to "virtual camera sensor".
  sp<Surface> getInputSurface();

  // Returns image format of the input surface
  ::aidl::android::companion::virtualcamera::Format getImageFormat() const;

  // Returns resolution of the input stream
  const Resolution& getInputResolution() const;

 private:
  RenderThreadTask dequeueTask() EXCLUDES(mLock);

  // Rendering thread entry point.
  void threadLoop();

  // Process single capture request task (always called on render thread).
  void processCaptureRequest(const ProcessCaptureRequestTask& captureRequestTask);

  // Complete the capture request with a recoverable error result.
  // This is used for timeouts, early exits, and during session flushing.
  void completeCaptureRequestWithError(
      const ProcessCaptureRequestTask& captureRequestTask);

  // Throttle the current thread to ensure that we are not rendering faster than
  // the virtual camera maxFps.
  // maxFps: The maximum fps in the capture request
  // lastAcquisitionTimestamp: timestamp of the previous frame
  void throttleRendering(int maxFps,
                         std::chrono::nanoseconds lastAcquisitionTimestamp);

  // Build a default capture result object populating the metadata from the request.
  std::unique_ptr<::aidl::android::hardware::camera::device::CaptureResult>
  createCaptureResult(
      int frameNumber,
      std::unique_ptr<aidl::android::hardware::camera::device::CameraMetadata>
          metadata);

  // Renders the images from the input surface into the request's buffers.
  void renderOutputBuffers(
      const ProcessCaptureRequestTask& request,
      ::aidl::android::hardware::camera::device::CaptureResult& captureResult);

  // Notify a shutter event for all the buffers in this request.
  //
  // isFrameProcessed: if true, that frame has already been processed once, so
  // shutter should not be notified, only buffer errors.
  ::ndk::ScopedAStatus notifyShutter(
      const ProcessCaptureRequestTask& request,
      const ::aidl::android::hardware::camera::device::CaptureResult& captureResult,
      std::chrono::nanoseconds captureTimestamp, bool isFrameProcessed);

  // Notify a timeout error for this request. The capture result still needs to
  // be submitted after this call.
  ::ndk::ScopedAStatus notifyTimeout(
      const ProcessCaptureRequestTask& request,
      ::aidl::android::hardware::camera::device::CaptureResult& captureResult);

  // Submit the capture result to the camera callback.
  ::ndk::ScopedAStatus submitCaptureResult(
      std::unique_ptr<::aidl::android::hardware::camera::device::CaptureResult>
          captureResult);

  // Returns true if mImageHandler initialized successfully. False otherwise
  bool initializeImageHandler();

  // Camera callback
  const std::shared_ptr<
      ::aidl::android::hardware::camera::device::ICameraDeviceCallback>
      mCameraDeviceCallback;

  const ::aidl::android::companion::virtualcamera::Format mImageFormat;
  const Resolution mInputSurfaceSize;
  const Resolution mReportedSensorSize;
  const int mInputSurfaceIndex;

  VirtualCameraSessionContext& mSessionContext;

  std::thread mThread;

  // Blocking queue implementation.
  std::mutex mLock;

  std::deque<std::unique_ptr<ProcessCaptureRequestTask>> mCaptureRequestQueue
      GUARDED_BY(mLock);
  std::condition_variable mTaskReadyCondVar;
  std::condition_variable mThrottlingCondVar;
  volatile bool GUARDED_BY(mLock) mTextureUpdateRequested = false;
  volatile bool GUARDED_BY(mLock) mPendingExit = false;

  // Number of consecutive timeouts.
  std::atomic<int> mWaitInputFrameTimeoutsCount{0};

  // Keeps track of the currently processed frame number.
  std::atomic<int> mProcessingFrameNumber{-1};
  std::atomic<int> mMaxFrameToFlush{-1};

  // Acquisition timestamp of last frame.
  std::atomic<uint64_t> mLastAcquisitionTimestampNanoseconds;

  std::unique_ptr<VirtualCameraImageHandler> mImageHandler;

  std::promise<bool> mImageHandlerInitialized;
  std::promise<sp<Surface>> mInputSurfacePromise;
  std::shared_future<sp<Surface>> mInputSurfaceFuture;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERARENDERTHREAD_H
