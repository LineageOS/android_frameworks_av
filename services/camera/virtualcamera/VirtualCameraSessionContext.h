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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASESSIONCONTEXT_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASESSIONCONTEXT_H

#include <map>
#include <memory>
#include <mutex>
#include <set>

#include "VirtualCameraStream.h"
#include "aidl/android/hardware/camera/device/BufferCache.h"
#include "aidl/android/hardware/camera/device/CaptureRequest.h"
#include "aidl/android/hardware/camera/device/Stream.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Encapsulates set of streams belonging to the same camera session.
class VirtualCameraSessionContext {
 public:
  // (Re)initialize the stream.
  //
  // Returns true if the stream is initialized for the first time.
  bool initializeStream(
      const ::aidl::android::hardware::camera::device::Stream& stream)
      EXCLUDES(mLock);

  // Close all streams and free all asociated buffers.
  void closeAllStreams() EXCLUDES(mLock);

  // Remove no longer needed buffers.
  void removeBufferCaches(
      const std::vector<::aidl::android::hardware::camera::device::BufferCache>&
          cachesToRemove) EXCLUDES(mLock);

  // Remove all streams not referenced by provided configuration.
  void removeStreamsNotInStreamConfiguration(
      const ::aidl::android::hardware::camera::device::StreamConfiguration&
          streamConfiguration) EXCLUDES(mLock);

  // Importored all not-yet imported buffers referenced by the capture request.
  bool importBuffersFromCaptureRequest(
      const ::aidl::android::hardware::camera::device::CaptureRequest&
          captureRequest) EXCLUDES(mLock);

  // Get stream configuration for provided stream id.
  // Returns nullopt in case there's no stream with provided stream id.
  std::optional<::aidl::android::hardware::camera::device::Stream>
  getStreamConfig(int streamId) const EXCLUDES(mLock);

  // Get hardware buffer for provided streamId & bufferId.
  // Returns nullptr in case there's no such buffer.
  std::shared_ptr<AHardwareBuffer> fetchHardwareBuffer(int streamId,
                                                       int bufferId) const
      EXCLUDES(mLock);

  // Get EGL framebuffer for provided EGL display, streamId & buffer id.
  //
  // This will also lazily create EglFrameBuffer for the provided EGLDisplay
  // connection and will cache it (subsequent calls for same EGLDisplay and
  // buffer will return same instance of EglFrameBuffer).
  //
  // Returns nullptr in case there's no such buffer or it was not possible
  // to create EglFrameBuffer.
  std::shared_ptr<EglFrameBuffer> fetchOrCreateEglFramebuffer(
      const EGLDisplay eglDisplay, int streamId, int bufferId) EXCLUDES(mLock);

  // Returns set of all stream ids managed by this instance.
  std::set<int> getStreamIds() const EXCLUDES(mLock);

 private:
  mutable std::mutex mLock;
  // streamId -> VirtualCameraStream mapping.
  std::map<int, std::unique_ptr<VirtualCameraStream>> mStreams GUARDED_BY(mLock);
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASESSIONCONTEXT_H
