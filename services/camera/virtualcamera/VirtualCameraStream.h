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
#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASTREAM_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASTREAM_H

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <tuple>
#include <unordered_map>

#include "EGL/egl.h"
#include "aidl/android/hardware/camera/device/Stream.h"
#include "aidl/android/hardware/camera/device/StreamBuffer.h"
#include "android/hardware_buffer.h"
#include "util/EglFramebuffer.h"
#include "utils/Mutex.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Encapsulates buffer management for the set of buffers belonging to the single
// camera stream.
class VirtualCameraStream {
 public:
  VirtualCameraStream(
      const ::aidl::android::hardware::camera::device::Stream& stream);

  std::shared_ptr<AHardwareBuffer> importBuffer(
      const ::aidl::android::hardware::camera::device::StreamBuffer& streamBuffer);

  // Get AHardwareBuffer instance corresponding to StreamBuffer from camera AIDL.
  // In case this is the first occurrence of the buffer, this will perform mapping
  // and stores hardware buffer in cache for further use.
  //
  // Returns nullptr in case buffer cannot be mapped or retrieved from the cache.
  std::shared_ptr<AHardwareBuffer> getHardwareBuffer(int bufferId)
      EXCLUDES(mLock);

  std::shared_ptr<EglFrameBuffer> getEglFrameBuffer(const EGLDisplay eglDisplay,
                                                    int bufferId)
      EXCLUDES(mLock);

  // Un-maps the previously mapped buffer and removes it from the stream cache.
  // Returns true if removal is successful, false otherwise.
  bool removeBuffer(int bufferId) EXCLUDES(mLock);

  // Returns AIDL Stream instance containing configuration of this stream.
  ::aidl::android::hardware::camera::device::Stream getStreamConfig() const;

 private:
  std::shared_ptr<AHardwareBuffer> getHardwareBufferLocked(int bufferId)
      REQUIRES(mLock);

  const ::aidl::android::hardware::camera::device::Stream mStreamConfig;
  std::mutex mLock;

  // Cache for already mapped buffers, mapping bufferId -> AHardwareBuffer instance.
  std::unordered_map<int, std::shared_ptr<AHardwareBuffer>> mBuffers
      GUARDED_BY(mLock);

  using FramebufferMapKey = std::pair<int, EGLDisplay>;
  struct FramebufferMapKeyHash {
    std::size_t operator()(const FramebufferMapKey& key) const {
      return std::hash<int>{}(key.first) ^
             (std::hash<void*>{}(reinterpret_cast<void*>(key.second)) << 1);
    }
  };
  std::unordered_map<FramebufferMapKey, std::shared_ptr<EglFrameBuffer>,
                     FramebufferMapKeyHash>
      mEglFramebuffers GUARDED_BY(mLock);
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASTREAM_H
