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

#include "VirtualCameraSessionContext.h"

#include <memory>
#include <mutex>
#include <unordered_set>

#include "VirtualCameraStream.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::hardware::camera::device::BufferCache;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamBuffer;
using ::aidl::android::hardware::camera::device::StreamConfiguration;

bool VirtualCameraSessionContext::initializeStream(
    const ::aidl::android::hardware::camera::device::Stream& stream) {
  std::lock_guard<std::mutex> lock(mLock);

  auto s = std::make_unique<VirtualCameraStream>(stream);

  const auto& [_, newlyInserted] = mStreams.emplace(
      std::piecewise_construct, std::forward_as_tuple(stream.id),
      std::forward_as_tuple(std::move(s)));
  return newlyInserted;
}

void VirtualCameraSessionContext::closeAllStreams() {
  std::lock_guard<std::mutex> lock(mLock);
  mStreams.clear();
}

bool VirtualCameraSessionContext::importBuffersFromCaptureRequest(
    const ::aidl::android::hardware::camera::device::CaptureRequest&
        captureRequest) {
  std::lock_guard<std::mutex> lock(mLock);

  for (const StreamBuffer& buffer : captureRequest.outputBuffers) {
    auto it = mStreams.find(buffer.streamId);
    if (it == mStreams.end()) {
      ALOGE("%s: Cannot import buffer for unknown stream with id %d", __func__,
            buffer.streamId);
      return false;
    }
    VirtualCameraStream& stream = *it->second;
    if (stream.getHardwareBuffer(buffer.bufferId) != nullptr) {
      // This buffer is already imported.
      continue;
    }

    if (stream.importBuffer(buffer) == nullptr) {
      ALOGE("%s: Failed to import buffer %" PRId64 " for streamId %d", __func__,
            buffer.bufferId, buffer.streamId);
      return false;
    }
  }

  return true;
}

void VirtualCameraSessionContext::removeBufferCaches(
    const std::vector<BufferCache>& cachesToRemove) {
  std::lock_guard<std::mutex> lock(mLock);
  for (const auto& bufferCache : cachesToRemove) {
    auto it = mStreams.find(bufferCache.streamId);
    if (it == mStreams.end()) {
      ALOGE("%s: Ask to remove buffer %" PRId64 " from unknown stream %d",
            __func__, bufferCache.bufferId, bufferCache.streamId);
      continue;
    }
    if (it->second->removeBuffer(bufferCache.bufferId)) {
      ALOGD("%s: Successfully removed buffer %" PRId64
            " from cache of stream %d",
            __func__, bufferCache.bufferId, bufferCache.streamId);
    } else {
      ALOGE("%s: Failed to remove buffer %" PRId64 " from cache of stream %d",
            __func__, bufferCache.bufferId, bufferCache.streamId);
    }
  }
}

void VirtualCameraSessionContext::removeStreamsNotInStreamConfiguration(
    const StreamConfiguration& streamConfiguration) {
  std::unordered_set<int> newConfigurationStreamIds;
  for (const Stream& stream : streamConfiguration.streams) {
    newConfigurationStreamIds.insert(stream.id);
  }

  std::lock_guard<std::mutex> lock(mLock);
  for (auto it = mStreams.begin(); it != mStreams.end();) {
    if (newConfigurationStreamIds.find(it->first) ==
        newConfigurationStreamIds.end()) {
      ALOGV(
          "Disposing of stream %d, since it is not referenced by new "
          "configuration.",
          it->first);
      it = mStreams.erase(it);
    } else {
      ++it;
    }
  }
}

std::optional<Stream> VirtualCameraSessionContext::getStreamConfig(
    int streamId) const {
  std::lock_guard<std::mutex> lock(mLock);
  auto it = mStreams.find(streamId);
  if (it == mStreams.end()) {
    ALOGE("%s: StreamBuffer references buffer of unknown streamId %d", __func__,
          streamId);
    return std::optional<Stream>();
  }
  VirtualCameraStream& stream = *it->second;
  return {stream.getStreamConfig()};
}

std::shared_ptr<AHardwareBuffer> VirtualCameraSessionContext::fetchHardwareBuffer(
    const int streamId, const int bufferId) const {
  std::lock_guard<std::mutex> lock(mLock);
  auto it = mStreams.find(streamId);
  if (it == mStreams.end()) {
    ALOGE("%s: StreamBuffer references buffer of unknown streamId %d", __func__,
          streamId);
    return nullptr;
  }
  VirtualCameraStream& stream = *it->second;
  return stream.getHardwareBuffer(bufferId);
}

std::shared_ptr<EglFrameBuffer>
VirtualCameraSessionContext::fetchOrCreateEglFramebuffer(
    const EGLDisplay eglDisplay, const int streamId, const int bufferId) {
  std::lock_guard<std::mutex> lock(mLock);
  auto it = mStreams.find(streamId);
  if (it == mStreams.end()) {
    ALOGE("%s: StreamBuffer references buffer of unknown streamId %d", __func__,
          streamId);
    return nullptr;
  }
  VirtualCameraStream& stream = *it->second;
  return stream.getEglFrameBuffer(eglDisplay, bufferId);
}

std::set<int> VirtualCameraSessionContext::getStreamIds() const {
  std::set<int> result;
  std::lock_guard<std::mutex> lock(mLock);
  for (const auto& [streamId, _] : mStreams) {
    result.insert(streamId);
  }
  return result;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
