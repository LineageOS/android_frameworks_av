/*
 * Copyright (C) 2024 The Android Open Source Project
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
#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERATESTINSTANCE_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERATESTINSTANCE_H

#include <atomic>
#include <condition_variable>
#include <memory>
#include <thread>

#include "aidl/android/companion/virtualcamera/BnVirtualCameraCallback.h"
#include "android/native_window.h"
#include "utils/Mutex.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Wraps render loop run in a dedicated thread, rendering test pattern to
// provided Surface (a.k.a. native window) at configured FPS.
class TestPatternRenderer
    : public std::enable_shared_from_this<TestPatternRenderer> {
 public:
  TestPatternRenderer(std::shared_ptr<ANativeWindow> nativeWindow, int fps);

  // Start rendering.
  void start() EXCLUDES(mLock);

  // Stop rendering.
  // Call returns immediatelly, render thread might take some time (1 frame)
  // to finish rendering and terminate the thread.
  void stop() EXCLUDES(mLock);

 private:
  // Render thread entry point.
  void renderThreadLoop(std::shared_ptr<ANativeWindow> nativeWindow);

  const int mFps;

  std::shared_ptr<ANativeWindow> mNativeWindow;

  std::mutex mLock;
  std::atomic_bool mRunning;
  std::thread mThread GUARDED_BY(mLock);
};

// VirtualCamera callback implementation for test camera.
//
// For every configure call, starts rendering of test pattern on provided surface.
class VirtualCameraTestInstance
    : public aidl::android::companion::virtualcamera::BnVirtualCameraCallback {
 public:
  explicit VirtualCameraTestInstance(int fps = 30);

  ::ndk::ScopedAStatus onStreamConfigured(
      int32_t streamId, const ::aidl::android::view::Surface& surface,
      int32_t width, int32_t height,
      ::aidl::android::companion::virtualcamera::Format pixelFormat) override
      EXCLUDES(mLock);

  ::ndk::ScopedAStatus onProcessCaptureRequest(int32_t in_streamId,
                                               int32_t in_frameId) override;

  ::ndk::ScopedAStatus onStreamClosed(int32_t streamId) override EXCLUDES(mLock);

 private:
  const int mFps;

  std::mutex mLock;
  std::shared_ptr<TestPatternRenderer> mRenderer GUARDED_BY(mLock);
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERATESTINSTANCE_H
