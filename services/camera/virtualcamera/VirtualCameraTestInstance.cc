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

// #define LOG_NDEBUG 0
#define LOG_TAG "VirtualCameraTestInstance"

#include "VirtualCameraTestInstance.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <ratio>
#include <thread>

#include "GLES/gl.h"
#include "android/binder_auto_utils.h"
#include "android/native_window.h"
#include "log/log.h"
#include "util/EglDisplayContext.h"
#include "util/EglProgram.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::view::Surface;
using ::ndk::ScopedAStatus;

namespace {

std::shared_ptr<ANativeWindow> nativeWindowFromSurface(const Surface& surface) {
  ANativeWindow* nativeWindow = surface.get();
  if (nativeWindow != nullptr) {
    ANativeWindow_acquire(nativeWindow);
  }
  return std::shared_ptr<ANativeWindow>(nativeWindow, ANativeWindow_release);
}

std::chrono::nanoseconds getCurrentTimestamp() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
}

}  // namespace

TestPatternRenderer::TestPatternRenderer(
    std::shared_ptr<ANativeWindow> nativeWindow, int fps)
    : mFps(fps), mNativeWindow(nativeWindow) {
}

void TestPatternRenderer::start() {
  std::lock_guard<std::mutex> lock(mLock);
  if (mRunning.exchange(true, std::memory_order_relaxed)) {
    ALOGW("Render thread already started.");
    return;
  }
  mThread =
      std::thread(&TestPatternRenderer::renderThreadLoop, this, mNativeWindow);
}

void TestPatternRenderer::stop() {
  std::lock_guard<std::mutex> lock(mLock);
  if (!mRunning.exchange(false, std::memory_order_relaxed)) {
    ALOGW("Render thread already stopped.");
    return;
  }
  mThread.detach();
  mRunning = false;
}

void TestPatternRenderer::renderThreadLoop(
    std::shared_ptr<ANativeWindow> nativeWindow) {
  // Prevent destruction of this instance until the thread terminates.
  std::shared_ptr<TestPatternRenderer> thiz = shared_from_this();

  ALOGV("Starting test client render loop");

  EglDisplayContext eglDisplayContext(nativeWindow);
  EglTestPatternProgram testPatternProgram;

  const std::chrono::nanoseconds frameDuration(
      static_cast<uint64_t>(1e9 / mFps));

  std::chrono::nanoseconds lastFrameTs(0);
  int frameNumber = 0;
  while (mRunning) {
    // Wait for appropriate amount of time to meet configured FPS.
    std::chrono::nanoseconds ts = getCurrentTimestamp();
    std::chrono::nanoseconds currentDuration = ts - lastFrameTs;
    if (currentDuration < frameDuration) {
      std::this_thread::sleep_for(frameDuration - currentDuration);
    }

    // Render the test pattern and update timestamp.
    testPatternProgram.draw(ts);
    eglDisplayContext.swapBuffers();
    lastFrameTs = getCurrentTimestamp();
  }

  ALOGV("Terminating test client render loop");
}

VirtualCameraTestInstance::VirtualCameraTestInstance(const int fps)
    : mFps(fps) {
}

ScopedAStatus VirtualCameraTestInstance::onStreamConfigured(
    const int32_t streamId, const Surface& surface, const int32_t width,
    const int32_t height, const Format pixelFormat) {
  ALOGV("%s: streamId %d, %dx%d pixFmt=%s", __func__, streamId, width, height,
        toString(pixelFormat).c_str());

  std::lock_guard<std::mutex> lock(mLock);
  mRenderer = std::make_shared<TestPatternRenderer>(
      nativeWindowFromSurface(surface), mFps);
  mRenderer->start();

  return ScopedAStatus::ok();
}

ScopedAStatus VirtualCameraTestInstance::onProcessCaptureRequest(
    const int32_t /*in_streamId*/, const int32_t /*in_frameId*/) {
  return ScopedAStatus::ok();
}

ScopedAStatus VirtualCameraTestInstance::onStreamClosed(const int32_t streamId) {
  ALOGV("%s: streamId %d", __func__, streamId);

  std::lock_guard<std::mutex> lock(mLock);
  if (mRenderer != nullptr) {
    mRenderer->stop();
    mRenderer.reset();
  }
  return ScopedAStatus::ok();
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
