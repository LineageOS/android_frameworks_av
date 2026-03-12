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

// #define LOG_NDEBUG 0
#define LOG_TAG "EglSurfaceTexture"

#include "EglSurfaceTexture.h"

#include <GLES/gl.h>
#include <com_android_graphics_libgui_flags.h>
#include <gui/BufferQueue.h>
#include <gui/GLConsumer.h>
#include <hardware/gralloc.h>

#include <chrono>
#include <cstdint>
#include <mutex>

#include "EglUtil.h"
#include "android-base/thread_annotations.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

// Maximal number of buffers producer can dequeue without blocking.
constexpr int kBufferProducerMaxDequeueBufferCount = 4;

}  // namespace

EglSurfaceTexture::FrameAvailableListenerProxy::FrameAvailableListenerProxy(
    EglSurfaceTexture* surface)
    : mSurface(*surface) {
}

void EglSurfaceTexture::FrameAvailableListenerProxy::setCallback(
    const std::function<void()>& callback) {
  mOnFrameAvailableCallback = callback;
}

void EglSurfaceTexture::FrameAvailableListenerProxy::onFrameAvailable(
    const BufferItem&) {
  mSurface.mFrameAvailableCondition.notify_all();
  if (mOnFrameAvailableCallback) {
    mOnFrameAvailableCallback();
  }
}

EglSurfaceTexture::EglSurfaceTexture(const uint32_t width, const uint32_t height)
    : mWidth(width), mHeight(height) {
  glGenTextures(1, &mTextureId);
  if (checkEglError("EglSurfaceTexture(): glGenTextures")) {
    ALOGE("Failed to generate texture");
    return;
  }

  std::tie(mGlConsumer, mSurface) = GLConsumer::create(
      mTextureId, GLConsumer::TEXTURE_EXTERNAL, false, false);
  mGlConsumer->setName(String8("VirtualCameraEglSurfaceTexture"));
  mGlConsumer->setDefaultBufferSize(mWidth, mHeight);
  mGlConsumer->setConsumerUsageBits(GRALLOC_USAGE_HW_TEXTURE);
  mGlConsumer->setDefaultBufferFormat(AHARDWAREBUFFER_FORMAT_Y8Cb8Cr8_420);

  mSurface->setMaxDequeuedBufferCount(kBufferProducerMaxDequeueBufferCount);

  mFrameAvailableListenerProxy = sp<FrameAvailableListenerProxy>::make(this);
  mGlConsumer->setFrameAvailableListener(mFrameAvailableListenerProxy);
}

EglSurfaceTexture::~EglSurfaceTexture() {
  if (mTextureId != 0) {
    glDeleteTextures(1, &mTextureId);
  }
  mGlConsumer->abandon();
  mGlConsumer.clear();
  mSurface.clear();
}

sp<Surface> EglSurfaceTexture::getSurface() {
  return mSurface;
}

sp<GraphicBuffer> EglSurfaceTexture::getCurrentBuffer() {
  return mGlConsumer->getCurrentBuffer();
}

void EglSurfaceTexture::setFrameAvailableListener(
    const std::function<void()>& listener) {
  mFrameAvailableListenerProxy->setCallback(listener);
}

bool EglSurfaceTexture::waitForNextFrame(const std::chrono::nanoseconds timeout) {
  std::unique_lock<std::mutex> lock(mWaitForFrameMutex);
  base::ScopedLockAssertion lockAssertion(mWaitForFrameMutex);
  mInterruptWait = false;
  mGlConsumer->updateTexImage();
  const long lastRenderedFrame = mGlConsumer->getFrameNumber();
  const long lastWaitedForFrame = mLastWaitedFrame.exchange(lastRenderedFrame);
  ALOGV("%s lastRenderedFrame:%ld lastWaitedForFrame: %ld", __func__,
        lastRenderedFrame, lastWaitedForFrame);
  if (lastRenderedFrame > lastWaitedForFrame) {
    return true;
  }
  ALOGV(
      "%s waiting for max %lld ns. Last waited frame:%ld, last rendered "
      "frame:%ld",
      __func__, timeout.count(), lastWaitedForFrame, lastRenderedFrame);
  mFrameAvailableCondition.wait_for(lock, timeout, [this]() {
    base::ScopedLockAssertion lockAssertion(mWaitForFrameMutex);
    if (std::exchange(mInterruptWait, false)) {
      return true;
    }
    // Call updateTexImage to update the frame number.
    mGlConsumer->updateTexImage();
    const long lastRenderedFrame = mGlConsumer->getFrameNumber();
    return lastRenderedFrame > mLastWaitedFrame.exchange(lastRenderedFrame);
  });

  // If we were notified, we need to check if it was because of an interrupt
  // or because a new frame was available.
  return mGlConsumer->getFrameNumber() > lastWaitedForFrame;
}

void EglSurfaceTexture::interruptWait() {
  std::lock_guard<std::mutex> lock(mWaitForFrameMutex);
  mInterruptWait = true;
  mFrameAvailableCondition.notify_all();
}

std::chrono::nanoseconds EglSurfaceTexture::getTimestamp() const {
  return std::chrono::nanoseconds(mGlConsumer->getTimestamp());
}

bool EglSurfaceTexture::isFirstFrameDrawn() {
  return mGlConsumer->getFrameNumber() > 0;
}

GLuint EglSurfaceTexture::updateTexture() {
  int previousFrameId;
  int framesAdvance = 0;
  // Consume buffers one at the time.
  // Contrary to the code comments in GLConsumer, the GLConsumer acquires
  // next queued buffer (not the most recently queued buffer).
  while (true) {
    previousFrameId = mGlConsumer->getFrameNumber();
    mGlConsumer->updateTexImage();
    int currentFrameId = mGlConsumer->getFrameNumber();
    if (previousFrameId == currentFrameId) {
      // Frame number didn't change after updating the texture,
      // this means we're at the end of the queue and current attached
      // buffer is the most recent buffer.
      break;
    }

    framesAdvance++;
    previousFrameId = currentFrameId;
  }
  ALOGV("%s: Advanced %d frames", __func__, framesAdvance);
  return mTextureId;
}

GLuint EglSurfaceTexture::getTextureId() const {
  return mTextureId;
}

std::array<float, 16> EglSurfaceTexture::getTransformMatrix() {
  std::array<float, 16> matrix;
  mGlConsumer->getTransformMatrix(matrix.data());
  return matrix;
}

uint32_t EglSurfaceTexture::getWidth() const {
  return mWidth;
}

uint32_t EglSurfaceTexture::getHeight() const {
  return mHeight;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
