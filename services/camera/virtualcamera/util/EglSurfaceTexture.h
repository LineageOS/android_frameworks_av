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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_EGLSURFACETEXTURE_H
#define ANDROID_COMPANION_VIRTUALCAMERA_EGLSURFACETEXTURE_H

#include <GLES/gl.h>
#include <gui/ConsumerBase.h>
#include <gui/Surface.h>
#include <utils/RefBase.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>

namespace android {

class GLConsumer;

namespace companion {
namespace virtualcamera {

// Encapsulates GLConsumer & Surface for rendering into EGL texture.
class EglSurfaceTexture {
 public:
  // Create new EGL Texture with specified size.
  EglSurfaceTexture(uint32_t width, uint32_t height);
  ~EglSurfaceTexture();

  // Get Surface backing up the texture.
  sp<Surface> getSurface();

  // Get GraphicBuffer backing the current texture.
  sp<GraphicBuffer> getCurrentBuffer();

  // Get width of surface / texture.
  uint32_t getWidth() const;

  // Get height of surface / texture.
  uint32_t getHeight() const;

  // Wait for next frame to be available in the surface
  // until timeout.
  //
  // Returns false on timeout, true if new frame was received before timeout.
  bool waitForNextFrame(std::chrono::nanoseconds timeout);

  // Interrupt any ongoing wait for a new frame.
  void interruptWait();

  void setFrameAvailableListener(const std::function<void()>& listener);

  // Update the texture with the most recent submitted buffer.
  // Must be called on thread with EGL context.
  //
  // Returns EGL texture id of the texture.
  GLuint updateTexture();

  // Returns EGL texture id of the underlying texture.
  GLuint getTextureId() const;

  // Returns 4x4 transformation matrix in column-major order,
  // which should be applied to EGL texture coordinates
  // before sampling from the texture backed by android native buffer,
  // so the corresponding region of the underlying buffer is sampled.
  //
  // See SurfaceTexture.getTransformMatrix for more details.
  std::array<float, 16> getTransformMatrix();

  // Retrieves the timestamp associated with the texture image
  // set by the most recent call to updateTexture.
  std::chrono::nanoseconds getTimestamp() const;

  // Returns true is a frame has ever been drawn on this surface.
  bool isFirstFrameDrawn();

  class FrameAvailableListenerProxy
      : public ConsumerBase::FrameAvailableListener {
   public:
    FrameAvailableListenerProxy(EglSurfaceTexture* surface);

    void setCallback(const std::function<void()>& callback);

    virtual void onFrameAvailable(const BufferItem&) override;

   private:
    EglSurfaceTexture& mSurface;
    std::function<void()> mOnFrameAvailableCallback;
  };

 private:
  sp<GLConsumer> mGlConsumer;
  sp<Surface> mSurface;
  GLuint mTextureId;
  const uint32_t mWidth;
  const uint32_t mHeight;
  std::atomic_long mLastWaitedFrame = 0;
  sp<FrameAvailableListenerProxy> mFrameAvailableListenerProxy;
  sp<ConsumerBase::FrameAvailableListener> mFrameAvailableListener;
  std::condition_variable mFrameAvailableCondition;
  std::mutex mWaitForFrameMutex;
  bool mInterruptWait GUARDED_BY(mWaitForFrameMutex) = false;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_EGLSURFACETEXTURE_H
