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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_EGLFRAMEBUFFER_H
#define ANDROID_COMPANION_VIRTUALCAMERA_EGLFRAMEBUFFER_H

#define EGL_EGLEXT_PROTOTYPES
#define GL_GLEXT_PROTOTYPES

#include <memory>

#include "EGL/egl.h"
#include "EGL/eglext.h"
#include "GLES/gl.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Encapsulates EGL Framebuffer backed by AHardwareBuffer instance.
//
// Note that the framebuffer is tied to EGLDisplay connection.
class EglFrameBuffer {
 public:
  EglFrameBuffer(EGLDisplay display, std::shared_ptr<AHardwareBuffer> hwBuffer);
  virtual ~EglFrameBuffer();

  // Prepare for rendering into the framebuffer.
  bool beforeDraw();

  // Finishes rendering into the framebuffer.
  bool afterDraw();

  // Return width of framebuffer (in pixels).
  int getWidth() const;

  // Return height of framebuffer (in pixels).
  int getHeight() const;

  // Return underlying hardware buffer.
  std::shared_ptr<AHardwareBuffer> getHardwareBuffer();

 private:
  // Keeping shared_ptr to hardware buffer instance here prevents it from being
  // freed while tied to EGL framebufer / EGL texture.
  std::shared_ptr<AHardwareBuffer> mHardwareBuffer;
  EGLDisplay mEglDisplay;
  EGLImageKHR mEglImageKhr{EGL_NO_IMAGE_KHR};
  GLuint mTextureId;
  GLuint mFramebufferId;

  int mWidth;
  int mHeight;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_EGLFRAMEBUFFER_H
