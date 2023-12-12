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
#define LOG_TAG "EglFramebuffer"
#include "EglFramebuffer.h"

#include "EGL/eglext.h"
#include "EglUtil.h"
#include "GLES/gl.h"
#include "GLES2/gl2.h"
#include "GLES2/gl2ext.h"
#include "android/hardware_buffer.h"
#include "log/log.h"

namespace android {
namespace companion {
namespace virtualcamera {

EglFrameBuffer::EglFrameBuffer(EGLDisplay display,
                               std::shared_ptr<AHardwareBuffer> hwBuffer)
    : mHardwareBuffer(hwBuffer), mEglDisplay(display) {
  if (hwBuffer == nullptr) {
    ALOGE("Cannot construct EglFramebuffer from null hwBuffer");
    return;
  }

  AHardwareBuffer_Desc hwBufferDesc;
  AHardwareBuffer_describe(hwBuffer.get(), &hwBufferDesc);
  mWidth = hwBufferDesc.width;
  mHeight = hwBufferDesc.height;

  EGLClientBuffer clientBuffer = eglGetNativeClientBufferANDROID(hwBuffer.get());
  mEglImageKhr = eglCreateImageKHR(display, EGL_NO_CONTEXT,
                                   EGL_NATIVE_BUFFER_ANDROID, clientBuffer, 0);
  if (checkEglError("eglCreateImageKHR")) {
    return;
  }

  // Create texture backed by the hardware buffer.
  glGenTextures(1, &mTextureId);
  glBindTexture(GL_TEXTURE_EXTERNAL_OES, mTextureId);
  glEGLImageTargetTexture2DOES(GL_TEXTURE_EXTERNAL_OES,
                               (GLeglImageOES)mEglImageKhr);
  if (checkEglError("configure external texture")) {
    return;
  }

  // Create framebuffer backed by the texture.
  glGenFramebuffers(1, &mFramebufferId);
  glBindFramebuffer(GL_FRAMEBUFFER, mFramebufferId);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                         GL_TEXTURE_EXTERNAL_OES, mTextureId, 0);
  GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
  if (status != GL_FRAMEBUFFER_COMPLETE) {
    ALOGE("Failed to configure framebuffer for texture");
    return;  // false;
  }
  if (checkEglError("glCheckFramebufferStatus")) {
    return;  // false;
  }
}

EglFrameBuffer::~EglFrameBuffer() {
  if (mFramebufferId != 0) {
    glDeleteFramebuffers(1, &mFramebufferId);
  }
  if (mTextureId != 0) {
    glDeleteTextures(1, &mTextureId);
  }
  if (mEglImageKhr != EGL_NO_IMAGE_KHR) {
    eglDestroyImageKHR(mEglDisplay, mEglDisplay);
  }
}

bool EglFrameBuffer::beforeDraw() {
  glBindFramebuffer(GL_FRAMEBUFFER, mFramebufferId);
  if (checkEglError("glBindFramebuffer")) {
    return false;
  }

  glViewport(0, 0, mWidth, mHeight);

  return true;
}

bool EglFrameBuffer::afterDraw() {
  glFinish();
  glBindFramebuffer(GL_FRAMEBUFFER, 0);
  glBindTexture(GL_TEXTURE_EXTERNAL_OES, 0);
  return true;
}

int EglFrameBuffer::getWidth() const {
  return mWidth;
}

int EglFrameBuffer::getHeight() const {
  return mHeight;
}

std::shared_ptr<AHardwareBuffer> EglFrameBuffer::getHardwareBuffer() {
  return mHardwareBuffer;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
