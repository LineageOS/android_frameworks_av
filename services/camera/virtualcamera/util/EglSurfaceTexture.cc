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

#include <cstdint>

#include "EglSurfaceTexture.h"
#include "EglUtil.h"
#include "GLES/gl.h"
#include "gui/BufferQueue.h"
#include "gui/GLConsumer.h"
#include "gui/IGraphicBufferProducer.h"
#include "hardware/gralloc.h"

namespace android {
namespace companion {
namespace virtualcamera {

namespace {

void submitBlackBufferYCbCr420(Surface& surface) {
    ANativeWindow_Buffer buffer;

    int ret = surface.lock(&buffer, nullptr);
    if (ret != NO_ERROR) {
        ALOGE("%s: Cannot lock output surface: %d", __func__, ret);
        return;
    }
    uint8_t* data = reinterpret_cast<uint8_t*>(buffer.bits);
    const int yPixNr = buffer.width * buffer.height;
    const int uvPixNr = (buffer.width / 2) * (buffer.height / 2);
    memset(data, 0x00, yPixNr);
    memset(data + yPixNr, 0x7f, 2 * uvPixNr);
    surface.unlockAndPost();
}

}  // namespace

EglSurfaceTexture::EglSurfaceTexture(const uint32_t width, const uint32_t height)
    : mWidth(width), mHeight(height) {
  glGenTextures(1, &mTextureId);
  if (checkEglError("EglSurfaceTexture(): glGenTextures")) {
    ALOGE("Failed to generate texture");
    return;
  }
  BufferQueue::createBufferQueue(&mBufferProducer, &mBufferConsumer);
  mGlConsumer = sp<GLConsumer>::make(
      mBufferConsumer, mTextureId, GLConsumer::TEXTURE_EXTERNAL, false, false);
  mGlConsumer->setName(String8("VirtualCameraEglSurfaceTexture"));
  mGlConsumer->setDefaultBufferSize(mWidth, mHeight);
  mGlConsumer->setConsumerUsageBits(GRALLOC_USAGE_HW_TEXTURE);
  mGlConsumer->setDefaultBufferFormat(AHARDWAREBUFFER_FORMAT_Y8Cb8Cr8_420);

  mSurface = sp<Surface>::make(mBufferProducer);
  // Submit black buffer to the surface to make sure there's input buffer
  // to process in case capture request comes before client writes something
  // to the surface.
  //
  // Note that if the client does write something before capture request is
  // processed (& updateTexture is called), this black buffer will be
  // skipped (and recycled).
  submitBlackBufferYCbCr420(*mSurface);
}

EglSurfaceTexture::~EglSurfaceTexture() {
  if (mTextureId != 0) {
    glDeleteTextures(1, &mTextureId);
  }
}

sp<Surface> EglSurfaceTexture::getSurface() {
  return mSurface;
}

sp<GraphicBuffer> EglSurfaceTexture::getCurrentBuffer() {
  return mGlConsumer->getCurrentBuffer();
}

GLuint EglSurfaceTexture::updateTexture() {
  mGlConsumer->updateTexImage();
  return mTextureId;
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
