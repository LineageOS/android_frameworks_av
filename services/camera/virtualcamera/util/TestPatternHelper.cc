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

#define LOG_TAG "TestPatternHelper"

#include "TestPatternHelper.h"

#include <complex>
#include <cstdint>

#include "log/log.h"
#include "nativebase/nativebase.h"
#include "system/graphics.h"
#include "ui/GraphicBuffer.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

namespace {

using namespace std::chrono_literals;

static constexpr std::chrono::milliseconds kAcquireFenceTimeout = 500ms;

uint8_t julia(const std::complex<float> n, const std::complex<float> c) {
  std::complex<float> z = n;
  for (int i = 0; i < 64; i++) {
    z = z * z + c;
    if (std::abs(z) > 2.0) return i * 4;
  }
  return 0xff;
}

uint8_t pixelToFractal(const int x, const int y, const int width,
                       const int height, const std::complex<float> c) {
  std::complex<float> n(float(x) / float(width) - 0.5,
                        float(y) / float(height) - 0.5);
  return julia(n * 5.f, c);
}

void renderTestPatternYcbCr420(const android_ycbcr& ycbr, const int width,
                               const int height, const int frameNumber) {
  float time = float(frameNumber) / 120.0f;
  const std::complex<float> c(std::sin(time), std::cos(time));

  uint8_t* y = reinterpret_cast<uint8_t*>(ycbr.y);
  uint8_t* cb = reinterpret_cast<uint8_t*>(ycbr.cb);
  uint8_t* cr = reinterpret_cast<uint8_t*>(ycbr.cr);

  for (int row = 0; row < height; row++) {
    for (int col = 0; col < width; col++) {
      y[row * ycbr.ystride + col] =
          pixelToFractal(col, row, width, height, c * 0.78f);
    }
  }

  int cWidth = width / 2;
  int cHeight = height / 2;
  for (int row = 0; row < cHeight; row++) {
    for (int col = 0; col < cWidth; col++) {
      cb[row * ycbr.cstride + col * ycbr.chroma_step] =
          static_cast<uint8_t>((float(col) / float(cWidth)) * 255.f);
      cr[row * ycbr.cstride + col * ycbr.chroma_step] =
          static_cast<uint8_t>((float(row) / float(cHeight)) * 255.f);
    }
  }
}

}  // namespace

void renderTestPatternYCbCr420(sp<Surface> surface, int frameNumber) {
  if (surface == nullptr) {
    ALOGE("%s: null surface, skipping render", __func__);
    return;
  }

  ANativeWindowBuffer* buffer;
  int fenceFd;
  int ret = ANativeWindow_dequeueBuffer(surface.get(), &buffer, &fenceFd);
  if (ret != NO_ERROR) {
    ALOGE(
        "%s: Error while deuqueing buffer from surface, "
        "ANativeWindow_dequeueBuffer returned %d",
        __func__, ret);
    return;
  }

  if (buffer == nullptr) {
    ALOGE("%s: ANativeWindowBuffer is null after dequeing", __func__);
    return;
  }

  sp<Fence> fence = sp<Fence>::make(fenceFd);
  if (fence->isValid()) {
    ret = fence->wait(kAcquireFenceTimeout.count());
    if (ret != NO_ERROR) {
      ALOGE("%s: Timeout while waiting for the fence to clear", __func__);
      ANativeWindow_queueBuffer(surface.get(), buffer, fence->dup());
      return;
    }
  }

  sp<GraphicBuffer> gBuffer = GraphicBuffer::from(buffer);
  android_ycbcr ycbr;

  ret = gBuffer->lockAsyncYCbCr(GraphicBuffer::USAGE_SW_WRITE_OFTEN, &ycbr,
                                fence->dup());
  if (ret != NO_ERROR) {
    ALOGE("%s: Failed to lock buffer retrieved from surface, ret %d", __func__,
          ret);
    return;
  }

  renderTestPatternYcbCr420(ycbr, gBuffer->getWidth(), gBuffer->getHeight(),
                            frameNumber);

  ret = gBuffer->unlock();
  if (ret != NO_ERROR) {
    ALOGE("%s: Failed to unlock buffer, ret %d", __func__, ret);
    return;
  }

  ret = ANativeWindow_queueBuffer(surface.get(), buffer, /*fenceFd=*/-1);
  if (ret != NO_ERROR) {
    ALOGE(
        "%s: Error while queing buffer to surface, ANativeWindow_queueBuffer "
        "returned %d",
        __func__, ret);
    return;
  }
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
