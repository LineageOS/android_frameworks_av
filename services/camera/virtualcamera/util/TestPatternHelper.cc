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
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {

namespace {

uint8_t julia(const std::complex<float> n, const std::complex<float> c) {
  std::complex<float> z = n;
  for (int i = 0; i < 64; i++) {
    z = z * z + c;
    if (std::abs(z) > 2.0) return i * 4;
  }
  return 0xff;
}

uint8_t pixelToFractal(const int x, const int y, const std::complex<float> c) {
  std::complex<float> n(float(x) / 640.0f - 0.5, float(y) / 480.0f - 0.5);
  return julia(n * 5.f, c);
}

void renderTestPatternYcbCr420(uint8_t* data_ptr, const int width,
                               const int height, const int frameNumber) {
  float time = float(frameNumber) / 120.0f;
  const std::complex<float> c(std::sin(time), std::cos(time));

  uint8_t* y_data = data_ptr;
  uint8_t* uv_data = static_cast<uint8_t*>(y_data + width * height);

  for (int i = 0; i < width; ++i) {
    for (int j = 0; j < height; ++j) {
      y_data[j * width + i] = pixelToFractal(i, j, c * 0.78f);
      if ((i & 1) && (j & 1)) {
        uv_data[((j / 2) * (width / 2) + i / 2) * 2] =
            static_cast<uint8_t>((float(i) / float(width)) * 255.f);
        uv_data[((j / 2) * (width / 2) + i / 2) * 2 + 1] =
            static_cast<uint8_t>((float(j) / float(height)) * 255.f);
      }
    }
  }
}

}  // namespace

// This is just to see some meaningfull image in the buffer for testing, only
// works with YcbCr420.
void renderTestPatternYCbCr420(const std::shared_ptr<AHardwareBuffer> buffer,
                               const int frameNumber, const int fence) {
  AHardwareBuffer_Planes planes_info;

  AHardwareBuffer_Desc hwBufferDesc;
  AHardwareBuffer_describe(buffer.get(), &hwBufferDesc);

  const int width = hwBufferDesc.width;
  const int height = hwBufferDesc.height;

  int result = AHardwareBuffer_lockPlanes(buffer.get(),
                                          AHARDWAREBUFFER_USAGE_CPU_READ_RARELY,
                                          fence, nullptr, &planes_info);
  if (result != OK) {
    ALOGE("%s: Failed to lock planes: %d", __func__, result);
    return;
  }

  renderTestPatternYcbCr420(
      reinterpret_cast<uint8_t*>(planes_info.planes[0].data), width, height,
      frameNumber);

  AHardwareBuffer_unlock(buffer.get(), nullptr);
}

void renderTestPatternYCbCr420(sp<Surface> surface, int frameNumber) {
  ANativeWindow_Buffer buffer;
  surface->lock(&buffer, nullptr);

  ALOGV("buffer: %dx%d stride %d, pixfmt %d", buffer.width, buffer.height,
        buffer.stride, buffer.format);

  renderTestPatternYcbCr420(reinterpret_cast<uint8_t*>(buffer.bits),
                            buffer.width, buffer.height, frameNumber);

  surface->unlockAndPost();
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
