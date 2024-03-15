/*
 * Copyright 2023 The Android Open Source Project
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

#include <sys/types.h>

#include "system/graphics.h"
#define LOG_TAG "JpegUtilTest"

#include <array>
#include <cstdint>
#include <cstring>

#include "android/hardware_buffer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "jpeglib.h"
#include "util/JpegUtil.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

using testing::Eq;
using testing::Gt;
using testing::Optional;
using testing::VariantWith;

constexpr int kOutputBufferSize = 1024 * 1024;  // 1 MiB.
constexpr int kJpegQuality = 80;

// Create black YUV420 buffer for testing purposes.
std::shared_ptr<AHardwareBuffer> createHardwareBufferForTest(const int width,
                                                             const int height) {
  const AHardwareBuffer_Desc desc{.width = static_cast<uint32_t>(width),
                                  .height = static_cast<uint32_t>(height),
                                  .layers = 1,
                                  .format = AHARDWAREBUFFER_FORMAT_Y8Cb8Cr8_420,
                                  .usage = AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
                                  .stride = 0,
                                  .rfu0 = 0,
                                  .rfu1 = 0};

  AHardwareBuffer* hwBufferPtr;
  int status = AHardwareBuffer_allocate(&desc, &hwBufferPtr);
  if (status != NO_ERROR) {
    ALOGE(
        "%s: Failed to allocate hardware buffer for temporary framebuffer: %d",
        __func__, status);
    return nullptr;
  }

  std::shared_ptr<AHardwareBuffer> hwBuffer(hwBufferPtr,
                                            AHardwareBuffer_release);

  YCbCrLockGuard yCbCrLock(hwBuffer, AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN);
  const android_ycbcr& ycbr = (*yCbCrLock);

  uint8_t* y = reinterpret_cast<uint8_t*>(ycbr.y);
  for (int r = 0; r < height; r++) {
    memset(y + r * ycbr.ystride, 0x00, width);
  }

  uint8_t* cb = reinterpret_cast<uint8_t*>(ycbr.cb);
  uint8_t* cr = reinterpret_cast<uint8_t*>(ycbr.cr);
  for (int r = 0; r < height / 2; r++) {
    for (int c = 0; c < width / 2; c++) {
      cb[r * ycbr.cstride + c * ycbr.chroma_step] = 0xff / 2;
      cr[r * ycbr.cstride + c * ycbr.chroma_step] = 0xff / 2;
    }
  }

  return hwBuffer;
}

// Decode JPEG header, return image resolution on success or error message on error.
std::variant<std::string, Resolution> verifyHeaderAndGetResolution(
    const uint8_t* data, int size) {
  struct jpeg_decompress_struct ctx;
  struct jpeg_error_mgr jerr;

  struct DecompressionError {
    bool success = true;
    std::string error;
  } result;

  ctx.client_data = &result;

  ctx.err = jpeg_std_error(&jerr);
  ctx.err->error_exit = [](j_common_ptr cinfo) {
    reinterpret_cast<DecompressionError*>(cinfo->client_data)->success = false;
  };
  ctx.err->output_message = [](j_common_ptr cinfo) {
    char buffer[JMSG_LENGTH_MAX];
    (*cinfo->err->format_message)(cinfo, buffer);
    reinterpret_cast<DecompressionError*>(cinfo->client_data)->error = buffer;
    ALOGE("libjpeg error: %s", buffer);
  };

  jpeg_create_decompress(&ctx);
  jpeg_mem_src(&ctx, data, size);
  jpeg_read_header(&ctx, /*require_image=*/true);

  if (!result.success) {
    jpeg_destroy_decompress(&ctx);
    return result.error;
  }

  Resolution resolution(ctx.image_width, ctx.image_height);
  jpeg_destroy_decompress(&ctx);
  return resolution;
}

TEST(JpegUtil, roundToDctSize) {
  EXPECT_THAT(roundTo2DctSize(Resolution(640, 480)), Eq(Resolution(640, 480)));
  EXPECT_THAT(roundTo2DctSize(Resolution(5, 5)), Eq(Resolution(16, 16)));
  EXPECT_THAT(roundTo2DctSize(Resolution(32, 32)), Eq(Resolution(32, 32)));
  EXPECT_THAT(roundTo2DctSize(Resolution(33, 32)), Eq(Resolution(48, 32)));
  EXPECT_THAT(roundTo2DctSize(Resolution(32, 33)), Eq(Resolution(32, 48)));
}

class JpegUtilTest : public ::testing::Test {
 public:
  void SetUp() override {
    std::fill(mOutputBuffer.begin(), mOutputBuffer.end(), 0);
  }

 protected:
  std::optional<size_t> compress(int imageWidth, int imageHeight,
                                 std::shared_ptr<AHardwareBuffer> inBuffer) {
    return compressJpeg(imageWidth, imageHeight, kJpegQuality, inBuffer,
                        /*app1ExifData=*/{}, mOutputBuffer.size(),
                        mOutputBuffer.data());
  }

  std::array<uint8_t, kOutputBufferSize> mOutputBuffer;
};

TEST_F(JpegUtilTest, compressImageSizeAlignedWithDctSucceeds) {
  std::shared_ptr<AHardwareBuffer> inBuffer =
      createHardwareBufferForTest(640, 480);

  std::optional<size_t> compressedSize = compress(640, 480, inBuffer);

  EXPECT_THAT(compressedSize, Optional(Gt(0)));
  EXPECT_THAT(verifyHeaderAndGetResolution(mOutputBuffer.data(),
                                           compressedSize.value()),
              VariantWith<Resolution>(Resolution(640, 480)));
}

TEST_F(JpegUtilTest, compressImageSizeNotAlignedWidthDctSucceeds) {
  std::shared_ptr<AHardwareBuffer> inBuffer =
      createHardwareBufferForTest(640, 480);

  std::optional<size_t> compressedSize = compress(630, 470, inBuffer);

  EXPECT_THAT(compressedSize, Optional(Gt(0)));
  EXPECT_THAT(verifyHeaderAndGetResolution(mOutputBuffer.data(),
                                           compressedSize.value()),
              VariantWith<Resolution>(Resolution(630, 470)));
}

TEST_F(JpegUtilTest, compressImageWithBufferNotAlignedWithDctFails) {
  std::shared_ptr<AHardwareBuffer> inBuffer =
      createHardwareBufferForTest(641, 480);

  std::optional<size_t> compressedSize = compress(640, 480, inBuffer);

  EXPECT_THAT(compressedSize, Eq(std::nullopt));
}

TEST_F(JpegUtilTest, compressImageWithBufferTooSmallFails) {
  std::shared_ptr<AHardwareBuffer> inBuffer =
      createHardwareBufferForTest(634, 464);

  std::optional<size_t> compressedSize = compress(640, 480, inBuffer);

  EXPECT_THAT(compressedSize, Eq(std::nullopt));
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
