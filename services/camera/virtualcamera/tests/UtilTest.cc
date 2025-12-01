/*
 * Copyright 2025 The Android Open Source Project
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
#define LOG_TAG "UtilTest"

#include <android_companion_virtualdevice_flags.h>
#include <flag_macros.h>
#include <sys/types.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "aidl/android/companion/virtualcamera/Format.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "system/graphics.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

namespace flags = ::android::companion::virtualdevice::flags;

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::graphics::common::Dataspace;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Ne;
using ::testing::Optional;
using ::testing::VariantWith;

const std::array<Format, 5> kImageFormats = {
    Format::UNKNOWN, Format::RGBA_8888, Format::YUV_420_888, Format::JPEG,
    Format::HEIC,
};

class UtilTest : public ::testing::Test {};

TEST_F(UtilTest, validateSupportedInputImageFormats) {
  for (Format f : kImageFormats) {
    switch (f) {
      case Format::UNKNOWN:
        EXPECT_FALSE(isImageFormatSupportedForInput(f));
        break;
      case Format::RGBA_8888:
        [[fallthrough]];
      case Format::YUV_420_888:
        EXPECT_TRUE(isImageFormatSupportedForInput(f));
        break;
      case Format::JPEG:
        [[fallthrough]];
      case Format::HEIC:
        EXPECT_EQ(isImageFormatSupportedForInput(f),
                  flags::virtual_camera_direct_blob_transfer());
        break;
    }
  }
}

TEST_F(UtilTest, IsFormatSupportedForInput_ReturnsTrueForValidNonBlobFormats) {
  // Test supported non-blob formats with valid parameters.
  EXPECT_TRUE(isFormatSupportedForInput(1920, 1080, Format::YUV_420_888, 30));
  EXPECT_TRUE(isFormatSupportedForInput(1280, 720, Format::RGBA_8888, 60));
}

TEST_F(UtilTest, IsFormatSupportedForInput_ReturnsFalseForInvalidWidth) {
  EXPECT_FALSE(isFormatSupportedForInput(0, 1080, Format::YUV_420_888, 30));
  EXPECT_FALSE(isFormatSupportedForInput(-1, 1080, Format::YUV_420_888, 30));
}

TEST_F(UtilTest, IsFormatSupportedForInput_ReturnsFalseForInvalidHeight) {
  EXPECT_FALSE(isFormatSupportedForInput(1920, 0, Format::YUV_420_888, 30));
  EXPECT_FALSE(isFormatSupportedForInput(1920, -1, Format::YUV_420_888, 30));
}

TEST_F(UtilTest, IsFormatSupportedForInput_ReturnsFalseForInvalidFps) {
  EXPECT_FALSE(isFormatSupportedForInput(1920, 1080, Format::YUV_420_888, 0));
  EXPECT_FALSE(isFormatSupportedForInput(1920, 1080, Format::YUV_420_888, -10));
  EXPECT_FALSE(isFormatSupportedForInput(1920, 1080, Format::YUV_420_888, 61));
}

TEST_F(UtilTest, IsFormatSupportedForInput_ReturnsFalseForUnknownFormat) {
  EXPECT_FALSE(isFormatSupportedForInput(1920, 1080, Format::UNKNOWN, 30));
}

TEST_F_WITH_FLAGS(
    UtilTest, IsFormatSupportedForInput_BlobFormatSupportedWhenFlagEnabled,
    REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(
        android::companion::virtualdevice::flags, virtual_camera_direct_blob_transfer))) {
  EXPECT_TRUE(isFormatSupportedForInput(800, 600, Format::JPEG, 30));
  EXPECT_TRUE(isFormatSupportedForInput(1024, 768, Format::HEIC, 30));
}

TEST_F_WITH_FLAGS(
    UtilTest, IsFormatSupportedForInput_BlobFormatUnsupportedWhenFlagDisabled,
    REQUIRES_FLAGS_DISABLED(ACONFIG_FLAG(
        android::companion::virtualdevice::flags, virtual_camera_direct_blob_transfer))) {
  EXPECT_FALSE(isFormatSupportedForInput(800, 600, Format::JPEG, 30));
  EXPECT_FALSE(isFormatSupportedForInput(1024, 768, Format::HEIC, 30));
}

TEST_F(
    UtilTest,
    IsFormatSupportedForInput_ReturnsFalseForBlobFormatsWithInvalidParameters) {
  // Blob formats with invalid parameters should always be unsupported,
  // regardless of the feature flag.
  // Invalid width with JPEG format.
  EXPECT_FALSE(isFormatSupportedForInput(0, 600, Format::JPEG, 30));
  // Invalid height with JPEG format.
  EXPECT_FALSE(isFormatSupportedForInput(800, 0, Format::JPEG, 30));
  // Invalid fps with JPEG format.
  EXPECT_FALSE(isFormatSupportedForInput(800, 600, Format::JPEG, 0));
  EXPECT_FALSE(isFormatSupportedForInput(800, 600, Format::JPEG, 61));
}

TEST_F(UtilTest, isBlobFormatTest) {
  for (Format f : kImageFormats) {
    switch (f) {
      case Format::UNKNOWN:
        [[fallthrough]];
      case Format::RGBA_8888:
        [[fallthrough]];
      case Format::YUV_420_888:
        EXPECT_FALSE(isBlobFormat(f));
        break;
      case Format::JPEG:
        [[fallthrough]];
      case Format::HEIC:
        EXPECT_TRUE(isBlobFormat(f));
        break;
    }
  }
}

TEST_F(UtilTest, isBlobStreamConfigTest) {
  Stream stream;

  // Check supported BLOB types
  stream.format = PixelFormat::BLOB;
  stream.dataSpace = Dataspace::HEIF;
  EXPECT_TRUE(isBlobStreamConfig(stream));

  stream.dataSpace = Dataspace::JFIF;
  EXPECT_TRUE(isBlobStreamConfig(stream));

  // Check unsupported BLOB types
  stream.dataSpace = Dataspace::JPEG_R;
  EXPECT_FALSE(isBlobStreamConfig(stream));

  // Check malformed streams
  stream.dataSpace = Dataspace::JFIF;
  stream.format = PixelFormat::YCBCR_420_888;
  EXPECT_FALSE(isBlobStreamConfig(stream));

  stream.format = PixelFormat::RGBA_8888;
  EXPECT_FALSE(isBlobStreamConfig(stream));

  // Check legal uncompressed streams
  stream.dataSpace = Dataspace::UNKNOWN;
  EXPECT_FALSE(isBlobStreamConfig(stream));

  stream.format = PixelFormat::YCBCR_420_888;
  EXPECT_FALSE(isBlobStreamConfig(stream));
}

TEST_F(UtilTest, areMatchingBlobTypesTest) {
  Stream halStream;
  SupportedStreamConfiguration inputConfig;

  // Test matching HEIC types
  halStream.format = PixelFormat::BLOB;
  halStream.dataSpace = Dataspace::HEIF;
  inputConfig.imageFormat = Format::HEIC;
  EXPECT_TRUE(areMatchingBlobTypes(halStream, inputConfig));

  // Test mis-matching blob types
  halStream.dataSpace = Dataspace::JFIF;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  halStream.dataSpace = Dataspace::HEIF;
  inputConfig.imageFormat = Format::JPEG;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  // Test matching JPEG types
  halStream.dataSpace = Dataspace::JFIF;
  EXPECT_TRUE(areMatchingBlobTypes(halStream, inputConfig));

  // Test mis-matching blob and scaler types
  inputConfig.imageFormat = Format::YUV_420_888;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  inputConfig.imageFormat = Format::RGBA_8888;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  inputConfig.imageFormat = Format::UNKNOWN;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  halStream.dataSpace = Dataspace::HEIF;
  inputConfig.imageFormat = Format::YUV_420_888;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  inputConfig.imageFormat = Format::RGBA_8888;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  inputConfig.imageFormat = Format::UNKNOWN;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  // Test matching scaler types. Expect fail since not blob
  inputConfig.imageFormat = Format::YUV_420_888;
  halStream.format = PixelFormat::YCRCB_420_SP;
  halStream.dataSpace = Dataspace::UNKNOWN;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));

  inputConfig.imageFormat = Format::RGBA_8888;
  halStream.format = PixelFormat::RGBA_8888;
  EXPECT_FALSE(areMatchingBlobTypes(halStream, inputConfig));
}

TEST_F(UtilTest, areMatchingBlobFormatsTest) {
  EXPECT_TRUE(areMatchingBlobTypes(Format::HEIC, Format::HEIC));
  EXPECT_TRUE(areMatchingBlobTypes(Format::JPEG, Format::JPEG));

  EXPECT_FALSE(areMatchingBlobTypes(Format::JPEG, Format::HEIC));
  EXPECT_FALSE(areMatchingBlobTypes(Format::JPEG, Format::YUV_420_888));
  EXPECT_FALSE(areMatchingBlobTypes(Format::JPEG, Format::RGBA_8888));
  EXPECT_FALSE(areMatchingBlobTypes(Format::JPEG, Format::UNKNOWN));

  EXPECT_FALSE(areMatchingBlobTypes(Format::HEIC, Format::YUV_420_888));
  EXPECT_FALSE(areMatchingBlobTypes(Format::HEIC, Format::RGBA_8888));
  EXPECT_FALSE(areMatchingBlobTypes(Format::HEIC, Format::UNKNOWN));
}

TEST_F(UtilTest, areDifferentBlobFormatsTest) {
  EXPECT_TRUE(areDifferentBlobTypes(Format::HEIC, Format::JPEG));

  EXPECT_FALSE(areDifferentBlobTypes(Format::HEIC, Format::HEIC));
  EXPECT_FALSE(areDifferentBlobTypes(Format::JPEG, Format::JPEG));

  EXPECT_FALSE(areDifferentBlobTypes(Format::JPEG, Format::YUV_420_888));
  EXPECT_FALSE(areDifferentBlobTypes(Format::JPEG, Format::RGBA_8888));
  EXPECT_FALSE(areDifferentBlobTypes(Format::JPEG, Format::UNKNOWN));
  EXPECT_FALSE(areDifferentBlobTypes(Format::HEIC, Format::YUV_420_888));
  EXPECT_FALSE(areDifferentBlobTypes(Format::HEIC, Format::RGBA_8888));
  EXPECT_FALSE(areDifferentBlobTypes(Format::HEIC, Format::UNKNOWN));
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
