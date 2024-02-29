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

#include <algorithm>
#include <iterator>
#include <memory>

#include "VirtualCameraDevice.h"
#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraConfiguration.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "aidl/android/hardware/graphics/common/PixelFormat.h"
#include "android/binder_interface_utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "log/log_main.h"
#include "system/camera_metadata.h"
#include "util/MetadataUtil.h"
#include "util/Util.h"
#include "utils/Errors.h"

namespace android {
namespace companion {
namespace virtualcamera {
namespace {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::LensFacing;
using ::aidl::android::companion::virtualcamera::SensorOrientation;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::camera::device::StreamType;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using ::testing::ElementsAre;
using ::testing::UnorderedElementsAreArray;
using metadata_stream_t =
    camera_metadata_enum_android_scaler_available_stream_configurations_t;

constexpr int kCameraId = 42;
constexpr int kQvgaWidth = 320;
constexpr int kQvgaHeight = 240;
constexpr int k360pWidth = 640;
constexpr int k360pHeight = 360;
constexpr int kVgaWidth = 640;
constexpr int kVgaHeight = 480;
constexpr int kHdWidth = 1280;
constexpr int kHdHeight = 720;
constexpr int kMaxFps = 30;

const Stream kVgaYUV420Stream = Stream{
    .streamType = StreamType::OUTPUT,
    .width = kVgaWidth,
    .height = kVgaHeight,
    .format = PixelFormat::YCBCR_420_888,
};

const Stream kVgaJpegStream = Stream{
    .streamType = StreamType::OUTPUT,
    .width = kVgaWidth,
    .height = kVgaHeight,
    .format = PixelFormat::BLOB,
};

struct AvailableStreamConfiguration {
  const int width;
  const int height;
  const int pixelFormat;
  const metadata_stream_t streamConfiguration =
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT;
};

bool operator==(const AvailableStreamConfiguration& a,
                const AvailableStreamConfiguration& b) {
  return a.width == b.width && a.height == b.height &&
         a.pixelFormat == b.pixelFormat &&
         a.streamConfiguration == b.streamConfiguration;
}

std::ostream& operator<<(std::ostream& os,
                         const AvailableStreamConfiguration& config) {
  os << config.width << "x" << config.height << " (pixfmt "
     << config.pixelFormat << ", streamConfiguration "
     << config.streamConfiguration << ")";
  return os;
}

std::vector<AvailableStreamConfiguration> getAvailableStreamConfigurations(
    const CameraMetadata& metadata) {
  const camera_metadata_t* const raw =
      reinterpret_cast<const camera_metadata_t*>(metadata.metadata.data());
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(
          raw, ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, &entry) !=
      NO_ERROR) {
    return {};
  }

  std::vector<AvailableStreamConfiguration> res;
  for (int i = 0; i < entry.count; i += 4) {
    res.push_back(AvailableStreamConfiguration{
        .width = entry.data.i32[i + 1],
        .height = entry.data.i32[i + 2],
        .pixelFormat = entry.data.i32[i],
        .streamConfiguration =
            static_cast<metadata_stream_t>(entry.data.i32[i + 3])});
  }
  return res;
}

struct VirtualCameraConfigTestParam {
  VirtualCameraConfiguration inputConfig;
  std::vector<AvailableStreamConfiguration> expectedAvailableStreamConfigs;
};

class VirtualCameraDeviceCharacterisicsTest
    : public testing::TestWithParam<VirtualCameraConfigTestParam> {};

TEST_P(VirtualCameraDeviceCharacterisicsTest,
       cameraCharacteristicsForInputFormat) {
  const VirtualCameraConfigTestParam& param = GetParam();
  std::shared_ptr<VirtualCameraDevice> camera =
      ndk::SharedRefBase::make<VirtualCameraDevice>(kCameraId,
                                                    param.inputConfig);

  CameraMetadata metadata;
  ASSERT_TRUE(camera->getCameraCharacteristics(&metadata).isOk());
  EXPECT_THAT(getAvailableStreamConfigurations(metadata),
              UnorderedElementsAreArray(param.expectedAvailableStreamConfigs));

  // Configuration needs to succeed for every available stream configuration
  for (const AvailableStreamConfiguration& config :
       param.expectedAvailableStreamConfigs) {
    StreamConfiguration configuration{
        .streams = std::vector<Stream>{Stream{
            .streamType = StreamType::OUTPUT,
            .width = config.width,
            .height = config.height,
            .format = static_cast<PixelFormat>(config.pixelFormat),
        }}};
    bool aidl_ret;
    ASSERT_TRUE(
        camera->isStreamCombinationSupported(configuration, &aidl_ret).isOk());
    EXPECT_TRUE(aidl_ret);
  }
}

INSTANTIATE_TEST_SUITE_P(
    cameraCharacteristicsForInputFormat, VirtualCameraDeviceCharacterisicsTest,
    testing::Values(
        VirtualCameraConfigTestParam{
            .inputConfig =
                VirtualCameraConfiguration{
                    .supportedStreamConfigs = {SupportedStreamConfiguration{
                        .width = kVgaWidth,
                        .height = kVgaHeight,
                        .pixelFormat = Format::YUV_420_888,
                        .maxFps = kMaxFps}},
                    .virtualCameraCallback = nullptr,
                    .sensorOrientation = SensorOrientation::ORIENTATION_0,
                    .lensFacing = LensFacing::FRONT},
            .expectedAvailableStreamConfigs =
                {AvailableStreamConfiguration{
                     .width = kQvgaWidth,
                     .height = kQvgaHeight,
                     .pixelFormat =
                         ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888},
                 AvailableStreamConfiguration{
                     .width = kQvgaWidth,
                     .height = kQvgaHeight,
                     .pixelFormat =
                         ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED},
                 AvailableStreamConfiguration{
                     .width = kQvgaWidth,
                     .height = kQvgaHeight,
                     .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB},
                 AvailableStreamConfiguration{
                     .width = kVgaWidth,
                     .height = kVgaHeight,
                     .pixelFormat =
                         ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888},
                 AvailableStreamConfiguration{
                     .width = kVgaWidth,
                     .height = kVgaHeight,
                     .pixelFormat =
                         ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED},
                 AvailableStreamConfiguration{
                     .width = kVgaWidth,
                     .height = kVgaHeight,
                     .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB}}},
        VirtualCameraConfigTestParam{
            .inputConfig =
                VirtualCameraConfiguration{
                    .supportedStreamConfigs =
                        {SupportedStreamConfiguration{
                             .width = kVgaWidth,
                             .height = kVgaHeight,
                             .pixelFormat = Format::YUV_420_888,
                             .maxFps = kMaxFps},
                         SupportedStreamConfiguration{
                             .width = kHdWidth,
                             .height = kHdHeight,
                             .pixelFormat = Format::YUV_420_888,
                             .maxFps = kMaxFps}},
                    .virtualCameraCallback = nullptr,
                    .sensorOrientation = SensorOrientation::ORIENTATION_0,
                    .lensFacing = LensFacing::BACK},
            .expectedAvailableStreamConfigs = {
                AvailableStreamConfiguration{
                    .width = kQvgaWidth,
                    .height = kQvgaHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888},
                AvailableStreamConfiguration{
                    .width = kQvgaWidth,
                    .height = kQvgaHeight,
                    .pixelFormat =
                        ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED},
                AvailableStreamConfiguration{
                    .width = kQvgaWidth,
                    .height = kQvgaHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB},
                AvailableStreamConfiguration{
                    .width = 640,
                    .height = 360,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888},
                AvailableStreamConfiguration{
                    .width = 640,
                    .height = 360,
                    .pixelFormat =
                        ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED},
                AvailableStreamConfiguration{
                    .width = 640,
                    .height = 360,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB},
                AvailableStreamConfiguration{
                    .width = kVgaWidth,
                    .height = kVgaHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888},
                AvailableStreamConfiguration{
                    .width = kVgaWidth,
                    .height = kVgaHeight,
                    .pixelFormat =
                        ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED},
                AvailableStreamConfiguration{
                    .width = kVgaWidth,
                    .height = kVgaHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB},
                AvailableStreamConfiguration{
                    .width = 1024,
                    .height = 576,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888},
                AvailableStreamConfiguration{
                    .width = 1024,
                    .height = 576,
                    .pixelFormat =
                        ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED},
                AvailableStreamConfiguration{
                    .width = 1024,
                    .height = 576,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB},
                AvailableStreamConfiguration{
                    .width = kHdWidth,
                    .height = kHdHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888},
                AvailableStreamConfiguration{
                    .width = kHdWidth,
                    .height = kHdHeight,
                    .pixelFormat =
                        ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED},
                AvailableStreamConfiguration{
                    .width = kHdWidth,
                    .height = kHdHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB}}}));

class VirtualCameraDeviceTest : public ::testing::Test {
 public:
  void SetUp() override {
    mCamera = ndk::SharedRefBase::make<VirtualCameraDevice>(
        kCameraId, VirtualCameraConfiguration{
                       .supportedStreamConfigs = {SupportedStreamConfiguration{
                           .width = kVgaWidth,
                           .height = kVgaHeight,
                           .pixelFormat = Format::YUV_420_888,
                           .maxFps = kMaxFps}},
                       .virtualCameraCallback = nullptr,
                       .sensorOrientation = SensorOrientation::ORIENTATION_0,
                       .lensFacing = LensFacing::FRONT});
  }

 protected:
  std::shared_ptr<VirtualCameraDevice> mCamera;
};

TEST_F(VirtualCameraDeviceTest, configureMaximalNumberOfNonStallStreamsSuceeds) {
  StreamConfiguration config;
  std::fill_n(std::back_insert_iterator(config.streams),
              VirtualCameraDevice::kMaxNumberOfProcessedStreams,
              kVgaYUV420Stream);

  bool aidl_ret;
  ASSERT_TRUE(mCamera->isStreamCombinationSupported(config, &aidl_ret).isOk());
  EXPECT_TRUE(aidl_ret);
}

TEST_F(VirtualCameraDeviceTest, configureTooManyNonStallStreamsFails) {
  StreamConfiguration config;
  std::fill_n(std::back_insert_iterator(config.streams),
              VirtualCameraDevice::kMaxNumberOfProcessedStreams + 1,
              kVgaYUV420Stream);

  bool aidl_ret;
  ASSERT_TRUE(mCamera->isStreamCombinationSupported(config, &aidl_ret).isOk());
  EXPECT_FALSE(aidl_ret);
}

TEST_F(VirtualCameraDeviceTest, configureMaximalNumberOfStallStreamsSuceeds) {
  StreamConfiguration config;
  std::fill_n(std::back_insert_iterator(config.streams),
              VirtualCameraDevice::kMaxNumberOfStallStreams, kVgaJpegStream);

  bool aidl_ret;
  ASSERT_TRUE(mCamera->isStreamCombinationSupported(config, &aidl_ret).isOk());
  EXPECT_TRUE(aidl_ret);
}

TEST_F(VirtualCameraDeviceTest, configureTooManyStallStreamsFails) {
  StreamConfiguration config;
  std::fill_n(std::back_insert_iterator(config.streams),
              VirtualCameraDevice::kMaxNumberOfStallStreams + 1, kVgaJpegStream);

  bool aidl_ret;
  ASSERT_TRUE(mCamera->isStreamCombinationSupported(config, &aidl_ret).isOk());
  EXPECT_FALSE(aidl_ret);
}

TEST_F(VirtualCameraDeviceTest, thumbnailSizeWithCompatibleAspectRatio) {
  CameraMetadata metadata;
  ASSERT_TRUE(mCamera->getCameraCharacteristics(&metadata).isOk());

  // Camera is configured with VGA input, we expect 240 x 180 thumbnail size in
  // characteristics, since it has same aspect ratio.
  EXPECT_THAT(getJpegAvailableThumbnailSizes(metadata),
              ElementsAre(Resolution(0, 0), Resolution(240, 180)));
}

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
