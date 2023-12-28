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

#include <memory>

#include "VirtualCameraDevice.h"
#include "aidl/android/companion/virtualcamera/Format.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraConfiguration.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "android/binder_interface_utils.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "log/log_main.h"
#include "system/camera_metadata.h"
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
using ::testing::UnorderedElementsAreArray;
using metadata_stream_t =
    camera_metadata_enum_android_scaler_available_stream_configurations_t;

constexpr int kCameraId = 42;
constexpr int kVgaWidth = 640;
constexpr int kVgaHeight = 480;
constexpr int kHdWidth = 1280;
constexpr int kHdHeight = 720;
constexpr int kMaxFps = 30;

struct AvailableStreamConfiguration {
  const int width;
  const int height;
  const int pixelFormat;
  const metadata_stream_t streamConfiguration;
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

class VirtualCameraDeviceTest
    : public testing::TestWithParam<VirtualCameraConfigTestParam> {};

TEST_P(VirtualCameraDeviceTest, cameraCharacteristicsForInputFormat) {
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
    cameraCharacteristicsForInputFormat, VirtualCameraDeviceTest,
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
                     .width = kVgaWidth,
                     .height = kVgaHeight,
                     .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888,
                     .streamConfiguration =
                         ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT},
                 AvailableStreamConfiguration{
                     .width = kVgaWidth,
                     .height = kVgaHeight,
                     .pixelFormat =
                         ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED,
                     .streamConfiguration =
                         ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT},
                 AvailableStreamConfiguration{
                     .width = kVgaWidth,
                     .height = kVgaHeight,
                     .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB,
                     .streamConfiguration =
                         ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT}}},
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
                    .width = kVgaWidth,
                    .height = kVgaHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888,
                    .streamConfiguration =
                        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT},
                AvailableStreamConfiguration{
                    .width = kVgaWidth,
                    .height = kVgaHeight,
                    .pixelFormat =
                        ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED,
                    .streamConfiguration =
                        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT},
                AvailableStreamConfiguration{
                    .width = kVgaWidth,
                    .height = kVgaHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB,
                    .streamConfiguration =
                        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT},
                AvailableStreamConfiguration{
                    .width = kHdWidth,
                    .height = kHdHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888,
                    .streamConfiguration =
                        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT},
                AvailableStreamConfiguration{
                    .width = kHdWidth,
                    .height = kHdHeight,
                    .pixelFormat =
                        ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED,
                    .streamConfiguration =
                        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT},
                AvailableStreamConfiguration{
                    .width = kHdWidth,
                    .height = kHdHeight,
                    .pixelFormat = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB,
                    .streamConfiguration =
                        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT}}}));

}  // namespace
}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
