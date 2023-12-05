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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_METADATABUILDER_H
#define ANDROID_COMPANION_VIRTUALCAMERA_METADATABUILDER_H

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <variant>
#include <vector>

#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "system/camera_metadata.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Convenience builder for the
// aidl::android::hardware::camera::device::CameraMetadata.
//
// Calling the same builder setter multiple will overwrite the value.
// This class is not thread-safe.
class MetadataBuilder {
 public:
  struct StreamConfiguration {
    int32_t width = 0;
    int32_t height = 0;
    int32_t format = 0;
    // Minimal frame duration - corresponds to maximal FPS for given format.
    // See ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS in CameraMetadataTag.aidl.
    std::chrono::nanoseconds minFrameDuration{std::chrono::seconds(1) / 30};
    // Minimal stall duration.
    // See ANDROID_SCALER_AVAILABLE_STALL_DURATIONS in CameraMetadataTag.aidl.
    std::chrono::nanoseconds minStallDuration{0};
  };

  struct ControlRegion {
    int32_t x0 = 0;
    int32_t y0 = 0;
    int32_t x1 = 0;
    int32_t y1 = 0;
    int32_t weight = 0;
  };

  MetadataBuilder() = default;
  ~MetadataBuilder() = default;

  // See ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL in CameraMetadataTag.aidl.
  MetadataBuilder& setSupportedHardwareLevel(
      camera_metadata_enum_android_info_supported_hardware_level_t hwLevel);

  // Whether this camera device has a flash unit
  // See ANDROID_FLASH_INFO_AVAILABLE in CameraMetadataTag.aidl.
  MetadataBuilder& setFlashAvailable(bool flashAvailable);

  // See ANDROID_LENS_FACING in CameraMetadataTag.aidl.
  MetadataBuilder& setLensFacing(
      camera_metadata_enum_android_lens_facing lensFacing);

  // See ANDROID_SENSOR_ORIENTATION in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorOrientation(int32_t sensorOrientation);

  // Time at start of exposure of first row of the image
  // sensor active array, in nanoseconds.
  //
  // See ANDROID_SENSOR_TIMESTAMP in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorTimestamp(std::chrono::nanoseconds timestamp);

  // See ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorActiveArraySize(int x0, int y0, int x1, int y1);

  // See ANDROID_STATISTICS_FACE_DETECT_MODE in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableFaceDetectModes(
      const std::vector<camera_metadata_enum_android_statistics_face_detect_mode_t>&
          faceDetectMode);

  // Sets available stream configurations along with corresponding minimal frame
  // durations (corresponding to max fps) and stall durations.
  //
  // See ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
  // ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS and
  // ANDROID_SCALER_AVAILABLE_STALL_DURATIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableOutputStreamConfigurations(
      const std::vector<StreamConfiguration>& streamConfigurations);

  // See ANDROID_CONTROL_AVAILABLE_MODES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAvailableModes(
      const std::vector<camera_metadata_enum_android_control_mode_t>&
          availableModes);

  // See ANDROID_CONTROL_AE_COMPENSATION_RANGE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeCompensationRange(int32_t min, int32_t max);

  // See ANDROID_CONTROL_AE_COMPENSATION_STEP in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeCompensationStep(camera_metadata_rational step);

  // See ANDROID_CONTROL_AF_AVAILABLE_MODES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAfAvailableModes(
      const std::vector<camera_metadata_enum_android_control_af_mode_t>&
          availableModes);

  // See ANDROID_CONTROL_AF_MODE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAfMode(
      const camera_metadata_enum_android_control_af_mode_t mode);

  // See ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeAvailableFpsRange(int32_t min, int32_t max);

  // See ANDROID_CONTROL_CAPTURE_INTENT in CameraMetadataTag.aidl.
  MetadataBuilder& setControlCaptureIntent(
      camera_metadata_enum_android_control_capture_intent_t intent);

  // See ANDROID_CONTROL_MAX_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlMaxRegions(int32_t maxAeRegions,
                                        int32_t maxAwbRegions,
                                        int32_t maxAfRegions);

  // See ANDROID_CONTROL_AE_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeRegions(
      const std::vector<ControlRegion>& aeRegions);

  // See ANDROID_CONTROL_AWB_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAwbRegions(
      const std::vector<ControlRegion>& awbRegions);

  // See ANDROID_CONTROL_AF_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAfRegions(
      const std::vector<ControlRegion>& afRegions);

  // The size of the compressed JPEG image, in bytes.
  //
  // See ANDROID_JPEG_SIZE in CameraMetadataTag.aidl.
  MetadataBuilder& setMaxJpegSize(int32_t size);

  // See ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableMaxDigitalZoom(const float maxZoom);

  // A list of all keys that the camera device has available to use with
  // CaptureRequest.
  //
  // See ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableRequestKeys(const std::vector<int32_t>& keys);

  // A list of all keys that the camera device has available to use with
  // CaptureResult.
  //
  // See ANDROID_RESULT_AVAILABLE_REQUEST_KEYS in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableResultKeys(const std::vector<int32_t>& keys);

  // See ANDROID_REQUEST_AVAILABLE_CAPABILITIES in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableCapabilities(
      const std::vector<
          camera_metadata_enum_android_request_available_capabilities_t>&
          capabilities);

  // A list of all keys that the camera device has available to use.
  //
  // See ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableCharacteristicKeys(
      const std::vector<camera_metadata_tag_t>& keys);

  // Extends metadata with ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS
  // containing all previously set tags.
  MetadataBuilder& setAvailableCharacteristicKeys();

  // Build CameraMetadata instance.
  //
  // Returns nullptr in case something went wrong.
  std::unique_ptr<::aidl::android::hardware::camera::device::CameraMetadata>
  build() const;

 private:
  // Maps metadata tags to vectors of values for the given tag.
  std::map<camera_metadata_tag_t,
           std::variant<std::vector<int64_t>, std::vector<int32_t>,
                        std::vector<uint8_t>, std::vector<float>,
                        std::vector<camera_metadata_rational_t>>>
      mEntryMap;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_METADATABUILDER_H
