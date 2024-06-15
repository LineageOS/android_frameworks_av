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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_METADATAUTIL_H
#define ANDROID_COMPANION_VIRTUALCAMERA_METADATAUTIL_H

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <variant>
#include <vector>

#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "system/camera_metadata.h"
#include "util/Util.h"

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
    std::chrono::nanoseconds minFrameDuration{0};
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

  struct FpsRange {
    int32_t minFps;
    int32_t maxFps;

    bool operator<(const FpsRange& other) const {
      return maxFps == other.maxFps ? minFps < other.minFps
                                    : maxFps < other.maxFps;
    }
  };

  MetadataBuilder() = default;
  ~MetadataBuilder() = default;

  // See ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL in CameraMetadataTag.aidl.
  MetadataBuilder& setSupportedHardwareLevel(
      camera_metadata_enum_android_info_supported_hardware_level_t hwLevel);

  // Whether this camera device has a flash unit
  // See ANDROID_FLASH_INFO_AVAILABLE in CameraMetadataTag.aidl.
  MetadataBuilder& setFlashAvailable(bool flashAvailable);

  // See FLASH_STATE in CaptureResult.java.
  MetadataBuilder& setFlashState(
      camera_metadata_enum_android_flash_state_t flashState);

  // See FLASH_MODE in CaptureRequest.java.
  MetadataBuilder& setFlashMode(
      camera_metadata_enum_android_flash_mode_t flashMode);

  // See ANDROID_LENS_FACING in CameraMetadataTag.aidl.
  MetadataBuilder& setLensFacing(
      camera_metadata_enum_android_lens_facing lensFacing);

  // See ANDROID_SENSOR_READOUT_TIMESTAMP in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorReadoutTimestamp(
      camera_metadata_enum_android_sensor_readout_timestamp_t
          sensorReadoutTimestamp);

  // See ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableFocalLengths(
      const std::vector<float>& focalLengths);

  // See ANDROID_LENS_FOCAL_LENGTH in CameraMetadataTag.aidl.
  MetadataBuilder& setFocalLength(float focalLength);

  // See ANDROID_SENSOR_ORIENTATION in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorOrientation(int32_t sensorOrientation);

  // Time at start of exposure of first row of the image
  // sensor active array, in nanoseconds.
  //
  // See ANDROID_SENSOR_TIMESTAMP in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorTimestamp(std::chrono::nanoseconds timestamp);

  // See SENSOR_INFO_TIMESTAMP_SOURCE in CameraCharacteristic.java.
  MetadataBuilder& setSensorTimestampSource(
      camera_metadata_enum_android_sensor_info_timestamp_source_t timestampSource);

  // See ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorActiveArraySize(int x0, int y0, int x1, int y1);

  // See ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorPixelArraySize(int width, int height);

  // See ANDROID_SENSOR_INFO_PHYSICAL_SIZE in CameraMetadataTag.aidl.
  MetadataBuilder& setSensorPhysicalSize(float width, float height);

  // See ANDROID_STATISTICS_FACE_DETECT_MODE in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableFaceDetectModes(
      const std::vector<camera_metadata_enum_android_statistics_face_detect_mode_t>&
          faceDetectMode);

  // See SENSOR_AVAILABLE_TEST_PATTERN_MODES in CameraCharacteristics.java.
  MetadataBuilder& setAvailableTestPatternModes(
      const std::vector<camera_metadata_enum_android_sensor_test_pattern_mode>&
          testPatternModes);

  // See ANDROID_STATISTICS_FACE_DETECT_MODE in CaptureRequest.java.
  MetadataBuilder& setFaceDetectMode(
      camera_metadata_enum_android_statistics_face_detect_mode_t faceDetectMode);

  // Sets available stream configurations along with corresponding minimal frame
  // durations (corresponding to max fps) and stall durations.
  //
  // See ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
  // ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS and
  // ANDROID_SCALER_AVAILABLE_STALL_DURATIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableOutputStreamConfigurations(
      const std::vector<StreamConfiguration>& streamConfigurations);

  // See COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES in CameraCharacteristics.java.
  MetadataBuilder& setAvailableAberrationCorrectionModes(
      const std::vector<
          camera_metadata_enum_android_color_correction_aberration_mode>&
          aberrationCorectionModes);

  // See COLOR_CORRECTION_ABERRATION_MODE in CaptureRequest.java.
  MetadataBuilder& setAberrationCorrectionMode(
      camera_metadata_enum_android_color_correction_aberration_mode
          aberrationCorrectionMode);

  // See NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES in CameraCharacteristics.java.
  MetadataBuilder& setAvailableNoiseReductionModes(
      const std::vector<camera_metadata_enum_android_noise_reduction_mode>&
          noiseReductionModes);

  // See NOISE_REDUCTION_MODE in CaptureRequest.java.
  MetadataBuilder& setNoiseReductionMode(
      camera_metadata_enum_android_noise_reduction_mode noiseReductionMode);

  // See REQUEST_PARTIAL_RESULT_COUNT in CameraCharacteristics.java.
  MetadataBuilder& setRequestPartialResultCount(int partialResultCount);

  // See SCALER_CROPPING_TYPE in CameraCharacteristics.java.
  MetadataBuilder& setCroppingType(
      camera_metadata_enum_android_scaler_cropping_type croppingType);

  // See STATISTICS_INFO_MAX_FACE_COUNT in CameraCharacteristic.java.
  MetadataBuilder& setMaxFaceCount(int maxFaceCount);

  // See ANDROID_CONTROL_AVAILABLE_MODES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAvailableModes(
      const std::vector<camera_metadata_enum_android_control_mode_t>&
          availableModes);

  // See ANDROID_CONTROL_MODE in CaptureRequest.java.
  MetadataBuilder& setControlMode(
      camera_metadata_enum_android_control_mode_t mode);

  // See ANDROID_CONTROL_AVAILABLE_SCENE_MODES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAvailableSceneModes(
      const std::vector<camera_metadata_enum_android_control_scene_mode>&
          availableSceneModes);

  // See ANDROID_CONTROL_AVAILABLE_EFFECTS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAvailableEffects(
      const std::vector<camera_metadata_enum_android_control_effect_mode>&
          availableEffects);

  // See CONTROL_EFFECT_MODE in CaptureRequest.java.
  MetadataBuilder& setControlEffectMode(
      camera_metadata_enum_android_control_effect_mode_t effectMode);

  // See ANDROID_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES
  MetadataBuilder& setControlAvailableVideoStabilizationModes(
      const std::vector<
          camera_metadata_enum_android_control_video_stabilization_mode_t>&
          videoStabilizationModes);

  // See CONTROL_AE_AVAILABLE_ANTIBANDING_MODES in CameraCharacteristics.java.
  MetadataBuilder& setControlAeAvailableAntibandingModes(
      const std::vector<camera_metadata_enum_android_control_ae_antibanding_mode_t>&
          antibandingModes);

  // See CONTROL_AE_ANTIBANDING_MODE in CaptureRequest.java.
  MetadataBuilder& setControlAeAntibandingMode(
      camera_metadata_enum_android_control_ae_antibanding_mode_t antibandingMode);

  // See ANDROID_CONTROL_AE_COMPENSATION_RANGE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeCompensationRange(int32_t min, int32_t max);

  // See ANDROID_CONTROL_AE_COMPENSATION_STEP in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeCompensationStep(camera_metadata_rational step);

  // See ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeExposureCompensation(int32_t exposureCompensation);

  // See ANDROID_CONTROL_AE_AVAILABLE_MODES in CameraCharacteristics.java.
  MetadataBuilder& setControlAeAvailableModes(
      const std::vector<camera_metadata_enum_android_control_ae_mode_t>& modes);

  // See ANDROID_CONTROL_AE_MODE in CaptureRequest.java.
  MetadataBuilder& setControlAeMode(
      camera_metadata_enum_android_control_ae_mode_t step);

  // See ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER in CaptureRequest.java.
  MetadataBuilder& setControlAePrecaptureTrigger(
      camera_metadata_enum_android_control_ae_precapture_trigger_t trigger);

  // See ANDROID_CONTROL_AF_AVAILABLE_MODES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAfAvailableModes(
      const std::vector<camera_metadata_enum_android_control_af_mode_t>&
          availableModes);

  // See ANDROID_CONTROL_AF_MODE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAfMode(
      const camera_metadata_enum_android_control_af_mode_t mode);

  // See ANDROID_CONTROL_AF_TRIGGER_MODE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAfTrigger(
      const camera_metadata_enum_android_control_af_trigger_t trigger);

  // See ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeAvailableFpsRanges(
      const std::vector<FpsRange>& fpsRanges);

  // See ANDROID_CONTROL_AE_TARGET_FPS_RANGE in CaptureRequest.java.
  MetadataBuilder& setControlAeTargetFpsRange(int32_t min, int32_t max);

  // See ANDROID_CONTROL_CAPTURE_INTENT in CameraMetadataTag.aidl.
  MetadataBuilder& setControlCaptureIntent(
      camera_metadata_enum_android_control_capture_intent_t intent);

  // See ANDROID_CONTROL_MAX_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlMaxRegions(int32_t maxAeRegions,
                                        int32_t maxAwbRegions,
                                        int32_t maxAfRegions);

  // See ANDROID_CONTROL_AWB_AVAILABLE_MODES in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAvailableAwbModes(
      const std::vector<camera_metadata_enum_android_control_awb_mode>& awbModes);

  // See ANDROID_CONTROL_AWB_AVAILABLE_MODE in CaptureRequest.java.
  MetadataBuilder& setControlAwbMode(
      camera_metadata_enum_android_control_awb_mode awb);

  // See CONTROL_AWB_LOCK_AVAILABLE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAwbLockAvailable(bool awbLockAvailable);

  // See CONTROL_AE_LOCK_AVAILABLE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeLockAvailable(bool aeLockAvailable);

  // See ANDROID_CONTROL_AE_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAeRegions(
      const std::vector<ControlRegion>& aeRegions);

  // See ANDROID_CONTROL_AWB_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAwbRegions(
      const std::vector<ControlRegion>& awbRegions);

  // See ANDROID_SCALER_CROP_REGION in CaptureRequest.java.
  MetadataBuilder& setCropRegion(int32_t x, int32_t y, int32_t width,
                                 int32_t height);

  // See ANDROID_CONTROL_AF_REGIONS in CameraMetadataTag.aidl.
  MetadataBuilder& setControlAfRegions(
      const std::vector<ControlRegion>& afRegions);

  // The size of the compressed JPEG image, in bytes.
  //
  // See ANDROID_JPEG_SIZE in CameraMetadataTag.aidl.
  MetadataBuilder& setMaxJpegSize(int32_t size);

  // See SENSOR_INFO_MAX_FRAME_DURATION in CameraCharacteristic.java.
  MetadataBuilder& setMaxFrameDuration(std::chrono::nanoseconds duration);

  // See JPEG_AVAILABLE_THUMBNAIL_SIZES in CameraCharacteristic.java.
  MetadataBuilder& setJpegAvailableThumbnailSizes(
      const std::vector<Resolution>& thumbnailSizes);

  // See JPEG_QUALITY in CaptureRequest.java.
  MetadataBuilder& setJpegQuality(uint8_t quality);

  // See JPEG_THUMBNAIL_SIZE in CaptureRequest.java.
  MetadataBuilder& setJpegThumbnailSize(int width, int height);

  // See JPEG_THUMBNAIL_QUALITY in CaptureRequest.java.
  MetadataBuilder& setJpegThumbnailQuality(uint8_t quality);

  // The maximum numbers of different types of output streams
  // that can be configured and used simultaneously by a camera device.
  //
  // See ANDROID_REQUEST_MAX_NUM_OUTPUT_STREAMS in CameraMetadataTag.aidl.
  MetadataBuilder& setMaxNumberOutputStreams(int32_t maxRawStreams,
                                             int32_t maxProcessedStreams,
                                             int32_t maxStallStreams);

  // See ANDROID_SYNC_MAX_LATENCY in CameraMetadataTag.aidl.
  MetadataBuilder& setSyncMaxLatency(
      camera_metadata_enum_android_sync_max_latency setSyncMaxLatency);

  // See REQUEST_PIPELINE_MAX_DEPTH in CameraCharacteristic.java.
  MetadataBuilder& setPipelineMaxDepth(uint8_t maxDepth);

  // See REQUEST_PIPELINE_DEPTH in CaptureResult.java.
  MetadataBuilder& setPipelineDepth(uint8_t depth);

  // See ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableMaxDigitalZoom(const float maxZoom);

  // See ANDROID_CONTROL_ZOOM_RATIO_RANGE in CameraMetadataTag.aidl.
  MetadataBuilder& setControlZoomRatioRange(float min, float max);

  // See ANDROID_REQUEST_AVAILABLE_CAPABILITIES in CameraMetadataTag.aidl.
  MetadataBuilder& setAvailableRequestCapabilities(
      const std::vector<
          camera_metadata_enum_android_request_available_capabilities_t>&
          requestCapabilities);

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
  // containing all set tags.
  MetadataBuilder& setAvailableCharacteristicKeys();

  // Build CameraMetadata instance.
  //
  // Returns nullptr in case something went wrong.
  std::unique_ptr<::aidl::android::hardware::camera::device::CameraMetadata>
  build();

 private:
  // Maps metadata tags to vectors of values for the given tag.
  std::map<camera_metadata_tag_t,
           std::variant<std::vector<int64_t>, std::vector<int32_t>,
                        std::vector<uint8_t>, std::vector<float>,
                        std::vector<camera_metadata_rational_t>>>
      mEntryMap;
  // Extend metadata with ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS.
  bool mExtendWithAvailableCharacteristicsKeys = false;
};

// Returns JPEG_QUALITY from metadata, or nullopt if the key is not present.
std::optional<int32_t> getJpegQuality(
    const aidl::android::hardware::camera::device::CameraMetadata& metadata);

// Returns JPEG_THUMBNAIL_SIZE from metadata, or nullopt if the key is not present.
std::optional<Resolution> getJpegThumbnailSize(
    const aidl::android::hardware::camera::device::CameraMetadata& metadata);

// Returns JPEG_THUMBNAIL_QUALITY from metadata, or nullopt if the key is not present.
std::optional<int32_t> getJpegThumbnailQuality(
    const aidl::android::hardware::camera::device::CameraMetadata& metadata);

// Returns JPEG_AVAILABLE_THUMBNAIL_SIZES from metadata, or nullopt if the key
// is not present.
std::vector<Resolution> getJpegAvailableThumbnailSizes(
    const aidl::android::hardware::camera::device::CameraMetadata& metadata);

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_METADATAUTIL_H
