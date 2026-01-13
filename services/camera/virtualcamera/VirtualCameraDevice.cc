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

// #define LOG_NDEBUG 0
#define LOG_TAG "VirtualCameraDevice"
#include "VirtualCameraDevice.h"

#include <android_companion_virtualdevice_flags.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "CameraMetadata.h"
#include "VirtualCameraService.h"
#include "VirtualCameraSession.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraConfiguration.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "android/binder_auto_utils.h"
#include "android/binder_status.h"
#include "system/camera_metadata.h"
#include "util/AidlUtil.h"
#include "util/JpegUtil.h"
#include "util/MetadataUtil.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::IVirtualCameraCallback;
using ::aidl::android::companion::virtualcamera::LensFacing;
using ::aidl::android::companion::virtualcamera::SensorOrientation;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;
using ::aidl::android::companion::virtualcamera::VirtualCameraMetadata;
using ::aidl::android::hardware::camera::common::CameraResourceCost;
using ::aidl::android::hardware::camera::common::Status;
using AidlCameraMetadata =
    ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::ICameraDeviceCallback;
using ::aidl::android::hardware::camera::device::ICameraDeviceSession;
using ::aidl::android::hardware::camera::device::ICameraInjectionSession;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::camera::device::StreamRotation;
using ::aidl::android::hardware::camera::device::StreamType;
using ::aidl::android::hardware::graphics::common::PixelFormat;
using HelperCameraMetadata =
    ::android::hardware::camera::common::helper::CameraMetadata;

namespace {

using namespace std::chrono_literals;

namespace flags = ::android::companion::virtualdevice::flags;

// Prefix of camera name - "device@1.1/virtual/{camera_id}"
const char* kDevicePathPrefix = "device@1.1/virtual/";

constexpr std::chrono::nanoseconds kMaxFrameDuration =
    std::chrono::duration_cast<std::chrono::nanoseconds>(
        1e9ns / VirtualCameraDevice::kMinFps);

constexpr uint8_t kPipelineMaxDepth = 2;

constexpr int k30Fps = 30;

constexpr MetadataBuilder::ControlRegion kDefaultEmptyControlRegion{};

const std::array<Resolution, 5> kStandardJpegThumbnailSizes{
    Resolution(176, 144), Resolution(240, 144), Resolution(256, 144),
    Resolution(240, 160), Resolution(240, 180)};

const std::array<PixelFormat, 3> kOutputFormats{
    PixelFormat::IMPLEMENTATION_DEFINED, PixelFormat::YCBCR_420_888,
    PixelFormat::BLOB};

// The resolutions below will used to extend the set of supported output formats.
// All resolutions with lower pixel count and same aspect ratio as some supported
// input resolution will be added to the set of supported output resolutions.
const std::array<Resolution, 10> kOutputResolutions{
    Resolution(320, 240),   Resolution(640, 360),  Resolution(640, 480),
    Resolution(720, 480),   Resolution(720, 576),  Resolution(800, 600),
    Resolution(1024, 576),  Resolution(1280, 720), Resolution(1280, 960),
    Resolution(1280, 1080),
};

std::vector<Resolution> getSupportedJpegThumbnailSizes(
    const std::vector<SupportedStreamConfiguration>& configs) {
  auto isSupportedByAnyInputConfig =
      [&configs](const Resolution thumbnailResolution) {
        return std::any_of(
            configs.begin(), configs.end(),
            [thumbnailResolution](const SupportedStreamConfiguration& config) {
              return isApproximatellySameAspectRatio(
                  thumbnailResolution, Resolution(config.width, config.height));
            });
      };

  std::vector<Resolution> supportedThumbnailSizes({Resolution(0, 0)});
  std::copy_if(kStandardJpegThumbnailSizes.begin(),
               kStandardJpegThumbnailSizes.end(),
               std::back_insert_iterator(supportedThumbnailSizes),
               isSupportedByAnyInputConfig);
  return supportedThumbnailSizes;
}

bool isSupportedOutputFormat(const PixelFormat pixelFormat) {
  return std::find(kOutputFormats.begin(), kOutputFormats.end(), pixelFormat) !=
         kOutputFormats.end();
}

std::vector<FpsRange> fpsRangesForInputConfig(
    const std::vector<SupportedStreamConfiguration>& configs) {
  std::set<FpsRange> availableRanges;

  for (const SupportedStreamConfiguration& config : configs) {
    availableRanges.insert(
        {.minFps = VirtualCameraDevice::kMinFps, .maxFps = config.maxFps});
    availableRanges.insert({.minFps = config.maxFps, .maxFps = config.maxFps});
  }

  if (std::any_of(configs.begin(), configs.end(),
                  [](const SupportedStreamConfiguration& config) {
                    return config.maxFps >= k30Fps;
                  })) {
    // Extend the set of available ranges with (minFps <= 15, 30) & (30, 30) as
    // required by CDD.
    availableRanges.insert(
        {.minFps = VirtualCameraDevice::kMinFps, .maxFps = k30Fps});
    availableRanges.insert({.minFps = k30Fps, .maxFps = k30Fps});
  }

  return std::vector<FpsRange>(availableRanges.begin(), availableRanges.end());
}

std::optional<Resolution> getMaxResolution(
    const std::vector<SupportedStreamConfiguration>& configs) {
  auto itMax = std::max_element(configs.begin(), configs.end(),
                                [](const SupportedStreamConfiguration& a,
                                   const SupportedStreamConfiguration& b) {
                                  return a.width * a.height < b.width * b.height;
                                });
  if (itMax == configs.end()) {
    ALOGE(
        "%s: empty vector of supported configurations, cannot find largest "
        "resolution.",
        __func__);
    return std::nullopt;
  }

  return Resolution(itMax->width, itMax->height);
}

// Returns a map of unique resolution to maximum maxFps for all streams with
// that resolution.
std::map<Resolution, int> getResolutionToMaxFpsMap(
    const std::vector<SupportedStreamConfiguration>& configs) {
  std::map<Resolution, int> resolutionToMaxFpsMap;

  for (const SupportedStreamConfiguration& config : configs) {
    Resolution resolution(config.width, config.height);
    if (resolutionToMaxFpsMap.find(resolution) == resolutionToMaxFpsMap.end()) {
      resolutionToMaxFpsMap[resolution] = config.maxFps;
    } else {
      int currentMaxFps = resolutionToMaxFpsMap[resolution];
      resolutionToMaxFpsMap[resolution] = std::max(currentMaxFps, config.maxFps);
    }
  }

  std::map<Resolution, int> additionalResolutionToMaxFpsMap;
  // Add additional resolutions we can support by downscaling input streams with
  // same aspect ratio.
  for (const Resolution& outputResolution : kOutputResolutions) {
    for (const auto& [resolution, maxFps] : resolutionToMaxFpsMap) {
      if (resolutionToMaxFpsMap.find(outputResolution) !=
          resolutionToMaxFpsMap.end()) {
        // Resolution is already in the map, skip it.
        continue;
      }

      if (outputResolution < resolution &&
          isApproximatellySameAspectRatio(outputResolution, resolution)) {
        // Lower resolution with same aspect ratio, we can achieve this by
        // downscaling, let's add it to the map.
        ALOGD(
            "Extending set of output resolutions with %dx%d which has same "
            "aspect ratio as supported input %dx%d.",
            outputResolution.width, outputResolution.height, resolution.width,
            resolution.height);
        additionalResolutionToMaxFpsMap[outputResolution] = maxFps;
        break;
      }
    }
  }

  // Add all resolution we can achieve by downscaling to the map.
  resolutionToMaxFpsMap.insert(additionalResolutionToMaxFpsMap.begin(),
                               additionalResolutionToMaxFpsMap.end());

  return resolutionToMaxFpsMap;
}

void separateScalerAndHeicInputConfigurations(
    const std::vector<SupportedStreamConfiguration>& allInputConfigs,
    std::vector<SupportedStreamConfiguration>& outScalerStreamInputConfigs,
    std::vector<SupportedStreamConfiguration>& outHeicStreamInputConfigs) {
  for (const auto& inputConfig : allInputConfigs) {
    if (inputConfig.imageFormat == Format::HEIC) {
      outHeicStreamInputConfigs.push_back(inputConfig);
    } else {
      outScalerStreamInputConfigs.push_back(inputConfig);
    }
  }
}

// Populates the maxResolution and the outputConfigurations
// from the list of supported stream configs
//
// Note: the provided configurations must represent scaler streams
status_t convertSupportedScalerStreams(
    const std::vector<SupportedStreamConfiguration>& supportedInputConfig,
    Resolution& maxResolution,
    std::vector<MetadataBuilder::StreamConfiguration>& outputConfigurations) {
  if (supportedInputConfig.empty()) {
    return OK;
  }

  std::optional<Resolution> resolution = getMaxResolution(supportedInputConfig);
  if (!resolution.has_value()) {
    return BAD_VALUE;
  }
  maxResolution.width = resolution.value().width;
  maxResolution.height = resolution.value().height;

  // TODO(b/301023410) Add also all "standard" resolutions we can rescale the
  // streams to (all standard resolutions with same aspect ratio).

  std::map<Resolution, int> resolutionToMaxFpsMap =
      getResolutionToMaxFpsMap(supportedInputConfig);

  // Add configurations for all unique input resolutions and output formats.
  for (const PixelFormat format : kOutputFormats) {
    std::transform(
        resolutionToMaxFpsMap.begin(), resolutionToMaxFpsMap.end(),
        std::back_inserter(outputConfigurations), [format](const auto& entry) {
          Resolution resolution = entry.first;
          int maxFps = entry.second;
          return MetadataBuilder::StreamConfiguration{
              .width = resolution.width,
              .height = resolution.height,
              .format = static_cast<int32_t>(format),
              .isInput = ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT,
              .minFrameDuration = std::chrono::nanoseconds(1s) / maxFps,
              .minStallDuration = 0s};
        });
  }

  return OK;
}

// Populates the maxResolution and the outputConfigurations
// from the list of supported stream configs
//
// Note: the provided configurations must represent HEIC streams
status_t convertSupportedHeicStreams(
    const std::vector<SupportedStreamConfiguration>& supportedInputConfigs,
    Resolution& maxResolution,
    std::vector<MetadataBuilder::StreamConfiguration>& outputConfigurations) {
  if (supportedInputConfigs.empty()) {
    return OK;
  }

  std::optional<Resolution> resolution = getMaxResolution(supportedInputConfigs);
  if (!resolution.has_value()) {
    ALOGE("%s: Failed to identify max resolution", __func__);
    return BAD_VALUE;
  }
  maxResolution.width = resolution.value().width;
  maxResolution.height = resolution.value().height;

  outputConfigurations.reserve(supportedInputConfigs.size());

  for (const auto& inputConfig : supportedInputConfigs) {
    if (inputConfig.width <= 0 || inputConfig.height <= 0 ||
        inputConfig.imageFormat != Format::HEIC || inputConfig.maxFps <= 0) {
      ALOGE(
          "%s: Received invalid HEIC format: width=%d, height=%d, format=0x%x, "
          "maxFps=%d",
          __func__, inputConfig.width, inputConfig.height,
          inputConfig.imageFormat, inputConfig.maxFps);
      return BAD_VALUE;
    }

    outputConfigurations.emplace_back(MetadataBuilder::StreamConfiguration{
        .width = inputConfig.width,
        .height = inputConfig.height,
        .format = static_cast<int>(PixelFormat::BLOB),
        .isInput = ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS_OUTPUT,
        .minFrameDuration = std::chrono::nanoseconds(1s) / inputConfig.maxFps,
        .minStallDuration = 0s});
  }

  return OK;
}

status_t updateStreamConfigurationMetadataHelper(
    HelperCameraMetadata& metadataHelper,
    const std::vector<MetadataBuilder::StreamConfiguration>&
        scalerOutputConfigurations,
    int androidAvailableStreamConfigurationsKey,
    int androidAvailableMinFrameDurationsKey,
    int androidAvailableStallDurationsKey) {
  std::vector<int32_t> metadataStreamConfigs;
  std::vector<int64_t> metadataMinFrameDurations;
  std::vector<int64_t> metadataStallDurations;

  convertStreamConfigurationsToMetadataValues(
      scalerOutputConfigurations, metadataStreamConfigs,
      metadataMinFrameDurations, metadataStallDurations);

  status_t ret = metadataHelper.update(androidAvailableStreamConfigurationsKey,
                                       metadataStreamConfigs.data(),
                                       metadataStreamConfigs.size());
  if (ret != OK) {
    ALOGE("%s: Can not set available stream configurations, metadata key=%d",
          __func__, androidAvailableStreamConfigurationsKey);
    return ret;
  }

  ret = metadataHelper.update(androidAvailableMinFrameDurationsKey,
                              metadataMinFrameDurations.data(),
                              metadataMinFrameDurations.size());
  if (ret != OK) {
    ALOGE("%s: Can not set available min frame durations, metadata key: %d",
          __func__, androidAvailableMinFrameDurationsKey);
    return ret;
  }

  ret = metadataHelper.update(androidAvailableStallDurationsKey,
                              metadataStallDurations.data(),
                              metadataStallDurations.size());
  if (ret != OK) {
    ALOGE("%s: Can not set available stall durations, metadata key=%d",
          __func__, androidAvailableStallDurationsKey);
    return ret;
  }

  return OK;
}

status_t updateScalerStreamConfigurationMetadata(
    HelperCameraMetadata& metadataHelper,
    const std::vector<MetadataBuilder::StreamConfiguration>&
        scalerOutputConfigurations) {
  if (scalerOutputConfigurations.empty()) {
    return OK;
  }

  ALOGV(
      "%s: Adding %zu output scaler configurations to configured "
      "CameraCharacteristics.",
      __func__, scalerOutputConfigurations.size());

  return updateStreamConfigurationMetadataHelper(
      metadataHelper, scalerOutputConfigurations,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
      ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
      ANDROID_SCALER_AVAILABLE_STALL_DURATIONS);
}

status_t updateHeicStreamConfigurationMetadata(
    HelperCameraMetadata& metadataHelper,
    const std::vector<MetadataBuilder::StreamConfiguration>&
        heicOutputConfigurations) {
  if (heicOutputConfigurations.empty()) {
    return OK;
  }

  ALOGV(
      "%s: Adding %zu output HEIC configurations to configured "
      "CameraCharacteristics.",
      __func__, heicOutputConfigurations.size());

  return updateStreamConfigurationMetadataHelper(
      metadataHelper, heicOutputConfigurations,
      ANDROID_HEIC_AVAILABLE_HEIC_STREAM_CONFIGURATIONS,
      ANDROID_HEIC_AVAILABLE_HEIC_MIN_FRAME_DURATIONS,
      ANDROID_HEIC_AVAILABLE_HEIC_STALL_DURATIONS);
}

std::unique_ptr<AidlCameraMetadata> createDefaultCameraCharacteristics(
    const std::vector<SupportedStreamConfiguration>& supportedInputConfig,
    const SensorOrientation sensorOrientation, const LensFacing lensFacing,
    const int32_t deviceId) {
  MetadataBuilder builder;
  builder
      .setSupportedHardwareLevel(ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL)
      .setDeviceId(deviceId)
      .setFlashAvailable(false)
      .setLensFacing(
          static_cast<camera_metadata_enum_android_lens_facing>(lensFacing))
      .setAvailableFocalLengths({VirtualCameraDevice::kFocalLength})
      .setSensorOrientation(static_cast<int32_t>(sensorOrientation))
      .setSensorReadoutTimestamp(ANDROID_SENSOR_READOUT_TIMESTAMP_NOT_SUPPORTED)
      .setSensorTimestampSource(ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE_UNKNOWN)
      .setSensorPhysicalSize(36.0, 24.0)
      .setAvailableAberrationCorrectionModes(
          {ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF})
      .setAvailableNoiseReductionModes({ANDROID_NOISE_REDUCTION_MODE_OFF})
      .setAvailableFaceDetectModes({ANDROID_STATISTICS_FACE_DETECT_MODE_OFF})
      .setAvailableStreamUseCases(
          {ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT,
           ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW,
           ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_STILL_CAPTURE,
           ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_RECORD,
           ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW_VIDEO_STILL,
           ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_CALL})
      .setAvailableTestPatternModes({ANDROID_SENSOR_TEST_PATTERN_MODE_OFF})
      .setAvailableMaxDigitalZoom(1.0)
      .setControlAvailableModes({ANDROID_CONTROL_MODE_AUTO})
      .setControlAfAvailableModes({ANDROID_CONTROL_AF_MODE_OFF})
      .setControlAvailableSceneModes({ANDROID_CONTROL_SCENE_MODE_DISABLED})
      .setControlAvailableEffects({ANDROID_CONTROL_EFFECT_MODE_OFF})
      .setControlAvailableVideoStabilizationModes(
          {ANDROID_CONTROL_VIDEO_STABILIZATION_MODE_OFF})
      .setControlAeAvailableModes({ANDROID_CONTROL_AE_MODE_ON})
      .setControlAeAvailableAntibandingModes(
          {ANDROID_CONTROL_AE_ANTIBANDING_MODE_AUTO})
      .setControlAeAvailableFpsRanges(
          fpsRangesForInputConfig(supportedInputConfig))
      .setControlMaxRegions(0, 0, 0)
      .setControlAfRegions({kDefaultEmptyControlRegion})
      .setControlAeRegions({kDefaultEmptyControlRegion})
      .setControlAwbRegions({kDefaultEmptyControlRegion})
      .setControlAeCompensationRange(0, 0)
      .setControlAeCompensationStep(camera_metadata_rational_t{0, 1})
      .setControlAwbLockAvailable(false)
      .setControlAeLockAvailable(false)
      .setControlAvailableAwbModes({ANDROID_CONTROL_AWB_MODE_AUTO})
      .setControlZoomRatioRange(/*min=*/1.0, /*max=*/1.0)
      .setCroppingType(ANDROID_SCALER_CROPPING_TYPE_CENTER_ONLY)
      .setJpegAvailableThumbnailSizes(
          getSupportedJpegThumbnailSizes(supportedInputConfig))
      .setMaxJpegSize(kMaxJpegSize)
      .setMaxFaceCount(0)
      .setMaxFrameDuration(kMaxFrameDuration)
      .setMaxNumberOutputStreams(
          VirtualCameraDevice::kMaxNumberOfRawStreams,
          VirtualCameraDevice::kMaxNumberOfProcessedStreams,
          VirtualCameraDevice::kMaxNumberOfStallStreams)
      .setRequestPartialResultCount(1)
      .setPipelineMaxDepth(kPipelineMaxDepth)
      .setSyncMaxLatency(ANDROID_SYNC_MAX_LATENCY_UNKNOWN)
      .setAvailableRequestKeys({ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
                                ANDROID_CONTROL_CAPTURE_INTENT,
                                ANDROID_CONTROL_AE_MODE,
                                ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
                                ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
                                ANDROID_CONTROL_AE_ANTIBANDING_MODE,
                                ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
                                ANDROID_CONTROL_AF_TRIGGER,
                                ANDROID_CONTROL_AF_MODE,
                                ANDROID_CONTROL_AWB_MODE,
                                ANDROID_SCALER_CROP_REGION,
                                ANDROID_CONTROL_EFFECT_MODE,
                                ANDROID_CONTROL_MODE,
                                ANDROID_CONTROL_SCENE_MODE,
                                ANDROID_CONTROL_VIDEO_STABILIZATION_MODE,
                                ANDROID_CONTROL_ZOOM_RATIO,
                                ANDROID_FLASH_MODE,
                                ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES,
                                ANDROID_JPEG_ORIENTATION,
                                ANDROID_JPEG_QUALITY,
                                ANDROID_JPEG_THUMBNAIL_QUALITY,
                                ANDROID_JPEG_THUMBNAIL_SIZE,
                                ANDROID_NOISE_REDUCTION_MODE,
                                ANDROID_STATISTICS_FACE_DETECT_MODE})
      .setAvailableResultKeys({
          ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
          ANDROID_CONTROL_AE_ANTIBANDING_MODE,
          ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
          ANDROID_CONTROL_AE_LOCK,
          ANDROID_CONTROL_AE_MODE,
          ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
          ANDROID_CONTROL_AE_STATE,
          ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
          ANDROID_CONTROL_AF_MODE,
          ANDROID_CONTROL_AF_STATE,
          ANDROID_CONTROL_AF_TRIGGER,
          ANDROID_CONTROL_AWB_LOCK,
          ANDROID_CONTROL_AWB_MODE,
          ANDROID_CONTROL_AWB_STATE,
          ANDROID_CONTROL_CAPTURE_INTENT,
          ANDROID_CONTROL_EFFECT_MODE,
          ANDROID_CONTROL_MODE,
          ANDROID_CONTROL_SCENE_MODE,
          ANDROID_CONTROL_VIDEO_STABILIZATION_MODE,
          ANDROID_STATISTICS_FACE_DETECT_MODE,
          ANDROID_FLASH_MODE,
          ANDROID_FLASH_STATE,
          ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES,
          ANDROID_JPEG_QUALITY,
          ANDROID_JPEG_THUMBNAIL_QUALITY,
          ANDROID_LENS_FOCAL_LENGTH,
          ANDROID_LENS_OPTICAL_STABILIZATION_MODE,
          ANDROID_NOISE_REDUCTION_MODE,
          ANDROID_REQUEST_PIPELINE_DEPTH,
          ANDROID_SENSOR_TIMESTAMP,
          ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE,
          ANDROID_STATISTICS_LENS_SHADING_MAP_MODE,
          ANDROID_STATISTICS_SCENE_FLICKER,
      })
      .setAvailableCapabilities(
          {ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE});

  // TODO(b/458068663): Consolidate stream configuration metadata handling
  // across the default and update cases
  std::vector<SupportedStreamConfiguration> scalerStreamInputConfigs;
  std::vector<SupportedStreamConfiguration> heicStreamInputConfigs;
  separateScalerAndHeicInputConfigurations(
      supportedInputConfig, scalerStreamInputConfigs, heicStreamInputConfigs);

  std::vector<MetadataBuilder::StreamConfiguration> scalerOutputConfigurations;
  std::vector<MetadataBuilder::StreamConfiguration> heicOutputConfigurations;

  Resolution maxScalerResolution;
  if (convertSupportedScalerStreams(scalerStreamInputConfigs,
                                    maxScalerResolution,
                                    scalerOutputConfigurations) != OK) {
    ALOGE(
        "Can not get max resolution from the scaler input stream configs, "
        "output "
        "streams not configured!");
    return nullptr;
  }

  ALOGV(
      "Adding %zu scaler output configurations to default "
      "CameraCharacteristics.",
      scalerOutputConfigurations.size());
  builder.setAvailableScalerOutputStreamConfigurations(
      scalerOutputConfigurations);

  Resolution maxHeicResolution;
  if (convertSupportedHeicStreams(heicStreamInputConfigs, maxHeicResolution,
                                  heicOutputConfigurations) != OK) {
    ALOGE("%s: Failed to convert supported HEIC input streams", __func__);
    return nullptr;
  }

  ALOGV(
      "Adding %zu HEIC output configurations to default CameraCharacteristics.",
      heicOutputConfigurations.size());
  builder.setAvailableHeicOutputStreamConfigurations(heicOutputConfigurations);

  Resolution maxResolution = (maxHeicResolution < maxScalerResolution)
                                 ? maxScalerResolution
                                 : maxHeicResolution;

  builder.setSensorActiveArraySize(0, 0, maxResolution.width,
                                   maxResolution.height);
  builder.setSensorPixelArraySize(maxResolution.width, maxResolution.height);

  return builder.setAvailableCharacteristicKeys().build();
}

status_t updateStreamConfigurations(
    HelperCameraMetadata& metadataHelper,
    const std::vector<SupportedStreamConfiguration>& supportedInputConfig) {
  std::vector<SupportedStreamConfiguration> scalerStreamInputConfigs;
  std::vector<SupportedStreamConfiguration> heicStreamInputConfigs;
  separateScalerAndHeicInputConfigurations(
      supportedInputConfig, scalerStreamInputConfigs, heicStreamInputConfigs);

  std::vector<MetadataBuilder::StreamConfiguration> scalerOutputConfigurations;
  std::vector<MetadataBuilder::StreamConfiguration> heicOutputConfigurations;

  Resolution maxScalerResolution;
  status_t ret = convertSupportedScalerStreams(
      scalerStreamInputConfigs, maxScalerResolution, scalerOutputConfigurations);
  if (ret != OK) {
    ALOGE(
        "Can not get max resolution from the scaler input stream configs, "
        "output "
        "streams not configured!");
    return ret;
  }

  ret = updateScalerStreamConfigurationMetadata(metadataHelper,
                                                scalerOutputConfigurations);
  if (ret != OK) {
    ALOGE("%s: failed to update scaler stream configuration metadata", __func__);
    return ret;
  }

  Resolution maxHeicResolution;
  ret = convertSupportedHeicStreams(heicStreamInputConfigs, maxHeicResolution,
                                    heicOutputConfigurations);
  if (ret != OK) {
    ALOGE(
        "Can not get max resolution from the heic input stream configs, "
        "output "
        "streams not configured!");
    return ret;
  }

  ret = updateHeicStreamConfigurationMetadata(metadataHelper,
                                              heicOutputConfigurations);
  if (ret != OK) {
    ALOGE("%s: failed to update HEIC stream configuration metadata", __func__);
    return ret;
  }

  Resolution maxResolution = (maxHeicResolution < maxScalerResolution)
                                 ? maxScalerResolution
                                 : maxHeicResolution;

  if (!metadataHelper.exists(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE)) {
    auto activeArraySizeVec =
        std::vector<int32_t>({0, 0, maxResolution.width, maxResolution.height});
    ret = metadataHelper.update(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE,
                                activeArraySizeVec.data(),
                                activeArraySizeVec.size());
    if (ret != OK) {
      ALOGE("Can not set ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE!");
      return ret;
    }
  }

  if (!metadataHelper.exists(ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE)) {
    auto pixelArraySizeVec =
        std::vector<int32_t>({maxResolution.width, maxResolution.height});
    ret = metadataHelper.update(ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE,
                                pixelArraySizeVec.data(),
                                pixelArraySizeVec.size());
    if (ret != OK) {
      ALOGE("Can not set ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE!");
      return ret;
    }
  }

  return ret;
}

std::optional<AidlCameraMetadata> initCameraCharacteristics(
    const std::vector<SupportedStreamConfiguration>& supportedInputConfig,
    const SensorOrientation sensorOrientation, const LensFacing lensFacing,
    const std::optional<VirtualCameraMetadata>& configCameraCharacteristics,
    const int32_t deviceId) {
  if (!std::all_of(supportedInputConfig.begin(), supportedInputConfig.end(),
                   [](const SupportedStreamConfiguration& config) {
                     return isFormatSupportedForInput(
                         config.width, config.height, config.imageFormat,
                         config.maxFps);
                   })) {
    ALOGE("%s: input configuration contains unsupported format", __func__);
    return std::nullopt;
  }

  std::unique_ptr<AidlCameraMetadata> aidlMetadata;
  // If the camera metadata is set by the VD owner, add the deviceId and pass it as it is
  if (configCameraCharacteristics.has_value()) {
    ALOGD("VirtualCameraDevice - using config CameraCharacteristics");
    AidlCameraMetadata deviceCameraMetadata;
    status_t ret = convertVirtualToDeviceCameraMetadata(
        configCameraCharacteristics.value(), deviceCameraMetadata);
    if (ret != OK) {
      ALOGE("Failed to convert virtual to device camera characteristics!");
      return AidlCameraMetadata();
    }

    HelperCameraMetadata metadataHelper = HelperCameraMetadata(
        clone_camera_metadata(reinterpret_cast<const camera_metadata_t*>(
            deviceCameraMetadata.metadata.data())));

    auto deviceIdVec = std::vector<int32_t>({deviceId});
    ret = metadataHelper.update(ANDROID_INFO_DEVICE_ID, deviceIdVec.data(),
                                deviceIdVec.size());
    if (ret != OK) {
      ALOGE(
          "Failed to update ANDROID_INFO_DEVICE_ID for camera "
          "characteristics!");
    }

    // internal values that can't be configured from external metadata
    auto jpegMaxSizeVec = std::vector<int32_t>({kMaxJpegSize});
    ret = metadataHelper.update(ANDROID_JPEG_MAX_SIZE, jpegMaxSizeVec.data(),
                                jpegMaxSizeVec.size());
    if (ret != OK) {
      ALOGE(
          "Failed to update ANDROID_JPEG_MAX_SIZE for camera characteristics!");
    }

    ret = updateStreamConfigurations(metadataHelper, supportedInputConfig);
    if (ret != OK) {
      ALOGE(
          "Failed to update output stream configurations for camera "
          "characteristics!");
    }

    aidlMetadata = cameraMetadataToHal(metadataHelper);
  } else {
    ALOGD("VirtualCameraDevice - createDefaultCameraCharacteristics");
    aidlMetadata = createDefaultCameraCharacteristics(
        supportedInputConfig, sensorOrientation, lensFacing, deviceId);
  }

  if (aidlMetadata == nullptr) {
    ALOGE("Failed to build metadata!");
    return AidlCameraMetadata();
  }

  return std::move(*aidlMetadata);
}

}  // namespace

VirtualCameraDevice::VirtualCameraDevice(
    const std::string& cameraId,
    const VirtualCameraConfiguration& configuration, int32_t deviceId)
    : mCameraId(cameraId),
      mVirtualCameraClientCallback(configuration.virtualCameraCallback),
      mSupportedInputConfigurations(configuration.supportedStreamConfigs),
      mPerFrameCameraMetadataEnabled(
          configuration.perFrameCameraMetadataEnabled),
      mConfigCameraCharacteristics(configuration.cameraCharacteristics),
      mIsMultiInputStreamEnabled(flags::camera_multiple_input_streams() &&
                                 configuration.isMultiInputStreamEnabled) {
  std::optional<AidlCameraMetadata> metadata = initCameraCharacteristics(
      mSupportedInputConfigurations, configuration.sensorOrientation,
      configuration.lensFacing, mConfigCameraCharacteristics, deviceId);

  if (metadata.has_value()) {
    mCameraCharacteristics = *metadata;
  } else {
    ALOGE(
        "%s: Failed to initialize camera characteristic based on provided "
        "configuration.",
        __func__);
  }
}

ndk::ScopedAStatus VirtualCameraDevice::getCameraCharacteristics(
    AidlCameraMetadata* _aidl_return) {
  ALOGV("%s", __func__);
  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  *_aidl_return = mCameraCharacteristics;
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraDevice::getPhysicalCameraCharacteristics(
    const std::string& in_physicalCameraId, AidlCameraMetadata* _aidl_return) {
  ALOGV("%s: physicalCameraId %s", __func__, in_physicalCameraId.c_str());
  (void)_aidl_return;

  // VTS tests expect this call to fail with illegal argument status for
  // all publicly advertised camera ids.
  // Because we don't support physical camera ids, we just always
  // fail with illegal argument (there's no valid argument to provide).
  return cameraStatus(Status::ILLEGAL_ARGUMENT);
}

ndk::ScopedAStatus VirtualCameraDevice::getResourceCost(
    CameraResourceCost* _aidl_return) {
  ALOGV("%s", __func__);
  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }
  _aidl_return->resourceCost = 100;  // ¯\_(ツ)_/¯
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraDevice::isStreamCombinationSupported(
    const StreamConfiguration& in_streams, bool* _aidl_return) {
  ALOGV("%s", __func__);

  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  *_aidl_return = isStreamCombinationSupported(in_streams);
  return ndk::ScopedAStatus::ok();
};

bool VirtualCameraDevice::isStreamCombinationSupported(
    const StreamConfiguration& streamConfiguration) const {
  if (streamConfiguration.streams.empty()) {
    ALOGE("%s: Querying empty configuration", __func__);
    return false;
  }
  if (!flags::virtual_camera_direct_blob_transfer()) {
    bool containsBlobInput =
        std::any_of(mSupportedInputConfigurations.begin(),
                    mSupportedInputConfigurations.end(),
                    [](const SupportedStreamConfiguration& inputConfig) {
                      return isBlobFormat(inputConfig.imageFormat);
                    });
    if (containsBlobInput) {
      ALOGE(
          "%s: input configurations contains BLOB format. This is "
          "not allowed since flags::virtual_camera_direct_blob_transfer "
          "is disabled",
          __func__);
      return false;
    }
  }

  const std::vector<Stream>& streams = streamConfiguration.streams;

  Resolution firstStreamResolution(streams[0].width, streams[0].height);
  auto isSameAspectRatioAsFirst = [firstStreamResolution](const Stream& stream) {
    return isApproximatellySameAspectRatio(
        firstStreamResolution, Resolution(stream.width, stream.height));
  };
  if (!std::all_of(streams.begin(), streams.end(), isSameAspectRatioAsFirst)) {
    ALOGW(
        "%s: Requested streams do not have same aspect ratio. Different aspect "
        "ratios are currently "
        "not supported by virtual camera. Stream configuration: %s",
        __func__, streamConfiguration.toString().c_str());
    return false;
  }

  int numberOfProcessedStreams = 0;
  int numberOfStallStreams = 0;
  for (const Stream& stream : streamConfiguration.streams) {
    ALOGV("%s: Configuration queried: %s", __func__, stream.toString().c_str());

    if (stream.streamType == StreamType::INPUT) {
      ALOGW("%s: Input stream type is not supported", __func__);
      return false;
    }

    if (stream.rotation != StreamRotation::ROTATION_0) {
      ALOGW("%s: Rotation is not supported", __func__);
      return false;
    }

    if (!isSupportedOutputFormat(stream.format)) {
      ALOGW("Unsupported output stream format:%s stream:%s ",
            toString(stream.format).c_str(), stream.toString().c_str());
      return false;
    }

    if (stream.format == PixelFormat::BLOB) {
      numberOfStallStreams++;
    } else {
      numberOfProcessedStreams++;
    }

    Resolution requestedResolution(stream.width, stream.height);
    auto matchesSupportedInputConfig =
        [requestedResolution,
         &stream](const SupportedStreamConfiguration& config) {
          Resolution supportedInputResolution(config.width, config.height);

          // Check for matching input that enables direct blob transfer
          //
          // Note: skip isJpegStreamConfig(stream) here because a JPEG output
          // stream can be generated from a bitmap input, e.g. YUV
          if (isBlobFormat(config.imageFormat) || isHeicStreamConfig(stream)) {
            if (!areMatchingBlobTypes(stream, config)) {
              return false;
            }

            // If a direct blob transfer is possible, then the resolutions must
            // match exactly
            return requestedResolution == supportedInputResolution;
          }

          // Direct blob transfer not possible here, so resolutions need not
          // perfectly match
          return requestedResolution <= supportedInputResolution &&
                 isApproximatellySameAspectRatio(requestedResolution,
                                                 supportedInputResolution);
        };
    if (std::none_of(mSupportedInputConfigurations.begin(),
                     mSupportedInputConfigurations.end(),
                     matchesSupportedInputConfig)) {
      ALOGW("Requested config doesn't match any supported input config");
      return false;
    }
  }

  if (numberOfProcessedStreams > kMaxNumberOfProcessedStreams) {
    ALOGE("%s: %d processed streams exceeds the supported maximum of %d",
          __func__, numberOfProcessedStreams, kMaxNumberOfProcessedStreams);
    return false;
  }

  if (numberOfStallStreams > kMaxNumberOfStallStreams) {
    ALOGE("%s: %d stall streams exceeds the supported maximum of %d", __func__,
          numberOfStallStreams, kMaxNumberOfStallStreams);
    return false;
  }

  return true;
}

ndk::ScopedAStatus VirtualCameraDevice::open(
    const std::shared_ptr<ICameraDeviceCallback>& in_callback,
    std::shared_ptr<ICameraDeviceSession>* _aidl_return) {
  ALOGV("%s", __func__);

  {
    std::lock_guard<std::mutex> lock(mSessionLock);
    auto currentSession = mSession.lock();
    if (currentSession != nullptr) {
      return cameraStatus(Status::CAMERA_IN_USE);
    }

    auto session = ndk::SharedRefBase::make<VirtualCameraSession>(
        sharedFromThis(), in_callback, mVirtualCameraClientCallback);
    *_aidl_return = session;

    mSession = session;
  }

  if (virtualdevice::flags::virtual_camera_on_open()) {
    if (mVirtualCameraClientCallback != nullptr) {
      mVirtualCameraClientCallback->onOpenCamera();
    }
  }

  return ndk::ScopedAStatus::ok();
};

ndk::ScopedAStatus VirtualCameraDevice::openInjectionSession(
    const std::shared_ptr<ICameraDeviceCallback>& in_callback,
    std::shared_ptr<ICameraInjectionSession>* _aidl_return) {
  ALOGV("%s", __func__);

  (void)in_callback;
  (void)_aidl_return;
  return cameraStatus(Status::OPERATION_NOT_SUPPORTED);
}

ndk::ScopedAStatus VirtualCameraDevice::setTorchMode(bool in_on) {
  ALOGV("%s: on = %s", __func__, in_on ? "on" : "off");
  return cameraStatus(Status::OPERATION_NOT_SUPPORTED);
}

ndk::ScopedAStatus VirtualCameraDevice::turnOnTorchWithStrengthLevel(
    int32_t in_torchStrength) {
  ALOGV("%s: torchStrength = %d", __func__, in_torchStrength);
  return cameraStatus(Status::OPERATION_NOT_SUPPORTED);
}

ndk::ScopedAStatus VirtualCameraDevice::getTorchStrengthLevel(
    int32_t* _aidl_return) {
  (void)_aidl_return;
  return cameraStatus(Status::OPERATION_NOT_SUPPORTED);
}

binder_status_t VirtualCameraDevice::dump(int fd, const char**, uint32_t) {
  ALOGD("Dumping virtual camera %s", mCameraId.c_str());
  const char* indent = "  ";
  const char* doubleIndent = "    ";
  dprintf(fd, "%svirtual_camera %s belongs to virtual device %d\n", indent,
          mCameraId.c_str(),
          getDeviceId(mCameraCharacteristics)
              .value_or(VirtualCameraService::kDefaultDeviceId));
  dprintf(fd, "%sSupportedStreamConfiguration:\n", indent);
  for (auto& config : mSupportedInputConfigurations) {
    dprintf(fd, "%s%s", doubleIndent, config.toString().c_str());
  }
  return STATUS_OK;
}

std::string VirtualCameraDevice::getCameraName() const {
  return std::string(kDevicePathPrefix) + mCameraId;
}

const std::vector<SupportedStreamConfiguration>&
VirtualCameraDevice::getInputConfigs() const {
  return mSupportedInputConfigurations;
}

Resolution VirtualCameraDevice::getMaxInputResolution() const {
  std::optional<Resolution> maxResolution =
      getMaxResolution(mSupportedInputConfigurations);
  if (!maxResolution.has_value()) {
    ALOGE(
        "%s: Cannot determine sensor size for virtual camera - input "
        "configurations empty?",
        __func__);
    return Resolution(0, 0);
  }
  return maxResolution.value();
}

int VirtualCameraDevice::allocateInputStreamId() {
  return mNextInputStreamId++;
}

std::shared_ptr<VirtualCameraDevice> VirtualCameraDevice::sharedFromThis() {
  // SharedRefBase which BnCameraDevice inherits from breaks
  // std::enable_shared_from_this. This is recommended replacement for
  // shared_from_this() per documentation in binder_interface_utils.h.
  return ref<VirtualCameraDevice>();
}

void VirtualCameraDevice::closeSession() {
  ALOGV("Close all sessions");
  std::shared_ptr<VirtualCameraSession> session;
  {
    std::lock_guard<std::mutex> lock(mSessionLock);
    session = mSession.lock();
    mSession.reset();
  }
  if (session != nullptr) {
    session->close();
  }
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
