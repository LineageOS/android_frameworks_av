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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <numeric>
#include <optional>
#include <string>
#include <vector>

#include "VirtualCameraSession.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/companion/virtualcamera/VirtualCameraConfiguration.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "android/binder_auto_utils.h"
#include "android/binder_status.h"
#include "log/log.h"
#include "system/camera_metadata.h"
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
using ::aidl::android::hardware::camera::common::CameraResourceCost;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::ICameraDeviceCallback;
using ::aidl::android::hardware::camera::device::ICameraDeviceSession;
using ::aidl::android::hardware::camera::device::ICameraInjectionSession;
using ::aidl::android::hardware::camera::device::Stream;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::camera::device::StreamRotation;
using ::aidl::android::hardware::camera::device::StreamType;
using ::aidl::android::hardware::graphics::common::PixelFormat;

namespace {

using namespace std::chrono_literals;

// Prefix of camera name - "device@1.1/virtual/{numerical_id}"
const char* kDevicePathPrefix = "device@1.1/virtual/";

constexpr int32_t kMaxJpegSize = 3 * 1024 * 1024 /*3MiB*/;

constexpr int32_t kMinFps = 15;

constexpr std::chrono::nanoseconds kMaxFrameDuration =
    std::chrono::duration_cast<std::chrono::nanoseconds>(1e9ns / kMinFps);

constexpr uint8_t kPipelineMaxDepth = 2;

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

std::vector<MetadataBuilder::FpsRange> fpsRangesForInputConfig(
    const std::vector<SupportedStreamConfiguration>& configs) {
  std::set<MetadataBuilder::FpsRange> availableRanges;

  for (const SupportedStreamConfiguration& config : configs) {
    availableRanges.insert({.minFps = kMinFps, .maxFps = config.maxFps});
    availableRanges.insert({.minFps = config.maxFps, .maxFps = config.maxFps});
  }

  if (std::any_of(configs.begin(), configs.end(),
                  [](const SupportedStreamConfiguration& config) {
                    return config.maxFps >= 30;
                  })) {
    availableRanges.insert({.minFps = kMinFps, .maxFps = 30});
    availableRanges.insert({.minFps = 30, .maxFps = 30});
  }

  return std::vector<MetadataBuilder::FpsRange>(availableRanges.begin(),
                                                availableRanges.end());
}

std::optional<Resolution> getMaxResolution(
    const std::vector<SupportedStreamConfiguration>& configs) {
  auto itMax = std::max_element(configs.begin(), configs.end(),
                                [](const SupportedStreamConfiguration& a,
                                   const SupportedStreamConfiguration& b) {
                                  return a.width * b.height < a.width * b.height;
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

// TODO(b/301023410) - Populate camera characteristics according to camera configuration.
std::optional<CameraMetadata> initCameraCharacteristics(
    const std::vector<SupportedStreamConfiguration>& supportedInputConfig,
    const SensorOrientation sensorOrientation, const LensFacing lensFacing) {
  if (!std::all_of(supportedInputConfig.begin(), supportedInputConfig.end(),
                   [](const SupportedStreamConfiguration& config) {
                     return isFormatSupportedForInput(
                         config.width, config.height, config.pixelFormat,
                         config.maxFps);
                   })) {
    ALOGE("%s: input configuration contains unsupported format", __func__);
    return std::nullopt;
  }

  MetadataBuilder builder =
      MetadataBuilder()
          .setSupportedHardwareLevel(
              ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL)
          .setFlashAvailable(false)
          .setLensFacing(
              static_cast<camera_metadata_enum_android_lens_facing>(lensFacing))
          .setAvailableFocalLengths({VirtualCameraDevice::kFocalLength})
          .setSensorOrientation(static_cast<int32_t>(sensorOrientation))
          .setSensorReadoutTimestamp(
              ANDROID_SENSOR_READOUT_TIMESTAMP_NOT_SUPPORTED)
          .setSensorTimestampSource(ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE_UNKNOWN)
          .setSensorPhysicalSize(36.0, 24.0)
          .setAvailableAberrationCorrectionModes(
              {ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF})
          .setAvailableNoiseReductionModes({ANDROID_NOISE_REDUCTION_MODE_OFF})
          .setAvailableFaceDetectModes({ANDROID_STATISTICS_FACE_DETECT_MODE_OFF})
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
                                    ANDROID_JPEG_QUALITY,
                                    ANDROID_JPEG_THUMBNAIL_QUALITY,
                                    ANDROID_NOISE_REDUCTION_MODE,
                                    ANDROID_STATISTICS_FACE_DETECT_MODE})
          .setAvailableResultKeys(
              {ANDROID_COLOR_CORRECTION_ABERRATION_MODE, ANDROID_CONTROL_AE_MODE,
               ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER, ANDROID_CONTROL_AF_MODE,
               ANDROID_CONTROL_AWB_MODE, ANDROID_CONTROL_EFFECT_MODE,
               ANDROID_CONTROL_MODE, ANDROID_FLASH_MODE, ANDROID_FLASH_STATE,
               ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES, ANDROID_JPEG_QUALITY,
               ANDROID_JPEG_THUMBNAIL_QUALITY, ANDROID_LENS_FOCAL_LENGTH,
               ANDROID_SENSOR_TIMESTAMP, ANDROID_NOISE_REDUCTION_MODE})
          .setAvailableCapabilities(
              {ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE});

  // Active array size must correspond to largest supported input resolution.
  std::optional<Resolution> maxResolution =
      getMaxResolution(supportedInputConfig);
  if (!maxResolution.has_value()) {
    return std::nullopt;
  }
  builder.setSensorActiveArraySize(0, 0, maxResolution->width,
                                   maxResolution->height);
  builder.setSensorPixelArraySize(maxResolution->width, maxResolution->height);

  std::vector<MetadataBuilder::StreamConfiguration> outputConfigurations;

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
              .minFrameDuration = std::chrono::nanoseconds(1s) / maxFps,
              .minStallDuration = 0s};
        });
  }

  ALOGV("Adding %zu output configurations", outputConfigurations.size());
  builder.setAvailableOutputStreamConfigurations(outputConfigurations);

  auto metadata = builder.setAvailableCharacteristicKeys().build();
  if (metadata == nullptr) {
    ALOGE("Failed to build metadata!");
    return CameraMetadata();
  }

  return std::move(*metadata);
}

}  // namespace

VirtualCameraDevice::VirtualCameraDevice(
    const uint32_t cameraId, const VirtualCameraConfiguration& configuration)
    : mCameraId(cameraId),
      mVirtualCameraClientCallback(configuration.virtualCameraCallback),
      mSupportedInputConfigurations(configuration.supportedStreamConfigs) {
  std::optional<CameraMetadata> metadata = initCameraCharacteristics(
      mSupportedInputConfigurations, configuration.sensorOrientation,
      configuration.lensFacing);
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
    CameraMetadata* _aidl_return) {
  ALOGV("%s", __func__);
  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  *_aidl_return = mCameraCharacteristics;
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraDevice::getPhysicalCameraCharacteristics(
    const std::string& in_physicalCameraId, CameraMetadata* _aidl_return) {
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

    if (stream.rotation != StreamRotation::ROTATION_0 ||
        !isSupportedOutputFormat(stream.format)) {
      ALOGV("Unsupported output stream type");
      return false;
    }

    if (stream.format == PixelFormat::BLOB) {
      numberOfStallStreams++;
    } else {
      numberOfProcessedStreams++;
    }

    Resolution requestedResolution(stream.width, stream.height);
    auto matchesSupportedInputConfig =
        [requestedResolution](const SupportedStreamConfiguration& config) {
          Resolution supportedInputResolution(config.width, config.height);
          return requestedResolution <= supportedInputResolution &&
                 isApproximatellySameAspectRatio(requestedResolution,
                                                 supportedInputResolution);
        };
    if (std::none_of(mSupportedInputConfigurations.begin(),
                     mSupportedInputConfigurations.end(),
                     matchesSupportedInputConfig)) {
      ALOGV("Requested config doesn't match any supported input config");
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

  *_aidl_return = ndk::SharedRefBase::make<VirtualCameraSession>(
      sharedFromThis(), in_callback, mVirtualCameraClientCallback);

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

binder_status_t VirtualCameraDevice::dump(int fd, const char** args,
                                          uint32_t numArgs) {
  // TODO(b/301023410) Implement.
  (void)fd;
  (void)args;
  (void)numArgs;
  return STATUS_OK;
}

std::string VirtualCameraDevice::getCameraName() const {
  return std::string(kDevicePathPrefix) + std::to_string(mCameraId);
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

std::shared_ptr<VirtualCameraDevice> VirtualCameraDevice::sharedFromThis() {
  // SharedRefBase which BnCameraDevice inherits from breaks
  // std::enable_shared_from_this. This is recommended replacement for
  // shared_from_this() per documentation in binder_interface_utils.h.
  return ref<VirtualCameraDevice>();
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
