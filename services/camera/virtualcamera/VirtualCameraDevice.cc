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
#define LOG_TAG "VirtualCameraDevice"
#include "VirtualCameraDevice.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>

#include "VirtualCameraSession.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "aidl/android/hardware/camera/device/StreamConfiguration.h"
#include "android/binder_auto_utils.h"
#include "android/binder_status.h"
#include "log/log.h"
#include "system/camera_metadata.h"
#include "util/MetadataBuilder.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::Format;
using ::aidl::android::companion::virtualcamera::IVirtualCameraCallback;
using ::aidl::android::companion::virtualcamera::SupportedStreamConfiguration;
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

constexpr std::chrono::nanoseconds kMinFrameDuration30Fps = 1s / 30;
constexpr int32_t kMaxJpegSize = 3 * 1024 * 1024 /*3MiB*/;

constexpr MetadataBuilder::ControlRegion kDefaultEmptyControlRegion{};

struct Resolution {
  Resolution(const int w, const int h) : width(w), height(h) {
  }

  bool operator<(const Resolution& other) const {
    return width * height < other.width * other.height;
  }

  bool operator==(const Resolution& other) const {
    return width == other.width && height == other.height;
  }

  const int width;
  const int height;
};

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

std::set<Resolution> getUniqueResolutions(
    const std::vector<SupportedStreamConfiguration>& configs) {
  std::set<Resolution> uniqueResolutions;
  std::transform(configs.begin(), configs.end(),
                 std::inserter(uniqueResolutions, uniqueResolutions.begin()),
                 [](const SupportedStreamConfiguration& config) {
                   return Resolution(config.width, config.height);
                 });
  return uniqueResolutions;
}

// TODO(b/301023410) - Populate camera characteristics according to camera configuration.
std::optional<CameraMetadata> initCameraCharacteristics(
    const std::vector<SupportedStreamConfiguration>& supportedInputConfig) {
  if (!std::all_of(supportedInputConfig.begin(), supportedInputConfig.end(),
                   [](const SupportedStreamConfiguration& config) {
                     return config.pixelFormat == Format::YUV_420_888;
                   })) {
    ALOGE("%s: input configuration contains unsupported pixel format", __func__);
    return std::nullopt;
  }

  MetadataBuilder builder =
      MetadataBuilder()
          .setSupportedHardwareLevel(
              ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL)
          .setFlashAvailable(false)
          .setLensFacing(ANDROID_LENS_FACING_EXTERNAL)
          .setSensorOrientation(0)
          .setAvailableFaceDetectModes({ANDROID_STATISTICS_FACE_DETECT_MODE_OFF})
          .setAvailableMaxDigitalZoom(1.0)
          .setControlAvailableModes({ANDROID_CONTROL_MODE_AUTO})
          .setControlAfAvailableModes({ANDROID_CONTROL_AF_MODE_OFF})
          .setControlAeAvailableFpsRange(10, 30)
          .setControlMaxRegions(0, 0, 0)
          .setControlAfRegions({kDefaultEmptyControlRegion})
          .setControlAeRegions({kDefaultEmptyControlRegion})
          .setControlAwbRegions({kDefaultEmptyControlRegion})
          .setControlAeCompensationRange(0, 1)
          .setControlAeCompensationStep(camera_metadata_rational_t{0, 1})
          .setMaxJpegSize(kMaxJpegSize)
          .setAvailableRequestKeys({ANDROID_CONTROL_AF_MODE})
          .setAvailableResultKeys({ANDROID_CONTROL_AF_MODE})
          .setAvailableCapabilities(
              {ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE})
          .setAvailableCharacteristicKeys();

  // Active array size must correspond to largest supported input resolution.
  std::optional<Resolution> maxResolution =
      getMaxResolution(supportedInputConfig);
  if (!maxResolution.has_value()) {
    return std::nullopt;
  }
  builder.setSensorActiveArraySize(0, 0, maxResolution->width,
                                   maxResolution->height);

  std::vector<MetadataBuilder::StreamConfiguration> outputConfigurations;

  // TODO(b/301023410) Add also all "standard" resolutions we can rescale the
  // streams to (all standard resolutions with same aspect ratio).

  // Add IMPLEMENTATION_DEFINED format for all supported input resolutions.
  std::set<Resolution> uniqueResolutions =
      getUniqueResolutions(supportedInputConfig);
  std::transform(
      uniqueResolutions.begin(), uniqueResolutions.end(),
      std::back_inserter(outputConfigurations),
      [](const Resolution& resolution) {
        return MetadataBuilder::StreamConfiguration{
            .width = resolution.width,
            .height = resolution.height,
            .format = ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED,
            .minFrameDuration = kMinFrameDuration30Fps,
            .minStallDuration = 0s};
      });

  // Add all supported configuration with explicit pixel format.
  std::transform(supportedInputConfig.begin(), supportedInputConfig.end(),
                 std::back_inserter(outputConfigurations),
                 [](const SupportedStreamConfiguration& config) {
                   return MetadataBuilder::StreamConfiguration{
                       .width = config.width,
                       .height = config.height,
                       .format = static_cast<int>(config.pixelFormat),
                       .minFrameDuration = kMinFrameDuration30Fps,
                       .minStallDuration = 0s};
                 });

  // TODO(b/301023410) We currently don't support rescaling for still capture,
  // so only announce BLOB support for formats exactly matching the input.
  std::transform(uniqueResolutions.begin(), uniqueResolutions.end(),
                 std::back_inserter(outputConfigurations),
                 [](const Resolution& resolution) {
                   return MetadataBuilder::StreamConfiguration{
                       .width = resolution.width,
                       .height = resolution.height,
                       .format = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB,
                       .minFrameDuration = kMinFrameDuration30Fps,
                       .minStallDuration = 0s};
                 });

  ALOGV("Adding %zu output configurations", outputConfigurations.size());
  builder.setAvailableOutputStreamConfigurations(outputConfigurations);

  auto metadata = builder.build();
  if (metadata == nullptr) {
    ALOGE("Failed to build metadata!");
    return CameraMetadata();
  }

  return std::move(*metadata);
}

}  // namespace

VirtualCameraDevice::VirtualCameraDevice(
    const uint32_t cameraId,
    const std::vector<SupportedStreamConfiguration>& supportedInputConfig,
    std::shared_ptr<IVirtualCameraCallback> virtualCameraClientCallback)
    : mCameraId(cameraId),
      mVirtualCameraClientCallback(virtualCameraClientCallback),
      mSupportedInputConfigurations(supportedInputConfig) {
  std::optional<CameraMetadata> metadata =
      initCameraCharacteristics(mSupportedInputConfigurations);
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
  for (const Stream& stream : streamConfiguration.streams) {
    ALOGV("%s: Configuration queried: %s", __func__, stream.toString().c_str());

    if (stream.streamType == StreamType::INPUT) {
      ALOGW("%s: Input stream type is not supported", __func__);
      return false;
    }

    // TODO(b/301023410) remove hardcoded format checks, verify against configuration.
    if (stream.rotation != StreamRotation::ROTATION_0 ||
        (stream.format != PixelFormat::IMPLEMENTATION_DEFINED &&
         stream.format != PixelFormat::YCBCR_420_888 &&
         stream.format != PixelFormat::BLOB)) {
      ALOGV("Unsupported output stream type");
      return false;
    }

    auto matchesSupportedInputConfig =
        [&stream](const SupportedStreamConfiguration& config) {
          return stream.width == config.width && stream.height == config.height;
        };
    if (std::none_of(mSupportedInputConfigurations.begin(),
                     mSupportedInputConfigurations.end(),
                     matchesSupportedInputConfig)) {
      ALOGV("Requested config doesn't match any supported input config");
      return false;
    }
  }
  return true;
}

ndk::ScopedAStatus VirtualCameraDevice::open(
    const std::shared_ptr<ICameraDeviceCallback>& in_callback,
    std::shared_ptr<ICameraDeviceSession>* _aidl_return) {
  ALOGV("%s", __func__);

  *_aidl_return = ndk::SharedRefBase::make<VirtualCameraSession>(
      *this, in_callback, mVirtualCameraClientCallback);

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

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
