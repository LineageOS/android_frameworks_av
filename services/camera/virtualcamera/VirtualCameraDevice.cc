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

#include <chrono>
#include <cstdint>
#include <string>

#include "VirtualCameraSession.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "aidl/android/hardware/camera/device/CameraMetadata.h"
#include "android/binder_auto_utils.h"
#include "android/binder_status.h"
#include "log/log.h"
#include "system/camera_metadata.h"
#include "util/MetadataBuilder.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::IVirtualCameraCallback;
using ::aidl::android::hardware::camera::common::CameraResourceCost;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::device::CameraMetadata;
using ::aidl::android::hardware::camera::device::ICameraDeviceCallback;
using ::aidl::android::hardware::camera::device::ICameraDeviceSession;
using ::aidl::android::hardware::camera::device::ICameraInjectionSession;
using ::aidl::android::hardware::camera::device::StreamConfiguration;
using ::aidl::android::hardware::camera::device::StreamRotation;
using ::aidl::android::hardware::camera::device::StreamType;
using ::aidl::android::hardware::graphics::common::PixelFormat;

namespace {

using namespace std::chrono_literals;

// Prefix of camera name - "device@1.1/virtual/{numerical_id}"
const char* kDevicePathPrefix = "device@1.1/virtual/";

constexpr int32_t kVgaWidth = 640;
constexpr int32_t kVgaHeight = 480;
constexpr std::chrono::nanoseconds kMinFrameDuration30Fps = 1s / 30;
constexpr int32_t kMaxJpegSize = 3 * 1024 * 1024 /*3MiB*/;

constexpr MetadataBuilder::ControlRegion kDefaultEmptyControlRegion{};

// TODO(b/301023410) - Populate camera characteristics according to camera configuration.
CameraMetadata initCameraCharacteristics() {
  auto metadata =
      MetadataBuilder()
          .setSupportedHardwareLevel(
              ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL)
          .setFlashAvailable(false)
          .setLensFacing(ANDROID_LENS_FACING_EXTERNAL)
          .setSensorOrientation(0)
          .setAvailableFaceDetectModes({ANDROID_STATISTICS_FACE_DETECT_MODE_OFF})
          .setControlAfAvailableModes({ANDROID_CONTROL_AF_MODE_OFF})
          .setAvailableOutputStreamConfigurations(
              {MetadataBuilder::StreamConfiguration{
                   .width = kVgaWidth,
                   .height = kVgaHeight,
                   .format =
                       ANDROID_SCALER_AVAILABLE_FORMATS_IMPLEMENTATION_DEFINED,
                   .minFrameDuration = kMinFrameDuration30Fps,
                   .minStallDuration = 0s},
               MetadataBuilder::StreamConfiguration{
                   .width = kVgaWidth,
                   .height = kVgaHeight,
                   .format = ANDROID_SCALER_AVAILABLE_FORMATS_YCbCr_420_888,
                   .minFrameDuration = kMinFrameDuration30Fps,
                   .minStallDuration = 0s},
               {MetadataBuilder::StreamConfiguration{
                   .width = kVgaWidth,
                   .height = kVgaHeight,
                   .format = ANDROID_SCALER_AVAILABLE_FORMATS_BLOB,
                   .minFrameDuration = kMinFrameDuration30Fps,
                   .minStallDuration = 0s}}})
          .setControlAeAvailableFpsRange(10, 30)
          .setControlMaxRegions(0, 0, 0)
          .setSensorActiveArraySize(0, 0, kVgaWidth, kVgaHeight)
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
          .setAvailableCharacteristicKeys()
          .build();

  if (metadata == nullptr) {
    ALOGE("Failed to build metadata!");
    return CameraMetadata();
  }

  return std::move(*metadata);
}

}  // namespace

VirtualCameraDevice::VirtualCameraDevice(
    const uint32_t cameraId,
    std::shared_ptr<IVirtualCameraCallback> virtualCameraClientCallback)
    : mCameraId(cameraId),
      mVirtualCameraClientCallback(virtualCameraClientCallback) {
  mCameraCharacteristics = initCameraCharacteristics();
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

  for (const auto& stream : in_streams.streams) {
    ALOGV("%s: Configuration queried: %s", __func__, stream.toString().c_str());

    if (stream.streamType == StreamType::INPUT) {
      ALOGW("%s: Input stream type is not supported", __func__);
      *_aidl_return = false;
      return ndk::ScopedAStatus::ok();
    }

    // TODO(b/301023410) remove hardcoded format checks, verify against configuration.
    if (stream.width != 640 || stream.height != 480 ||
        stream.rotation != StreamRotation::ROTATION_0 ||
        (stream.format != PixelFormat::IMPLEMENTATION_DEFINED &&
         stream.format != PixelFormat::YCBCR_420_888 &&
         stream.format != PixelFormat::BLOB)) {
      *_aidl_return = false;
      return ndk::ScopedAStatus::ok();
    }
  }

  *_aidl_return = true;
  return ndk::ScopedAStatus::ok();
};

ndk::ScopedAStatus VirtualCameraDevice::open(
    const std::shared_ptr<ICameraDeviceCallback>& in_callback,
    std::shared_ptr<ICameraDeviceSession>* _aidl_return) {
  ALOGV("%s", __func__);

  *_aidl_return = ndk::SharedRefBase::make<VirtualCameraSession>(
      std::to_string(mCameraId), in_callback, mVirtualCameraClientCallback);

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
