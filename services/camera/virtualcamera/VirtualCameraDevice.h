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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERADEVICE_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERADEVICE_H

#include <cstdint>
#include <memory>

#include "aidl/android/companion/virtualcamera/IVirtualCameraCallback.h"
#include "aidl/android/companion/virtualcamera/SupportedStreamConfiguration.h"
#include "aidl/android/hardware/camera/device/BnCameraDevice.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Representation of single virtual camera device, implements
// ICameraDevice AIDL to expose camera to camera framework.
class VirtualCameraDevice
    : public ::aidl::android::hardware::camera::device::BnCameraDevice {
 public:
  explicit VirtualCameraDevice(
      uint32_t cameraId,
      const std::vector<
          aidl::android::companion::virtualcamera::SupportedStreamConfiguration>&
          supportedInputConfig,
      std::shared_ptr<
          ::aidl::android::companion::virtualcamera::IVirtualCameraCallback>
          virtualCameraClientCallback = nullptr);

  virtual ~VirtualCameraDevice() override = default;

  ndk::ScopedAStatus getCameraCharacteristics(
      ::aidl::android::hardware::camera::device::CameraMetadata* _aidl_return)
      override;

  ndk::ScopedAStatus getPhysicalCameraCharacteristics(
      const std::string& in_physicalCameraId,
      ::aidl::android::hardware::camera::device::CameraMetadata* _aidl_return)
      override;

  ndk::ScopedAStatus getResourceCost(
      ::aidl::android::hardware::camera::common::CameraResourceCost*
          _aidl_return) override;

  ndk::ScopedAStatus isStreamCombinationSupported(
      const ::aidl::android::hardware::camera::device::StreamConfiguration&
          in_streams,
      bool* _aidl_return) override;

  bool isStreamCombinationSupported(
      const ::aidl::android::hardware::camera::device::StreamConfiguration&
          in_streams) const;

  ndk::ScopedAStatus open(
      const std::shared_ptr<
          ::aidl::android::hardware::camera::device::ICameraDeviceCallback>&
          in_callback,
      std::shared_ptr<
          ::aidl::android::hardware::camera::device::ICameraDeviceSession>*
          _aidl_return) override;

  ndk::ScopedAStatus openInjectionSession(
      const std::shared_ptr<
          ::aidl::android::hardware::camera::device::ICameraDeviceCallback>&
          in_callback,
      std::shared_ptr<
          ::aidl::android::hardware::camera::device::ICameraInjectionSession>*
          _aidl_return) override;

  ndk::ScopedAStatus setTorchMode(bool in_on) override;

  ndk::ScopedAStatus turnOnTorchWithStrengthLevel(
      int32_t in_torchStrength) override;

  ndk::ScopedAStatus getTorchStrengthLevel(int32_t* _aidl_return) override;

  binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;

  // Returns unique virtual camera name in form
  // "device@{major}.{minor}/virtual/{numerical_id}"
  std::string getCameraName() const;

  uint32_t getCameraId() const { return mCameraId; }

 private:
  const uint32_t mCameraId;
  const std::shared_ptr<
      ::aidl::android::companion::virtualcamera::IVirtualCameraCallback>
      mVirtualCameraClientCallback;

  ::aidl::android::hardware::camera::device::CameraMetadata mCameraCharacteristics;

  const std::vector<
      aidl::android::companion::virtualcamera::SupportedStreamConfiguration>
      mSupportedInputConfigurations;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERADEVICE_H
