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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAPROVIDER_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAPROVIDER_H

#include <atomic>
#include <map>
#include <memory>
#include <mutex>

#include "VirtualCameraDevice.h"
#include "aidl/android/companion/virtualcamera/BnVirtualCameraCallback.h"
#include "aidl/android/hardware/camera/common/VendorTagSection.h"
#include "aidl/android/hardware/camera/device/ICameraDevice.h"
#include "aidl/android/hardware/camera/provider/BnCameraProvider.h"
#include "aidl/android/hardware/camera/provider/CameraIdAndStreamCombination.h"
#include "aidl/android/hardware/camera/provider/ConcurrentCameraIdCombination.h"
#include "aidl/android/hardware/camera/provider/ICameraProviderCallback.h"
#include "utils/Mutex.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Entry point for virtual camera HAL.
// Allows to create and keep track of virtual camera and implements
// IAudioProvider AIDL interface to expose virtual camera devices to camera framework.
class VirtualCameraProvider
    : public ::aidl::android::hardware::camera::provider::BnCameraProvider {
 public:
  ~VirtualCameraProvider() override = default;

  ndk::ScopedAStatus setCallback(
      const std::shared_ptr<
          ::aidl::android::hardware::camera::provider::ICameraProviderCallback>&
          in_callback) override;

  ndk::ScopedAStatus getVendorTags(
      std::vector<::aidl::android::hardware::camera::common::VendorTagSection>*
          _aidl_return) override;

  ndk::ScopedAStatus getCameraIdList(
      std::vector<std::string>* _aidl_return) override;

  ndk::ScopedAStatus getCameraDeviceInterface(
      const std::string& in_cameraDeviceName,
      std::shared_ptr<::aidl::android::hardware::camera::device::ICameraDevice>*
          _aidl_return) override;

  ndk::ScopedAStatus notifyDeviceStateChange(int64_t in_deviceState) override;

  ndk::ScopedAStatus getConcurrentCameraIds(
      std::vector<::aidl::android::hardware::camera::provider::
                      ConcurrentCameraIdCombination>* _aidl_return) override;

  ndk::ScopedAStatus isConcurrentStreamCombinationSupported(
      const std::vector<::aidl::android::hardware::camera::provider::
                            CameraIdAndStreamCombination>& in_configs,
      bool* _aidl_return) override;

  // Create new virtual camera devices
  // Returns nullptr if creation was not successful.
  std::shared_ptr<VirtualCameraDevice> createCamera(
      const aidl::android::companion::virtualcamera::VirtualCameraConfiguration&
          configuration);

  std::shared_ptr<VirtualCameraDevice> getCamera(const std::string& name);

  bool removeCamera(const std::string& name);

 private:
  std::mutex mLock;

  std::shared_ptr<
      ::aidl::android::hardware::camera::provider::ICameraProviderCallback>
      mCameraProviderCallback GUARDED_BY(mLock);

  std::map<std::string, std::shared_ptr<VirtualCameraDevice>> mCameras
      GUARDED_BY(mLock);

  // Numerical id to assign to next created camera.
  static std::atomic_int sNextId;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERAPROVIDER_H
