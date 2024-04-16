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

#ifndef ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASERVICE_H
#define ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASERVICE_H

#include <memory>
#include <mutex>
#include <unordered_map>

#include "VirtualCameraDevice.h"
#include "VirtualCameraProvider.h"
#include "aidl/android/companion/virtualcamera/BnVirtualCameraService.h"
#include "util/Permissions.h"

namespace android {
namespace companion {
namespace virtualcamera {

// Implementation of Virtual Camera Service for managing virtual camera devices.
class VirtualCameraService
    : public aidl::android::companion::virtualcamera::BnVirtualCameraService {
 public:
  VirtualCameraService(
      std::shared_ptr<VirtualCameraProvider> virtualCameraProvider,
      const PermissionsProxy& permissionProxy = PermissionsProxy::get());

  // Register camera corresponding to the binder token.
  ndk::ScopedAStatus registerCamera(
      const ::ndk::SpAIBinder& token,
      const ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration&
          configuration,
      int32_t deviceId, bool* _aidl_return) override EXCLUDES(mLock);

  // Register camera corresponding to the binder token.
  ndk::ScopedAStatus registerCamera(
      const ::ndk::SpAIBinder& token,
      const ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration&
          configuration,
      int cameraId, int32_t deviceId, bool* _aidl_return) EXCLUDES(mLock);

  // Unregisters camera corresponding to the binder token.
  ndk::ScopedAStatus unregisterCamera(const ::ndk::SpAIBinder& token) override
      EXCLUDES(mLock);

  // Returns the camera id corresponding to the binder token.
  ndk::ScopedAStatus getCameraId(
      const ::ndk::SpAIBinder& token, int32_t* _aidl_return) override EXCLUDES(mLock);

  // Returns VirtualCameraDevice corresponding to binder token or nullptr if
  // there's no camera asociated with the token.
  std::shared_ptr<VirtualCameraDevice> getCamera(const ::ndk::SpAIBinder& token)
      EXCLUDES(mLock);

  // Handle cmd shell commands `adb shell cmd virtual_camera_service` [args].
  binder_status_t handleShellCommand(int in, int out, int err, const char** args,
                                     uint32_t numArgs) override;

  // Do not verify presence on required EGL extensions when registering virtual
  // camera. Only to be used by unit tests.
  void disableEglVerificationForTest() {
    mVerifyEglExtensions = false;
  }

  // Default virtual device id (the host device id)
  static constexpr int kDefaultDeviceId = 0;

 private:
  // Create and enable test camera instance if there's none.
  binder_status_t enableTestCameraCmd(
      int out, int err, const std::map<std::string, std::string>& options);
  // Disable and destroy test camera instance if there's one.
  void disableTestCameraCmd(int out);

  std::shared_ptr<VirtualCameraProvider> mVirtualCameraProvider;
  bool mVerifyEglExtensions = true;
  const PermissionsProxy& mPermissionProxy;

  std::mutex mLock;
  struct BinderTokenHash {
    std::size_t operator()(const ::ndk::SpAIBinder& key) const {
      return std::hash<void*>{}(reinterpret_cast<void*>(key.get()));
    }
  };
  // Map Binder tokens to names of cameras managed by camera provider.
  std::unordered_map<::ndk::SpAIBinder, std::string, BinderTokenHash>
      mTokenToCameraName GUARDED_BY(mLock);

  // Local binder token for test camera instance, or nullptr if there's none.
  ::ndk::SpAIBinder mTestCameraToken;

  // Numerical id to assign to next created camera.
  static std::atomic_int sNextId;
};

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android

#endif  // ANDROID_COMPANION_VIRTUALCAMERA_VIRTUALCAMERASERVICE_H
