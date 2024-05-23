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
#define LOG_TAG "VirtualCameraProvider"
#include "VirtualCameraProvider.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <tuple>
#include <utility>

#include "VirtualCameraDevice.h"
#include "aidl/android/hardware/camera/common/Status.h"
#include "log/log.h"
#include "util/Util.h"

namespace android {
namespace companion {
namespace virtualcamera {

using ::aidl::android::companion::virtualcamera::VirtualCameraConfiguration;
using ::aidl::android::hardware::camera::common::CameraDeviceStatus;
using ::aidl::android::hardware::camera::common::Status;
using ::aidl::android::hardware::camera::common::VendorTagSection;
using ::aidl::android::hardware::camera::device::ICameraDevice;
using ::aidl::android::hardware::camera::provider::CameraIdAndStreamCombination;
using ::aidl::android::hardware::camera::provider::ConcurrentCameraIdCombination;
using ::aidl::android::hardware::camera::provider::ICameraProviderCallback;

// TODO(b/301023410) Make camera id range configurable / dynamic
// based on already registered devices.
std::atomic_int VirtualCameraProvider::sNextId{42};

ndk::ScopedAStatus VirtualCameraProvider::setCallback(
    const std::shared_ptr<ICameraProviderCallback>& in_callback) {
  ALOGV("%s", __func__);

  if (in_callback == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  {
    const std::lock_guard<std::mutex> lock(mLock);
    mCameraProviderCallback = in_callback;

    for (const auto& [cameraName, _] : mCameras) {
      auto ret = mCameraProviderCallback->cameraDeviceStatusChange(
          cameraName, CameraDeviceStatus::PRESENT);
      if (!ret.isOk()) {
        ALOGE("Failed to announce camera status change: %s",
              ret.getDescription().c_str());
      }
    }
  }
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraProvider::getVendorTags(
    std::vector<VendorTagSection>* _aidl_return) {
  ALOGV("%s", __func__);

  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  // No vendor tags supported.
  _aidl_return->clear();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraProvider::getCameraIdList(
    std::vector<std::string>* _aidl_return) {
  ALOGV("%s", __func__);

  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  {
    const std::lock_guard<std::mutex> lock(mLock);
    _aidl_return->clear();
    _aidl_return->reserve(mCameras.size());
    for (const auto& [cameraName, _] : mCameras) {
      _aidl_return->emplace_back(cameraName);
    }
  }
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraProvider::getCameraDeviceInterface(
    const std::string& in_cameraDeviceName,
    std::shared_ptr<ICameraDevice>* _aidl_return) {
  ALOGV("%s cameraDeviceName %s", __func__, in_cameraDeviceName.c_str());

  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  {
    const std::lock_guard<std::mutex> lock(mLock);
    const auto it = mCameras.find(in_cameraDeviceName);
    *_aidl_return = (it == mCameras.end()) ? nullptr : it->second;
  }

  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraProvider::notifyDeviceStateChange(
    int64_t in_deviceState) {
  ALOGV("%s", __func__);
  (void)in_deviceState;
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraProvider::getConcurrentCameraIds(
    std::vector<ConcurrentCameraIdCombination>* _aidl_return) {
  ALOGV("%s", __func__);
  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  // No support for any concurrent combination.
  _aidl_return->clear();
  return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus VirtualCameraProvider::isConcurrentStreamCombinationSupported(
    const std::vector<CameraIdAndStreamCombination>& in_configs,
    bool* _aidl_return) {
  ALOGV("%s", __func__);
  (void)in_configs;
  if (_aidl_return == nullptr) {
    return cameraStatus(Status::ILLEGAL_ARGUMENT);
  }

  // No support for any stream combination at the moment.
  *_aidl_return = false;
  return ndk::ScopedAStatus::ok();
}

std::shared_ptr<VirtualCameraDevice> VirtualCameraProvider::createCamera(
    const VirtualCameraConfiguration& configuration) {
  auto camera =
      ndk::SharedRefBase::make<VirtualCameraDevice>(sNextId++, configuration);
  std::shared_ptr<ICameraProviderCallback> callback;
  {
    const std::lock_guard<std::mutex> lock(mLock);
    if (mCameras.find(camera->getCameraName()) != mCameras.end()) {
      ALOGE("Camera with identical name already exists.");
      return nullptr;
    }
    mCameras.emplace(std::piecewise_construct,
                     std::forward_as_tuple(camera->getCameraName()),
                     std::forward_as_tuple(camera));
    callback = mCameraProviderCallback;
  }

  if (callback != nullptr) {
    auto ret = callback->cameraDeviceStatusChange(camera->getCameraName(),
                                                  CameraDeviceStatus::PRESENT);
    if (!ret.isOk()) {
      ALOGE("Failed to announce camera %s status change (PRESENT): %s",
            camera->getCameraName().c_str(), ret.getDescription().c_str());
    }
  }
  return camera;
}

std::shared_ptr<VirtualCameraDevice> VirtualCameraProvider::getCamera(
    const std::string& cameraName) {
  const std::lock_guard<std::mutex> lock(mLock);
  auto it = mCameras.find(cameraName);
  return it == mCameras.end() ? nullptr : it->second;
}

bool VirtualCameraProvider::removeCamera(const std::string& name) {
  std::shared_ptr<ICameraProviderCallback> callback;
  {
    const std::lock_guard<std::mutex> lock(mLock);
    auto it = mCameras.find(name);
    if (it == mCameras.end()) {
      ALOGE("Cannot remove camera %s: no such camera", name.c_str());
      return false;
    }
    // TODO(b/301023410) Gracefully shut down camera.
    mCameras.erase(it);
    callback = mCameraProviderCallback;
  }

  if (callback != nullptr) {
    auto ret = callback->cameraDeviceStatusChange(
        name, CameraDeviceStatus::NOT_PRESENT);
    if (!ret.isOk()) {
      ALOGE("Failed to announce camera %s status change (NOT_PRESENT): %s",
            name.c_str(), ret.getDescription().c_str());
    }
  }

  return true;
}

}  // namespace virtualcamera
}  // namespace companion
}  // namespace android
