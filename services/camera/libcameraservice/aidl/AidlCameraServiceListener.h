/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERASERVICELISTENER_H_
#define FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERASERVICELISTENER_H_


#include <aidl/DeathPipe.h>
#include <aidl/android/frameworks/cameraservice/service/CameraDeviceStatus.h>
#include <aidl/android/frameworks/cameraservice/service/ICameraServiceListener.h>
#include <android/hardware/BnCameraServiceListener.h>

namespace android::frameworks::cameraservice::service::implementation {

using ::android::frameworks::cameraservice::utils::DeathPipe;

// VNDK classes
using SCameraDeviceStatus = ::aidl::android::frameworks::cameraservice::service::CameraDeviceStatus;
using SICameraServiceListener =
        ::aidl::android::frameworks::cameraservice::service::ICameraServiceListener;
// NDK classes
using UBnCameraServiceListener = ::android::hardware::BnCameraServiceListener;

/**
 * A simple shim to pass calls from CameraService to VNDK client.
 */
class AidlCameraServiceListener : public UBnCameraServiceListener {
  public:
    AidlCameraServiceListener(const std::shared_ptr<SICameraServiceListener>& base):
          mBase(base), mDeathPipe(this, base->asBinder()) {}

    ~AidlCameraServiceListener() = default;

    ::android::binder::Status onStatusChanged(int32_t status,
            const std::string& cameraId, int32_t deviceId) override;
    ::android::binder::Status onPhysicalCameraStatusChanged(int32_t status,
            const std::string& cameraId,
            const std::string& physicalCameraId,
            int32_t deviceId) override;

    ::android::binder::Status onTorchStatusChanged(
            int32_t status, const std::string& cameraId, int32_t deviceId) override;
    ::android::binder::Status onTorchStrengthLevelChanged(
            const std::string& cameraId, int32_t newStrengthLevel, int32_t deviceId) override;
    binder::Status onCameraAccessPrioritiesChanged() override {
        // TODO: no implementation yet.
        return binder::Status::ok();
    }
    binder::Status onCameraOpened([[maybe_unused]] const std::string& /*cameraId*/,
            [[maybe_unused]] const std::string& /*clientPackageId*/,
            [[maybe_unused]] int32_t /*deviceId*/) override {
        // empty implementation
        return binder::Status::ok();
    }
    binder::Status onCameraClosed([[maybe_unused]] const std::string& /*cameraId*/,
            [[maybe_unused]] int32_t /*deviceId*/) override {
        // empty implementation
        return binder::Status::ok();
    }

    status_t linkToDeath(const sp<DeathRecipient>& recipient, void* cookie,
                         uint32_t flags) override;
    status_t unlinkToDeath(const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
                           wp<DeathRecipient>* outRecipient) override;

  private:
    std::shared_ptr<SICameraServiceListener> mBase;

    // Pipes death subscription to current NDK AIDL interface to VNDK mBase.
    // Should consume calls to linkToDeath and unlinkToDeath.
    DeathPipe mDeathPipe;
};

} // android

#endif // FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERASERVICELISTENER_H_