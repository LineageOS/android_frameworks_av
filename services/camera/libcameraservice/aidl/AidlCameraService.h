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

#ifndef FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERASERVICE_H_
#define FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERASERVICE_H_

#include <CameraService.h>
#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <aidl/android/frameworks/cameraservice/service/BnCameraService.h>

namespace android::frameworks::cameraservice::service::implementation {

// VNDK classes
using SBnCameraService = ::aidl::android::frameworks::cameraservice::service::BnCameraService;
using SCameraMetadata = ::aidl::android::frameworks::cameraservice::device::CameraMetadata;
using SCameraStatusAndId = ::aidl::android::frameworks::cameraservice::service::CameraStatusAndId;
using SICameraDeviceCallback =
        ::aidl::android::frameworks::cameraservice::device::ICameraDeviceCallback;
using SICameraDeviceUser = ::aidl::android::frameworks::cameraservice::device::ICameraDeviceUser;
using SICameraServiceListener =
        ::aidl::android::frameworks::cameraservice::service::ICameraServiceListener;
using SProviderIdAndVendorTagSections =
        ::aidl::android::frameworks::cameraservice::common::ProviderIdAndVendorTagSections;
using SStatus = ::aidl::android::frameworks::cameraservice::common::Status;
// NDK classes
using UICameraServiceListener = ::android::hardware::ICameraServiceListener;

class AidlCameraService: public SBnCameraService {
  public:
    static bool registerService(::android::CameraService* cameraService);

    explicit AidlCameraService(::android::CameraService* cameraService);
    ~AidlCameraService() override = default;
    ndk::ScopedAStatus getCameraCharacteristics(const std::string& in_cameraId,
                                                SCameraMetadata* _aidl_return) override;

    ndk::ScopedAStatus connectDevice(const std::shared_ptr<SICameraDeviceCallback>& in_callback,
                                     const std::string& in_cameraId,
                                     std::shared_ptr<SICameraDeviceUser>* _aidl_return) override;

    ndk::ScopedAStatus addListener(const std::shared_ptr<SICameraServiceListener>& in_listener,
                                   std::vector<SCameraStatusAndId>* _aidl_return) override;

    ndk::ScopedAStatus getCameraVendorTagSections(
            std::vector<SProviderIdAndVendorTagSections>* _aidl_return) override;

    ndk::ScopedAStatus removeListener(
            const std::shared_ptr<SICameraServiceListener>& in_listener) override;

  private:
    void addToListenerCacheLocked(std::shared_ptr<SICameraServiceListener> stableCsListener,
                                  sp<hardware::ICameraServiceListener> csListener);

    sp<UICameraServiceListener> searchListenerCacheLocked(
            const std::shared_ptr<SICameraServiceListener>& listener, bool removeIfFound = false);

    SStatus addListenerInternal(const std::shared_ptr<SICameraServiceListener>& listener,
                                std::vector<hardware::CameraStatus>* cameraStatusAndIds);


    ::android::CameraService* mCameraService;

    Mutex mListenerListLock;
    std::list<std::pair<std::shared_ptr<SICameraServiceListener>,
                        sp<UICameraServiceListener>>> mListeners;
    int mVndkVersion = -1;

};

} // namespace android::frameworks::cameraservice::service::implementation

#endif // FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERASERVICE_H_
