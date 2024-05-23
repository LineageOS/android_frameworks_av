/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef CAMERA_NDK_VENDOR_UTILS_H
#define CAMERA_NDK_VENDOR_UTILS_H

#include <CameraMetadata.h>
#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <aidl/android/frameworks/cameraservice/device/CameraMetadata.h>
#include <aidl/android/frameworks/cameraservice/device/CaptureRequest.h>
#include <aidl/android/frameworks/cameraservice/device/ICameraDeviceUser.h>
#include <aidl/android/frameworks/cameraservice/device/OutputConfiguration.h>
#include <aidl/android/frameworks/cameraservice/device/PhysicalCameraSettings.h>
#include <aidl/android/frameworks/cameraservice/device/TemplateId.h>
#include <aidl/android/frameworks/cameraservice/service/ICameraService.h>
#include <camera/NdkCameraDevice.h>
#include <hardware/camera3.h>
#include <utils/RefBase.h>

namespace android {
namespace acam {
namespace utils {

using ::aidl::android::frameworks::cameraservice::common::Status;
using ::aidl::android::frameworks::cameraservice::device::OutputConfiguration;
using ::aidl::android::frameworks::cameraservice::device::PhysicalCameraSettings;
using ::aidl::android::frameworks::cameraservice::device::TemplateId;
using ::android::hardware::camera::common::V1_0::helper::CameraMetadata;
using AidlCameraMetadata = ::aidl::android::frameworks::cameraservice::device::CameraMetadata;
using AidlCaptureRequest = ::aidl::android::frameworks::cameraservice::device::CaptureRequest;

// Utility class so that CaptureRequest can be stored by sp<>
struct CaptureRequest: public RefBase {
  AidlCaptureRequest mCaptureRequest;
  std::vector<ANativeWindow *> mSurfaceList;
  // Physical camera settings metadata is stored here, as the capture request
  // might not contain it. That's since, fmq might have consumed it.
  std::vector<PhysicalCameraSettings> mPhysicalCameraSettings;
};

AidlCaptureRequest convertToAidl(const CaptureRequest *captureRequest);

OutputConfiguration::Rotation convertToAidl(int rotation);

bool cloneFromAidl(const AidlCameraMetadata & srcMetadata, camera_metadata_t** dst);

// Note: existing data in dst will be gone.
void convertToAidl(const camera_metadata_t *src, AidlCameraMetadata * dst);

TemplateId convertToAidl(ACameraDevice_request_template templateId);

camera_status_t convertFromAidl(Status status);

} // namespace utils
} // namespace acam
} // namespace android

#endif // CAMERA_NDK_VENDOR_UTILS_H
