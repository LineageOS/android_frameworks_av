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

#ifndef FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLUTILS_H_
#define FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLUTILS_H_

#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <aidl/android/frameworks/cameraservice/device/CameraMetadata.h>
#include <aidl/android/frameworks/cameraservice/device/CaptureResultExtras.h>
#include <aidl/android/frameworks/cameraservice/device/ErrorCode.h>
#include <aidl/android/frameworks/cameraservice/device/CaptureMetadataInfo.h>
#include <aidl/android/frameworks/cameraservice/device/OutputConfiguration.h>
#include <aidl/android/frameworks/cameraservice/device/PhysicalCaptureResultInfo.h>
#include <aidl/android/frameworks/cameraservice/device/SessionConfiguration.h>
#include <aidl/android/frameworks/cameraservice/device/StreamConfigurationMode.h>
#include <aidl/android/frameworks/cameraservice/device/SubmitInfo.h>
#include <aidl/android/frameworks/cameraservice/device/TemplateId.h>
#include <aidl/android/frameworks/cameraservice/service/CameraDeviceStatus.h>
#include <aidl/android/frameworks/cameraservice/service/CameraStatusAndId.h>
#include <android/hardware/ICameraService.h>
#include <android/hardware/camera2/ICameraDeviceUser.h>
#include <android/hardware/graphics/bufferqueue/1.0/IGraphicBufferProducer.h>
#include <camera/CameraMetadata.h>
#include <fmq/AidlMessageQueue.h>
#include <hardware/camera.h>

namespace android::hardware::cameraservice::utils::conversion::aidl {

using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::android::AidlMessageQueue;
using ::android::CameraMetadata;
using CaptureResultMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;

// VNDK classes
using SCameraDeviceStatus = ::aidl::android::frameworks::cameraservice::service::CameraDeviceStatus;
using SCameraMetadata = ::aidl::android::frameworks::cameraservice::device::CameraMetadata;
using SCameraStatusAndId = ::aidl::android::frameworks::cameraservice::service::CameraStatusAndId;
using SCaptureResultExtras =
        ::aidl::android::frameworks::cameraservice::device::CaptureResultExtras;
using SErrorCode = ::aidl::android::frameworks::cameraservice::device::ErrorCode;
using SCaptureMetadataInfo = ::aidl::android::frameworks::cameraservice::device::CaptureMetadataInfo;
using SOutputConfiguration =
        ::aidl::android::frameworks::cameraservice::device::OutputConfiguration;
using SPhysicalCaptureResultInfo =
        ::aidl::android::frameworks::cameraservice::device::PhysicalCaptureResultInfo;
using SSessionConfiguration =
        ::aidl::android::frameworks::cameraservice::device::SessionConfiguration;
using SStatus = ::aidl::android::frameworks::cameraservice::common::Status;
using SStreamConfigurationMode =
        ::aidl::android::frameworks::cameraservice::device::StreamConfigurationMode;
using SSubmitInfo = ::aidl::android::frameworks::cameraservice::device::SubmitInfo;
using STemplateId = ::aidl::android::frameworks::cameraservice::device::TemplateId;
// NDK classes
using UCaptureResultExtras = ::android::hardware::camera2::impl::CaptureResultExtras;
using UOutputConfiguration = ::android::hardware::camera2::params::OutputConfiguration;
using UPhysicalCaptureResultInfo = ::android::hardware::camera2::impl::PhysicalCaptureResultInfo;
using USessionConfiguration = ::android::hardware::camera2::params::SessionConfiguration;

// Common macro to log errors returned from stable AIDL calls
#define LOG_STATUS_ERROR_IF_NOT_OK(status, callName)                                        \
    if (!(status).isOk()) {                                                                 \
        if ((status).getExceptionCode() == EX_SERVICE_SPECIFIC) {                           \
            SStatus errStatus = static_cast<SStatus>((status).getServiceSpecificError());   \
            ALOGE("%s: %s callback failed: %s", __FUNCTION__, callName,                     \
                  toString(errStatus).c_str());                                             \
        } else {                                                                            \
            ALOGE("%s: Transaction failed during %s: %d", __FUNCTION__, callName,           \
                  (status).getExceptionCode());                                             \
        }                                                                                   \
    }

// Note: existing data in dst will be gone. Caller still owns the memory of src
void cloneToAidl(const camera_metadata_t *src, SCameraMetadata* dst);

bool cloneFromAidl(const SCameraMetadata &src, CameraMetadata *dst);

int32_t convertFromAidl(SStreamConfigurationMode streamConfigurationMode);

UOutputConfiguration convertFromAidl(const SOutputConfiguration &src);

USessionConfiguration convertFromAidl(const SSessionConfiguration &src);

int convertFromAidl(SOutputConfiguration::Rotation rotation);

int32_t convertFromAidl(STemplateId templateId);

void convertToAidl(const hardware::camera2::utils::SubmitInfo &submitInfo,
                   SSubmitInfo *hSubmitInfo);

SStatus convertToAidl(const binder::Status &status);

SCaptureResultExtras convertToAidl(const UCaptureResultExtras &captureResultExtras);

SErrorCode convertToAidl(int32_t errorCode);

std::vector<SPhysicalCaptureResultInfo> convertToAidl(
        const std::vector<UPhysicalCaptureResultInfo>& src,
        std::shared_ptr<CaptureResultMetadataQueue>& fmq);

SPhysicalCaptureResultInfo convertToAidl(const UPhysicalCaptureResultInfo& src,
                                         std::shared_ptr<CaptureResultMetadataQueue>& fmq);

void convertToAidl(const std::vector<hardware::CameraStatus> &src,
                   std::vector<SCameraStatusAndId>* dst);

SCameraDeviceStatus convertCameraStatusToAidl(int32_t src);

bool areBindersEqual(const ndk::SpAIBinder& b1, const ndk::SpAIBinder& b2);

status_t filterVndkKeys(int vndkVersion, CameraMetadata &metadata, bool isStatic = true);

bool areExtensionKeysSupported(const CameraMetadata& metadata);

status_t filterExtensionKeys(CameraMetadata* metadata /*out*/);
} // namespace android::hardware::cameraservice::utils::conversion::aidl

#endif  // FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLUTILS_H_
