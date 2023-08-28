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

#ifndef FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERADEVICEUSER_H_
#define FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERADEVICEUSER_H_

#include <CameraService.h>
#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <aidl/android/frameworks/cameraservice/device/BnCameraDeviceUser.h>
#include <aidl/android/frameworks/cameraservice/device/CameraMetadata.h>
#include <aidl/android/frameworks/cameraservice/device/OutputConfiguration.h>
#include <aidl/android/frameworks/cameraservice/device/PhysicalCameraSettings.h>
#include <aidl/android/frameworks/cameraservice/device/SessionConfiguration.h>
#include <aidl/android/frameworks/cameraservice/device/StreamConfigurationMode.h>
#include <aidl/android/frameworks/cameraservice/device/SubmitInfo.h>
#include <aidl/android/frameworks/cameraservice/device/TemplateId.h>
#include <aidl/android/hardware/common/fmq/MQDescriptor.h>
#include <android/hardware/camera2/ICameraDeviceCallbacks.h>
#include <fmq/AidlMessageQueue.h>
#include <memory>

namespace android::frameworks::cameraservice::device::implementation {

using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::android::AidlMessageQueue;
using CaptureRequestMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;
using CaptureResultMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;

// Stable NDK classes
using SBnCameraDeviceUser = ::aidl::android::frameworks::cameraservice::device::BnCameraDeviceUser;
using SCameraMetadata = ::aidl::android::frameworks::cameraservice::device::CameraMetadata;
using SCaptureRequest = ::aidl::android::frameworks::cameraservice::device::CaptureRequest;
using SOutputConfiguration =
        ::aidl::android::frameworks::cameraservice::device::OutputConfiguration;
using SPhysicalCameraSettings =
        ::aidl::android::frameworks::cameraservice::device::PhysicalCameraSettings;
using SSessionConfiguration =
        ::aidl::android::frameworks::cameraservice::device::SessionConfiguration;
using SStatus = ::aidl::android::frameworks::cameraservice::common::Status;
using SStreamConfigurationMode =
        ::aidl::android::frameworks::cameraservice::device::StreamConfigurationMode;
using SSubmitInfo = ::aidl::android::frameworks::cameraservice::device::SubmitInfo;
using STemplateId = ::aidl::android::frameworks::cameraservice::device::TemplateId;
// Unstable NDK classes
using UCaptureRequest= ::android::hardware::camera2::CaptureRequest;
using UICameraDeviceUser = ::android::hardware::camera2::ICameraDeviceUser;

static constexpr int32_t REQUEST_ID_NONE = -1;

class AidlCameraDeviceUser final : public SBnCameraDeviceUser {
  public:
    explicit AidlCameraDeviceUser(const sp<UICameraDeviceUser> &deviceRemote);
    ~AidlCameraDeviceUser() override = default;

    ndk::ScopedAStatus beginConfigure() override;
    ndk::ScopedAStatus cancelRepeatingRequest(int64_t* _aidl_return) override;
    ndk::ScopedAStatus createDefaultRequest(STemplateId in_templateId,
                                            SCameraMetadata* _aidl_return) override;
    ndk::ScopedAStatus createStream(const SOutputConfiguration& in_outputConfiguration,
                                    int32_t* _aidl_return) override;
    ndk::ScopedAStatus deleteStream(int32_t in_streamId) override;
    ndk::ScopedAStatus disconnect() override;
    ndk::ScopedAStatus endConfigure(SStreamConfigurationMode in_operatingMode,
                                    const SCameraMetadata& in_sessionParams,
                                    int64_t in_startTimeNs) override;
    ndk::ScopedAStatus flush(int64_t* _aidl_return) override;
    ndk::ScopedAStatus getCaptureRequestMetadataQueue(
            MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) override;
    ndk::ScopedAStatus getCaptureResultMetadataQueue(
            MQDescriptor<int8_t, SynchronizedReadWrite>* _aidl_return) override;
    ndk::ScopedAStatus isSessionConfigurationSupported(
            const SSessionConfiguration& in_sessionConfiguration, bool* _aidl_return) override;
    ndk::ScopedAStatus prepare(int32_t in_streamId) override;
    ndk::ScopedAStatus submitRequestList(const std::vector<SCaptureRequest>& in_requestList,
                                         bool in_isRepeating, SSubmitInfo* _aidl_return) override;
    ndk::ScopedAStatus updateOutputConfiguration(
            int32_t in_streamId, const SOutputConfiguration& in_outputConfiguration) override;
    ndk::ScopedAStatus waitUntilIdle() override;

    [[nodiscard]] bool initStatus() const { return mInitSuccess; }

    std::shared_ptr<CaptureResultMetadataQueue> getCaptureResultMetadataQueue() {
        return mCaptureResultMetadataQueue;
    }

  private:
    bool initDevice();

    bool convertRequestFromAidl(const SCaptureRequest &src, UCaptureRequest *dst);
    bool copyPhysicalCameraSettings(const std::vector<SPhysicalCameraSettings> &src,
                                    std::vector<CaptureRequest::PhysicalCameraSettings> *dst);

    const sp<UICameraDeviceUser> mDeviceRemote;
    std::unique_ptr<CaptureRequestMetadataQueue> mCaptureRequestMetadataQueue = nullptr;
    std::shared_ptr<CaptureResultMetadataQueue> mCaptureResultMetadataQueue = nullptr;
    bool mInitSuccess = false;
    int32_t mRequestId = REQUEST_ID_NONE;
    int mVndkVersion = -1;
};

} // namespace android::frameworks::cameraservice::device::implementation

#endif  // FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERADEVICEUSER_H_
