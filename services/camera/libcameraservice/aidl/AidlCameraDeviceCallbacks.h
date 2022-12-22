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

#ifndef FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERADEVICECALLBACKS_H_
#define FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERADEVICECALLBACKS_H_

#include <CameraService.h>
#include <aidl/DeathPipe.h>
#include <aidl/android/frameworks/cameraservice/device/BnCameraDeviceCallback.h>
#include <aidl/android/frameworks/cameraservice/device/CaptureMetadataInfo.h>
#include <aidl/android/frameworks/cameraservice/device/PhysicalCaptureResultInfo.h>
#include <android/hardware/camera2/BnCameraDeviceCallbacks.h>
#include <fmq/AidlMessageQueue.h>
#include <media/stagefright/foundation/AHandler.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/foundation/AMessage.h>
#include <mutex>
#include <thread>
#include <utility>

namespace android::frameworks::cameraservice::device::implementation {

// VNDK classes
using SCaptureMetadataInfo = ::aidl::android::frameworks::cameraservice::device::CaptureMetadataInfo;
using SICameraDeviceCallback =
        ::aidl::android::frameworks::cameraservice::device::ICameraDeviceCallback;
// NDK classes
using UBnCameraDeviceCallbacks = ::android::hardware::camera2::BnCameraDeviceCallbacks;

using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::android::AidlMessageQueue;
using ::android::frameworks::cameraservice::utils::DeathPipe;
using ::android::hardware::camera2::impl::CameraMetadataNative;

using CaptureResultMetadataQueue = AidlMessageQueue<int8_t, SynchronizedReadWrite>;

class AidlCameraDeviceCallbacks : public UBnCameraDeviceCallbacks {
  public:
    explicit AidlCameraDeviceCallbacks(const std::shared_ptr<SICameraDeviceCallback>& base);

    ~AidlCameraDeviceCallbacks() override;

    bool initializeLooper(int vndkVersion);

    binder::Status onDeviceError(int32_t errorCode,
                                 const CaptureResultExtras& resultExtras) override;

    binder::Status onDeviceIdle() override;

    binder::Status onCaptureStarted(const CaptureResultExtras& resultExtras,
                                    int64_t timestamp) override;

    binder::Status onResultReceived(
            const CameraMetadataNative& result, const CaptureResultExtras& resultExtras,
            const std::vector<PhysicalCaptureResultInfo>& physicalCaptureResultInfos) override;

    binder::Status onPrepared(int32_t streamId) override;

    binder::Status onRepeatingRequestError(int64_t lastFrameNumber,
                                           int32_t repeatingRequestId) override;

    binder::Status onRequestQueueEmpty() override;

    status_t linkToDeath(const sp<DeathRecipient>& recipient, void* cookie,
                         uint32_t flags) override;
    status_t unlinkToDeath(const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
                           wp<DeathRecipient>* outRecipient) override;

    void setCaptureResultMetadataQueue(std::shared_ptr<CaptureResultMetadataQueue> metadataQueue) {
        mCaptureResultMetadataQueue = std::move(metadataQueue);
    }

 private:
    // Wrapper struct so that parameters to onResultReceived callback may be
    // sent through an AMessage.
    struct ResultWrapper : public RefBase {
        CameraMetadataNative mResult;
        CaptureResultExtras mResultExtras;
        std::vector<PhysicalCaptureResultInfo> mPhysicalCaptureResultInfos;

        ResultWrapper(CameraMetadataNative &result,
                      CaptureResultExtras  resultExtras,
                      std::vector<PhysicalCaptureResultInfo> physicalCaptureResultInfos) :
              // TODO: make this std::movable
              mResult(result),
              mResultExtras(std::move(resultExtras)),
              mPhysicalCaptureResultInfos(std::move(physicalCaptureResultInfos)) { }
    };

    struct CallbackHandler : public AHandler {
        public:
            void onMessageReceived(const sp<AMessage> &msg) override;
            CallbackHandler(AidlCameraDeviceCallbacks *converter, int vndkVersion) :
                    mConverter(converter), mVndkVersion(vndkVersion) { }
        private:
            void processResultMessage(sp<ResultWrapper> &resultWrapper);
            wp<AidlCameraDeviceCallbacks> mConverter = nullptr;
            int mVndkVersion = -1;
    };

    void convertResultMetadataToAidl(const camera_metadata * src, SCaptureMetadataInfo * dst);
    enum {
        kWhatResultReceived,
    };

    static const char *kResultKey;

  private:
    std::shared_ptr<SICameraDeviceCallback> mBase;
    std::shared_ptr<CaptureResultMetadataQueue> mCaptureResultMetadataQueue = nullptr;
    sp<CallbackHandler> mHandler = nullptr;
    sp<ALooper> mCbLooper = nullptr;

    // Pipes death subscription from current NDK interface to VNDK mBase.
    // Should consume calls to linkToDeath and unlinkToDeath.
    DeathPipe mDeathPipe;
};

} // namespace android::frameworks::cameraservice::device::implementation
#endif // FRAMEWORKS_AV_SERVICES_CAMERA_LIBCAMERASERVICE_AIDL_AIDLCAMERADEVICECALLBACKS_H_
