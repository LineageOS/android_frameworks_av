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

#define LOG_TAG "AidlCameraDeviceCallbacks"

#include <aidl/AidlCameraDeviceCallbacks.h>
#include <aidl/AidlUtils.h>
#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <hidl/Utils.h>
#include <utility>

namespace android::frameworks::cameraservice::device::implementation {

// VNDK classes
using SCameraMetadata = ::aidl::android::frameworks::cameraservice::device::CameraMetadata;
using SCaptureResultExtras =
        ::aidl::android::frameworks::cameraservice::device::CaptureResultExtras;
using SPhysicalCaptureResultInfo =
        ::aidl::android::frameworks::cameraservice::device::PhysicalCaptureResultInfo;
using SStatus = ::aidl::android::frameworks::cameraservice::common::Status;
// NDK classes
using UCaptureResultExtras = ::android::hardware::camera2::impl::CaptureResultExtras;
using UPhysicalCaptureResultInfo = ::android::hardware::camera2::impl::PhysicalCaptureResultInfo;

using ::android::hardware::cameraservice::utils::conversion::aidl::convertToAidl;
using ::android::hardware::cameraservice::utils::conversion::aidl::filterVndkKeys;

const char *AidlCameraDeviceCallbacks::kResultKey = "CaptureResult";


bool AidlCameraDeviceCallbacks::initializeLooper(int vndkVersion) {
    mCbLooper = new ALooper;
    mCbLooper->setName("cs-looper");
    status_t err = mCbLooper->start(/*runOnCallingThread*/ false, /*canCallJava*/ false,
                                    PRIORITY_DEFAULT);
    if (err !=OK) {
        ALOGE("Unable to start camera device callback looper");
        return false;
    }
    mHandler = new CallbackHandler(this, vndkVersion);
    mCbLooper->registerHandler(mHandler);
    return true;
}

AidlCameraDeviceCallbacks::AidlCameraDeviceCallbacks(
        const std::shared_ptr<SICameraDeviceCallback>& base):
      mBase(base), mDeathPipe(this, base->asBinder()) {}

AidlCameraDeviceCallbacks::~AidlCameraDeviceCallbacks() {
    if (mCbLooper != nullptr) {
        if (mHandler != nullptr) {
            mCbLooper->unregisterHandler(mHandler->id());
        }
        mCbLooper->stop();
    }
    mCbLooper.clear();
    mHandler.clear();
}

binder::Status AidlCameraDeviceCallbacks::onDeviceError(
    int32_t errorCode, const CaptureResultExtras& resultExtras) {
    using hardware::cameraservice::utils::conversion::aidl::convertToAidl;
    SCaptureResultExtras cre = convertToAidl(resultExtras);
    auto ret = mBase->onDeviceError(convertToAidl(errorCode), cre);
    LOG_STATUS_ERROR_IF_NOT_OK(ret, "onDeviceError")
    return binder::Status::ok();
}

binder::Status AidlCameraDeviceCallbacks::onDeviceIdle() {
    auto ret = mBase->onDeviceIdle();
    LOG_STATUS_ERROR_IF_NOT_OK(ret, "onDeviceIdle")
    return binder::Status::ok();
}

binder::Status AidlCameraDeviceCallbacks::onCaptureStarted(
        const CaptureResultExtras& resultExtras, int64_t timestamp) {
    using hardware::cameraservice::utils::conversion::aidl::convertToAidl;
    SCaptureResultExtras hCaptureResultExtras = convertToAidl(resultExtras);
    auto ret = mBase->onCaptureStarted(hCaptureResultExtras, timestamp);
    LOG_STATUS_ERROR_IF_NOT_OK(ret, "onCaptureStarted")
    return binder::Status::ok();
}

void AidlCameraDeviceCallbacks::convertResultMetadataToAidl(const camera_metadata_t* src,
                                                            SCaptureMetadataInfo* dst) {
    // First try writing to fmq.
    size_t metadata_size = get_camera_metadata_size(src);
    if ((metadata_size > 0) &&
        (mCaptureResultMetadataQueue->availableToWrite() > 0)) {
        if (mCaptureResultMetadataQueue->write((int8_t *)src, metadata_size)) {
            dst->set<SCaptureMetadataInfo::fmqMetadataSize>(metadata_size);
        } else {
            ALOGW("%s Couldn't use fmq, falling back to hwbinder", __FUNCTION__);
            SCameraMetadata metadata;
            hardware::cameraservice::utils::conversion::aidl::cloneToAidl(src, &metadata);
            dst->set<SCaptureMetadataInfo::metadata>(std::move(metadata));
        }
    }
}

void AidlCameraDeviceCallbacks::CallbackHandler::onMessageReceived(const sp<AMessage> &msg) {
    sp<RefBase> obj = nullptr;
    sp<ResultWrapper> resultWrapper = nullptr;
    bool found = false;
    switch (msg->what()) {
        case kWhatResultReceived:
            found = msg->findObject(kResultKey, &obj);
            if (!found || obj == nullptr) {
                ALOGE("Cannot find result object in callback message");
                return;
            }
            resultWrapper = static_cast<ResultWrapper*>(obj.get());
            processResultMessage(resultWrapper);
            break;
        default:
            ALOGE("Unknown callback sent");
            break;
    }
    }

void AidlCameraDeviceCallbacks::CallbackHandler::processResultMessage(
    sp<ResultWrapper> &resultWrapper) {
    sp<AidlCameraDeviceCallbacks> converter = mConverter.promote();
    if (converter == nullptr) {
        ALOGE("Callback wrapper has died, result callback cannot be made");
        return;
    }
    CameraMetadataNative &result = resultWrapper->mResult;
    auto resultExtras = resultWrapper->mResultExtras;
    SCaptureResultExtras convResultExtras =
            hardware::cameraservice::utils::conversion::aidl::convertToAidl(resultExtras);

    // Convert Metadata into HCameraMetadata;
    SCaptureMetadataInfo captureMetadataInfo;
    if (filterVndkKeys(mVndkVersion, result, /*isStatic*/false) != OK) {
        ALOGE("%s: filtering vndk keys from result failed, not sending onResultReceived callback",
                __FUNCTION__);
        return;
    }
    const camera_metadata_t *rawMetadata = result.getAndLock();
    converter->convertResultMetadataToAidl(rawMetadata, &captureMetadataInfo);
    result.unlock(rawMetadata);

    auto &physicalCaptureResultInfos = resultWrapper->mPhysicalCaptureResultInfos;
    std::vector<SPhysicalCaptureResultInfo> stableCaptureResInfo =
            convertToAidl(physicalCaptureResultInfos, converter->mCaptureResultMetadataQueue);
    auto ret = converter->mBase->onResultReceived(captureMetadataInfo,
                                                  convResultExtras,
                                                  stableCaptureResInfo);

    LOG_STATUS_ERROR_IF_NOT_OK(ret, "OnResultReceived")
}

binder::Status AidlCameraDeviceCallbacks::onResultReceived(
    const CameraMetadataNative& result,
    const UCaptureResultExtras& resultExtras,
    const ::std::vector<UPhysicalCaptureResultInfo>& physicalCaptureResultInfos) {
    // Wrap CameraMetadata, resultExtras and physicalCaptureResultInfos in on
    // sp<RefBase>-able structure and post it.
    sp<ResultWrapper> resultWrapper = new ResultWrapper(const_cast<CameraMetadataNative &>(result),
                                                        resultExtras, physicalCaptureResultInfos);
    sp<AMessage> msg = new AMessage(kWhatResultReceived, mHandler);
    msg->setObject(kResultKey, resultWrapper);
    msg->post();
    return binder::Status::ok();
}

binder::Status AidlCameraDeviceCallbacks::onPrepared(int32_t streamId) {
    auto ret = mBase->onPrepared(streamId);
    LOG_STATUS_ERROR_IF_NOT_OK(ret, "onPrepared")
    return binder::Status::ok();
}

binder::Status AidlCameraDeviceCallbacks::onRepeatingRequestError(
    int64_t lastFrameNumber,
    int32_t repeatingRequestId) {
    auto ret =
        mBase->onRepeatingRequestError(lastFrameNumber, repeatingRequestId);
    LOG_STATUS_ERROR_IF_NOT_OK(ret, "onRepeatingRequestError")
    return binder::Status::ok();
}

binder::Status AidlCameraDeviceCallbacks::onRequestQueueEmpty() {
    // not implemented
    return binder::Status::ok();
}

status_t AidlCameraDeviceCallbacks::linkToDeath(const sp<DeathRecipient>& recipient,
                                                void* cookie, uint32_t flags) {
    return mDeathPipe.linkToDeath(recipient, cookie, flags);
}
status_t AidlCameraDeviceCallbacks::unlinkToDeath(const wp<DeathRecipient>& recipient,
                                                  void* cookie,
                                                  uint32_t flags,
                                                  wp<DeathRecipient>* outRecipient) {
    return mDeathPipe.unlinkToDeath(recipient, cookie, flags, outRecipient);
}

} // namespace android::frameworks::cameraservice::device::implementation
