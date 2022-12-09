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

#define LOG_TAG "AidlCamera3-OffLnSsn"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0
//#define LOG_NNDEBUG 0  // Per-frame verbose logging

#ifdef LOG_NNDEBUG
#define ALOGVV(...) ALOGV(__VA_ARGS__)
#else
#define ALOGVV(...) ((void)0)
#endif

#include <inttypes.h>

#include <utils/Trace.h>

#include <android/hardware/camera2/ICameraDeviceCallbacks.h>
#include <android/binder_ibinder_platform.h>

#include "device3/aidl/AidlCamera3OfflineSession.h"
#include "device3/Camera3OutputStream.h"
#include "device3/aidl/AidlCamera3OutputUtils.h"
#include "device3/Camera3InputStream.h"
#include "device3/Camera3SharedOutputStream.h"
#include "utils/CameraTraces.h"

using namespace android::camera3;
using namespace aidl::android::hardware;

namespace android {


AidlCamera3OfflineSession::~AidlCamera3OfflineSession() {
    ATRACE_CALL();
    ALOGV("%s: Tearing down aidl offline session for camera id %s", __FUNCTION__, mId.string());
    AidlCamera3OfflineSession::disconnectSession();
}

status_t AidlCamera3OfflineSession::initialize(wp<NotificationListener> listener) {
    ATRACE_CALL();

    if (mSession == nullptr) {
        ALOGE("%s: AIDL session is null!", __FUNCTION__);
        return DEAD_OBJECT;
    }

    {
        std::lock_guard<std::mutex> lock(mLock);

        mListener = listener;

        // setup result FMQ
        std::unique_ptr<AidlResultMetadataQueue>& resQueue = mResultMetadataQueue;
        ::aidl::android::hardware::common::fmq::MQDescriptor<
            int8_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> desc;
        ::ndk::ScopedAStatus resultQueueRet = mSession->getCaptureResultMetadataQueue(&desc);
        if (!resultQueueRet.isOk()) {
            ALOGE("Transaction error when getting result metadata queue from camera session: %s",
                    resultQueueRet.getMessage());
            return DEAD_OBJECT;
        }
        resQueue = std::make_unique<AidlResultMetadataQueue>(desc);
        if (!resQueue->isValid() || resQueue->availableToWrite() <= 0) {
            ALOGE("HAL returns empty result metadata fmq, not use it");
            resQueue = nullptr;
            // Don't use resQueue onwards.
        }

        mStatus = STATUS_ACTIVE;
    }

    mSession->setCallback(mCallbacks);

    return OK;
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::AidlCameraDeviceCallbacks::processCaptureResult(
        const std::vector<camera::device::CaptureResult>& results) {
    sp<AidlCamera3OfflineSession> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->processCaptureResult(results);
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::processCaptureResult(
        const std::vector<camera::device::CaptureResult>& results) {
    sp<NotificationListener> listener;
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return ::ndk::ScopedAStatus::ok();
        }
        listener = mListener.promote();
    }

    AidlCaptureOutputStates states {
      {mId,
        mOfflineReqsLock, mLastCompletedRegularFrameNumber,
        mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
        mOfflineReqs, mOutputLock, mResultQueue, mResultSignal,
        mNextShutterFrameNumber,
        mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
        mNextResultFrameNumber,
        mNextReprocessResultFrameNumber, mNextZslStillResultFrameNumber,
        mUseHalBufManager, mUsePartialResult, mNeedFixupMonochromeTags,
        mNumPartialResults, mVendorTagId, mDeviceInfo, mPhysicalDeviceInfoMap,
        mDistortionMappers, mZoomRatioMappers, mRotateAndCropMappers,
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this,
        *this, mBufferRecords, /*legacyClient*/ false, mMinExpectedDuration, mIsFixedFps},
      mResultMetadataQueue
    };

    std::lock_guard<std::mutex> lock(mProcessCaptureResultLock);
    for (const auto& result : results) {
        processOneCaptureResultLocked(states, result, result.physicalCameraMetadata);
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::AidlCameraDeviceCallbacks::notify(
        const std::vector<camera::device::NotifyMsg>& msgs) {
    sp<AidlCamera3OfflineSession> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->notify(msgs);
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::notify(
        const std::vector<camera::device::NotifyMsg>& msgs) {
    sp<NotificationListener> listener;
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return ::ndk::ScopedAStatus::ok();
        }
        listener = mListener.promote();
    }

    AidlCaptureOutputStates states {
      {mId,
        mOfflineReqsLock, mLastCompletedRegularFrameNumber,
        mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
        mOfflineReqs, mOutputLock, mResultQueue, mResultSignal,
        mNextShutterFrameNumber,
        mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
        mNextResultFrameNumber,
        mNextReprocessResultFrameNumber, mNextZslStillResultFrameNumber,
        mUseHalBufManager, mUsePartialResult, mNeedFixupMonochromeTags,
        mNumPartialResults, mVendorTagId, mDeviceInfo, mPhysicalDeviceInfoMap,
        mDistortionMappers, mZoomRatioMappers, mRotateAndCropMappers,
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this,
        *this, mBufferRecords, /*legacyClient*/ false, mMinExpectedDuration, mIsFixedFps},
      mResultMetadataQueue
    };
    for (const auto& msg : msgs) {
        camera3::notify(states, msg);
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::AidlCameraDeviceCallbacks::requestStreamBuffers(
        const std::vector<::aidl::android::hardware::camera::device::BufferRequest>& bufReqs,
        std::vector<::aidl::android::hardware::camera::device::StreamBufferRet>* buffers,
        ::aidl::android::hardware::camera::device::BufferRequestStatus* status) {
    sp<AidlCamera3OfflineSession> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->requestStreamBuffers(bufReqs, buffers, status);
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::requestStreamBuffers(
        const std::vector<::aidl::android::hardware::camera::device::BufferRequest>& bufReqs,
        std::vector<::aidl::android::hardware::camera::device::StreamBufferRet>* buffers,
        ::aidl::android::hardware::camera::device::BufferRequestStatus* status) {

    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return ::ndk::ScopedAStatus::ok();
        }
    }

    RequestBufferStates states {
        mId, mRequestBufferInterfaceLock, mUseHalBufManager, mOutputStreams, mSessionStatsBuilder,
        *this, mBufferRecords, *this};
    camera3::requestStreamBuffers(states, bufReqs, buffers, status);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::AidlCameraDeviceCallbacks::returnStreamBuffers(
        const std::vector<camera::device::StreamBuffer>& buffers) {
    sp<AidlCamera3OfflineSession> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->returnStreamBuffers(buffers);
}

::ndk::SpAIBinder AidlCamera3OfflineSession::AidlCameraDeviceCallbacks::createBinder() {
    auto binder = BnCameraDeviceCallback::createBinder();
    AIBinder_setInheritRt(binder.get(), /*inheritRt*/ true);
    return binder;
}

::ndk::ScopedAStatus AidlCamera3OfflineSession::returnStreamBuffers(
        const std::vector<camera::device::StreamBuffer>& buffers) {
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return ::ndk::ScopedAStatus::ok();
        }
    }

    ReturnBufferStates states {
        mId, mUseHalBufManager, mOutputStreams, mSessionStatsBuilder,
        mBufferRecords};

    camera3::returnStreamBuffers(states, buffers);
    return ::ndk::ScopedAStatus::ok();
}

void AidlCamera3OfflineSession::disconnectSession() {
  std::lock_guard<std::mutex> lock(mLock);
  if (mSession != nullptr) {
      mSession->close();
  }
  mSession.reset();
}

}; // namespace android
