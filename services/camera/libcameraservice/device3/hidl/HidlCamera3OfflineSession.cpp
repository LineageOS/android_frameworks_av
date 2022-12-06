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

#define LOG_TAG "Hidl-Camera3-OffLnSsn"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <inttypes.h>

#include <utils/Trace.h>

#include <android/hardware/camera2/ICameraDeviceCallbacks.h>

#include "device3/hidl/HidlCamera3OfflineSession.h"
#include "device3/Camera3OutputStream.h"
#include "device3/hidl/HidlCamera3OutputUtils.h"
#include "device3/Camera3InputStream.h"
#include "device3/Camera3SharedOutputStream.h"
#include "utils/CameraTraces.h"

using namespace android::camera3;
using namespace android::hardware::camera;

namespace android {

HidlCamera3OfflineSession::~HidlCamera3OfflineSession() {
    ATRACE_CALL();
    ALOGV("%s: Tearing down hidl offline session for camera id %s", __FUNCTION__, mId.string());
    HidlCamera3OfflineSession::disconnectSession();
}

status_t HidlCamera3OfflineSession::initialize(wp<NotificationListener> listener) {
    ATRACE_CALL();

    if (mSession == nullptr) {
        ALOGE("%s: HIDL session is null!", __FUNCTION__);
        return DEAD_OBJECT;
    }

    {
        std::lock_guard<std::mutex> lock(mLock);

        mListener = listener;

        // setup result FMQ
        std::unique_ptr<ResultMetadataQueue>& resQueue = mResultMetadataQueue;
        auto resultQueueRet = mSession->getCaptureResultMetadataQueue(
            [&resQueue](const auto& descriptor) {
                resQueue = std::make_unique<ResultMetadataQueue>(descriptor);
                if (!resQueue->isValid() || resQueue->availableToWrite() <= 0) {
                    ALOGE("HAL returns empty result metadata fmq, not use it");
                    resQueue = nullptr;
                    // Don't use resQueue onwards.
                }
            });
        if (!resultQueueRet.isOk()) {
            ALOGE("Transaction error when getting result metadata queue from camera session: %s",
                    resultQueueRet.description().c_str());
            return DEAD_OBJECT;
        }
        mStatus = STATUS_ACTIVE;
    }

    mSession->setCallback(this);

    return OK;
}

hardware::Return<void> HidlCamera3OfflineSession::processCaptureResult_3_4(
        const hardware::hidl_vec<
                hardware::camera::device::V3_4::CaptureResult>& results) {
    sp<NotificationListener> listener;
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return hardware::Void();
        }
        listener = mListener.promote();
    }

    HidlCaptureOutputStates states {
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
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this, *this,
        mBufferRecords, /*legacyClient*/ false, mMinExpectedDuration, mIsFixedFps},
      mResultMetadataQueue
    };

    std::lock_guard<std::mutex> lock(mProcessCaptureResultLock);
    for (const auto& result : results) {
        processOneCaptureResultLocked(states, result.v3_2, result.physicalCameraMetadata);
    }
    return hardware::Void();
}

hardware::Return<void> HidlCamera3OfflineSession::processCaptureResult(
        const hardware::hidl_vec<
                hardware::camera::device::V3_2::CaptureResult>& results) {
    // TODO: changed impl to call into processCaptureResult_3_4 instead?
    //       might need to figure how to reduce copy though.
    sp<NotificationListener> listener;
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return hardware::Void();
        }
        listener = mListener.promote();
    }

    hardware::hidl_vec<hardware::camera::device::V3_4::PhysicalCameraMetadata> noPhysMetadata;

    HidlCaptureOutputStates states {
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
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this, *this,
        mBufferRecords, /*legacyClient*/ false, mMinExpectedDuration, mIsFixedFps},
      mResultMetadataQueue
    };

    std::lock_guard<std::mutex> lock(mProcessCaptureResultLock);
    for (const auto& result : results) {
        processOneCaptureResultLocked(states, result, noPhysMetadata);
    }
    return hardware::Void();
}

hardware::Return<void> HidlCamera3OfflineSession::notify(
        const hardware::hidl_vec<hardware::camera::device::V3_2::NotifyMsg>& msgs) {
    sp<NotificationListener> listener;
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return hardware::Void();
        }
        listener = mListener.promote();
    }

    HidlCaptureOutputStates states {
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
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this, *this,
        mBufferRecords, /*legacyClient*/ false, mMinExpectedDuration, mIsFixedFps},
      mResultMetadataQueue
    };
    for (const auto& msg : msgs) {
        camera3::notify(states, msg);
    }
    return hardware::Void();
}

hardware::Return<void> HidlCamera3OfflineSession::requestStreamBuffers(
        const hardware::hidl_vec<hardware::camera::device::V3_5::BufferRequest>& bufReqs,
        requestStreamBuffers_cb _hidl_cb) {
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return hardware::Void();
        }
    }

    RequestBufferStates states {
        mId, mRequestBufferInterfaceLock, mUseHalBufManager, mOutputStreams, mSessionStatsBuilder,
        *this, mBufferRecords, *this};
    camera3::requestStreamBuffers(states, bufReqs, _hidl_cb);
    return hardware::Void();
}

hardware::Return<void> HidlCamera3OfflineSession::returnStreamBuffers(
        const hardware::hidl_vec<hardware::camera::device::V3_2::StreamBuffer>& buffers) {
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStatus != STATUS_ACTIVE) {
            ALOGE("%s called in wrong state %d", __FUNCTION__, mStatus);
            return hardware::Void();
        }
    }

    ReturnBufferStates states {
        mId, mUseHalBufManager, mOutputStreams, mSessionStatsBuilder, mBufferRecords};

    camera3::returnStreamBuffers(states, buffers);
    return hardware::Void();
}

void HidlCamera3OfflineSession::disconnectSession() {
  // TODO: Make sure this locking is correct.
  std::lock_guard<std::mutex> lock(mLock);
  if (mSession != nullptr) {
      mSession->close();
  }
  mSession.clear();
}

}; // namespace android
