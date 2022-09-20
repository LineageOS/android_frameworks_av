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

#define LOG_TAG "AidlCamera3-Device"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0
//#define LOG_NNDEBUG 0  // Per-frame verbose logging

#ifdef LOG_NNDEBUG
#define ALOGVV(...) ALOGV(__VA_ARGS__)
#else
#define ALOGVV(...) ((void)0)
#endif

// Convenience macro for transient errors
#define CLOGE(fmt, ...) ALOGE("Camera %s: %s: " fmt, mId.string(), __FUNCTION__, \
            ##__VA_ARGS__)

#define CLOGW(fmt, ...) ALOGW("Camera %s: %s: " fmt, mId.string(), __FUNCTION__, \
            ##__VA_ARGS__)

// Convenience macros for transitioning to the error state
#define SET_ERR(fmt, ...) setErrorState(   \
    "%s: " fmt, __FUNCTION__,              \
    ##__VA_ARGS__)
#define SET_ERR_L(fmt, ...) setErrorStateLocked( \
    "%s: " fmt, __FUNCTION__,                    \
    ##__VA_ARGS__)

#include <inttypes.h>

#include <utility>

#include <utils/Log.h>
#include <utils/Trace.h>
#include <utils/Timers.h>
#include <cutils/properties.h>

#include <aidl/android/hardware/camera/device/ICameraInjectionSession.h>
#include <aidlcommonsupport/NativeHandle.h>
#include <android/binder_ibinder_platform.h>
#include <android/hardware/camera2/ICameraDeviceUser.h>

#include "utils/CameraTraces.h"
#include "mediautils/SchedulingPolicyService.h"
#include "device3/Camera3OutputStream.h"
#include "device3/Camera3InputStream.h"
#include "device3/Camera3FakeStream.h"
#include "device3/Camera3SharedOutputStream.h"
#include "device3/aidl/AidlCamera3OutputUtils.h"
#include "device3/aidl/AidlCamera3OfflineSession.h"
#include "CameraService.h"
#include "utils/CameraThreadState.h"
#include "utils/SessionConfigurationUtils.h"
#include "utils/TraceHFR.h"
#include "utils/CameraServiceProxyWrapper.h"

#include "../../common/aidl/AidlProviderInfo.h"

#include <algorithm>

#include "AidlCamera3Device.h"

using namespace android::camera3;
using namespace aidl::android::hardware;
using aidl::android::hardware::camera::metadata::SensorPixelMode;
using aidl::android::hardware::camera::metadata::RequestAvailableDynamicRangeProfilesMap;
using aidl::android::hardware::camera::metadata::ScalerAvailableStreamUseCases;

namespace android {

RequestAvailableDynamicRangeProfilesMap
mapToAidlDynamicProfile(int64_t dynamicRangeProfile) {
    return static_cast<RequestAvailableDynamicRangeProfilesMap>(dynamicRangeProfile);
}

aidl::android::hardware::graphics::common::PixelFormat AidlCamera3Device::mapToAidlPixelFormat(
        int frameworkFormat) {
    return (aidl::android::hardware::graphics::common::PixelFormat) frameworkFormat;
}

aidl::android::hardware::graphics::common::Dataspace AidlCamera3Device::mapToAidlDataspace(
        android_dataspace dataSpace) {
    return (aidl::android::hardware::graphics::common::Dataspace)dataSpace;
}

aidl::android::hardware::graphics::common::BufferUsage AidlCamera3Device::mapToAidlConsumerUsage(
        uint64_t usage) {
    return (aidl::android::hardware::graphics::common::BufferUsage)usage;
}

aidl::android::hardware::camera::device::StreamRotation
AidlCamera3Device::mapToAidlStreamRotation(camera_stream_rotation_t rotation) {
    switch (rotation) {
        case CAMERA_STREAM_ROTATION_0:
            return aidl::android::hardware::camera::device::StreamRotation::ROTATION_0;
        case CAMERA_STREAM_ROTATION_90:
            return aidl::android::hardware::camera::device::StreamRotation::ROTATION_90;
        case CAMERA_STREAM_ROTATION_180:
            return aidl::android::hardware::camera::device::StreamRotation::ROTATION_180;
        case CAMERA_STREAM_ROTATION_270:
            return aidl::android::hardware::camera::device::StreamRotation::ROTATION_270;
    }
    ALOGE("%s: Unknown stream rotation %d", __FUNCTION__, rotation);
    return aidl::android::hardware::camera::device::StreamRotation::ROTATION_0;
}

status_t AidlCamera3Device::mapToAidlStreamConfigurationMode(
        camera_stream_configuration_mode_t operationMode,
        aidl::android::hardware::camera::device::StreamConfigurationMode *mode) {
    using StreamConfigurationMode =
            aidl::android::hardware::camera::device::StreamConfigurationMode;
    if (mode == nullptr) return BAD_VALUE;
    if (operationMode < CAMERA_VENDOR_STREAM_CONFIGURATION_MODE_START) {
        switch(operationMode) {
            case CAMERA_STREAM_CONFIGURATION_NORMAL_MODE:
                *mode = StreamConfigurationMode::NORMAL_MODE;
                break;
            case CAMERA_STREAM_CONFIGURATION_CONSTRAINED_HIGH_SPEED_MODE:
                *mode = StreamConfigurationMode::CONSTRAINED_HIGH_SPEED_MODE;
                break;
            default:
                ALOGE("%s: Unknown stream configuration mode %d", __FUNCTION__, operationMode);
                return BAD_VALUE;
        }
    } else {
        *mode = static_cast<StreamConfigurationMode>(operationMode);
    }
    return OK;
}

int AidlCamera3Device::mapToFrameworkFormat(
        aidl::android::hardware::graphics::common::PixelFormat pixelFormat) {
    return static_cast<uint32_t>(pixelFormat);
}

android_dataspace AidlCamera3Device::mapToFrameworkDataspace(
        aidl::android::hardware::graphics::common::Dataspace dataSpace) {
    return static_cast<android_dataspace>(dataSpace);
}

uint64_t AidlCamera3Device::mapConsumerToFrameworkUsage(
        aidl::android::hardware::graphics::common::BufferUsage usage) {
    return (uint64_t)usage;
}

uint64_t AidlCamera3Device::mapProducerToFrameworkUsage(
       aidl::android::hardware::graphics::common::BufferUsage usage) {
    return (uint64_t)usage;
}

AidlCamera3Device::AidlCamera3Device(const String8& id, bool overrideForPerfClass,
            bool legacyClient) : Camera3Device(id, overrideForPerfClass, legacyClient) {
        mCallbacks = ndk::SharedRefBase::make<AidlCameraDeviceCallbacks>(this);
}

status_t AidlCamera3Device::initialize(sp<CameraProviderManager> manager,
        const String8& monitorTags) {
    ATRACE_CALL();
    Mutex::Autolock il(mInterfaceLock);
    Mutex::Autolock l(mLock);

    ALOGV("%s: Initializing AIDL device for camera %s", __FUNCTION__, mId.string());
    if (mStatus != STATUS_UNINITIALIZED) {
        CLOGE("Already initialized!");
        return INVALID_OPERATION;
    }
    if (manager == nullptr) return INVALID_OPERATION;

    std::shared_ptr<camera::device::ICameraDeviceSession> session;
    ATRACE_BEGIN("CameraHal::openSession");
    status_t res = manager->openAidlSession(mId.string(), mCallbacks,
            /*out*/ &session);
    ATRACE_END();
    if (res != OK) {
        SET_ERR_L("Could not open camera session: %s (%d)", strerror(-res), res);
        return res;
    }
    if (session == nullptr) {
      SET_ERR("Session iface returned is null");
      return INVALID_OPERATION;
    }
    res = manager->getCameraCharacteristics(mId.string(), mOverrideForPerfClass, &mDeviceInfo);
    if (res != OK) {
        SET_ERR_L("Could not retrieve camera characteristics: %s (%d)", strerror(-res), res);
        session->close();
        return res;
    }
    mSupportNativeZoomRatio = manager->supportNativeZoomRatio(mId.string());

    std::vector<std::string> physicalCameraIds;
    bool isLogical = manager->isLogicalCamera(mId.string(), &physicalCameraIds);
    if (isLogical) {
        for (auto& physicalId : physicalCameraIds) {
            // Do not override characteristics for physical cameras
            res = manager->getCameraCharacteristics(
                    physicalId, /*overrideForPerfClass*/false, &mPhysicalDeviceInfoMap[physicalId]);
            if (res != OK) {
                SET_ERR_L("Could not retrieve camera %s characteristics: %s (%d)",
                        physicalId.c_str(), strerror(-res), res);
                session->close();
                return res;
            }

            bool usePrecorrectArray =
                    DistortionMapper::isDistortionSupported(mPhysicalDeviceInfoMap[physicalId]);
            if (usePrecorrectArray) {
                res = mDistortionMappers[physicalId].setupStaticInfo(
                        mPhysicalDeviceInfoMap[physicalId]);
                if (res != OK) {
                    SET_ERR_L("Unable to read camera %s's calibration fields for distortion "
                            "correction", physicalId.c_str());
                    session->close();
                    return res;
                }
            }

            mZoomRatioMappers[physicalId] = ZoomRatioMapper(
                    &mPhysicalDeviceInfoMap[physicalId],
                    mSupportNativeZoomRatio, usePrecorrectArray);

            if (SessionConfigurationUtils::isUltraHighResolutionSensor(
                    mPhysicalDeviceInfoMap[physicalId])) {
                mUHRCropAndMeteringRegionMappers[physicalId] =
                        UHRCropAndMeteringRegionMapper(mPhysicalDeviceInfoMap[physicalId],
                                usePrecorrectArray);
            }
        }
    }

    std::shared_ptr<AidlRequestMetadataQueue> queue;
    ::aidl::android::hardware::common::fmq::MQDescriptor<
            int8_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> desc;

    ::ndk::ScopedAStatus requestQueueRet = session->getCaptureRequestMetadataQueue(&desc);
    if (!requestQueueRet.isOk()) {
        ALOGE("Transaction error when getting result metadata queue from camera session: %s",
                requestQueueRet.getMessage());
        return AidlProviderInfo::mapToStatusT(requestQueueRet);
    }
    queue = std::make_unique<AidlRequestMetadataQueue>(desc);
    if (!queue->isValid() || queue->availableToWrite() <= 0) {
        ALOGE("HAL returns empty result metadata fmq, not use it");
        queue = nullptr;
        // Don't use resQueue onwards.
    }

    std::unique_ptr<AidlResultMetadataQueue>& resQueue = mResultMetadataQueue;
    ::aidl::android::hardware::common::fmq::MQDescriptor<
        int8_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> resDesc;
    ::ndk::ScopedAStatus resultQueueRet = session->getCaptureResultMetadataQueue(&resDesc);
    if (!resultQueueRet.isOk()) {
        ALOGE("Transaction error when getting result metadata queue from camera session: %s",
                resultQueueRet.getMessage());
        return AidlProviderInfo::mapToStatusT(resultQueueRet);
    }
    resQueue = std::make_unique<AidlResultMetadataQueue>(resDesc);
    if (!resQueue->isValid() || resQueue->availableToWrite() <= 0) {
        ALOGE("HAL returns empty result metadata fmq, not use it");
        resQueue = nullptr;
        // Don't use resQueue onwards.
    }

    camera_metadata_entry bufMgrMode =
            mDeviceInfo.find(ANDROID_INFO_SUPPORTED_BUFFER_MANAGEMENT_VERSION);
    if (bufMgrMode.count > 0) {
        mUseHalBufManager = (bufMgrMode.data.u8[0] ==
                ANDROID_INFO_SUPPORTED_BUFFER_MANAGEMENT_VERSION_HIDL_DEVICE_3_5);
    }

    camera_metadata_entry_t capabilities = mDeviceInfo.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    for (size_t i = 0; i < capabilities.count; i++) {
        uint8_t capability = capabilities.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_OFFLINE_PROCESSING) {
            mSupportOfflineProcessing = true;
        }
    }

    mInterface = new AidlHalInterface(session, queue, mUseHalBufManager, mSupportOfflineProcessing);

    std::string providerType;
    mVendorTagId = manager->getProviderTagIdLocked(mId.string());
    mTagMonitor.initialize(mVendorTagId);
    if (!monitorTags.isEmpty()) {
        mTagMonitor.parseTagsToMonitor(String8(monitorTags));
    }

    for (size_t i = 0; i < capabilities.count; i++) {
        uint8_t capability = capabilities.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MONOCHROME) {
            mNeedFixupMonochromeTags = true;
        }
    }

    return initializeCommonLocked();
}

::ndk::ScopedAStatus AidlCamera3Device::AidlCameraDeviceCallbacks::processCaptureResult(
            const std::vector<camera::device::CaptureResult>& results) {
    sp<AidlCamera3Device> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->processCaptureResult(results);
}

::ndk::ScopedAStatus AidlCamera3Device::AidlCameraDeviceCallbacks::notify(
        const std::vector<camera::device::NotifyMsg>& msgs) {
    sp<AidlCamera3Device> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->notify(msgs);
}

::ndk::ScopedAStatus AidlCamera3Device::processCaptureResult(
            const std::vector<camera::device::CaptureResult>& results) {
    // Ideally we should grab mLock, but that can lead to deadlock, and
    // it's not super important to get up to date value of mStatus for this
    // warning print, hence skipping the lock here
    if (mStatus == STATUS_ERROR) {
        // Per API contract, HAL should act as closed after device error
        // But mStatus can be set to error by framework as well, so just log
        // a warning here.
        ALOGW("%s: received capture result in error state.", __FUNCTION__);
    }

    sp<NotificationListener> listener;
    {
        std::lock_guard<std::mutex> l(mOutputLock);
        listener = mListener.promote();
    }

    if (mProcessCaptureResultLock.tryLock() != OK) {
        // This should never happen; it indicates a wrong client implementation
        // that doesn't follow the contract. But, we can be tolerant here.
        ALOGE("%s: callback overlapped! waiting 1s...",
                __FUNCTION__);
        if (mProcessCaptureResultLock.timedLock(1000000000 /* 1s */) != OK) {
            ALOGE("%s: cannot acquire lock in 1s, dropping results",
                    __FUNCTION__);
            // really don't know what to do, so bail out.
            return ::ndk::ScopedAStatus::ok();
        }
    }
    AidlCaptureOutputStates states {
       {
        mId,
        mInFlightLock, mLastCompletedRegularFrameNumber,
        mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
        mInFlightMap, mOutputLock, mResultQueue, mResultSignal,
        mNextShutterFrameNumber,
        mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
        mNextResultFrameNumber,
        mNextReprocessResultFrameNumber, mNextZslStillResultFrameNumber,
        mUseHalBufManager, mUsePartialResult, mNeedFixupMonochromeTags,
        mNumPartialResults, mVendorTagId, mDeviceInfo, mPhysicalDeviceInfoMap,
        mDistortionMappers, mZoomRatioMappers, mRotateAndCropMappers,
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this,
        *this, *(mInterface), mLegacyClient, mMinExpectedDuration}, mResultMetadataQueue
    };

    for (const auto& result : results) {
        processOneCaptureResultLocked(states, result, result.physicalCameraMetadata);
    }
    mProcessCaptureResultLock.unlock();
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus AidlCamera3Device::notify(
        const std::vector<camera::device::NotifyMsg>& msgs) {
    // Ideally we should grab mLock, but that can lead to deadlock, and
    // it's not super important to get up to date value of mStatus for this
    // warning print, hence skipping the lock here
    if (mStatus == STATUS_ERROR) {
        // Per API contract, HAL should act as closed after device error
        // But mStatus can be set to error by framework as well, so just log
        // a warning here.
        ALOGW("%s: received notify message in error state.", __FUNCTION__);
    }

    sp<NotificationListener> listener;
    {
        std::lock_guard<std::mutex> l(mOutputLock);
        listener = mListener.promote();
    }

    AidlCaptureOutputStates states {
      { mId,
        mInFlightLock, mLastCompletedRegularFrameNumber,
        mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
        mInFlightMap, mOutputLock, mResultQueue, mResultSignal,
        mNextShutterFrameNumber,
        mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
        mNextResultFrameNumber,
        mNextReprocessResultFrameNumber, mNextZslStillResultFrameNumber,
        mUseHalBufManager, mUsePartialResult, mNeedFixupMonochromeTags,
        mNumPartialResults, mVendorTagId, mDeviceInfo, mPhysicalDeviceInfoMap,
        mDistortionMappers, mZoomRatioMappers, mRotateAndCropMappers,
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this,
        *this, *(mInterface), mLegacyClient, mMinExpectedDuration}, mResultMetadataQueue
    };
    for (const auto& msg : msgs) {
        camera3::notify(states, msg);
    }
    return ::ndk::ScopedAStatus::ok();

}

status_t AidlCamera3Device::switchToOffline(
        const std::vector<int32_t>& streamsToKeep,
        /*out*/ sp<CameraOfflineSessionBase>* session) {
    ATRACE_CALL();
    if (session == nullptr) {
        ALOGE("%s: session must not be null", __FUNCTION__);
        return BAD_VALUE;
    }

    Mutex::Autolock il(mInterfaceLock);

    bool hasInputStream = mInputStream != nullptr;
    int32_t inputStreamId = hasInputStream ? mInputStream->getId() : -1;
    bool inputStreamSupportsOffline = hasInputStream ?
            mInputStream->getOfflineProcessingSupport() : false;
    auto outputStreamIds = mOutputStreams.getStreamIds();
    auto streamIds = outputStreamIds;
    if (hasInputStream) {
        streamIds.push_back(mInputStream->getId());
    }

    // Check all streams in streamsToKeep supports offline mode
    for (auto id : streamsToKeep) {
        if (std::find(streamIds.begin(), streamIds.end(), id) == streamIds.end()) {
            ALOGE("%s: Unknown stream ID %d", __FUNCTION__, id);
            return BAD_VALUE;
        } else if (id == inputStreamId) {
            if (!inputStreamSupportsOffline) {
                ALOGE("%s: input stream %d cannot be switched to offline",
                        __FUNCTION__, id);
                return BAD_VALUE;
            }
        } else {
            sp<camera3::Camera3OutputStreamInterface> stream = mOutputStreams.get(id);
            if (!stream->getOfflineProcessingSupport()) {
                ALOGE("%s: output stream %d cannot be switched to offline",
                        __FUNCTION__, id);
                return BAD_VALUE;
            }
        }
    }
    // TODO: block surface sharing and surface group streams until we can support them

    // Stop repeating request, wait until all remaining requests are submitted, then call into
    // HAL switchToOffline
    camera::device::CameraOfflineSessionInfo offlineSessionInfo;
    std::shared_ptr<camera::device::ICameraOfflineSession> offlineSession;
    camera3::BufferRecords bufferRecords;
    status_t ret = static_cast<AidlRequestThread *>(mRequestThread.get())->switchToOffline(
            streamsToKeep, &offlineSessionInfo, &offlineSession, &bufferRecords);

    if (ret != OK) {
        SET_ERR("Switch to offline failed: %s (%d)", strerror(-ret), ret);
        return ret;
    }

    bool succ = mRequestBufferSM.onSwitchToOfflineSuccess();
    if (!succ) {
        SET_ERR("HAL must not be calling requestStreamBuffers call");
        // TODO: block ALL callbacks from HAL till app configured new streams?
        return UNKNOWN_ERROR;
    }

    // Verify offlineSessionInfo
    std::vector<int32_t> offlineStreamIds;
    offlineStreamIds.reserve(offlineSessionInfo.offlineStreams.size());
    for (auto offlineStream : offlineSessionInfo.offlineStreams) {
        // verify stream IDs
        int32_t id = offlineStream.id;
        if (std::find(streamIds.begin(), streamIds.end(), id) == streamIds.end()) {
            SET_ERR("stream ID %d not found!", id);
            return UNKNOWN_ERROR;
        }

        // When not using HAL buf manager, only allow streams requested by app to be preserved
        if (!mUseHalBufManager) {
            if (std::find(streamsToKeep.begin(), streamsToKeep.end(), id) == streamsToKeep.end()) {
                SET_ERR("stream ID %d must not be switched to offline!", id);
                return UNKNOWN_ERROR;
            }
        }

        offlineStreamIds.push_back(id);
        sp<Camera3StreamInterface> stream = (id == inputStreamId) ?
                static_cast<sp<Camera3StreamInterface>>(mInputStream) :
                static_cast<sp<Camera3StreamInterface>>(mOutputStreams.get(id));
        // Verify number of outstanding buffers
        if (stream->getOutstandingBuffersCount() != (uint32_t)offlineStream.numOutstandingBuffers) {
            SET_ERR("Offline stream %d # of remaining buffer mismatch: (%zu,%d) (service/HAL)",
                    id, stream->getOutstandingBuffersCount(), offlineStream.numOutstandingBuffers);
            return UNKNOWN_ERROR;
        }
    }

    // Verify all streams to be deleted don't have any outstanding buffers
    if (hasInputStream && std::find(offlineStreamIds.begin(), offlineStreamIds.end(),
                inputStreamId) == offlineStreamIds.end()) {
        if (mInputStream->hasOutstandingBuffers()) {
            SET_ERR("Input stream %d still has %zu outstanding buffer!",
                    inputStreamId, mInputStream->getOutstandingBuffersCount());
            return UNKNOWN_ERROR;
        }
    }

    for (const auto& outStreamId : outputStreamIds) {
        if (std::find(offlineStreamIds.begin(), offlineStreamIds.end(),
                outStreamId) == offlineStreamIds.end()) {
            auto outStream = mOutputStreams.get(outStreamId);
            if (outStream->hasOutstandingBuffers()) {
                SET_ERR("Output stream %d still has %zu outstanding buffer!",
                        outStreamId, outStream->getOutstandingBuffersCount());
                return UNKNOWN_ERROR;
            }
        }
    }

    InFlightRequestMap offlineReqs;
    // Verify inflight requests and their pending buffers
    {
        std::lock_guard<std::mutex> l(mInFlightLock);
        for (auto offlineReq : offlineSessionInfo.offlineRequests) {
            int idx = mInFlightMap.indexOfKey(offlineReq.frameNumber);
            if (idx == NAME_NOT_FOUND) {
                SET_ERR("Offline request frame number %d not found!", offlineReq.frameNumber);
                return UNKNOWN_ERROR;
            }

            const auto& inflightReq = mInFlightMap.valueAt(idx);
            // TODO: check specific stream IDs
            size_t numBuffersLeft = static_cast<size_t>(inflightReq.numBuffersLeft);
            if (numBuffersLeft != offlineReq.pendingStreams.size()) {
                SET_ERR("Offline request # of remaining buffer mismatch: (%d,%d) (service/HAL)",
                        inflightReq.numBuffersLeft, offlineReq.pendingStreams.size());
                return UNKNOWN_ERROR;
            }
            offlineReqs.add(offlineReq.frameNumber, inflightReq);
        }
    }

    // Create Camera3OfflineSession and transfer object ownership
    //   (streams, inflight requests, buffer caches)
    camera3::StreamSet offlineStreamSet;
    sp<camera3::Camera3Stream> inputStream;
    for (auto offlineStream : offlineSessionInfo.offlineStreams) {
        int32_t id = offlineStream.id;
        if (mInputStream != nullptr && id == mInputStream->getId()) {
            inputStream = mInputStream;
        } else {
            offlineStreamSet.add(id, mOutputStreams.get(id));
        }
    }

    // TODO: check if we need to lock before copying states
    //       though technically no other thread should be talking to Camera3Device at this point
    Camera3OfflineStates offlineStates(
            mTagMonitor, mVendorTagId, mUseHalBufManager, mNeedFixupMonochromeTags,
            mUsePartialResult, mNumPartialResults, mLastCompletedRegularFrameNumber,
            mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
            mNextResultFrameNumber, mNextReprocessResultFrameNumber,
            mNextZslStillResultFrameNumber, mNextShutterFrameNumber,
            mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
            mDeviceInfo, mPhysicalDeviceInfoMap, mDistortionMappers,
            mZoomRatioMappers, mRotateAndCropMappers);

    *session = new AidlCamera3OfflineSession(mId, inputStream, offlineStreamSet,
            std::move(bufferRecords), offlineReqs, offlineStates, offlineSession);

    // Delete all streams that has been transferred to offline session
    Mutex::Autolock l(mLock);
    for (auto offlineStream : offlineSessionInfo.offlineStreams) {
        int32_t id = offlineStream.id;
        if (mInputStream != nullptr && id == mInputStream->getId()) {
            mInputStream.clear();
        } else {
            mOutputStreams.remove(id);
        }
    }

    // disconnect all other streams and switch to UNCONFIGURED state
    if (mInputStream != nullptr) {
        ret = mInputStream->disconnect();
        if (ret != OK) {
            SET_ERR_L("disconnect input stream failed!");
            return UNKNOWN_ERROR;
        }
    }

    for (auto streamId : mOutputStreams.getStreamIds()) {
        sp<Camera3StreamInterface> stream = mOutputStreams.get(streamId);
        ret = stream->disconnect();
        if (ret != OK) {
            SET_ERR_L("disconnect output stream %d failed!", streamId);
            return UNKNOWN_ERROR;
        }
    }

    mInputStream.clear();
    mOutputStreams.clear();
    mNeedConfig = true;
    internalUpdateStatusLocked(STATUS_UNCONFIGURED);
    mOperatingMode = NO_MODE;
    mIsConstrainedHighSpeedConfiguration = false;
    mRequestThread->clearPreviousRequest();

    return OK;
    // TO be done by CameraDeviceClient/Camera3OfflineSession
    // register the offline client to camera service
    // Setup result passthing threads etc
    // Initialize offline session so HAL can start sending callback to it (result Fmq)
    // TODO: check how many onIdle callback will be sent
    // Java side to make sure the CameraCaptureSession is properly closed
}

::ndk::ScopedAStatus AidlCamera3Device::AidlCameraDeviceCallbacks::requestStreamBuffers(
        const std::vector<camera::device::BufferRequest>& bufReqs,
        std::vector<aidl::android::hardware::camera::device::StreamBufferRet>* outBuffers,
        aidl::android::hardware::camera::device::BufferRequestStatus* status) {

    sp<AidlCamera3Device> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->requestStreamBuffers(bufReqs, outBuffers, status);
}

::ndk::ScopedAStatus AidlCamera3Device::requestStreamBuffers(
        const std::vector<camera::device::BufferRequest>& bufReqs,
        std::vector<aidl::android::hardware::camera::device::StreamBufferRet>* outBuffers,
        aidl::android::hardware::camera::device::BufferRequestStatus* status) {

    RequestBufferStates states {
        mId, mRequestBufferInterfaceLock, mUseHalBufManager, mOutputStreams,
        mSessionStatsBuilder, *this, *(mInterface), *this};
    camera3::requestStreamBuffers(states, bufReqs, outBuffers, status);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus AidlCamera3Device::AidlCameraDeviceCallbacks::returnStreamBuffers(
        const std::vector<camera::device::StreamBuffer>& buffers) {
    sp<AidlCamera3Device> p = mParent.promote();
    if (p == nullptr) {
        ALOGE("%s Parent AidlCameraDevice not alive, can't process callbacks", __FUNCTION__);
        return ::ndk::ScopedAStatus::ok();
    }
    return p->returnStreamBuffers(buffers);
}

::ndk::SpAIBinder AidlCamera3Device::AidlCameraDeviceCallbacks::createBinder() {
    auto binder = BnCameraDeviceCallback::createBinder();
    AIBinder_setInheritRt(binder.get(), /*inheritRt*/ true);
    return binder;
}

::ndk::ScopedAStatus AidlCamera3Device::returnStreamBuffers(
        const std::vector<camera::device::StreamBuffer>& buffers) {
    ReturnBufferStates states {
        mId, mUseHalBufManager, mOutputStreams,  mSessionStatsBuilder,
        *(mInterface)};
    camera3::returnStreamBuffers(states, buffers);
    return ::ndk::ScopedAStatus::ok();
}

AidlCamera3Device::AidlHalInterface::AidlHalInterface(
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceSession> &session,
            std::shared_ptr<AidlRequestMetadataQueue> queue,
            bool useHalBufManager, bool supportOfflineProcessing) :
        HalInterface(useHalBufManager, supportOfflineProcessing),
        mAidlSession(session),
        mRequestMetadataQueue(queue) { }

AidlCamera3Device::AidlHalInterface::AidlHalInterface(
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraDeviceSession>
                    &deviceSession,
            std::shared_ptr<aidl::android::hardware::camera::device::ICameraInjectionSession>
                    &injectionSession, std::shared_ptr<AidlRequestMetadataQueue> queue,
            bool useHalBufManager, bool supportOfflineProcessing) :
        HalInterface(useHalBufManager, supportOfflineProcessing),
        mAidlSession(deviceSession),
        mAidlInjectionSession(injectionSession),
        mRequestMetadataQueue(queue) { }

bool AidlCamera3Device::AidlHalInterface::valid() {
    return (mAidlSession != nullptr);
}

void AidlCamera3Device::AidlHalInterface::clear() {
    mAidlSession.reset();
}

status_t AidlCamera3Device::AidlHalInterface::flush() {
    ATRACE_NAME("CameraHal::flush");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    auto err = mAidlSession->flush();
    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.getMessage());
        res = AidlProviderInfo::mapToStatusT(err);
    }

    return res;
}

status_t AidlCamera3Device::AidlHalInterface::dump(int /*fd*/) {
    ATRACE_NAME("CameraHal::dump");
    if (!valid()) return INVALID_OPERATION;

    // Handled by CameraProviderManager::dump

    return OK;
}

status_t AidlCamera3Device::AidlHalInterface::repeatingRequestEnd(uint32_t frameNumber,
        const std::vector<int32_t> &streamIds) {
    ATRACE_NAME("AidlCameraHal::repeatingRequestEnd");
    if (!valid()) return INVALID_OPERATION;

    auto err = mAidlSession->repeatingRequestEnd(frameNumber, streamIds);
    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.getMessage());
        return AidlProviderInfo::mapToStatusT(err);
    }

    return OK;
}

status_t AidlCamera3Device::AidlHalInterface::close() {
    ATRACE_NAME("CameraHal::close()");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    auto err = mAidlSession->close();
    // Interface will be dead shortly anyway, so don't log errors
    if (!err.isOk()) {
        res = DEAD_OBJECT;
    }

    return res;
}

void AidlCamera3Device::AidlHalInterface::signalPipelineDrain(const std::vector<int>& streamIds) {
    ATRACE_NAME("CameraHal::signalPipelineDrain");
    if (!valid()) {
        ALOGE("%s called on invalid camera!", __FUNCTION__);
        return;
    }

    auto err = mAidlSession->signalStreamFlush(streamIds, mNextStreamConfigCounter - 1);
    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.getMessage());
        return;
    }
}

bool AidlCamera3Device::AidlHalInterface::isReconfigurationRequired(
        CameraMetadata& oldSessionParams, CameraMetadata& newSessionParams) {
    // We do reconfiguration by default;
    bool required = true;
    if (mIsReconfigurationQuerySupported) {
        aidl::android::hardware::camera::device::CameraMetadata oldParams, newParams;
        camera_metadata_t* oldSessionMeta = const_cast<camera_metadata_t*>(
                oldSessionParams.getAndLock());
        uint8_t *oldSessionByteP = reinterpret_cast<uint8_t*>(oldSessionMeta);

        camera_metadata_t* newSessionMeta = const_cast<camera_metadata_t*>(
                newSessionParams.getAndLock());
        uint8_t *newSessionByteP = reinterpret_cast<uint8_t*>(newSessionMeta);
        // std::vector has no setToExternal, so we hacve to copy
        oldParams.metadata.assign(oldSessionByteP,
                oldSessionByteP + get_camera_metadata_size(oldSessionMeta));
        newParams.metadata.assign(newSessionByteP,
                newSessionByteP + get_camera_metadata_size(newSessionMeta));
        auto err = mAidlSession->isReconfigurationRequired(oldParams, newParams, &required);
        oldSessionParams.unlock(oldSessionMeta);
        newSessionParams.unlock(newSessionMeta);
        if (!err.isOk()) {
            ALOGE("%s: Unexpected binder error: %s", __FUNCTION__, err.getMessage());
            return true;
        }
    }

    return required;
}

status_t AidlCamera3Device::AidlHalInterface::constructDefaultRequestSettings(
        camera_request_template_t templateId,
        /*out*/ camera_metadata_t **requestTemplate) {
    ATRACE_NAME("CameraAidlHal::constructDefaultRequestSettings");
    using aidl::android::hardware::camera::device::RequestTemplate;
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    RequestTemplate id;
    aidl::android::hardware::camera::device::CameraMetadata request;
    switch (templateId) {
        case CAMERA_TEMPLATE_PREVIEW:
            id = RequestTemplate::PREVIEW;
            break;
        case CAMERA_TEMPLATE_STILL_CAPTURE:
            id = RequestTemplate::STILL_CAPTURE;
            break;
        case CAMERA_TEMPLATE_VIDEO_RECORD:
            id = RequestTemplate::VIDEO_RECORD;
            break;
        case CAMERA_TEMPLATE_VIDEO_SNAPSHOT:
            id = RequestTemplate::VIDEO_SNAPSHOT;
            break;
        case CAMERA_TEMPLATE_ZERO_SHUTTER_LAG:
            id = RequestTemplate::ZERO_SHUTTER_LAG;
            break;
        case CAMERA_TEMPLATE_MANUAL:
            id = RequestTemplate::MANUAL;
            break;
        default:
            // Unknown template ID, or this HAL is too old to support it
            return BAD_VALUE;
    }
    auto err = mAidlSession->constructDefaultRequestSettings(id, &request);

    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.getMessage());
        return AidlProviderInfo::mapToStatusT(err);
    }
    const camera_metadata *r =
            reinterpret_cast<const camera_metadata_t*>(request.metadata.data());
    size_t expectedSize = request.metadata.size();
    int ret = validate_camera_metadata_structure(r, &expectedSize);
    if (ret == OK || ret == CAMERA_METADATA_VALIDATION_SHIFTED) {
        *requestTemplate = clone_camera_metadata(r);
        if (*requestTemplate == nullptr) {
            ALOGE("%s: Unable to clone camera metadata received from HAL",
                    __FUNCTION__);
            res = UNKNOWN_ERROR;
        }
    } else {
        ALOGE("%s: Malformed camera metadata received from HAL", __FUNCTION__);
        res = UNKNOWN_ERROR;
    }

    return res;
}

status_t AidlCamera3Device::AidlHalInterface::configureStreams(
    const camera_metadata_t *sessionParams,
        camera_stream_configuration *config, const std::vector<uint32_t>& bufferSizes) {
    using camera::device::StreamType;
    using camera::device::StreamConfigurationMode;

    ATRACE_NAME("CameraHal::configureStreams");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    // Convert stream config to AIDL
    std::set<int> activeStreams;
    camera::device::StreamConfiguration requestedConfiguration;
    requestedConfiguration.streams.resize(config->num_streams);
    for (size_t i = 0; i < config->num_streams; i++) {
        camera::device::Stream &dst = requestedConfiguration.streams[i];
        camera3::camera_stream_t *src = config->streams[i];

        Camera3Stream* cam3stream = Camera3Stream::cast(src);
        cam3stream->setBufferFreedListener(this);
        int streamId = cam3stream->getId();
        StreamType streamType;
        switch (src->stream_type) {
            case CAMERA_STREAM_OUTPUT:
                streamType = StreamType::OUTPUT;
                break;
            case CAMERA_STREAM_INPUT:
                streamType = StreamType::INPUT;
                break;
            default:
                ALOGE("%s: Stream %d: Unsupported stream type %d",
                        __FUNCTION__, streamId, config->streams[i]->stream_type);
                return BAD_VALUE;
        }
        dst.id = streamId;
        dst.streamType = streamType;
        dst.width = src->width;
        dst.height = src->height;
        dst.usage = mapToAidlConsumerUsage(cam3stream->getUsage());
        dst.rotation = mapToAidlStreamRotation((camera_stream_rotation_t) src->rotation);
        dst.format = mapToAidlPixelFormat(cam3stream->isFormatOverridden() ?
                    cam3stream->getOriginalFormat() : src->format);
        dst.dataSpace = mapToAidlDataspace(cam3stream->isDataSpaceOverridden() ?
                    cam3stream->getOriginalDataSpace() : src->data_space);

        dst.bufferSize = bufferSizes[i];
        if (src->physical_camera_id != nullptr) {
            dst.physicalCameraId = src->physical_camera_id;
        }
        dst.groupId = cam3stream->getHalStreamGroupId();
        dst.sensorPixelModesUsed.resize(src->sensor_pixel_modes_used.size());
        size_t j = 0;
        for (int mode : src->sensor_pixel_modes_used) {
            dst.sensorPixelModesUsed[j++] = static_cast<SensorPixelMode>(mode);
        }
        dst.dynamicRangeProfile = mapToAidlDynamicProfile(src->dynamic_range_profile);
        dst.useCase = static_cast<ScalerAvailableStreamUseCases>(src->use_case);
        activeStreams.insert(streamId);
        // Create Buffer ID map if necessary
        mBufferRecords.tryCreateBufferCache(streamId);
    }
    // remove BufferIdMap for deleted streams
    mBufferRecords.removeInactiveBufferCaches(activeStreams);

    StreamConfigurationMode operationMode;
    res = mapToAidlStreamConfigurationMode(
            (camera_stream_configuration_mode_t) config->operation_mode,
            /*out*/ &operationMode);
    if (res != OK) {
        return res;
    }
    requestedConfiguration.operationMode = operationMode;
    size_t sessionParamSize = get_camera_metadata_size(sessionParams);
    uint8_t *sessionParamP =
            reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(sessionParams));

    // std::vector has no setToExternal, so we have to copy
    requestedConfiguration.sessionParams.metadata.assign(
                sessionParamP, sessionParamP + sessionParamSize);
    requestedConfiguration.operationMode = operationMode;

    // Invoke configureStreams
    std::vector<camera::device::HalStream> finalConfiguration;

    requestedConfiguration.streamConfigCounter = mNextStreamConfigCounter++;
    requestedConfiguration.multiResolutionInputImage = config->input_is_multi_resolution;
    auto err = mAidlSession->configureStreams(requestedConfiguration, &finalConfiguration);
    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.getMessage());
        return AidlProviderInfo::mapToStatusT(err);
    }

    // And convert output stream configuration from AIDL

    for (size_t i = 0; i < config->num_streams; i++) {
        camera3::camera_stream_t *dst = config->streams[i];
        int streamId = Camera3Stream::cast(dst)->getId();

        // Start scan at i, with the assumption that the stream order matches
        size_t realIdx = i;
        bool found = false;
        size_t halStreamCount = finalConfiguration.size();
        for (size_t idx = 0; idx < halStreamCount; idx++) {
            if (finalConfiguration[realIdx].id == streamId) {
                found = true;
                break;
            }
            realIdx = (realIdx >= halStreamCount - 1) ? 0 : realIdx + 1;
        }
        if (!found) {
            ALOGE("%s: Stream %d not found in stream configuration response from HAL",
                    __FUNCTION__, streamId);
            return INVALID_OPERATION;
        }
        camera::device::HalStream &src = finalConfiguration[realIdx];

        Camera3Stream* dstStream = Camera3Stream::cast(dst);
        int overrideFormat = mapToFrameworkFormat(src.overrideFormat);
        android_dataspace overrideDataSpace = mapToFrameworkDataspace(src.overrideDataSpace);

        dstStream->setOfflineProcessingSupport(src.supportOffline);

        if (dstStream->getOriginalFormat() != HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) {
            dstStream->setFormatOverride(false);
            dstStream->setDataSpaceOverride(false);
            if (dst->format != overrideFormat) {
                ALOGE("%s: Stream %d: Format override not allowed for format 0x%x", __FUNCTION__,
                        streamId, dst->format);
            }
            if (dst->data_space != overrideDataSpace) {
                ALOGE("%s: Stream %d: DataSpace override not allowed for format 0x%x", __FUNCTION__,
                        streamId, dst->format);
            }
        } else {
            bool needFormatOverride =
                    requestedConfiguration.streams[i].format != src.overrideFormat;
            bool needDataspaceOverride =
                    requestedConfiguration.streams[i].dataSpace != src.overrideDataSpace;
            // Override allowed with IMPLEMENTATION_DEFINED
            dstStream->setFormatOverride(needFormatOverride);
            dstStream->setDataSpaceOverride(needDataspaceOverride);
            dst->format = overrideFormat;
            dst->data_space = overrideDataSpace;
        }

        if (dst->stream_type == CAMERA_STREAM_INPUT) {
            if (static_cast<int64_t>(src.producerUsage) != 0) {
                ALOGE("%s: Stream %d: INPUT streams must have 0 for producer usage",
                        __FUNCTION__, streamId);
                return INVALID_OPERATION;
            }
            dstStream->setUsage(
                    mapConsumerToFrameworkUsage(src.consumerUsage));
        } else {
            // OUTPUT
            if (static_cast<int64_t>(src.consumerUsage) != 0) {
                ALOGE("%s: Stream %d: OUTPUT streams must have 0 for consumer usage",
                        __FUNCTION__, streamId);
                return INVALID_OPERATION;
            }
            dstStream->setUsage(
                    mapProducerToFrameworkUsage(src.producerUsage));
        }
        dst->max_buffers = src.maxBuffers;
    }

    return res;
}

status_t AidlCamera3Device::AidlHalInterface::configureInjectedStreams(
        const camera_metadata_t* sessionParams, camera_stream_configuration* config,
        const std::vector<uint32_t>& bufferSizes,
        const CameraMetadata& cameraCharacteristics) {
    using camera::device::StreamType;
    using camera::device::StreamConfigurationMode;

    ATRACE_NAME("InjectionCameraHal::configureStreams");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    if (config->input_is_multi_resolution) {
        ALOGE("%s: Injection camera device doesn't support multi-resolution input "
                "stream", __FUNCTION__);
        return BAD_VALUE;
    }

    // Convert stream config to AIDL
    std::set<int> activeStreams;
    camera::device::StreamConfiguration requestedConfiguration;
    requestedConfiguration.streams.resize(config->num_streams);
    for (size_t i = 0; i < config->num_streams; i++) {
        camera::device::Stream& dst = requestedConfiguration.streams[i];
        camera3::camera_stream_t* src = config->streams[i];

        Camera3Stream* cam3stream = Camera3Stream::cast(src);
        cam3stream->setBufferFreedListener(this);
        int streamId = cam3stream->getId();
        StreamType streamType;
        switch (src->stream_type) {
            case CAMERA_STREAM_OUTPUT:
                streamType = StreamType::OUTPUT;
                break;
            case CAMERA_STREAM_INPUT:
                streamType = StreamType::INPUT;
                break;
            default:
                ALOGE("%s: Stream %d: Unsupported stream type %d", __FUNCTION__,
                        streamId, config->streams[i]->stream_type);
            return BAD_VALUE;
        }
        dst.id = streamId;
        dst.streamType = streamType;
        dst.width = src->width;
        dst.height = src->height;
        dst.usage = mapToAidlConsumerUsage(cam3stream->getUsage());
        dst.rotation = mapToAidlStreamRotation((camera_stream_rotation_t)src->rotation);
        dst.format =
            mapToAidlPixelFormat(cam3stream->isFormatOverridden() ? cam3stream->getOriginalFormat()
                    : src->format);
        dst.dataSpace =
            mapToAidlDataspace(cam3stream->isDataSpaceOverridden() ?
                    cam3stream->getOriginalDataSpace() : src->data_space);
        dst.bufferSize = bufferSizes[i];
        if (src->physical_camera_id != nullptr) {
            dst.physicalCameraId = src->physical_camera_id;
        }
        dst.groupId = cam3stream->getHalStreamGroupId();
        dst.sensorPixelModesUsed.resize(src->sensor_pixel_modes_used.size());
        size_t j = 0;
        for (int mode : src->sensor_pixel_modes_used) {
            dst.sensorPixelModesUsed[j++] = static_cast<SensorPixelMode>(mode);
        }
        activeStreams.insert(streamId);
        // Create Buffer ID map if necessary
        mBufferRecords.tryCreateBufferCache(streamId);
    }
    // remove BufferIdMap for deleted streams
    mBufferRecords.removeInactiveBufferCaches(activeStreams);

    StreamConfigurationMode operationMode;
    res = mapToAidlStreamConfigurationMode(
            (camera_stream_configuration_mode_t)config->operation_mode,
            /*out*/ &operationMode);
    if (res != OK) {
        return res;
    }
    requestedConfiguration.operationMode = operationMode;
    size_t sessionParamSize = get_camera_metadata_size(sessionParams);
    uint8_t *sessionParamP =
            reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(sessionParams));
    requestedConfiguration.operationMode = operationMode;
    requestedConfiguration.sessionParams.metadata.assign(
            sessionParamP, sessionParamP + sessionParamSize);

    // See which version of HAL we have
    if (mAidlInjectionSession != nullptr) {
        requestedConfiguration.streamConfigCounter = mNextStreamConfigCounter++;
        requestedConfiguration.multiResolutionInputImage = config->input_is_multi_resolution;

        const camera_metadata_t* rawMetadata = cameraCharacteristics.getAndLock();
        uint8_t *aidlCharsP =
                reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(rawMetadata));
        aidl::android::hardware::camera::device::CameraMetadata aidlChars;
        aidlChars.metadata.assign(aidlCharsP, aidlCharsP + get_camera_metadata_size(rawMetadata));
        cameraCharacteristics.unlock(rawMetadata);

        auto err = mAidlInjectionSession->configureInjectionStreams(requestedConfiguration,
                aidlChars);
        if (!err.isOk()) {
            ALOGE("%s: Transaction error: %s", __FUNCTION__, err.getMessage());
            return AidlProviderInfo::mapToStatusT(err);
        }
    } else {
        ALOGE("%s: mAidlInjectionSession == nullptr, the injection not supported ", __FUNCTION__);
        return INVALID_OPERATION;
   }

    return res;
}

status_t AidlCamera3Device::AidlHalInterface::processBatchCaptureRequests(
        std::vector<camera_capture_request_t*>& requests,/*out*/uint32_t* numRequestProcessed) {
    ATRACE_NAME("CameraHal::processBatchCaptureRequests");
    if (!valid()) return INVALID_OPERATION;

    std::vector<camera::device::CaptureRequest> captureRequests;
    size_t batchSize = requests.size();
    if (batchSize > INT_MAX) {
        ALOGE("%s batchSize %zu > INT_MAX, aidl interface cannot handle batch size", __FUNCTION__,
                  batchSize);
        return BAD_VALUE;
    }
    captureRequests.resize(batchSize);
    std::vector<native_handle_t*> handlesCreated;
    std::vector<std::pair<int32_t, int32_t>> inflightBuffers;

    status_t res = OK;
    for (size_t i = 0; i < batchSize; i++) {
       res = wrapAsAidlRequest(requests[i], /*out*/&captureRequests[i],
                    /*out*/&handlesCreated, /*out*/&inflightBuffers);

        if (res != OK) {
            mBufferRecords.popInflightBuffers(inflightBuffers);
            cleanupNativeHandles(&handlesCreated);
            return res;
        }
    }

    std::vector<camera::device::BufferCache> cachesToRemove;
    {
        std::lock_guard<std::mutex> lock(mFreedBuffersLock);
        for (auto& pair : mFreedBuffers) {
            // The stream might have been removed since onBufferFreed
            if (mBufferRecords.isStreamCached(pair.first)) {
                cachesToRemove.push_back({pair.first, static_cast<int64_t>(pair.second)});
            }
        }
        mFreedBuffers.clear();
    }

    *numRequestProcessed = 0;

    // Write metadata to FMQ.
    for (size_t i = 0; i < batchSize; i++) {
        camera_capture_request_t* request = requests[i];
        camera::device::CaptureRequest* captureRequest;
        captureRequest = &captureRequests[i];

        if (request->settings != nullptr) {
            size_t settingsSize = get_camera_metadata_size(request->settings);
            if (mRequestMetadataQueue != nullptr && mRequestMetadataQueue->write(
                    reinterpret_cast<const int8_t*>(request->settings), settingsSize)) {
                captureRequest->settings.metadata.resize(0);
                captureRequest->fmqSettingsSize = settingsSize;
            } else {
                if (mRequestMetadataQueue != nullptr) {
                    ALOGW("%s: couldn't utilize fmq, fallback to hwbinder", __FUNCTION__);
                }
                uint8_t *settingsP =
                        reinterpret_cast<uint8_t*>(
                                const_cast<camera_metadata_t*>(request->settings));
                size_t settingsSize =  get_camera_metadata_size(request->settings);
                captureRequest->settings.metadata.assign(settingsP, settingsP + settingsSize);
                captureRequest->fmqSettingsSize = 0u;
            }
        } else {
            // A null request settings maps to a size-0 CameraMetadata
            captureRequest->settings.metadata.resize(0);
            captureRequest->fmqSettingsSize = 0u;
        }

        captureRequest ->inputWidth = request->input_width;
        captureRequest->inputHeight = request->input_height;

        std::vector<camera::device::PhysicalCameraSetting>& physicalCameraSettings =
                captureRequest->physicalCameraSettings;
        physicalCameraSettings.resize(request->num_physcam_settings);
        for (size_t j = 0; j < request->num_physcam_settings; j++) {
            if (request->physcam_settings != nullptr) {
                size_t settingsSize = get_camera_metadata_size(request->physcam_settings[j]);
                if (mRequestMetadataQueue != nullptr && mRequestMetadataQueue->write(
                            reinterpret_cast<const int8_t*>(request->physcam_settings[j]),
                            settingsSize)) {
                    physicalCameraSettings[j].settings.metadata.resize(0);
                    physicalCameraSettings[j].fmqSettingsSize = settingsSize;
                } else {
                    if (mRequestMetadataQueue != nullptr) {
                        ALOGW("%s: couldn't utilize fmq, fallback to hwbinder", __FUNCTION__);
                    }
                    uint8_t *physicalSettingsP =
                            reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(
                                    request->physcam_settings[j]));
                    physicalCameraSettings[j].settings.metadata.assign(physicalSettingsP,
                            physicalSettingsP + settingsSize);
                    physicalCameraSettings[j].fmqSettingsSize = 0u;
                }
            } else {
                physicalCameraSettings[j].fmqSettingsSize = 0u;
                physicalCameraSettings[j].settings.metadata.resize(0);
            }
            physicalCameraSettings[j].physicalCameraId = request->physcam_id[j];
        }
    }

    int32_t numRequests = 0;
    auto retS = mAidlSession->processCaptureRequest(captureRequests, cachesToRemove,
            &numRequests);
    if (!retS.isOk()) {
        res = AidlProviderInfo::mapToStatusT(retS);
    }
    if (res == OK) {
        if (numRequests < 0) {
            res = INVALID_OPERATION;
        } else {
            *numRequestProcessed = static_cast<uint32_t>(numRequests);
        }

    }
    if (res == OK && *numRequestProcessed == batchSize) {
        if (mAidlSession->isRemote()) {
            // Only close acquire fence FDs when the AIDL transaction succeeds (so the FDs have been
            // sent to camera HAL processes)
            cleanupNativeHandles(&handlesCreated, /*closeFd*/true);
        } else {
            // In passthrough mode the FDs are now owned by HAL
            cleanupNativeHandles(&handlesCreated);
        }
    } else {
        ALOGE("%s Error with processCaptureRequest %s ", __FUNCTION__, retS.getMessage());
        mBufferRecords.popInflightBuffers(inflightBuffers);
        cleanupNativeHandles(&handlesCreated);
    }
    return res;
}

status_t AidlCamera3Device::AidlHalInterface::wrapAsAidlRequest(camera_capture_request_t* request,
        /*out*/camera::device::CaptureRequest* captureRequest,
        /*out*/std::vector<native_handle_t*>* handlesCreated,
        /*out*/std::vector<std::pair<int32_t, int32_t>>* inflightBuffers) {
    using camera::device::BufferStatus;
    using camera::device::StreamBuffer;
    ATRACE_CALL();
    if (captureRequest == nullptr || handlesCreated == nullptr || inflightBuffers == nullptr) {
        ALOGE("%s: captureRequest (%p), handlesCreated (%p), and inflightBuffers(%p) "
                "must not be null", __FUNCTION__, captureRequest, handlesCreated, inflightBuffers);
        return BAD_VALUE;
    }

    captureRequest->frameNumber = request->frame_number;

    captureRequest->fmqSettingsSize = 0;

    {
        if (request->input_buffer != nullptr) {
            int32_t streamId = Camera3Stream::cast(request->input_buffer->stream)->getId();
            buffer_handle_t buf = *(request->input_buffer->buffer);
            auto pair = getBufferId(buf, streamId);
            bool isNewBuffer = pair.first;
            uint64_t bufferId = pair.second;
            captureRequest->inputBuffer.streamId = streamId;
            captureRequest->inputBuffer.bufferId = bufferId;
            captureRequest->inputBuffer.buffer =
                    (isNewBuffer) ? camera3::dupToAidlIfNotNull(buf) :
                            aidl::android::hardware::common::NativeHandle();
            captureRequest->inputBuffer.status = BufferStatus::OK;
            native_handle_t *acquireFence = nullptr;
            if (request->input_buffer->acquire_fence != -1) {
                acquireFence = native_handle_create(1,0);
                acquireFence->data[0] = request->input_buffer->acquire_fence;
                handlesCreated->push_back(acquireFence);
            }
            // duping here is okay, in aidl ownership is not given to aidl_handle
            captureRequest->inputBuffer.acquireFence = camera3::dupToAidlIfNotNull(acquireFence);
            captureRequest->inputBuffer.releaseFence =
                    aidl::android::hardware::common::NativeHandle();

            mBufferRecords.pushInflightBuffer(captureRequest->frameNumber, streamId,
                    request->input_buffer->buffer);
            inflightBuffers->push_back(std::make_pair(captureRequest->frameNumber, streamId));
        } else {
            captureRequest->inputBuffer.streamId = -1;
            captureRequest->inputBuffer.bufferId = BUFFER_ID_NO_BUFFER;
        }

        captureRequest->outputBuffers.resize(request->num_output_buffers);
        for (size_t i = 0; i < request->num_output_buffers; i++) {
            const camera_stream_buffer_t *src = request->output_buffers + i;
            StreamBuffer &dst = captureRequest->outputBuffers[i];
            int32_t streamId = Camera3Stream::cast(src->stream)->getId();
            if (src->buffer != nullptr) {
                buffer_handle_t buf = *(src->buffer);
                auto pair = getBufferId(buf, streamId);
                bool isNewBuffer = pair.first;
                dst.bufferId = pair.second;
                dst.buffer = isNewBuffer ?
                        camera3::dupToAidlIfNotNull(buf) :
                                aidl::android::hardware::common::NativeHandle();
                native_handle_t *acquireFence = nullptr;
                if (src->acquire_fence != -1) {
                    acquireFence = native_handle_create(1,0);
                    acquireFence->data[0] = src->acquire_fence;
                    handlesCreated->push_back(acquireFence);
                }
                dst.acquireFence = camera3::dupToAidlIfNotNull(acquireFence);
            } else if (mUseHalBufManager) {
                // HAL buffer management path
                dst.bufferId = BUFFER_ID_NO_BUFFER;
                dst.buffer = aidl::android::hardware::common::NativeHandle();
                dst.acquireFence = aidl::android::hardware::common::NativeHandle();
            } else {
                ALOGE("%s: cannot send a null buffer in capture request!", __FUNCTION__);
                return BAD_VALUE;
            }
            dst.streamId = streamId;
            dst.status = BufferStatus::OK;
            dst.releaseFence = aidl::android::hardware::common::NativeHandle();

            // Output buffers are empty when using HAL buffer manager
            if (!mUseHalBufManager) {
                mBufferRecords.pushInflightBuffer(
                        captureRequest->frameNumber, streamId, src->buffer);
                inflightBuffers->push_back(std::make_pair(captureRequest->frameNumber, streamId));
            }
        }
    }
    return OK;
}

status_t AidlCamera3Device::AidlHalInterface::switchToOffline(
        const std::vector<int32_t>& streamsToKeep,
        /*out*/aidl::android::hardware::camera::device::CameraOfflineSessionInfo*
                offlineSessionInfo,
        /*out*/std::shared_ptr<aidl::android::hardware::camera::device::ICameraOfflineSession>*
                offlineSession,
        /*out*/camera3::BufferRecords* bufferRecords) {
    ATRACE_NAME("CameraHal::switchToOffline");
    if (!valid()) {
        ALOGE("%s called on invalid camera!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    if (offlineSessionInfo == nullptr || offlineSession == nullptr || bufferRecords == nullptr) {
        ALOGE("%s: output arguments must not be null!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    auto err = mAidlSession->switchToOffline(streamsToKeep, offlineSessionInfo, offlineSession);

    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.getMessage());
        return AidlProviderInfo::mapToStatusT(err);
    }

    return verifyBufferCaches(offlineSessionInfo, bufferRecords);
}

AidlCamera3Device::AidlRequestThread::AidlRequestThread(wp<Camera3Device> parent,
                sp<camera3::StatusTracker> statusTracker,
                sp<HalInterface> interface,
                const Vector<int32_t>& sessionParamKeys,
                bool useHalBufManager,
                bool supportCameraMute) :
          RequestThread(parent, statusTracker, interface, sessionParamKeys, useHalBufManager,
                  supportCameraMute) {}

status_t AidlCamera3Device::AidlRequestThread::switchToOffline(
        const std::vector<int32_t>& streamsToKeep,
        /*out*/camera::device::CameraOfflineSessionInfo* offlineSessionInfo,
        /*out*/std::shared_ptr<camera::device::ICameraOfflineSession>* offlineSession,
        /*out*/camera3::BufferRecords* bufferRecords) {
    Mutex::Autolock l(mRequestLock);
    clearRepeatingRequestsLocked(/*lastFrameNumber*/nullptr);

    // Wait until request thread is fully stopped
    // TBD: check if request thread is being paused by other APIs (shouldn't be)

    // We could also check for mRepeatingRequests.empty(), but the API interface
    // is serialized by Camera3Device::mInterfaceLock so no one should be able to submit any
    // new requests during the call; hence skip that check.
    bool queueEmpty = mNextRequests.empty() && mRequestQueue.empty();
    while (!queueEmpty) {
        status_t res = mRequestSubmittedSignal.waitRelative(mRequestLock, kRequestSubmitTimeout);
        if (res == TIMED_OUT) {
            ALOGE("%s: request thread failed to submit one request within timeout!", __FUNCTION__);
            return res;
        } else if (res != OK) {
            ALOGE("%s: request thread failed to submit a request: %s (%d)!",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
        queueEmpty = mNextRequests.empty() && mRequestQueue.empty();
    }
    return (static_cast<AidlHalInterface *>(mInterface.get()))->switchToOffline(
            streamsToKeep, offlineSessionInfo, offlineSession, bufferRecords);
}

status_t AidlCamera3Device::AidlCamera3DeviceInjectionMethods::injectionInitialize(
        const String8& injectedCamId, sp<CameraProviderManager> manager,
        const std::shared_ptr<camera::device::ICameraDeviceCallback>&callback) {
    ATRACE_CALL();
    Mutex::Autolock lock(mInjectionLock);

    if (manager == nullptr) {
        ALOGE("%s: manager does not exist!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    sp<Camera3Device> parent = mParent.promote();
    if (parent == nullptr) {
        ALOGE("%s: parent does not exist!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    if (parent->getTransportType() != IPCTransport::AIDL) {
        ALOGE("%s Parent transport not AIDL for injected camera id %s, aborting", __FUNCTION__,
                  injectedCamId.c_str());
        return INVALID_OPERATION;
    }
    mInjectedCamId = injectedCamId;
    std::shared_ptr<camera::device::ICameraInjectionSession> injectionSession;
    ATRACE_BEGIN("Injection CameraHal::openSession");
    status_t res = manager->openAidlInjectionSession(injectedCamId.string(), callback,
                                          /*out*/ &injectionSession);
    ATRACE_END();
    if (res != OK) {
        ALOGE("Injection camera could not open camera session: %s (%d)",
                strerror(-res), res);
        return res;
    }
    std::shared_ptr<camera::device::ICameraDeviceSession> deviceSession = nullptr;
    auto ret = injectionSession->getCameraDeviceSession(&deviceSession);
    if (!ret.isOk() || deviceSession == nullptr) {
        ALOGE("%s Camera injection session couldn't return ICameraDeviceSession", __FUNCTION__);
        return AidlProviderInfo::mapToStatusT(ret);
    }

    std::shared_ptr<AidlRequestMetadataQueue> queue;
    ::aidl::android::hardware::common::fmq::MQDescriptor<
            int8_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> desc;

    ::ndk::ScopedAStatus requestQueueRet = deviceSession->getCaptureRequestMetadataQueue(&desc);
    if (!requestQueueRet.isOk()) {
        ALOGE("Injection camera transaction error when getting result metadata queue from camera"
                " session: %s", requestQueueRet.getMessage());
        return AidlProviderInfo::mapToStatusT(requestQueueRet);
    }
    queue = std::make_unique<AidlRequestMetadataQueue>(desc);
    if (!queue->isValid() || queue->availableToWrite() <= 0) {
        ALOGE("HAL returns empty result metadata fmq, not use it");
        queue = nullptr;
        // Don't use resQueue onwards.
    }

    std::unique_ptr<AidlResultMetadataQueue>& resQueue = mInjectionResultMetadataQueue;
    ::aidl::android::hardware::common::fmq::MQDescriptor<
        int8_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite> resDesc;
    ::ndk::ScopedAStatus resultQueueRet = deviceSession->getCaptureResultMetadataQueue(&resDesc);
    if (!resultQueueRet.isOk()) {
        ALOGE("Transaction error when getting result metadata queue from camera session: %s",
                resultQueueRet.getMessage());
        return AidlProviderInfo::mapToStatusT(resultQueueRet);
    }
    resQueue = std::make_unique<AidlResultMetadataQueue>(resDesc);
    if (!resQueue->isValid() || resQueue->availableToWrite() <= 0) {
        ALOGE("HAL returns empty result metadata fmq, not use it");
        resQueue = nullptr;
        // Don't use resQueue onwards.
    }

    ALOGV("%s: Injection camera interface = new HalInterface()", __FUNCTION__);

    mInjectedCamHalInterface =
            new AidlHalInterface(deviceSession, injectionSession, queue, parent->mUseHalBufManager,
                       parent->mSupportOfflineProcessing);
    if (mInjectedCamHalInterface == nullptr) {
        ALOGE("%s: mInjectedCamHalInterface does not exist!", __FUNCTION__);
        return DEAD_OBJECT;
    }

    return OK;
}

status_t AidlCamera3Device::AidlCamera3DeviceInjectionMethods::replaceHalInterface(
        sp<HalInterface> newHalInterface, bool keepBackup) {
    Mutex::Autolock lock(mInjectionLock);
    if (newHalInterface.get() == nullptr) {
        ALOGE("%s: The newHalInterface does not exist, to stop replacing.",
                __FUNCTION__);
        return DEAD_OBJECT;
    }

    sp<Camera3Device> parent = mParent.promote();
    if (parent == nullptr) {
        ALOGE("%s: parent does not exist!", __FUNCTION__);
        return INVALID_OPERATION;
    }
    if (parent->getTransportType() != IPCTransport::AIDL ||
            newHalInterface->getTransportType() != IPCTransport::AIDL) {
        ALOGE("%s Parent transport not AIDL for replacing hal interface", __FUNCTION__);
        return INVALID_OPERATION;
    }

    AidlCamera3Device *aidlParent = static_cast<AidlCamera3Device *>(parent.get());
    if (keepBackup) {
        if (mBackupHalInterface == nullptr) {
            mBackupHalInterface = parent->mInterface;
        }
        if (mBackupResultMetadataQueue == nullptr) {
            mBackupResultMetadataQueue = std::move(aidlParent->mResultMetadataQueue);
            aidlParent->mResultMetadataQueue = std::move(mInjectionResultMetadataQueue);
        }
    } else {
        mBackupHalInterface = nullptr;
        aidlParent->mResultMetadataQueue = std::move(mBackupResultMetadataQueue);
        mBackupResultMetadataQueue = nullptr;
    }
    parent->mInterface = newHalInterface;
    return OK;
}

status_t AidlCamera3Device::injectionCameraInitialize(const String8 &injectedCamId,
            sp<CameraProviderManager> manager) {
        return (static_cast<AidlCamera3DeviceInjectionMethods *>
                    (mInjectionMethods.get()))->injectionInitialize(injectedCamId, manager,
                        std::shared_ptr<camera::device::ICameraDeviceCallback>(mCallbacks));
};

sp<Camera3Device::RequestThread> AidlCamera3Device::createNewRequestThread(
                wp<Camera3Device> parent, sp<camera3::StatusTracker> statusTracker,
                sp<Camera3Device::HalInterface> interface,
                const Vector<int32_t>& sessionParamKeys,
                bool useHalBufManager,
                bool supportCameraMute) {
    return new AidlRequestThread(parent, statusTracker, interface, sessionParamKeys,
            useHalBufManager, supportCameraMute);
};

sp<Camera3Device::Camera3DeviceInjectionMethods>
AidlCamera3Device::createCamera3DeviceInjectionMethods(wp<Camera3Device> parent) {
    return new AidlCamera3DeviceInjectionMethods(parent);
}

}; // namespace android
