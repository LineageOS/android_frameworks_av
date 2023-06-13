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

#define LOG_TAG "HidlCamera3-Device"
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

#include <android/hardware/camera/device/3.7/ICameraInjectionSession.h>
#include <android/hardware/camera2/ICameraDeviceUser.h>

#include "device3/hidl/HidlCamera3OutputUtils.h"
#include "device3/hidl/HidlCamera3OfflineSession.h"
#include "utils/SessionConfigurationUtilsHidl.h"
#include "utils/TraceHFR.h"

#include "../../common/hidl/HidlProviderInfo.h"
#include "HidlCamera3Device.h"

#include <algorithm>
#include <tuple>

using namespace android::camera3;
using namespace android::hardware::camera;
using namespace android::hardware::camera::device::V3_2;
using android::hardware::camera::metadata::V3_6::CameraMetadataEnumAndroidSensorPixelMode;

namespace android {

hardware::graphics::common::V1_0::PixelFormat HidlCamera3Device::mapToPixelFormat(
        int frameworkFormat) {
    return (hardware::graphics::common::V1_0::PixelFormat) frameworkFormat;
}

DataspaceFlags HidlCamera3Device::mapToHidlDataspace(
        android_dataspace dataSpace) {
    return dataSpace;
}

BufferUsageFlags HidlCamera3Device::mapToConsumerUsage(
        uint64_t usage) {
    return usage;
}

StreamRotation HidlCamera3Device::mapToStreamRotation(camera_stream_rotation_t rotation) {
    switch (rotation) {
        case CAMERA_STREAM_ROTATION_0:
            return StreamRotation::ROTATION_0;
        case CAMERA_STREAM_ROTATION_90:
            return StreamRotation::ROTATION_90;
        case CAMERA_STREAM_ROTATION_180:
            return StreamRotation::ROTATION_180;
        case CAMERA_STREAM_ROTATION_270:
            return StreamRotation::ROTATION_270;
    }
    ALOGE("%s: Unknown stream rotation %d", __FUNCTION__, rotation);
    return StreamRotation::ROTATION_0;
}

status_t HidlCamera3Device::mapToStreamConfigurationMode(
        camera_stream_configuration_mode_t operationMode, StreamConfigurationMode *mode) {
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

int HidlCamera3Device::mapToFrameworkFormat(
        hardware::graphics::common::V1_0::PixelFormat pixelFormat) {
    return static_cast<uint32_t>(pixelFormat);
}

android_dataspace HidlCamera3Device::mapToFrameworkDataspace(
        DataspaceFlags dataSpace) {
    return static_cast<android_dataspace>(dataSpace);
}

uint64_t HidlCamera3Device::mapConsumerToFrameworkUsage(
        BufferUsageFlags usage) {
    return usage;
}

uint64_t HidlCamera3Device::mapProducerToFrameworkUsage(
        BufferUsageFlags usage) {
    return usage;
}

status_t HidlCamera3Device::initialize(sp<CameraProviderManager> manager,
        const String8& monitorTags) {
    ATRACE_CALL();
    Mutex::Autolock il(mInterfaceLock);
    Mutex::Autolock l(mLock);

    ALOGV("%s: Initializing HIDL device for camera %s", __FUNCTION__, mId.string());
    if (mStatus != STATUS_UNINITIALIZED) {
        CLOGE("Already initialized!");
        return INVALID_OPERATION;
    }
    if (manager == nullptr) return INVALID_OPERATION;

    sp<ICameraDeviceSession> session;
    ATRACE_BEGIN("CameraHal::openSession");
    status_t res = manager->openHidlSession(mId.string(), this,
            /*out*/ &session);
    ATRACE_END();
    if (res != OK) {
        SET_ERR_L("Could not open camera session: %s (%d)", strerror(-res), res);
        return res;
    }

    res = manager->getCameraCharacteristics(mId.string(), mOverrideForPerfClass, &mDeviceInfo,
            /*overrideToPortrait*/false);
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
                    physicalId, /*overrideForPerfClass*/false, &mPhysicalDeviceInfoMap[physicalId],
                    /*overrideToPortrait*/false);
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

    std::shared_ptr<RequestMetadataQueue> queue;
    auto requestQueueRet = session->getCaptureRequestMetadataQueue(
        [&queue](const auto& descriptor) {
            queue = std::make_shared<RequestMetadataQueue>(descriptor);
            if (!queue->isValid() || queue->availableToWrite() <= 0) {
                ALOGE("HAL returns empty request metadata fmq, not use it");
                queue = nullptr;
                // don't use the queue onwards.
            }
        });
    if (!requestQueueRet.isOk()) {
        ALOGE("Transaction error when getting request metadata fmq: %s, not use it",
                requestQueueRet.description().c_str());
        return DEAD_OBJECT;
    }

    std::unique_ptr<ResultMetadataQueue>& resQueue = mResultMetadataQueue;
    auto resultQueueRet = session->getCaptureResultMetadataQueue(
        [&resQueue](const auto& descriptor) {
            resQueue = std::make_unique<ResultMetadataQueue>(descriptor);
            if (!resQueue->isValid() || resQueue->availableToWrite() <= 0) {
                ALOGE("HAL returns empty result metadata fmq, not use it");
                resQueue = nullptr;
                // Don't use the resQueue onwards.
            }
        });
    if (!resultQueueRet.isOk()) {
        ALOGE("Transaction error when getting result metadata queue from camera session: %s",
                resultQueueRet.description().c_str());
        return DEAD_OBJECT;
    }
    IF_ALOGV() {
        session->interfaceChain([](
            ::android::hardware::hidl_vec<::android::hardware::hidl_string> interfaceChain) {
                ALOGV("Session interface chain:");
                for (const auto& iface : interfaceChain) {
                    ALOGV("  %s", iface.c_str());
                }
            });
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

    mInterface = new HidlHalInterface(session, queue, mUseHalBufManager, mSupportOfflineProcessing);

    std::string providerType;
    mVendorTagId = manager->getProviderTagIdLocked(mId.string());
    mTagMonitor.initialize(mVendorTagId);
    if (!monitorTags.isEmpty()) {
        mTagMonitor.parseTagsToMonitor(String8(monitorTags));
    }

    // Metadata tags needs fixup for monochrome camera device version less
    // than 3.5.
    hardware::hidl_version maxVersion{0,0};
    IPCTransport transport = IPCTransport::HIDL;
    res = manager->getHighestSupportedVersion(mId.string(), &maxVersion, &transport);
    if (res != OK) {
        ALOGE("%s: Error in getting camera device version id: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }
    int deviceVersion = HARDWARE_DEVICE_API_VERSION(
            maxVersion.get_major(), maxVersion.get_minor());

    bool isMonochrome = false;
    for (size_t i = 0; i < capabilities.count; i++) {
        uint8_t capability = capabilities.data.u8[i];
        if (capability == ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MONOCHROME) {
            isMonochrome = true;
        }
    }
    mNeedFixupMonochromeTags = (isMonochrome && deviceVersion < CAMERA_DEVICE_API_VERSION_3_5);

    return initializeCommonLocked();
}

hardware::Return<void> HidlCamera3Device::requestStreamBuffers(
        const hardware::hidl_vec<hardware::camera::device::V3_5::BufferRequest>& bufReqs,
        requestStreamBuffers_cb _hidl_cb) {
    RequestBufferStates states {
        mId, mRequestBufferInterfaceLock, mUseHalBufManager, mOutputStreams, mSessionStatsBuilder,
        *this, *mInterface, *this};
    camera3::requestStreamBuffers(states, bufReqs, _hidl_cb);
    return hardware::Void();
}

hardware::Return<void> HidlCamera3Device::returnStreamBuffers(
        const hardware::hidl_vec<hardware::camera::device::V3_2::StreamBuffer>& buffers) {
    ReturnBufferStates states {
        mId, mUseHalBufManager, mOutputStreams, mSessionStatsBuilder, *mInterface};
    camera3::returnStreamBuffers(states, buffers);
    return hardware::Void();
}

hardware::Return<void> HidlCamera3Device::processCaptureResult_3_4(
        const hardware::hidl_vec<
                hardware::camera::device::V3_4::CaptureResult>& results) {
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
            return hardware::Void();
        }
    }
    HidlCaptureOutputStates states {
       {
        mId,
        mInFlightLock, mLastCompletedRegularFrameNumber,
        mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
        mInFlightMap, mOutputLock,  mResultQueue, mResultSignal,
        mNextShutterFrameNumber,
        mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
        mNextResultFrameNumber,
        mNextReprocessResultFrameNumber, mNextZslStillResultFrameNumber,
        mUseHalBufManager, mUsePartialResult, mNeedFixupMonochromeTags,
        mNumPartialResults, mVendorTagId, mDeviceInfo, mPhysicalDeviceInfoMap,
        mDistortionMappers, mZoomRatioMappers, mRotateAndCropMappers,
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this, *this,
        *mInterface, mLegacyClient, mMinExpectedDuration, mIsFixedFps, mOverrideToPortrait,
        mActivePhysicalId}, mResultMetadataQueue
    };

    //HidlCaptureOutputStates hidlStates {
    //}

    for (const auto& result : results) {
        processOneCaptureResultLocked(states, result.v3_2, result.physicalCameraMetadata);
    }
    mProcessCaptureResultLock.unlock();
    return hardware::Void();
}

// Only one processCaptureResult should be called at a time, so
// the locks won't block. The locks are present here simply to enforce this.
hardware::Return<void> HidlCamera3Device::processCaptureResult(
        const hardware::hidl_vec<
                hardware::camera::device::V3_2::CaptureResult>& results) {
    hardware::hidl_vec<hardware::camera::device::V3_4::PhysicalCameraMetadata> noPhysMetadata;

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
            return hardware::Void();
        }
    }

    HidlCaptureOutputStates states {
      {mId,
        mInFlightLock, mLastCompletedRegularFrameNumber,
        mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
        mInFlightMap, mOutputLock,  mResultQueue, mResultSignal,
        mNextShutterFrameNumber,
        mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
        mNextResultFrameNumber,
        mNextReprocessResultFrameNumber, mNextZslStillResultFrameNumber,
        mUseHalBufManager, mUsePartialResult, mNeedFixupMonochromeTags,
        mNumPartialResults, mVendorTagId, mDeviceInfo, mPhysicalDeviceInfoMap,
        mDistortionMappers, mZoomRatioMappers, mRotateAndCropMappers,
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this, *this,
        *mInterface, mLegacyClient, mMinExpectedDuration, mIsFixedFps, mOverrideToPortrait,
        mActivePhysicalId}, mResultMetadataQueue
    };

    for (const auto& result : results) {
        processOneCaptureResultLocked(states, result, noPhysMetadata);
    }
    mProcessCaptureResultLock.unlock();
    return hardware::Void();
}

hardware::Return<void> HidlCamera3Device::notify(
        const hardware::hidl_vec<hardware::camera::device::V3_2::NotifyMsg>& msgs) {
    return notifyHelper<hardware::camera::device::V3_2::NotifyMsg>(msgs);
}

template<typename NotifyMsgType>
hardware::Return<void> HidlCamera3Device::notifyHelper(
        const hardware::hidl_vec<NotifyMsgType>& msgs) {
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

    HidlCaptureOutputStates states {
      {mId,
        mInFlightLock, mLastCompletedRegularFrameNumber,
        mLastCompletedReprocessFrameNumber, mLastCompletedZslFrameNumber,
        mInFlightMap, mOutputLock,  mResultQueue, mResultSignal,
        mNextShutterFrameNumber,
        mNextReprocessShutterFrameNumber, mNextZslStillShutterFrameNumber,
        mNextResultFrameNumber,
        mNextReprocessResultFrameNumber, mNextZslStillResultFrameNumber,
        mUseHalBufManager, mUsePartialResult, mNeedFixupMonochromeTags,
        mNumPartialResults, mVendorTagId, mDeviceInfo, mPhysicalDeviceInfoMap,
        mDistortionMappers, mZoomRatioMappers, mRotateAndCropMappers,
        mTagMonitor, mInputStream, mOutputStreams, mSessionStatsBuilder, listener, *this, *this,
        *mInterface, mLegacyClient, mMinExpectedDuration, mIsFixedFps, mOverrideToPortrait,
        mActivePhysicalId}, mResultMetadataQueue
    };
    for (const auto& msg : msgs) {
        camera3::notify(states, msg);
    }
    return hardware::Void();
}

status_t HidlCamera3Device::switchToOffline(
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
    hardware::camera::device::V3_6::CameraOfflineSessionInfo offlineSessionInfo;
    sp<hardware::camera::device::V3_6::ICameraOfflineSession> offlineSession;
    camera3::BufferRecords bufferRecords;
    status_t ret = static_cast<HidlRequestThread *>(mRequestThread.get())->switchToOffline(
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
        if (stream->getOutstandingBuffersCount() != offlineStream.numOutstandingBuffers) {
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

    *session = new HidlCamera3OfflineSession(mId, inputStream, offlineStreamSet,
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

sp<Camera3Device::RequestThread> HidlCamera3Device::createNewRequestThread(
                wp<Camera3Device> parent, sp<camera3::StatusTracker> statusTracker,
                sp<Camera3Device::HalInterface> interface,
                const Vector<int32_t>& sessionParamKeys,
                bool useHalBufManager,
                bool supportCameraMute,
                bool overrideToPortrait) {
        return new HidlRequestThread(parent, statusTracker, interface, sessionParamKeys,
                useHalBufManager, supportCameraMute, overrideToPortrait);
};

sp<Camera3Device::Camera3DeviceInjectionMethods>
HidlCamera3Device::createCamera3DeviceInjectionMethods(wp<Camera3Device> parent) {
    return new HidlCamera3DeviceInjectionMethods(parent);
}

status_t HidlCamera3Device::injectionCameraInitialize(const String8 &injectedCamId,
            sp<CameraProviderManager> manager) {
        return (static_cast<HidlCamera3DeviceInjectionMethods *>(
                mInjectionMethods.get()))->injectionInitialize(injectedCamId, manager, this);
};


HidlCamera3Device::HidlHalInterface::HidlHalInterface(
            sp<device::V3_2::ICameraDeviceSession> &session,
            std::shared_ptr<RequestMetadataQueue> queue,
            bool useHalBufManager, bool supportOfflineProcessing) :
        HalInterface(useHalBufManager, supportOfflineProcessing),
        mHidlSession(session),
        mRequestMetadataQueue(queue) {
    // Check with hardware service manager if we can downcast these interfaces
    // Somewhat expensive, so cache the results at startup
    auto castResult_3_7 = device::V3_7::ICameraDeviceSession::castFrom(mHidlSession);
    if (castResult_3_7.isOk()) {
        mHidlSession_3_7 = castResult_3_7;
    }
    auto castResult_3_6 = device::V3_6::ICameraDeviceSession::castFrom(mHidlSession);
    if (castResult_3_6.isOk()) {
        mHidlSession_3_6 = castResult_3_6;
    }
    auto castResult_3_5 = device::V3_5::ICameraDeviceSession::castFrom(mHidlSession);
    if (castResult_3_5.isOk()) {
        mHidlSession_3_5 = castResult_3_5;
    }
    auto castResult_3_4 = device::V3_4::ICameraDeviceSession::castFrom(mHidlSession);
    if (castResult_3_4.isOk()) {
        mHidlSession_3_4 = castResult_3_4;
    }
    auto castResult_3_3 = device::V3_3::ICameraDeviceSession::castFrom(mHidlSession);
    if (castResult_3_3.isOk()) {
        mHidlSession_3_3 = castResult_3_3;
    }
}

bool HidlCamera3Device::HidlHalInterface::valid() {
    return (mHidlSession != nullptr);
}

void HidlCamera3Device::HidlHalInterface::clear() {
    mHidlSession_3_7.clear();
    mHidlSession_3_6.clear();
    mHidlSession_3_5.clear();
    mHidlSession_3_4.clear();
    mHidlSession_3_3.clear();
    mHidlSession.clear();
}

status_t HidlCamera3Device::HidlHalInterface::constructDefaultRequestSettings(
        camera_request_template_t templateId,
        /*out*/ camera_metadata_t **requestTemplate) {
    ATRACE_NAME("CameraHidlHal::constructDefaultRequestSettings");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    common::V1_0::Status status;

    auto requestCallback = [&status, &requestTemplate]
            (common::V1_0::Status s, const device::V3_2::CameraMetadata& request) {
            status = s;
            if (status == common::V1_0::Status::OK) {
                const camera_metadata *r =
                        reinterpret_cast<const camera_metadata_t*>(request.data());
                size_t expectedSize = request.size();
                int ret = validate_camera_metadata_structure(r, &expectedSize);
                if (ret == OK || ret == CAMERA_METADATA_VALIDATION_SHIFTED) {
                    *requestTemplate = clone_camera_metadata(r);
                    if (*requestTemplate == nullptr) {
                        ALOGE("%s: Unable to clone camera metadata received from HAL",
                                __FUNCTION__);
                        status = common::V1_0::Status::INTERNAL_ERROR;
                    }
                } else {
                    ALOGE("%s: Malformed camera metadata received from HAL", __FUNCTION__);
                    status = common::V1_0::Status::INTERNAL_ERROR;
                }
            }
        };
    hardware::Return<void> err;
    RequestTemplate id;
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
    err = mHidlSession->constructDefaultRequestSettings(id, requestCallback);

    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
        res = DEAD_OBJECT;
    } else {
        res = HidlProviderInfo::mapToStatusT(status);
    }

    return res;
}

bool HidlCamera3Device::HidlHalInterface::isReconfigurationRequired(
        CameraMetadata& oldSessionParams, CameraMetadata& newSessionParams) {
    // We do reconfiguration by default;
    bool ret = true;
    if ((mHidlSession_3_5 != nullptr) && mIsReconfigurationQuerySupported) {
        android::hardware::hidl_vec<uint8_t> oldParams, newParams;
        camera_metadata_t* oldSessioMeta = const_cast<camera_metadata_t*>(
                oldSessionParams.getAndLock());
        camera_metadata_t* newSessioMeta = const_cast<camera_metadata_t*>(
                newSessionParams.getAndLock());
        oldParams.setToExternal(reinterpret_cast<uint8_t*>(oldSessioMeta),
                get_camera_metadata_size(oldSessioMeta));
        newParams.setToExternal(reinterpret_cast<uint8_t*>(newSessioMeta),
                get_camera_metadata_size(newSessioMeta));
        hardware::camera::common::V1_0::Status callStatus;
        bool required;
        auto hidlCb = [&callStatus, &required] (hardware::camera::common::V1_0::Status s,
                bool requiredFlag) {
            callStatus = s;
            required = requiredFlag;
        };
        auto err = mHidlSession_3_5->isReconfigurationRequired(oldParams, newParams, hidlCb);
        oldSessionParams.unlock(oldSessioMeta);
        newSessionParams.unlock(newSessioMeta);
        if (err.isOk()) {
            switch (callStatus) {
                case hardware::camera::common::V1_0::Status::OK:
                    ret = required;
                    break;
                case hardware::camera::common::V1_0::Status::METHOD_NOT_SUPPORTED:
                    mIsReconfigurationQuerySupported = false;
                    ret = true;
                    break;
                default:
                    ALOGV("%s: Reconfiguration query failed: %d", __FUNCTION__, callStatus);
                    ret = true;
            }
        } else {
            ALOGE("%s: Unexpected binder error: %s", __FUNCTION__, err.description().c_str());
            ret = true;
        }
    }

    return ret;
}

status_t HidlCamera3Device::HidlHalInterface::configureStreams(
        const camera_metadata_t *sessionParams,
        camera_stream_configuration *config, const std::vector<uint32_t>& bufferSizes) {
    ATRACE_NAME("CameraHal::configureStreams");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    if (config->input_is_multi_resolution && mHidlSession_3_7 == nullptr) {
        ALOGE("%s: Camera device doesn't support multi-resolution input stream", __FUNCTION__);
        return BAD_VALUE;
    }

    // Convert stream config to HIDL
    std::set<int> activeStreams;
    device::V3_2::StreamConfiguration requestedConfiguration3_2;
    device::V3_4::StreamConfiguration requestedConfiguration3_4;
    device::V3_7::StreamConfiguration requestedConfiguration3_7;
    requestedConfiguration3_2.streams.resize(config->num_streams);
    requestedConfiguration3_4.streams.resize(config->num_streams);
    requestedConfiguration3_7.streams.resize(config->num_streams);
    for (size_t i = 0; i < config->num_streams; i++) {
        device::V3_2::Stream &dst3_2 = requestedConfiguration3_2.streams[i];
        device::V3_4::Stream &dst3_4 = requestedConfiguration3_4.streams[i];
        device::V3_7::Stream &dst3_7 = requestedConfiguration3_7.streams[i];
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
        dst3_2.id = streamId;
        dst3_2.streamType = streamType;
        dst3_2.width = src->width;
        dst3_2.height = src->height;
        dst3_2.usage = mapToConsumerUsage(cam3stream->getUsage());
        dst3_2.rotation = mapToStreamRotation((camera_stream_rotation_t) src->rotation);
        // For HidlSession version 3.5 or newer, the format and dataSpace sent
        // to HAL are original, not the overridden ones.
        if (mHidlSession_3_5 != nullptr) {
            dst3_2.format = mapToPixelFormat(cam3stream->isFormatOverridden() ?
                    cam3stream->getOriginalFormat() : src->format);
            dst3_2.dataSpace = mapToHidlDataspace(cam3stream->isDataSpaceOverridden() ?
                    cam3stream->getOriginalDataSpace() : src->data_space);
        } else {
            dst3_2.format = mapToPixelFormat(src->format);
            dst3_2.dataSpace = mapToHidlDataspace(src->data_space);
        }
        dst3_4.v3_2 = dst3_2;
        dst3_4.bufferSize = bufferSizes[i];
        if (src->physical_camera_id != nullptr) {
            dst3_4.physicalCameraId = src->physical_camera_id;
        }
        dst3_7.v3_4 = dst3_4;
        dst3_7.groupId = cam3stream->getHalStreamGroupId();
        dst3_7.sensorPixelModesUsed.resize(src->sensor_pixel_modes_used.size());
        size_t j = 0;
        for (int mode : src->sensor_pixel_modes_used) {
            dst3_7.sensorPixelModesUsed[j++] =
                    static_cast<CameraMetadataEnumAndroidSensorPixelMode>(mode);
        }
        if (src->dynamic_range_profile !=
                    ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD) {
            ALOGE("%s: Camera device doesn't support non-standard dynamic range profiles: %" PRIx64,
                    __FUNCTION__, src->dynamic_range_profile);
            return BAD_VALUE;
        }
        if (src->use_case != ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT) {
            ALOGE("%s: Camera device doesn't support non-default stream use case %" PRId64 "!",
                    __FUNCTION__, src->use_case);
            return BAD_VALUE;
        }
        activeStreams.insert(streamId);
        // Create Buffer ID map if necessary
        mBufferRecords.tryCreateBufferCache(streamId);
    }
    // remove BufferIdMap for deleted streams
    mBufferRecords.removeInactiveBufferCaches(activeStreams);

    StreamConfigurationMode operationMode;
    res = mapToStreamConfigurationMode(
            (camera_stream_configuration_mode_t) config->operation_mode,
            /*out*/ &operationMode);
    if (res != OK) {
        return res;
    }
    requestedConfiguration3_2.operationMode = operationMode;
    requestedConfiguration3_4.operationMode = operationMode;
    requestedConfiguration3_7.operationMode = operationMode;
    size_t sessionParamSize = get_camera_metadata_size(sessionParams);
    requestedConfiguration3_4.sessionParams.setToExternal(
            reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(sessionParams)),
            sessionParamSize);
    requestedConfiguration3_7.sessionParams.setToExternal(
            reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(sessionParams)),
            sessionParamSize);

    // Invoke configureStreams
    device::V3_3::HalStreamConfiguration finalConfiguration;
    device::V3_4::HalStreamConfiguration finalConfiguration3_4;
    device::V3_6::HalStreamConfiguration finalConfiguration3_6;
    common::V1_0::Status status;

    auto configStream34Cb = [&status, &finalConfiguration3_4]
            (common::V1_0::Status s, const device::V3_4::HalStreamConfiguration& halConfiguration) {
                finalConfiguration3_4 = halConfiguration;
                status = s;
            };

    auto configStream36Cb = [&status, &finalConfiguration3_6]
            (common::V1_0::Status s, const device::V3_6::HalStreamConfiguration& halConfiguration) {
                finalConfiguration3_6 = halConfiguration;
                status = s;
            };

    auto postprocConfigStream34 = [&finalConfiguration, &finalConfiguration3_4]
            (hardware::Return<void>& err) -> status_t {
                if (!err.isOk()) {
                    ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
                    return DEAD_OBJECT;
                }
                finalConfiguration.streams.resize(finalConfiguration3_4.streams.size());
                for (size_t i = 0; i < finalConfiguration3_4.streams.size(); i++) {
                    finalConfiguration.streams[i] = finalConfiguration3_4.streams[i].v3_3;
                }
                return OK;
            };

    auto postprocConfigStream36 = [&finalConfiguration, &finalConfiguration3_6]
            (hardware::Return<void>& err) -> status_t {
                if (!err.isOk()) {
                    ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
                    return DEAD_OBJECT;
                }
                finalConfiguration.streams.resize(finalConfiguration3_6.streams.size());
                for (size_t i = 0; i < finalConfiguration3_6.streams.size(); i++) {
                    finalConfiguration.streams[i] = finalConfiguration3_6.streams[i].v3_4.v3_3;
                }
                return OK;
            };

    if (mHidlSession_3_7 != nullptr) {
        ALOGV("%s: v3.7 device found", __FUNCTION__);
        requestedConfiguration3_7.streamConfigCounter = mNextStreamConfigCounter++;
        requestedConfiguration3_7.multiResolutionInputImage = config->input_is_multi_resolution;
        auto err = mHidlSession_3_7->configureStreams_3_7(
                requestedConfiguration3_7, configStream36Cb);
        res = postprocConfigStream36(err);
        if (res != OK) {
            return res;
        }
    } else if (mHidlSession_3_6 != nullptr) {
        ALOGV("%s: v3.6 device found", __FUNCTION__);
        device::V3_5::StreamConfiguration requestedConfiguration3_5;
        requestedConfiguration3_5.v3_4 = requestedConfiguration3_4;
        requestedConfiguration3_5.streamConfigCounter = mNextStreamConfigCounter++;
        auto err = mHidlSession_3_6->configureStreams_3_6(
                requestedConfiguration3_5, configStream36Cb);
        res = postprocConfigStream36(err);
        if (res != OK) {
            return res;
        }
    } else if (mHidlSession_3_5 != nullptr) {
        ALOGV("%s: v3.5 device found", __FUNCTION__);
        device::V3_5::StreamConfiguration requestedConfiguration3_5;
        requestedConfiguration3_5.v3_4 = requestedConfiguration3_4;
        requestedConfiguration3_5.streamConfigCounter = mNextStreamConfigCounter++;
        auto err = mHidlSession_3_5->configureStreams_3_5(
                requestedConfiguration3_5, configStream34Cb);
        res = postprocConfigStream34(err);
        if (res != OK) {
            return res;
        }
    } else if (mHidlSession_3_4 != nullptr) {
        // We do; use v3.4 for the call
        ALOGV("%s: v3.4 device found", __FUNCTION__);
        auto err = mHidlSession_3_4->configureStreams_3_4(
                requestedConfiguration3_4, configStream34Cb);
        res = postprocConfigStream34(err);
        if (res != OK) {
            return res;
        }
    } else if (mHidlSession_3_3 != nullptr) {
        // We do; use v3.3 for the call
        ALOGV("%s: v3.3 device found", __FUNCTION__);
        auto err = mHidlSession_3_3->configureStreams_3_3(requestedConfiguration3_2,
            [&status, &finalConfiguration]
            (common::V1_0::Status s, const device::V3_3::HalStreamConfiguration& halConfiguration) {
                finalConfiguration = halConfiguration;
                status = s;
            });
        if (!err.isOk()) {
            ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
            return DEAD_OBJECT;
        }
    } else {
        // We don't; use v3.2 call and construct a v3.3 HalStreamConfiguration
        ALOGV("%s: v3.2 device found", __FUNCTION__);
        HalStreamConfiguration finalConfiguration_3_2;
        auto err = mHidlSession->configureStreams(requestedConfiguration3_2,
                [&status, &finalConfiguration_3_2]
                (common::V1_0::Status s, const HalStreamConfiguration& halConfiguration) {
                    finalConfiguration_3_2 = halConfiguration;
                    status = s;
                });
        if (!err.isOk()) {
            ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
            return DEAD_OBJECT;
        }
        finalConfiguration.streams.resize(finalConfiguration_3_2.streams.size());
        for (size_t i = 0; i < finalConfiguration_3_2.streams.size(); i++) {
            finalConfiguration.streams[i].v3_2 = finalConfiguration_3_2.streams[i];
            finalConfiguration.streams[i].overrideDataSpace =
                    requestedConfiguration3_2.streams[i].dataSpace;
        }
    }

    if (status != common::V1_0::Status::OK ) {
        return HidlProviderInfo::mapToStatusT(status);
    }

    // And convert output stream configuration from HIDL

    for (size_t i = 0; i < config->num_streams; i++) {
        camera3::camera_stream_t *dst = config->streams[i];
        int streamId = Camera3Stream::cast(dst)->getId();

        // Start scan at i, with the assumption that the stream order matches
        size_t realIdx = i;
        bool found = false;
        size_t halStreamCount = finalConfiguration.streams.size();
        for (size_t idx = 0; idx < halStreamCount; idx++) {
            if (finalConfiguration.streams[realIdx].v3_2.id == streamId) {
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
        device::V3_3::HalStream &src = finalConfiguration.streams[realIdx];
        device::V3_6::HalStream &src_36 = finalConfiguration3_6.streams[realIdx];

        Camera3Stream* dstStream = Camera3Stream::cast(dst);
        int overrideFormat = mapToFrameworkFormat(src.v3_2.overrideFormat);
        android_dataspace overrideDataSpace = mapToFrameworkDataspace(src.overrideDataSpace);

        if (mHidlSession_3_6 != nullptr) {
            dstStream->setOfflineProcessingSupport(src_36.supportOffline);
        }

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
                    requestedConfiguration3_2.streams[i].format != src.v3_2.overrideFormat;
            bool needDataspaceOverride =
                    requestedConfiguration3_2.streams[i].dataSpace != src.overrideDataSpace;
            // Override allowed with IMPLEMENTATION_DEFINED
            dstStream->setFormatOverride(needFormatOverride);
            dstStream->setDataSpaceOverride(needDataspaceOverride);
            dst->format = overrideFormat;
            dst->data_space = overrideDataSpace;
        }

        if (dst->stream_type == CAMERA_STREAM_INPUT) {
            if (src.v3_2.producerUsage != 0) {
                ALOGE("%s: Stream %d: INPUT streams must have 0 for producer usage",
                        __FUNCTION__, streamId);
                return INVALID_OPERATION;
            }
            dstStream->setUsage(
                    mapConsumerToFrameworkUsage(src.v3_2.consumerUsage));
        } else {
            // OUTPUT
            if (src.v3_2.consumerUsage != 0) {
                ALOGE("%s: Stream %d: OUTPUT streams must have 0 for consumer usage",
                        __FUNCTION__, streamId);
                return INVALID_OPERATION;
            }
            dstStream->setUsage(
                    mapProducerToFrameworkUsage(src.v3_2.producerUsage));
        }
        dst->max_buffers = src.v3_2.maxBuffers;
    }

    return res;
}

status_t HidlCamera3Device::HidlHalInterface::configureInjectedStreams(
        const camera_metadata_t* sessionParams, camera_stream_configuration* config,
        const std::vector<uint32_t>& bufferSizes,
        const CameraMetadata& cameraCharacteristics) {
    ATRACE_NAME("InjectionCameraHal::configureStreams");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    if (config->input_is_multi_resolution) {
        ALOGE("%s: Injection camera device doesn't support multi-resolution input "
                "stream", __FUNCTION__);
        return BAD_VALUE;
    }

    // Convert stream config to HIDL
    std::set<int> activeStreams;
    device::V3_2::StreamConfiguration requestedConfiguration3_2;
    device::V3_4::StreamConfiguration requestedConfiguration3_4;
    device::V3_7::StreamConfiguration requestedConfiguration3_7;
    requestedConfiguration3_2.streams.resize(config->num_streams);
    requestedConfiguration3_4.streams.resize(config->num_streams);
    requestedConfiguration3_7.streams.resize(config->num_streams);
    for (size_t i = 0; i < config->num_streams; i++) {
        device::V3_2::Stream& dst3_2 = requestedConfiguration3_2.streams[i];
        device::V3_4::Stream& dst3_4 = requestedConfiguration3_4.streams[i];
        device::V3_7::Stream& dst3_7 = requestedConfiguration3_7.streams[i];
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
        dst3_2.id = streamId;
        dst3_2.streamType = streamType;
        dst3_2.width = src->width;
        dst3_2.height = src->height;
        dst3_2.usage = mapToConsumerUsage(cam3stream->getUsage());
        dst3_2.rotation =
                mapToStreamRotation((camera_stream_rotation_t)src->rotation);
        // For HidlSession version 3.5 or newer, the format and dataSpace sent
        // to HAL are original, not the overridden ones.
        if (mHidlSession_3_5 != nullptr) {
            dst3_2.format = mapToPixelFormat(cam3stream->isFormatOverridden()
                                            ? cam3stream->getOriginalFormat()
                                            : src->format);
            dst3_2.dataSpace =
                    mapToHidlDataspace(cam3stream->isDataSpaceOverridden()
                                    ? cam3stream->getOriginalDataSpace()
                                    : src->data_space);
        } else {
            dst3_2.format = mapToPixelFormat(src->format);
            dst3_2.dataSpace = mapToHidlDataspace(src->data_space);
        }
        dst3_4.v3_2 = dst3_2;
        dst3_4.bufferSize = bufferSizes[i];
        if (src->physical_camera_id != nullptr) {
            dst3_4.physicalCameraId = src->physical_camera_id;
        }
        dst3_7.v3_4 = dst3_4;
        dst3_7.groupId = cam3stream->getHalStreamGroupId();
        dst3_7.sensorPixelModesUsed.resize(src->sensor_pixel_modes_used.size());
        size_t j = 0;
        for (int mode : src->sensor_pixel_modes_used) {
            dst3_7.sensorPixelModesUsed[j++] =
                    static_cast<CameraMetadataEnumAndroidSensorPixelMode>(mode);
        }
        activeStreams.insert(streamId);
        // Create Buffer ID map if necessary
        mBufferRecords.tryCreateBufferCache(streamId);
    }
    // remove BufferIdMap for deleted streams
    mBufferRecords.removeInactiveBufferCaches(activeStreams);

    StreamConfigurationMode operationMode;
    res = mapToStreamConfigurationMode(
            (camera_stream_configuration_mode_t)config->operation_mode,
            /*out*/ &operationMode);
    if (res != OK) {
        return res;
    }
    requestedConfiguration3_7.operationMode = operationMode;
    size_t sessionParamSize = get_camera_metadata_size(sessionParams);
    requestedConfiguration3_7.operationMode = operationMode;
    requestedConfiguration3_7.sessionParams.setToExternal(
            reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(sessionParams)),
            sessionParamSize);

    // See which version of HAL we have
    if (mHidlSession_3_7 != nullptr) {
        requestedConfiguration3_7.streamConfigCounter = mNextStreamConfigCounter++;
        requestedConfiguration3_7.multiResolutionInputImage =
                config->input_is_multi_resolution;

        const camera_metadata_t* rawMetadata = cameraCharacteristics.getAndLock();
        ::android::hardware::camera::device::V3_2::CameraMetadata hidlChars = {};
        hidlChars.setToExternal(
                reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(rawMetadata)),
                get_camera_metadata_size(rawMetadata));
        cameraCharacteristics.unlock(rawMetadata);

        sp<hardware::camera::device::V3_7::ICameraInjectionSession>
                hidlInjectionSession_3_7;
        auto castInjectionResult_3_7 =
                device::V3_7::ICameraInjectionSession::castFrom(mHidlSession_3_7);
        if (castInjectionResult_3_7.isOk()) {
            hidlInjectionSession_3_7 = castInjectionResult_3_7;
        } else {
            ALOGE("%s: Transaction error: %s", __FUNCTION__,
                    castInjectionResult_3_7.description().c_str());
            return DEAD_OBJECT;
        }

        auto err = hidlInjectionSession_3_7->configureInjectionStreams(
                requestedConfiguration3_7, hidlChars);
        if (!err.isOk()) {
            ALOGE("%s: Transaction error: %s", __FUNCTION__,
                    err.description().c_str());
            return DEAD_OBJECT;
        }
    } else {
        ALOGE("%s: mHidlSession_3_7 does not exist, the lowest version of injection "
                "session is 3.7", __FUNCTION__);
        return DEAD_OBJECT;
    }

    return res;
}

status_t HidlCamera3Device::HidlHalInterface::wrapAsHidlRequest(camera_capture_request_t* request,
        /*out*/device::V3_2::CaptureRequest* captureRequest,
        /*out*/std::vector<native_handle_t*>* handlesCreated,
        /*out*/std::vector<std::pair<int32_t, int32_t>>* inflightBuffers) {
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
            captureRequest->inputBuffer.buffer = (isNewBuffer) ? buf : nullptr;
            captureRequest->inputBuffer.status = BufferStatus::OK;
            native_handle_t *acquireFence = nullptr;
            if (request->input_buffer->acquire_fence != -1) {
                acquireFence = native_handle_create(1,0);
                acquireFence->data[0] = request->input_buffer->acquire_fence;
                handlesCreated->push_back(acquireFence);
            }
            captureRequest->inputBuffer.acquireFence = acquireFence;
            captureRequest->inputBuffer.releaseFence = nullptr;

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
                dst.buffer = isNewBuffer ? buf : nullptr;
                native_handle_t *acquireFence = nullptr;
                if (src->acquire_fence != -1) {
                    acquireFence = native_handle_create(1,0);
                    acquireFence->data[0] = src->acquire_fence;
                    handlesCreated->push_back(acquireFence);
                }
                dst.acquireFence = acquireFence;
            } else if (mUseHalBufManager) {
                // HAL buffer management path
                dst.bufferId = BUFFER_ID_NO_BUFFER;
                dst.buffer = nullptr;
                dst.acquireFence = nullptr;
            } else {
                ALOGE("%s: cannot send a null buffer in capture request!", __FUNCTION__);
                return BAD_VALUE;
            }
            dst.streamId = streamId;
            dst.status = BufferStatus::OK;
            dst.releaseFence = nullptr;

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

status_t HidlCamera3Device::HidlHalInterface::flush() {
    ATRACE_NAME("CameraHal::flush");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    auto err = mHidlSession->flush();
    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
        res = DEAD_OBJECT;
    } else {
        res = HidlProviderInfo::mapToStatusT(err);
    }

    return res;
}

status_t HidlCamera3Device::HidlHalInterface::dump(int /*fd*/) {
    ATRACE_NAME("CameraHal::dump");
    if (!valid()) return INVALID_OPERATION;

    // Handled by CameraProviderManager::dump

    return OK;
}

status_t HidlCamera3Device::HidlHalInterface::repeatingRequestEnd(uint32_t /*frameNumber*/,
        const std::vector<int32_t> &/*streamIds*/) {
    ATRACE_NAME("CameraHal::repeatingRequestEnd");
    return INVALID_OPERATION;
}

status_t HidlCamera3Device::HidlHalInterface::close() {
    ATRACE_NAME("CameraHal::close()");
    if (!valid()) return INVALID_OPERATION;
    status_t res = OK;

    auto err = mHidlSession->close();
    // Interface will be dead shortly anyway, so don't log errors
    if (!err.isOk()) {
        res = DEAD_OBJECT;
    }

    return res;
}

void HidlCamera3Device::HidlHalInterface::signalPipelineDrain(const std::vector<int>& streamIds) {
    ATRACE_NAME("CameraHal::signalPipelineDrain");
    if (!valid() || mHidlSession_3_5 == nullptr) {
        ALOGE("%s called on invalid camera!", __FUNCTION__);
        return;
    }

    auto err = mHidlSession_3_5->signalStreamFlush(streamIds, mNextStreamConfigCounter - 1);
    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
        return;
    }
}

status_t HidlCamera3Device::HidlHalInterface::processBatchCaptureRequests(
        std::vector<camera_capture_request_t*>& requests,/*out*/uint32_t* numRequestProcessed) {
    ATRACE_NAME("CameraHal::processBatchCaptureRequests");
    if (!valid()) return INVALID_OPERATION;

    sp<device::V3_4::ICameraDeviceSession> hidlSession_3_4;
    sp<device::V3_7::ICameraDeviceSession> hidlSession_3_7;
    auto castResult_3_7 = device::V3_7::ICameraDeviceSession::castFrom(mHidlSession);
    if (castResult_3_7.isOk()) {
        hidlSession_3_7 = castResult_3_7;
    }
    auto castResult_3_4 = device::V3_4::ICameraDeviceSession::castFrom(mHidlSession);
    if (castResult_3_4.isOk()) {
        hidlSession_3_4 = castResult_3_4;
    }

    hardware::hidl_vec<device::V3_2::CaptureRequest> captureRequests;
    hardware::hidl_vec<device::V3_4::CaptureRequest> captureRequests_3_4;
    hardware::hidl_vec<device::V3_7::CaptureRequest> captureRequests_3_7;
    size_t batchSize = requests.size();
    if (hidlSession_3_7 != nullptr) {
        captureRequests_3_7.resize(batchSize);
    } else if (hidlSession_3_4 != nullptr) {
        captureRequests_3_4.resize(batchSize);
    } else {
        captureRequests.resize(batchSize);
    }
    std::vector<native_handle_t*> handlesCreated;
    std::vector<std::pair<int32_t, int32_t>> inflightBuffers;

    status_t res = OK;
    for (size_t i = 0; i < batchSize; i++) {
        if (hidlSession_3_7 != nullptr) {
            res = wrapAsHidlRequest(requests[i], /*out*/&captureRequests_3_7[i].v3_4.v3_2,
                    /*out*/&handlesCreated, /*out*/&inflightBuffers);
        } else if (hidlSession_3_4 != nullptr) {
            res = wrapAsHidlRequest(requests[i], /*out*/&captureRequests_3_4[i].v3_2,
                    /*out*/&handlesCreated, /*out*/&inflightBuffers);
        } else {
            res = wrapAsHidlRequest(requests[i], /*out*/&captureRequests[i],
                    /*out*/&handlesCreated, /*out*/&inflightBuffers);
        }
        if (res != OK) {
            mBufferRecords.popInflightBuffers(inflightBuffers);
            cleanupNativeHandles(&handlesCreated);
            return res;
        }
    }

    std::vector<device::V3_2::BufferCache> cachesToRemove;
    {
        std::lock_guard<std::mutex> lock(mFreedBuffersLock);
        for (auto& pair : mFreedBuffers) {
            // The stream might have been removed since onBufferFreed
            if (mBufferRecords.isStreamCached(pair.first)) {
                cachesToRemove.push_back({pair.first, pair.second});
            }
        }
        mFreedBuffers.clear();
    }

    common::V1_0::Status status = common::V1_0::Status::INTERNAL_ERROR;
    *numRequestProcessed = 0;

    // Write metadata to FMQ.
    for (size_t i = 0; i < batchSize; i++) {
        camera_capture_request_t* request = requests[i];
        device::V3_2::CaptureRequest* captureRequest;
        if (hidlSession_3_7 != nullptr) {
            captureRequest = &captureRequests_3_7[i].v3_4.v3_2;
        } else if (hidlSession_3_4 != nullptr) {
            captureRequest = &captureRequests_3_4[i].v3_2;
        } else {
            captureRequest = &captureRequests[i];
        }

        if (request->settings != nullptr) {
            size_t settingsSize = get_camera_metadata_size(request->settings);
            if (mRequestMetadataQueue != nullptr && mRequestMetadataQueue->write(
                    reinterpret_cast<const uint8_t*>(request->settings), settingsSize)) {
                captureRequest->settings.resize(0);
                captureRequest->fmqSettingsSize = settingsSize;
            } else {
                if (mRequestMetadataQueue != nullptr) {
                    ALOGW("%s: couldn't utilize fmq, fallback to hwbinder", __FUNCTION__);
                }
                captureRequest->settings.setToExternal(
                        reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(
                                request->settings)),
                        get_camera_metadata_size(request->settings));
                captureRequest->fmqSettingsSize = 0u;
            }
        } else {
            // A null request settings maps to a size-0 CameraMetadata
            captureRequest->settings.resize(0);
            captureRequest->fmqSettingsSize = 0u;
        }

        // hidl session 3.7 specific handling.
        if (hidlSession_3_7 != nullptr) {
            captureRequests_3_7[i].inputWidth = request->input_width;
            captureRequests_3_7[i].inputHeight = request->input_height;
        }

        // hidl session 3.7 and 3.4 specific handling.
        if (hidlSession_3_7 != nullptr || hidlSession_3_4 != nullptr) {
            hardware::hidl_vec<device::V3_4::PhysicalCameraSetting>& physicalCameraSettings =
                    (hidlSession_3_7 != nullptr) ?
                    captureRequests_3_7[i].v3_4.physicalCameraSettings :
                    captureRequests_3_4[i].physicalCameraSettings;
            physicalCameraSettings.resize(request->num_physcam_settings);
            for (size_t j = 0; j < request->num_physcam_settings; j++) {
                if (request->physcam_settings != nullptr) {
                    size_t settingsSize = get_camera_metadata_size(request->physcam_settings[j]);
                    if (mRequestMetadataQueue != nullptr && mRequestMetadataQueue->write(
                                reinterpret_cast<const uint8_t*>(request->physcam_settings[j]),
                                settingsSize)) {
                        physicalCameraSettings[j].settings.resize(0);
                        physicalCameraSettings[j].fmqSettingsSize = settingsSize;
                    } else {
                        if (mRequestMetadataQueue != nullptr) {
                            ALOGW("%s: couldn't utilize fmq, fallback to hwbinder", __FUNCTION__);
                        }
                        physicalCameraSettings[j].settings.setToExternal(
                                reinterpret_cast<uint8_t*>(const_cast<camera_metadata_t*>(
                                        request->physcam_settings[j])),
                                get_camera_metadata_size(request->physcam_settings[j]));
                        physicalCameraSettings[j].fmqSettingsSize = 0u;
                    }
                } else {
                    physicalCameraSettings[j].fmqSettingsSize = 0u;
                    physicalCameraSettings[j].settings.resize(0);
                }
                physicalCameraSettings[j].physicalCameraId = request->physcam_id[j];
            }
        }
    }

    hardware::details::return_status err;
    auto resultCallback =
        [&status, &numRequestProcessed] (auto s, uint32_t n) {
                status = s;
                *numRequestProcessed = n;
        };
    if (hidlSession_3_7 != nullptr) {
        err = hidlSession_3_7->processCaptureRequest_3_7(captureRequests_3_7, cachesToRemove,
                                                         resultCallback);
    } else if (hidlSession_3_4 != nullptr) {
        err = hidlSession_3_4->processCaptureRequest_3_4(captureRequests_3_4, cachesToRemove,
                                                         resultCallback);
    } else {
        err = mHidlSession->processCaptureRequest(captureRequests, cachesToRemove,
                                                  resultCallback);
    }
    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
        status = common::V1_0::Status::CAMERA_DISCONNECTED;
    }

    if (status == common::V1_0::Status::OK && *numRequestProcessed != batchSize) {
        ALOGE("%s: processCaptureRequest returns OK but processed %d/%zu requests",
                __FUNCTION__, *numRequestProcessed, batchSize);
        status = common::V1_0::Status::INTERNAL_ERROR;
    }

    res = HidlProviderInfo::mapToStatusT(status);
    if (res == OK) {
        if (mHidlSession->isRemote()) {
            // Only close acquire fence FDs when the HIDL transaction succeeds (so the FDs have been
            // sent to camera HAL processes)
            cleanupNativeHandles(&handlesCreated, /*closeFd*/true);
        } else {
            // In passthrough mode the FDs are now owned by HAL
            cleanupNativeHandles(&handlesCreated);
        }
    } else {
        mBufferRecords.popInflightBuffers(inflightBuffers);
        cleanupNativeHandles(&handlesCreated);
    }
    return res;
}

status_t HidlCamera3Device::HidlHalInterface::switchToOffline(
        const std::vector<int32_t>& streamsToKeep,
        /*out*/hardware::camera::device::V3_6::CameraOfflineSessionInfo* offlineSessionInfo,
        /*out*/sp<hardware::camera::device::V3_6::ICameraOfflineSession>* offlineSession,
        /*out*/camera3::BufferRecords* bufferRecords) {
    ATRACE_NAME("CameraHal::switchToOffline");
    if (!valid() || mHidlSession_3_6 == nullptr) {
        ALOGE("%s called on invalid camera!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    if (offlineSessionInfo == nullptr || offlineSession == nullptr || bufferRecords == nullptr) {
        ALOGE("%s: output arguments must not be null!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    common::V1_0::Status status = common::V1_0::Status::INTERNAL_ERROR;
    auto resultCallback =
        [&status, &offlineSessionInfo, &offlineSession] (auto s, auto info, auto session) {
                status = s;
                *offlineSessionInfo = info;
                *offlineSession = session;
        };
    auto err = mHidlSession_3_6->switchToOffline(streamsToKeep, resultCallback);

    if (!err.isOk()) {
        ALOGE("%s: Transaction error: %s", __FUNCTION__, err.description().c_str());
        return DEAD_OBJECT;
    }

    status_t ret = HidlProviderInfo::mapToStatusT(status);
    if (ret != OK) {
        return ret;
    }

    return verifyBufferCaches(offlineSessionInfo, bufferRecords);
}

HidlCamera3Device::HidlRequestThread::HidlRequestThread(wp<Camera3Device> parent,
                sp<camera3::StatusTracker> statusTracker,
                sp<HalInterface> interface,
                const Vector<int32_t>& sessionParamKeys,
                bool useHalBufManager,
                bool supportCameraMute,
                bool overrideToPortrait) :
          RequestThread(parent, statusTracker, interface, sessionParamKeys, useHalBufManager,
                  supportCameraMute, overrideToPortrait) {}

status_t HidlCamera3Device::HidlRequestThread::switchToOffline(
        const std::vector<int32_t>& streamsToKeep,
        /*out*/hardware::camera::device::V3_6::CameraOfflineSessionInfo* offlineSessionInfo,
        /*out*/sp<hardware::camera::device::V3_6::ICameraOfflineSession>* offlineSession,
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
    return (static_cast<HidlHalInterface *>(mInterface.get()))->switchToOffline(
            streamsToKeep, offlineSessionInfo, offlineSession, bufferRecords);
}

status_t HidlCamera3Device::HidlCamera3DeviceInjectionMethods::injectionInitialize(
        const String8& injectedCamId, sp<CameraProviderManager> manager,
        const sp<android::hardware::camera::device::V3_2::ICameraDeviceCallback>&
                callback) {
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

    mInjectedCamId = injectedCamId;
    sp<ICameraDeviceSession> session;
    ATRACE_BEGIN("Injection CameraHal::openSession");
    status_t res = manager->openHidlSession(injectedCamId.string(), callback,
                                          /*out*/ &session);
    ATRACE_END();
    if (res != OK) {
        ALOGE("Injection camera could not open camera session: %s (%d)",
                strerror(-res), res);
        return res;
    }

    std::shared_ptr<RequestMetadataQueue> queue;
    auto requestQueueRet =
        session->getCaptureRequestMetadataQueue([&queue](const auto& descriptor) {
            queue = std::make_shared<RequestMetadataQueue>(descriptor);
            if (!queue->isValid() || queue->availableToWrite() <= 0) {
                ALOGE("Injection camera HAL returns empty request metadata fmq, not "
                        "use it");
                queue = nullptr;
                // don't use the queue onwards.
            }
        });
    if (!requestQueueRet.isOk()) {
        ALOGE("Injection camera transaction error when getting request metadata fmq: "
                "%s, not use it", requestQueueRet.description().c_str());
        return DEAD_OBJECT;
    }

    std::unique_ptr<ResultMetadataQueue>& resQueue = mInjectionResultMetadataQueue;
    auto resultQueueRet = session->getCaptureResultMetadataQueue(
        [&resQueue](const auto& descriptor) {
            resQueue = std::make_unique<ResultMetadataQueue>(descriptor);
            if (!resQueue->isValid() || resQueue->availableToWrite() <= 0) {
                ALOGE("Injection camera HAL returns empty result metadata fmq, not use "
                        "it");
                resQueue = nullptr;
                // Don't use the resQueue onwards.
            }
        });
    if (!resultQueueRet.isOk()) {
        ALOGE("Injection camera transaction error when getting result metadata queue "
                "from camera session: %s", resultQueueRet.description().c_str());
        return DEAD_OBJECT;
    }
    IF_ALOGV() {
        session->interfaceChain(
                [](::android::hardware::hidl_vec<::android::hardware::hidl_string>
                        interfaceChain) {
                        ALOGV("Injection camera session interface chain:");
                        for (const auto& iface : interfaceChain) {
                            ALOGV("  %s", iface.c_str());
                        }
                });
    }

    ALOGV("%s: Injection camera interface = new HalInterface()", __FUNCTION__);

    mInjectedCamHalInterface =
            new HidlHalInterface(session, queue, parent->mUseHalBufManager,
                       parent->mSupportOfflineProcessing);
    if (mInjectedCamHalInterface == nullptr) {
        ALOGE("%s: mInjectedCamHalInterface does not exist!", __FUNCTION__);
        return DEAD_OBJECT;
    }

    return OK;
}

status_t HidlCamera3Device::HidlCamera3DeviceInjectionMethods::replaceHalInterface(
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
    if (newHalInterface->getTransportType() != IPCTransport::HIDL) {
        ALOGE("%s Replacing HIDL HalInterface with another transport unsupported", __FUNCTION__);
        return INVALID_OPERATION;
    }

    HidlCamera3Device *hidlParent = static_cast<HidlCamera3Device *>(parent.get());
    if (keepBackup) {
        if (mBackupHalInterface == nullptr) {
            mBackupHalInterface = parent->mInterface;
        }
        if (mBackupResultMetadataQueue == nullptr) {
            mBackupResultMetadataQueue = std::move(hidlParent->mResultMetadataQueue);
            hidlParent->mResultMetadataQueue = std::move(mInjectionResultMetadataQueue);
        }
    } else {
        mBackupHalInterface = nullptr;
        hidlParent->mResultMetadataQueue = std::move(mBackupResultMetadataQueue);
        mBackupResultMetadataQueue = nullptr;
    }
    parent->mInterface = newHalInterface;

    return OK;
}

}; // namespace android
