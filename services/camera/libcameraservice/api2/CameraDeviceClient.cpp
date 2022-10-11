/*
 * Copyright (C) 2013-2018 The Android Open Source Project
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

#include "system/camera_metadata.h"
#define LOG_TAG "CameraDeviceClient"
#define ATRACE_TAG ATRACE_TAG_CAMERA
#ifdef LOG_NNDEBUG
#define ALOGVV(...) ALOGV(__VA_ARGS__)
#else
#define ALOGVV(...) ((void)0)
#endif
//#define LOG_NDEBUG 0

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/content/res/CameraCompatibilityInfo.h>
#include <camera/CameraUtils.h>
#include <camera/StringUtils.h>
#include <camera/camera2/CaptureRequest.h>
#include <com_android_internal_camera_flags.h>
#include <cutils/properties.h>
#include <gui/Surface.h>
#include <utils/Log.h>
#include <utils/SessionConfigurationUtils.h>
#include <utils/Trace.h>

#include "common/CameraDeviceBase.h"
#include "device3/Camera3Device.h"
#include "device3/Camera3OutputStream.h"
#include "api2/CameraDeviceClient.h"

#include <camera_metadata_hidden.h>

#include "DepthCompositeStream.h"
#include "HeicCompositeStream.h"
#include "JpegRCompositeStream.h"
#include "utils/Utils.h"

// Convenience methods for constructing binder::Status objects for error returns
#define STATUS_ERROR(errorCode, errorString) \
    binder::Status::fromServiceSpecificError(errorCode, \
            fmt::sprintf("%s:%d: %s", __FUNCTION__, __LINE__, errorString).c_str())

#define STATUS_ERROR_FMT(errorCode, errorString, ...) \
    binder::Status::fromServiceSpecificError(errorCode, \
            fmt::sprintf("%s:%d: " errorString, __FUNCTION__, __LINE__, \
                    __VA_ARGS__).c_str())

namespace android {
using namespace camera2;
using namespace camera3;
using camera3::camera_stream_rotation_t::CAMERA_STREAM_ROTATION_0;
using hardware::camera2::ICameraDeviceUser::NO_IN_FLIGHT_REPEATING_FRAMES;

namespace flags = com::android::internal::camera::flags;

CameraDeviceClientBase::CameraDeviceClientBase(
        const sp<CameraService>& cameraService,
        const sp<hardware::camera2::ICameraDeviceCallbacks>& remoteCallback,
        std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
        const AttributionSourceState& clientAttribution, int callingPid, bool systemNativeClient,
        const std::string& cameraId, [[maybe_unused]] int api1CameraId, int cameraFacing,
        int sensorOrientation, int servicePid, const CameraCompatibilityInfo& compatInfo,
        bool sharedMode)
    : BasicClient(cameraService, IInterface::asBinder(remoteCallback),
                  attributionAndPermissionUtils, clientAttribution, callingPid, systemNativeClient,
                  cameraId, cameraFacing, sensorOrientation, servicePid, compatInfo,
                  sharedMode),
      mRemoteCallback(remoteCallback) {}

// Interface used by CameraService

CameraDeviceClient::CameraDeviceClient(
        const sp<CameraService>& cameraService,
        const sp<hardware::camera2::ICameraDeviceCallbacks>& remoteCallback,
        std::shared_ptr<CameraServiceProxyWrapper> cameraServiceProxyWrapper,
        std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
        const AttributionSourceState& clientAttribution, int callingPid, bool systemNativeClient,
        const std::string& cameraId, int cameraFacing, int sensorOrientation, int servicePid,
        bool overrideForPerfClass, const CameraCompatibilityInfo& compatInfo,
        const std::string& originalCameraId, bool sharedMode, bool isVendorClient)
    : Camera2ClientBase(cameraService, remoteCallback, cameraServiceProxyWrapper,
                        attributionAndPermissionUtils, clientAttribution, callingPid,
                        systemNativeClient, cameraId, /*API1 camera ID*/ -1, cameraFacing,
                        sensorOrientation, servicePid, overrideForPerfClass, compatInfo,
                        sharedMode, isVendorClient),
      mInputStream(),
      mStreamingRequestId(REQUEST_ID_NONE),
      mStreamingRequestLastFrameNumber(NO_IN_FLIGHT_REPEATING_FRAMES),
      mRequestIdCounter(0),
      mPrivilegedClient(false),
      mOverrideForPerfClass(overrideForPerfClass),
      mOriginalCameraId(originalCameraId),
      mIsVendorClient(isVendorClient) {

    std::vector<std::string> privilegedClientList = android::base::Split(
            android::base::GetProperty("persist.vendor.camera.privapp.list", ""), ",");
    auto it = std::find(privilegedClientList.begin(), privilegedClientList.end(),
            getPackageName());
    mPrivilegedClient = it != privilegedClientList.end();

    ATRACE_CALL();
    ALOGV("CameraDeviceClient %s: Opened", cameraId.c_str());
}

status_t CameraDeviceClient::initialize(sp<CameraProviderManager> manager,
        const std::string& monitorTags) {
    return initializeImpl(manager, monitorTags);
}

template<typename TProviderPtr>
status_t CameraDeviceClient::initializeImpl(TProviderPtr providerPtr,
        const std::string& monitorTags) {
    ATRACE_CALL();
    status_t res;

    res = Camera2ClientBase::initialize(providerPtr, monitorTags);
    if (res != OK) {
        return res;
    }

    if (mSharedMode) {
        // In shared camera device mode, there can be more than one clients and
        // frame processor thread is started by shared camera device.
        mFrameProcessor = mDevice->getSharedFrameProcessor();
        if (mFrameProcessor == nullptr) {
            ALOGE("%s: Unable to start frame processor thread", __FUNCTION__);
            return UNKNOWN_ERROR;
        }
    } else {
        mFrameProcessor = new FrameProcessorBase(mDevice);
        std::string threadName = std::string("CDU-") + mCameraIdStr + "-FrameProc";
        res = mFrameProcessor->run(threadName.c_str());
        if (res != OK) {
            ALOGE("%s: Unable to start frame processor thread: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    mFrameProcessor->registerListener(camera2::FrameProcessorBase::FRAME_PROCESSOR_LISTENER_MIN_ID,
                                      camera2::FrameProcessorBase::FRAME_PROCESSOR_LISTENER_MAX_ID,
                                      /*listener*/this,
                                      /*sendPartials*/true);

    const CameraMetadata &deviceInfo = mDevice->info();
    camera_metadata_ro_entry_t physicalKeysEntry = deviceInfo.find(
            ANDROID_REQUEST_AVAILABLE_PHYSICAL_CAMERA_REQUEST_KEYS);
    if (physicalKeysEntry.count > 0) {
        mSupportedPhysicalRequestKeys.insert(mSupportedPhysicalRequestKeys.begin(),
                physicalKeysEntry.data.i32,
                physicalKeysEntry.data.i32 + physicalKeysEntry.count);
    }

    auto entry = deviceInfo.find(ANDROID_REQUEST_AVAILABLE_CAPABILITIES);
    mDynamicProfileMap.emplace(
            ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD,
            ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD);
    if (entry.count > 0) {
        const auto it = std::find(entry.data.u8, entry.data.u8 + entry.count,
                ANDROID_REQUEST_AVAILABLE_CAPABILITIES_DYNAMIC_RANGE_TEN_BIT);
        if (it != entry.data.u8 + entry.count) {
            entry = deviceInfo.find(ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP);
            if (entry.count > 0 || ((entry.count % 3) != 0)) {
                int64_t standardBitmap =
                        ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD;
                for (size_t i = 0; i < entry.count; i += 3) {
                    if (entry.data.i64[i] !=
                            ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD) {
                        mDynamicProfileMap.emplace(entry.data.i64[i], entry.data.i64[i+1]);
                        if ((entry.data.i64[i+1] == 0) || (entry.data.i64[i+1] &
                                ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD)) {
                            standardBitmap |= entry.data.i64[i];
                        }
                    } else {
                        ALOGE("%s: Device %s includes unexpected profile entry: 0x%" PRIx64 "!",
                                __FUNCTION__, mCameraIdStr.c_str(), entry.data.i64[i]);
                    }
                }
                mDynamicProfileMap[ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD] =
                        standardBitmap;
            } else {
                ALOGE("%s: Device %s supports 10-bit output but doesn't include a dynamic range"
                        " profile map!", __FUNCTION__, mCameraIdStr.c_str());
            }
        }
    }

    mProviderManager = providerPtr;
    // Cache physical camera ids corresponding to this device and also the high
    // resolution sensors in this device + physical camera ids
    mProviderManager->isLogicalCamera(mCameraIdStr, &mPhysicalCameraIds);
    if (supportsUltraHighResolutionCapture(mCameraIdStr)) {
        mHighResolutionSensors.insert(mCameraIdStr);
    }
    for (auto &physicalId : mPhysicalCameraIds) {
        if (supportsUltraHighResolutionCapture(physicalId)) {
            mHighResolutionSensors.insert(physicalId);
        }
    }
    size_t fmqHalSize = mDevice->getCaptureResultFMQSize();
    size_t resultMQSize =
            property_get_int32(FMQ_SIZE_PROP.c_str(), /*default*/0);
    resultMQSize = resultMQSize > 0 ? resultMQSize : fmqHalSize;
    res = CreateMetadataQueue(&mResultMetadataQueue, resultMQSize);
    if (res != OK) {
        ALOGE("%s: Creating result metadata queue failed: %s(%d)", __FUNCTION__,
            strerror(-res), res);
        return res;
    }
    mDevice->setPrivilegedClient(mPrivilegedClient);
    return OK;
}

CameraDeviceClient::~CameraDeviceClient() {
}

binder::Status CameraDeviceClient::submitRequest(
        const hardware::camera2::CaptureRequest& request,
        bool streaming,
        /*out*/
        hardware::camera2::utils::SubmitInfo *submitInfo) {
    std::vector<hardware::camera2::CaptureRequest> requestList = { request };
    return submitRequestList(requestList, streaming, submitInfo);
}

status_t CameraDeviceClient::getSurfaceKey(ParcelableSurfaceType surface, SurfaceKey* out) const {
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
    auto ret = surface.getUniqueId(out);
    if (ret != OK) {
        ALOGE("%s: Camera %s: Could not getUniqueId.", __FUNCTION__, mCameraIdStr.c_str());
        return ret;
    }
    return OK;
#else
    *out = IInterface::asBinder(surface);
    return OK;
#endif
}

status_t CameraDeviceClient::getSurfaceKey(sp<Surface> surface, SurfaceKey* out) const {
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
    auto ret = surface->getUniqueId(out);
    if (ret != OK) {
        ALOGE("%s: Camera %s: Could not getUniqueId.", __FUNCTION__, mCameraIdStr.c_str());
        return ret;
    }
    return OK;
#else
    *out = IInterface::asBinder(surface->getIGraphicBufferProducer());
    return OK;
#endif
}

binder::Status CameraDeviceClient::insertSurfaceLocked(const ParcelableSurfaceType& surface,
        SurfaceMap* outSurfaceMap, Vector<int32_t>* outputStreamIds, int32_t *currentStreamId) {
    int compositeIdx;
    SurfaceKey surfaceKey;
    status_t ret = getSurfaceKey(surface, &surfaceKey);
    if(ret != OK) {
        ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__, mCameraIdStr.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, "Could not get the SurfaceKey");
    }
    int idx = mStreamMap.indexOfKey(surfaceKey);

    Mutex::Autolock l(mCompositeLock);
    // Trying to submit request with surface that wasn't created
    if (idx == NAME_NOT_FOUND) {
        ALOGE("%s: Camera %s: Tried to submit a request with a surface that"
                " we have not called createStream on",
                __FUNCTION__, mCameraIdStr.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Request targets Surface that is not part of current capture session");
    } else if ((compositeIdx = mCompositeStreamMap.indexOfKey(surfaceKey))
            != NAME_NOT_FOUND) {
        mCompositeStreamMap.valueAt(compositeIdx)->insertGbp(outSurfaceMap, outputStreamIds,
                currentStreamId);
        return binder::Status::ok();
    }

    const StreamSurfaceId& streamSurfaceId = mStreamMap.valueAt(idx);
    if (outSurfaceMap->find(streamSurfaceId.streamId()) == outSurfaceMap->end()) {
        outputStreamIds->push_back(streamSurfaceId.streamId());
    }
    (*outSurfaceMap)[streamSurfaceId.streamId()].push_back(streamSurfaceId.surfaceId());

    ALOGV("%s: Camera %s: Appending output stream %d surface %d to request",
            __FUNCTION__, mCameraIdStr.c_str(), streamSurfaceId.streamId(),
            streamSurfaceId.surfaceId());

    if (currentStreamId != nullptr) {
        *currentStreamId = streamSurfaceId.streamId();
    }

    return binder::Status::ok();
}

static std::list<int> getIntersection(const std::unordered_set<int> &streamIdsForThisCamera,
        const Vector<int> &streamIdsForThisRequest) {
    std::list<int> intersection;
    for (auto &streamId : streamIdsForThisRequest) {
        if (streamIdsForThisCamera.find(streamId) != streamIdsForThisCamera.end()) {
            intersection.emplace_back(streamId);
        }
    }
    return intersection;
}

binder::Status CameraDeviceClient::startStreaming(const std::vector<int>& streamIds,
            const std::vector<int>& surfaceIds,
            /*out*/
            hardware::camera2::utils::SubmitInfo *submitInfo) {
    ATRACE_CALL();
    ALOGV("%s-start of function. Stream list size %zu. Surface list size %zu", __FUNCTION__,
            streamIds.size(), surfaceIds.size());

    binder::Status res = binder::Status::ok();
    status_t err;
    if ( !(res = checkPidStatus(__FUNCTION__) ).isOk()) {
        return res;
    }

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    if (!mSharedMode) {
        ALOGE("%s: Camera %s: Invalid operation.", __FUNCTION__, mCameraIdStr.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, "Invalid operation");
    }

    if (streamIds.empty() || surfaceIds.empty()) {
        ALOGE("%s: Camera %s: Sent empty streamIds or surface Ids. Rejecting request.",
              __FUNCTION__, mCameraIdStr.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, "Empty Stream or surface Ids");
    }

    if (streamIds.size() != surfaceIds.size()) {
        ALOGE("%s: Camera %s: Sent different size array for stream and surface Ids.",
              __FUNCTION__, mCameraIdStr.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Stream and surface Ids are not of same size");
    }

    submitInfo->mRequestId = mRequestIdCounter;
    SurfaceMap surfaceMap;
    Vector<int32_t> outputStreamIds;
    for (size_t i = 0; i < streamIds.size(); i++) {
        int streamId = streamIds[i];
        int surfaceIdx = surfaceIds[i];

        ssize_t index = mConfiguredOutputs.indexOfKey(streamId);
        if (index < 0) {
            ALOGE("%s: Camera %s: Tried to start streaming with a surface that"
                    " we have not called createStream on: stream %d",
                    __FUNCTION__, mCameraIdStr.c_str(), streamId);
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "Start streaming targets Surface that is not part of current capture session");
        }

        const auto& surfaces = mConfiguredOutputs.valueAt(index).getSurfaces();
        if ((size_t)surfaceIdx >= surfaces.size()) {
            ALOGE("%s: Camera %s: Tried to start streaming with a surface that"
                    " we have not called createStream on: stream %d, surfaceIdx %d",
                     __FUNCTION__, mCameraIdStr.c_str(), streamId, surfaceIdx);
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "Start streaming targets Surface has invalid surface index");
        }

        res = insertSurfaceLocked(surfaces[surfaceIdx], &surfaceMap, &outputStreamIds, nullptr);

        if (!res.isOk()) {
            return res;
        }
    }

    mRequestIdCounter++;
    int sharedReqID;

    err = mDevice->startStreaming(submitInfo->mRequestId, surfaceMap, &sharedReqID,
            &(submitInfo->mLastFrameNumber));
    if (err != OK) {
        std::string msg = fmt::sprintf(
            "Camera %s:  Got error %s (%d) after trying to start streaming request",
            mCameraIdStr.c_str(), strerror(-err), err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    } else {
        Mutex::Autolock idLock(mStreamingRequestIdLock);
        mStreamingRequestId = submitInfo->mRequestId;
        mSharedStreamingRequest = {sharedReqID, submitInfo->mRequestId};
    }

    markClientActive();
    ALOGV("%s: Camera %s: End of function", __FUNCTION__, mCameraIdStr.c_str());
    return binder::Status::ok();
}

binder::Status CameraDeviceClient::submitRequestList(
        const std::vector<hardware::camera2::CaptureRequest>& requests,
        bool streaming,
        /*out*/
        hardware::camera2::utils::SubmitInfo *submitInfo) {
    ATRACE_CALL();
    ALOGV("%s-start of function. Request list size %zu", __FUNCTION__, requests.size());

    binder::Status res = binder::Status::ok();
    status_t err;
    if ( !(res = checkPidStatus(__FUNCTION__) ).isOk()) {
        return res;
    }

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    if (requests.empty()) {
        ALOGE("%s: Camera %s: Sent null request. Rejecting request.",
              __FUNCTION__, mCameraIdStr.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, "Empty request list");
    }

    if (mSharedMode && !mIsPrimaryClient) {
        ALOGE("%s: Camera %s: This client is not a primary client of the shared camera device.",
              __FUNCTION__, mCameraIdStr.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, "Invalid Operation.");
    }

    List<const CameraDeviceBase::PhysicalCameraSettingsList> metadataRequestList;
    std::list<SurfaceMap> surfaceMapList;
    submitInfo->mRequestId = mRequestIdCounter;
    uint32_t loopCounter = 0;

    for (auto&& request: requests) {
        if (request.mIsReprocess) {
            if (!mInputStream.configured) {
                ALOGE("%s: Camera %s: no input stream is configured.", __FUNCTION__,
                        mCameraIdStr.c_str());
                return STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "No input configured for camera %s but request is for reprocessing",
                        mCameraIdStr.c_str());
            } else if (streaming) {
                ALOGE("%s: Camera %s: streaming reprocess requests not supported.", __FUNCTION__,
                        mCameraIdStr.c_str());
                return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "Repeating reprocess requests not supported");
            } else if (request.mPhysicalCameraSettings.size() > 1) {
                ALOGE("%s: Camera %s: reprocess requests not supported for "
                        "multiple physical cameras.", __FUNCTION__,
                        mCameraIdStr.c_str());
                return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "Reprocess requests not supported for multiple cameras");
            }
        }

        if (request.mPhysicalCameraSettings.empty()) {
            ALOGE("%s: Camera %s: request doesn't contain any settings.", __FUNCTION__,
                    mCameraIdStr.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "Request doesn't contain any settings");
        }

        //The first capture settings should always match the logical camera id
        const std::string &logicalId = request.mPhysicalCameraSettings.begin()->id;
        if (mDevice->getId() != logicalId && mOriginalCameraId != logicalId) {
            ALOGE("%s: Camera %s: Invalid camera request settings.", __FUNCTION__,
                    mCameraIdStr.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "Invalid camera request settings");
        }

        if (request.mSurfaceList.isEmpty() && request.mStreamIdxList.size() == 0) {
            ALOGE("%s: Camera %s: Requests must have at least one surface target. "
                    "Rejecting request.", __FUNCTION__, mCameraIdStr.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "Request has no output targets");
        }

        /**
         * Write in the output stream IDs and map from stream ID to surface ID
         * which we calculate from the capture request's list of surface target
         */
        SurfaceMap surfaceMap;
        Vector<int32_t> outputStreamIds;
        std::vector<std::string> requestedPhysicalIds;
        uint64_t dynamicProfileBitmap = 0;
        if (request.mSurfaceList.size() > 0) {
            for (const sp<Surface>& surface : request.mSurfaceList) {
                if (surface == 0) continue;

                int32_t streamId;
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
                ParcelableSurfaceType surface_type = view::Surface::fromSurface(surface);
#else
                ParcelableSurfaceType surface_type = surface->getIGraphicBufferProducer();
#endif
                res = insertSurfaceLocked(surface_type, &surfaceMap, &outputStreamIds, &streamId);
                if (!res.isOk()) {
                    return res;
                }

                ssize_t index = mConfiguredOutputs.indexOfKey(streamId);
                if (index >= 0) {
                    const std::string &requestedPhysicalId =
                            mConfiguredOutputs.valueAt(index).getPhysicalCameraId();
                    requestedPhysicalIds.push_back(requestedPhysicalId);
                    dynamicProfileBitmap |=
                            mConfiguredOutputs.valueAt(index).getDynamicRangeProfile();
                } else {
                    ALOGW("%s: Output stream Id not found among configured outputs!", __FUNCTION__);
                }
            }
        } else {
            for (size_t i = 0; i < request.mStreamIdxList.size(); i++) {
                int streamId = request.mStreamIdxList.itemAt(i);
                int surfaceIdx = request.mSurfaceIdxList.itemAt(i);

                ssize_t index = mConfiguredOutputs.indexOfKey(streamId);
                if (index < 0) {
                    ALOGE("%s: Camera %s: Tried to submit a request with a surface that"
                            " we have not called createStream on: stream %d",
                            __FUNCTION__, mCameraIdStr.c_str(), streamId);
                    return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                            "Request targets Surface that is not part of current capture session");
                }

                const auto& surfaces = mConfiguredOutputs.valueAt(index).getSurfaces();
                if ((size_t)surfaceIdx >= surfaces.size()) {
                    ALOGE("%s: Camera %s: Tried to submit a request with a surface that"
                            " we have not called createStream on: stream %d, surfaceIdx %d",
                            __FUNCTION__, mCameraIdStr.c_str(), streamId, surfaceIdx);
                    return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                            "Request targets Surface has invalid surface index");
                }

                res = insertSurfaceLocked(surfaces[surfaceIdx], &surfaceMap, &outputStreamIds,
                                          nullptr);

                if (!res.isOk()) {
                    return res;
                }

                const std::string &requestedPhysicalId =
                        mConfiguredOutputs.valueAt(index).getPhysicalCameraId();
                requestedPhysicalIds.push_back(requestedPhysicalId);
                dynamicProfileBitmap |=
                        mConfiguredOutputs.valueAt(index).getDynamicRangeProfile();
            }
        }

        if (dynamicProfileBitmap !=
                    ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD) {

            auto currentMax = ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_MAX;
            if (flags::new_dynamic_range_profiles()) {
                if ((dynamicProfileBitmap & currentMax) != 0) {
                    ALOGE("%s: Camera %s: Tried to submit a request with a surface that"
                          " includes the unsupported PUBLIC_MAX dynamic range profile"
                          " 0x%" PRIx64 "!",
                          __FUNCTION__, mCameraIdStr.c_str(), dynamicProfileBitmap);
                    return STATUS_ERROR(
                            CameraService::ERROR_ILLEGAL_ARGUMENT,
                            "Request targets the unsupported PUBLIC_MAX dynamic range profile");
                }
                currentMax = ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_MAX_312;
            }
            for (uint64_t i = ANDROID_REQUEST_AVAILABLE_DYNAMIC_RANGE_PROFILES_MAP_STANDARD;
                    i < currentMax; i <<= 1) {
                if ((dynamicProfileBitmap & i) == 0) {
                    continue;
                }

                const auto& it = mDynamicProfileMap.find(i);
                if (it != mDynamicProfileMap.end()) {
                    if ((it->second == 0) ||
                            ((it->second & dynamicProfileBitmap) == dynamicProfileBitmap)) {
                        continue;
                    } else {
                        ALOGE("%s: Camera %s: Tried to submit a request with a surfaces that"
                                " reference an unsupported dynamic range profile combination"
                                " 0x%" PRIx64 "!", __FUNCTION__, mCameraIdStr.c_str(),
                                dynamicProfileBitmap);
                        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                                "Request targets an unsupported dynamic range profile"
                                " combination");
                    }
                } else {
                    ALOGE("%s: Camera %s: Tried to submit a request with a surface that"
                            " references unsupported dynamic range profile 0x%" PRIx64 "!",
                            __FUNCTION__, mCameraIdStr.c_str(), i);
                    return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                            "Request targets 10-bit Surface with unsupported dynamic range"
                            " profile");
                }
            }
        }

        CameraDeviceBase::PhysicalCameraSettingsList physicalSettingsList;
        for (const auto& it : request.mPhysicalCameraSettings) {
            const std::string resolvedId = (mOriginalCameraId == it.id) ? mDevice->getId() : it.id;
            if (it.settings.isEmpty()) {
                ALOGE("%s: Camera %s: Sent empty metadata packet. Rejecting request.",
                        __FUNCTION__, mCameraIdStr.c_str());
                return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "Request settings are empty");
            }

            // Check whether the physical / logical stream has settings
            // consistent with the sensor pixel mode(s) it was configured with.
            // mCameraIdToStreamSet will only have ids that are high resolution
            const auto streamIdSetIt = mHighResolutionCameraIdToStreamIdSet.find(resolvedId);
            if (streamIdSetIt != mHighResolutionCameraIdToStreamIdSet.end()) {
                std::list<int> streamIdsUsedInRequest = getIntersection(streamIdSetIt->second,
                        outputStreamIds);
                if (!request.mIsReprocess &&
                        !isSensorPixelModeConsistent(streamIdsUsedInRequest, it.settings)) {
                     ALOGE("%s: Camera %s: Request settings CONTROL_SENSOR_PIXEL_MODE not "
                            "consistent with configured streams. Rejecting request.",
                            __FUNCTION__, resolvedId.c_str());
                    return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "Request settings CONTROL_SENSOR_PIXEL_MODE are not consistent with "
                        "streams configured");
                }
            }

            const std::string &physicalId = resolvedId;
            bool hasTestPatternModePhysicalKey = std::find(mSupportedPhysicalRequestKeys.begin(),
                    mSupportedPhysicalRequestKeys.end(), ANDROID_SENSOR_TEST_PATTERN_MODE) !=
                    mSupportedPhysicalRequestKeys.end();
            bool hasTestPatternDataPhysicalKey = std::find(mSupportedPhysicalRequestKeys.begin(),
                    mSupportedPhysicalRequestKeys.end(), ANDROID_SENSOR_TEST_PATTERN_DATA) !=
                    mSupportedPhysicalRequestKeys.end();
            if (physicalId != mDevice->getId()) {
                auto found = std::find(requestedPhysicalIds.begin(), requestedPhysicalIds.end(),
                        resolvedId);
                if (found == requestedPhysicalIds.end()) {
                    ALOGE("%s: Camera %s: Physical camera id: %s not part of attached outputs.",
                            __FUNCTION__, mCameraIdStr.c_str(), physicalId.c_str());
                    return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                            "Invalid physical camera id");
                }

                if (!mSupportedPhysicalRequestKeys.empty()) {
                    // Filter out any unsupported physical request keys.
                    CameraMetadata filteredParams(mSupportedPhysicalRequestKeys.size());
                    camera_metadata_t *meta = const_cast<camera_metadata_t *>(
                            filteredParams.getAndLock());
                    set_camera_metadata_vendor_id(meta, mDevice->getVendorTagId());
                    filteredParams.unlock(meta);

                    for (const auto& keyIt : mSupportedPhysicalRequestKeys) {
                        camera_metadata_ro_entry entry = it.settings.find(keyIt);
                        if (entry.count > 0) {
                            filteredParams.update(entry);
                        }
                    }

                    physicalSettingsList.push_back({resolvedId, filteredParams,
                            hasTestPatternModePhysicalKey, hasTestPatternDataPhysicalKey});
                }
            } else {
                physicalSettingsList.push_back({resolvedId, it.settings});
            }
        }

        if (!enforceRequestPermissions(physicalSettingsList.begin()->metadata)) {
            // Callee logs
            return STATUS_ERROR(CameraService::ERROR_PERMISSION_DENIED,
                    "Caller does not have permission to change restricted controls");
        }

        physicalSettingsList.begin()->metadata.update(ANDROID_REQUEST_OUTPUT_STREAMS,
                &outputStreamIds[0], outputStreamIds.size());

        if (request.mIsReprocess) {
            physicalSettingsList.begin()->metadata.update(ANDROID_REQUEST_INPUT_STREAMS,
                    &mInputStream.id, 1);
        }

        physicalSettingsList.begin()->metadata.update(ANDROID_REQUEST_ID,
                &(submitInfo->mRequestId), /*size*/1);
        loopCounter++; // loopCounter starts from 1
        ALOGV("%s: Camera %s: Creating request with ID %d (%d of %zu)",
                __FUNCTION__, mCameraIdStr.c_str(), submitInfo->mRequestId,
                loopCounter, requests.size());

        metadataRequestList.push_back(physicalSettingsList);
        surfaceMapList.push_back(surfaceMap);

        // Save certain CaptureRequest settings
        if (!request.mUserTag.empty()) {
            mRunningSessionStats.mUserTag = request.mUserTag;
        }
        camera_metadata_entry entry =
                physicalSettingsList.begin()->metadata.find(
                        ANDROID_CONTROL_VIDEO_STABILIZATION_MODE);
        if (entry.count == 1) {
            mRunningSessionStats.mVideoStabilizationMode = entry.data.u8[0];
        }

        if (!mRunningSessionStats.mUsedUltraWide) {
            entry = physicalSettingsList.begin()->metadata.find(
                    ANDROID_CONTROL_ZOOM_RATIO);
            if (entry.count == 1 && entry.data.f[0] < 1.0f ) {
                mRunningSessionStats.mUsedUltraWide = true;
            }
        }
        if (!mRunningSessionStats.mUsedSettingsOverrideZoom) {
            entry = physicalSettingsList.begin()->metadata.find(
                    ANDROID_CONTROL_SETTINGS_OVERRIDE);
            if (entry.count == 1 && entry.data.i32[0] ==
                    ANDROID_CONTROL_SETTINGS_OVERRIDE_ZOOM) {
                mRunningSessionStats.mUsedSettingsOverrideZoom = true;
            }
        }
    }
    mRequestIdCounter++;

    int32_t sharedReqID;
    if (streaming) {
        if (mSharedMode) {
            err = mDevice->setSharedStreamingRequest(*metadataRequestList.begin(),
                    *surfaceMapList.begin(), &sharedReqID, &(submitInfo->mLastFrameNumber));
        } else {
            err = mDevice->setStreamingRequestList(metadataRequestList, surfaceMapList,
                    &(submitInfo->mLastFrameNumber));
        }

        if (err != OK) {
            std::string msg = fmt::sprintf(
                "Camera %s:  Got error %s (%d) after trying to set streaming request",
                mCameraIdStr.c_str(), strerror(-err), err);
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            res = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                    msg.c_str());
        } else {
            Mutex::Autolock idLock(mStreamingRequestIdLock);
            mStreamingRequestId = submitInfo->mRequestId;
            if (mSharedMode) {
                mSharedStreamingRequest = {sharedReqID, submitInfo->mRequestId};
                markClientActive();
            }
        }
    } else {
        if (mSharedMode) {
            err = mDevice->setSharedCaptureRequest(*metadataRequestList.begin(),
                    *surfaceMapList.begin(), &sharedReqID, &(submitInfo->mLastFrameNumber));
         } else {
            err = mDevice->captureList(metadataRequestList, surfaceMapList,
                    &(submitInfo->mLastFrameNumber));
        }
        if (err != OK) {
            std::string msg = fmt::sprintf(
                "Camera %s: Got error %s (%d) after trying to submit capture request",
                mCameraIdStr.c_str(), strerror(-err), err);
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            res = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                    msg.c_str());
        }
        if (mSharedMode) {
            mSharedRequestMap[sharedReqID] = submitInfo->mRequestId;
            markClientActive();
        }
        ALOGV("%s: requestId = %d ", __FUNCTION__, submitInfo->mRequestId);
    }

    ALOGV("%s: Camera %s: End of function", __FUNCTION__, mCameraIdStr.c_str());
    return res;
}

binder::Status CameraDeviceClient::cancelRequest(
        int requestId,
        /*out*/
        int64_t* lastFrameNumber) {
    ATRACE_CALL();
    ALOGV("%s, requestId = %d", __FUNCTION__, requestId);

    status_t err;
    binder::Status res;

    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    Mutex::Autolock idLock(mStreamingRequestIdLock);
    if (mStreamingRequestId != requestId) {
        std::string msg = fmt::sprintf("Camera %s: Canceling request ID %d doesn't match "
                "current request ID %d", mCameraIdStr.c_str(), requestId, mStreamingRequestId);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    if (mSharedMode) {
        err = mDevice->clearSharedStreamingRequest(lastFrameNumber);
    } else {
        err = mDevice->clearStreamingRequest(lastFrameNumber);
    }

    if (err == OK) {
        ALOGV("%s: Camera %s: Successfully cleared streaming request",
                __FUNCTION__, mCameraIdStr.c_str());
        mStreamingRequestId = REQUEST_ID_NONE;
        if (mSharedMode) {
            mStreamingRequestLastFrameNumber = *lastFrameNumber;
        }
    } else {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error clearing streaming request: %s (%d)",
                mCameraIdStr.c_str(), strerror(-err), err);
    }

    return res;
}

binder::Status CameraDeviceClient::beginConfigure() {
    ATRACE_CALL();
    Mutex::Autolock icl(mBinderSerializationLock);
    return beginConfigureLocked();
}

binder::Status CameraDeviceClient::beginConfigureLocked() {
    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }
    status_t res = mDevice->beginConfigure();
    if (res != OK) {
        std::string msg = fmt::sprintf("Camera %s: Error beginning stream configuration: %s (%d)",
                mCameraIdStr.c_str(), strerror(-res), res);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    }
    return binder::Status::ok();
}

binder::Status CameraDeviceClient::endConfigure(int operatingMode,
        const hardware::camera2::impl::CameraMetadataNative& sessionParams, int64_t startTimeMs,
        std::vector<int>* offlineStreamIds /*out*/) {
    ATRACE_CALL();
    ALOGV("%s: ending configure (%d input stream, %zu output surfaces)",
            __FUNCTION__, mInputStream.configured ? 1 : 0,
            mStreamMap.size());

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    if (offlineStreamIds == nullptr) {
        std::string msg = "Invalid offline stream ids";
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    Mutex::Autolock icl(mBinderSerializationLock);
    return endConfigureLocked(operatingMode, sessionParams, startTimeMs, offlineStreamIds);

}

binder::Status CameraDeviceClient::endConfigureLocked(int operatingMode,
        const hardware::camera2::impl::CameraMetadataNative& sessionParams, int64_t startTimeMs,
        std::vector<int>* offlineStreamIds /*out*/) {
    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    binder::Status res =
            SessionConfigurationUtils::checkOperatingMode(operatingMode, mDevice->info(),
            mCameraIdStr);
    if (!res.isOk()) {
        return res;
    }

    if (mSharedMode) {
        // For shared camera session, streams are already configured
        // earlier, hence no need to do it here.
        return res;
    }

    status_t err = mDevice->configureStreams(sessionParams, operatingMode);
    if (err == BAD_VALUE) {
        std::string msg = fmt::sprintf("Camera %s: Unsupported set of inputs/outputs provided",
                mCameraIdStr.c_str());
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        res = STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    } else if (err != OK) {
        std::string msg = fmt::sprintf("Camera %s: Error configuring streams: %s (%d)",
                mCameraIdStr.c_str(), strerror(-err), err);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        res = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    } else {
        offlineStreamIds->clear();
        mDevice->getOfflineStreamIds(offlineStreamIds);

        Mutex::Autolock l(mCompositeLock);
        for (size_t i = 0; i < mCompositeStreamMap.size(); ++i) {
            err = mCompositeStreamMap.valueAt(i)->configureStream();
            if (err != OK) {
                std::string msg = fmt::sprintf("Camera %s: Error configuring composite "
                        "streams: %s (%d)", mCameraIdStr.c_str(), strerror(-err), err);
                ALOGE("%s: %s", __FUNCTION__, msg.c_str());
                res = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
                break;
            }

            // Composite streams can only support offline mode in case all individual internal
            // streams are also supported.
            std::vector<int> internalStreams;
            mCompositeStreamMap.valueAt(i)->insertCompositeStreamIds(&internalStreams);
            offlineStreamIds->erase(
                    std::remove_if(offlineStreamIds->begin(), offlineStreamIds->end(),
                    [&internalStreams] (int streamId) {
                        auto it = std::find(internalStreams.begin(), internalStreams.end(),
                                streamId);
                        if (it != internalStreams.end()) {
                            internalStreams.erase(it);
                            return true;
                        }

                        return false;}), offlineStreamIds->end());
            if (internalStreams.empty()) {
                offlineStreamIds->push_back(mCompositeStreamMap.valueAt(i)->getStreamId());
            }
        }

        for (const auto& offlineStreamId : *offlineStreamIds) {
            mStreamInfoMap[offlineStreamId].supportsOffline = true;
        }

        nsecs_t configureEnd = systemTime();
        int32_t configureDurationMs = ns2ms(configureEnd) - startTimeMs;
        int32_t inputFormat = mInputStream.configured ? mInputStream.format : -1;
        mCameraServiceProxyWrapper->logStreamConfigured(mCameraIdStr, operatingMode,
                false /*internalReconfig*/, configureDurationMs, inputFormat);
    }

    return res;
}

binder::Status CameraDeviceClient::isSessionConfigurationSupported(
        const SessionConfiguration& sessionConfiguration, bool *status /*out*/) {

    ATRACE_CALL();
    binder::Status res;
    status_t ret = OK;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    if (status == nullptr) {
        std::string msg = fmt::sprintf( "Camera %s: Invalid status!", mCameraIdStr.c_str());
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    *status = false;
    ret = mProviderManager->isSessionConfigurationSupported(mCameraIdStr.c_str(),
            sessionConfiguration, mOverrideForPerfClass, /*checkSessionParams*/false,
            status);
    switch (ret) {
        case OK:
            // Expected, do nothing.
            break;
        case INVALID_OPERATION: {
                std::string msg = fmt::sprintf(
                        "Camera %s: Session configuration query not supported!",
                        mCameraIdStr.c_str());
                ALOGD("%s: %s", __FUNCTION__, msg.c_str());
                res = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
            }

            break;
        default: {
                std::string msg = fmt::sprintf( "Camera %s: Error: %s (%d)", mCameraIdStr.c_str(),
                        strerror(-ret), ret);
                ALOGE("%s: %s", __FUNCTION__, msg.c_str());
                res = STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        msg.c_str());
            }
    }

    return res;
}

void CameraDeviceClient::cleanUpStreamsLocked(
        const std::vector<int32_t>& newOutputStreamIds, int32_t newInputStreamId) {
    // delete the input stream, if present
    if (newInputStreamId != CAMERA3_STREAM_ID_INVALID) {
        ALOGV("%s: Cleaning up input stream id %d", __FUNCTION__, newInputStreamId);
        deleteStreamLocked(newInputStreamId);
    }
    // delete output streams
    for (const auto& streamId : newOutputStreamIds) {
        ALOGV("%s: Cleaning up output stream id %d", __FUNCTION__, streamId);
        deleteStreamLocked(streamId);
    }
}

binder::Status CameraDeviceClient::configureStreams(
        const hardware::camera2::utils::SessionConfigurationAndStreamIds&
                sessionConfigurationAndStreamIds,
        /*out*/
        hardware::camera2::utils::OutputAndInputStreamIds* outputAndInputStreamIds) {
    ATRACE_CALL();
    ALOGV("%s: configuring streams", __FUNCTION__);
    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    if (outputAndInputStreamIds == nullptr) {
        std::string msg = fmt::sprintf("Camera %s: Invalid output and input stream ids",
                mCameraIdStr.c_str());
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }
    Mutex::Autolock icl(mBinderSerializationLock);
    // begin configure
    if (!(res = beginConfigureLocked()).isOk()) {
        return res;
    }

    // delete the input stream, if present
    if (sessionConfigurationAndStreamIds.deletedInputStreamId != CAMERA3_STREAM_ID_INVALID) {
        if (!(res = deleteStreamLocked(
                sessionConfigurationAndStreamIds.deletedInputStreamId)).isOk()) {
            return res;
        }
    }

    // create an input stream, if present
    int32_t newInputStreamId = CAMERA3_STREAM_ID_INVALID;
    const SessionConfiguration &sessionConfigurationDelta =
            sessionConfigurationAndStreamIds.sessionConfigurationDelta;
    if ((sessionConfigurationDelta.getInputHeight() > 0) &&
            (sessionConfigurationDelta.getInputWidth() > 0)) {
        ALOGV("%s: Input stream width %d, height %d format %d", __FUNCTION__,
                sessionConfigurationDelta.getInputWidth(),
                sessionConfigurationDelta.getInputHeight(),
                sessionConfigurationDelta.getInputFormat());
        if (!(res = createInputStreamLocked(sessionConfigurationDelta.getInputWidth(),
                sessionConfigurationDelta.getInputHeight(),
                sessionConfigurationDelta.getInputFormat(),
                sessionConfigurationDelta.inputIsMultiResolution(),
                &newInputStreamId)).isOk()) {
            return res;
        }
    }

    // delete output streams
    for (const auto& streamId : sessionConfigurationAndStreamIds.deletedStreamIds) {
        if (!(res = deleteStreamLocked(streamId)).isOk()) {
            return res;
        }
    }

    // create new output streams
    std::vector<int32_t> newStreamIds;
    for (const auto& outputConfiguration : sessionConfigurationDelta.getOutputConfigurations()) {
        int32_t newStreamId = CAMERA3_STREAM_ID_INVALID;
        ALOGV("%s: Output stream width %d, height %d format %d", __FUNCTION__,
                outputConfiguration.getWidth(), outputConfiguration.getHeight(),
                outputConfiguration.getFormat());
        if (!(res = createStreamLocked(outputConfiguration, &newStreamId)).isOk()) {
            cleanUpStreamsLocked(newStreamIds, newInputStreamId);
            return res;
        }
        newStreamIds.push_back(newStreamId);
    }

    std::vector<int32_t> offlineStreamIds;
    // end configure
    if (!(res = endConfigureLocked(sessionConfigurationDelta.getOperatingMode(),
            sessionConfigurationDelta.getSessionParameters(),
            sessionConfigurationAndStreamIds.createSessionTime, &offlineStreamIds)).isOk()) {
        cleanUpStreamsLocked(newStreamIds, newInputStreamId);
        return res;
    }

    outputAndInputStreamIds->outputStreamIds = std::move(newStreamIds);
    if (newInputStreamId != CAMERA3_STREAM_ID_INVALID) {
        outputAndInputStreamIds->inputStreamId = newInputStreamId;
    }
    outputAndInputStreamIds->offlineStreamIds = std::move(offlineStreamIds);

    return binder::Status::ok();
}

binder::Status CameraDeviceClient::deleteStream(int streamId) {
    ATRACE_CALL();
    ALOGV("%s (streamId = 0x%x)", __FUNCTION__, streamId);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);
    return deleteStreamLocked(streamId);
}

binder::Status CameraDeviceClient::deleteStreamLocked(int streamId) {
    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    bool isInput = false;
    std::vector<SurfaceKey> surfaces;
    std::vector<size_t> removedSurfaceIds;
    ssize_t dIndex = NAME_NOT_FOUND;
    ssize_t compositeIndex  = NAME_NOT_FOUND;

    if (mInputStream.configured && mInputStream.id == streamId) {
        isInput = true;
    } else {
        // Guard against trying to delete non-created streams
        for (size_t i = 0; i < mStreamMap.size(); ++i) {
            if (streamId == mStreamMap.valueAt(i).streamId()) {
                surfaces.push_back(mStreamMap.keyAt(i));
                if (mSharedMode) {
                    removedSurfaceIds.push_back(mStreamMap.valueAt(i).surfaceId());
                }
            }
        }

        // See if this stream is one of the deferred streams.
        for (size_t i = 0; i < mDeferredStreams.size(); ++i) {
            if (streamId == mDeferredStreams[i]) {
                dIndex = i;
                break;
            }
        }

        Mutex::Autolock l(mCompositeLock);
        for (size_t i = 0; i < mCompositeStreamMap.size(); ++i) {
            if (streamId == mCompositeStreamMap.valueAt(i)->getStreamId()) {
                compositeIndex = i;
                break;
            }
        }

        if (surfaces.empty() && dIndex == NAME_NOT_FOUND) {
            std::string msg = fmt::sprintf("Camera %s: Invalid stream ID (%d) specified, no such"
                    " stream created yet", mCameraIdStr.c_str(), streamId);
            ALOGW("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
        }
    }


    status_t err;
    if (mSharedMode) {
        err = mDevice->removeSharedSurfaces(streamId, removedSurfaceIds);
    } else {
        // Also returns BAD_VALUE if stream ID was not valid
        err = mDevice->deleteStream(streamId);
    }
    binder::Status res = binder::Status::ok();
    if (err != OK) {
        std::string msg = fmt::sprintf("Camera %s: Unexpected error %s (%d) when deleting stream "
                "%d", mCameraIdStr.c_str(), strerror(-err), err, streamId);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        res = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    } else {
        if (isInput) {
            mInputStream.configured = false;
        } else {
            for (auto& surface : surfaces) {
                mStreamMap.removeItem(surface);
            }

            mConfiguredOutputs.removeItem(streamId);

            if (dIndex != NAME_NOT_FOUND) {
                mDeferredStreams.removeItemsAt(dIndex);
            }

            if (compositeIndex != NAME_NOT_FOUND) {
                Mutex::Autolock l(mCompositeLock);
                status_t ret;
                if ((ret = mCompositeStreamMap.valueAt(compositeIndex)->deleteStream())
                        != OK) {
                    std::string msg = fmt::sprintf("Camera %s: Unexpected error %s (%d) when "
                            "deleting composite stream %d", mCameraIdStr.c_str(), strerror(-err),
                            err, streamId);
                    ALOGE("%s: %s", __FUNCTION__, msg.c_str());
                    res = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
                }
                mCompositeStreamMap.removeItemsAt(compositeIndex);
            }
            for (auto &mapIt: mHighResolutionCameraIdToStreamIdSet) {
                auto &streamSet = mapIt.second;
                if (streamSet.find(streamId) != streamSet.end()) {
                    streamSet.erase(streamId);
                    break;
                }
            }
            mStreamInfoMap.erase(streamId);
        }
    }

    return res;
}

binder::Status CameraDeviceClient::createStream(
        const hardware::camera2::params::OutputConfiguration &outputConfiguration,
        /*out*/
        int32_t* newStreamId) {
    ATRACE_CALL();

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);
    return createStreamLocked(outputConfiguration, newStreamId);
}

binder::Status CameraDeviceClient::createStreamLocked(
        const hardware::camera2::params::OutputConfiguration &outputConfiguration,
        /*out*/
        int32_t* newStreamId) {
    if (!flags::seamless_transitions()) {
        if (!outputConfiguration.isComplete()) {
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "OutputConfiguration isn't valid!");
        }
    }

    const std::vector<ParcelableSurfaceType>& surfaces = outputConfiguration.getSurfaces();
    size_t numSurfaces = surfaces.size();
    bool deferredConsumer = outputConfiguration.isDeferred();
    bool isShared = outputConfiguration.isShared();
    const std::string &physicalCameraId = outputConfiguration.getPhysicalCameraId();
    bool deferredConsumerOnly = deferredConsumer && numSurfaces == 0;
    int multiResMode  = outputConfiguration.getMultiResMode();
    int64_t dynamicRangeProfile = outputConfiguration.getDynamicRangeProfile();
    int64_t streamUseCase = outputConfiguration.getStreamUseCase();
    int timestampBase = outputConfiguration.getTimestampBase();
    int32_t colorSpace = outputConfiguration.getColorSpace();
    bool useReadoutTimestamp = outputConfiguration.useReadoutTimestamp();

    binder::Status res = SessionConfigurationUtils::checkSurfaceType(numSurfaces, deferredConsumer,
            outputConfiguration.getSurfaceType(), /*isConfigurationComplete*/true);
    if (!res.isOk()) {
        return res;
    }

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }
    res = SessionConfigurationUtils::checkPhysicalCameraId(mPhysicalCameraIds,
            physicalCameraId, mCameraIdStr);
    if (!res.isOk()) {
        return res;
    }

    std::vector<SurfaceHolder> surfaceHolders;
    std::vector<SurfaceKey> surfaceKeys;
    std::vector<OutputStreamInfo> streamInfos;
    status_t err;

    // Create stream for deferred surface case.
    if (deferredConsumerOnly) {
        return createDeferredSurfaceStreamLocked(outputConfiguration, isShared, newStreamId);
    }

    OutputStreamInfo streamInfo;
    bool isStreamInfoValid = false;
    const std::vector<int32_t> &sensorPixelModesUsed =
            outputConfiguration.getSensorPixelModesUsed();

    for (auto& surface : surfaces) {
        // Don't create multiple streams for the same target surface
        SurfaceKey surfaceKey;
        status_t ret = getSurfaceKey(surface, &surfaceKey);
        if(ret != OK) {
            ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                mCameraIdStr.c_str());
            return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                "Could not get the SurfaceKey");
        }

        ssize_t index = mStreamMap.indexOfKey(surfaceKey);
        if (index != NAME_NOT_FOUND) {
            std::string msg = std::string("Camera ") + mCameraIdStr
                    + ": Surface already has a stream created for it (ID "
                    + std::to_string(index) + ")";
            ALOGW("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ALREADY_EXISTS, msg.c_str());
        }

        int mirrorMode = outputConfiguration.getMirrorMode(surface);
        sp<Surface> outSurface;
        res = SessionConfigurationUtils::createConfiguredSurface(streamInfo,
                isStreamInfoValid, outputConfiguration, outSurface,
                flagtools::convertParcelableSurfaceTypeToSurface(surface), mCameraIdStr,
                mDevice->info(), mDevice->infoPhysical(physicalCameraId), sensorPixelModesUsed,
                dynamicRangeProfile, streamUseCase, timestampBase, mirrorMode, colorSpace,
                /*respectSurfaceSize*/false, multiResMode, mPrivilegedClient);

        if (!res.isOk())
            return res;

        if (!isStreamInfoValid) {
            isStreamInfoValid = true;
        }

        surfaceKeys.push_back(surfaceKey);
        surfaceHolders.push_back({outSurface, mirrorMode});
        if (mSharedMode) {
            streamInfos.push_back(streamInfo);
        }
    }

    int streamId = camera3::CAMERA3_STREAM_ID_INVALID;
    std::vector<int> surfaceIds;
    if (mSharedMode) {
        std::vector<int> streamIds;
        err = mDevice->getSharedStreamIds(streamInfo, streamIds);
        if (err == OK) {
            for (auto id: streamIds) {
                if (!mStreamInfoMap.contains(id)) {
                    streamId = id;
                    break;
                }
            }
            if (streamId == camera3::CAMERA3_STREAM_ID_INVALID && !streamIds.empty()) {
                streamId = streamIds[0];
                ALOGI("%s: Camera %s: Reusing shared streamId %d already owned by this client",
                        __FUNCTION__, mCameraIdStr.c_str(), streamId);
            }
            if (streamId == camera3::CAMERA3_STREAM_ID_INVALID) {
                ALOGE("%s: Camera %s: No valid shared stream ID found in %zu candidates. "
                        "OutputConfiguration isn't valid!",
                        __FUNCTION__, mCameraIdStr.c_str(), streamIds.size());
                return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "OutputConfiguration isn't valid!");
            }
            err = mDevice->addSharedSurfaces(streamId, streamInfos, surfaceHolders, &surfaceIds);
        }
    } else {
        bool isDepthCompositeStream =
                camera3::DepthCompositeStream::isDepthCompositeStream(surfaceHolders[0].mSurface);
        bool isHeicCompositeStream = camera3::HeicCompositeStream::isHeicCompositeStream(
                surfaceHolders[0].mSurface, mDevice->isCompositeHeicDisabled(),
                mDevice->isCompositeHeicUltraHDRDisabled());
        bool isJpegRCompositeStream =
            camera3::JpegRCompositeStream::isJpegRCompositeStream(surfaceHolders[0].mSurface) &&
            !mDevice->isCompositeJpegRDisabled();
        if (isDepthCompositeStream || isHeicCompositeStream || isJpegRCompositeStream) {
            sp<CompositeStream> compositeStream;
            if (isDepthCompositeStream) {
                compositeStream = new camera3::DepthCompositeStream(mDevice, getRemoteCallback());
            } else if (isHeicCompositeStream) {
                compositeStream = new camera3::HeicCompositeStream(mDevice, getRemoteCallback());
            } else {
                compositeStream = new camera3::JpegRCompositeStream(mDevice, getRemoteCallback());
            }
            err = compositeStream->createStream(
                    surfaceHolders, deferredConsumer, streamInfo.width, streamInfo.height,
                    streamInfo.format,
                    static_cast<camera_stream_rotation_t>(outputConfiguration.getRotation()),
                    &streamId, physicalCameraId, streamInfo.sensorPixelModesUsed, &surfaceIds,
                    outputConfiguration.getSurfaceSetID(), isShared, multiResMode,
                    streamInfo.colorSpace, streamInfo.dynamicRangeProfile, streamInfo.streamUseCase,
                    useReadoutTimestamp, outputConfiguration.getDataspace());
            if (err == OK) {
                Mutex::Autolock l(mCompositeLock);
                SurfaceKey surfaceKey;
                status_t ret = getSurfaceKey(surfaceHolders[0].mSurface, &surfaceKey);
                if(ret != OK) {
                    ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                        mCameraIdStr.c_str());
                    return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                        "Could not get the SurfaceKey");
                }
                mCompositeStreamMap.add(surfaceKey, compositeStream);
            }
        } else {
            err = mDevice->createStream(surfaceHolders, deferredConsumer, streamInfo.width,
                    streamInfo.height, streamInfo.format, streamInfo.dataSpace,
                    static_cast<camera_stream_rotation_t>(outputConfiguration.getRotation()),
                    &streamId, physicalCameraId, streamInfo.sensorPixelModesUsed, &surfaceIds,
                    outputConfiguration.getSurfaceSetID(), isShared, multiResMode,
                    /*consumerUsage*/0, streamInfo.dynamicRangeProfile, streamInfo.streamUseCase,
                    streamInfo.timestampBase, streamInfo.colorSpace, useReadoutTimestamp);
        }
    }

    if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error creating output stream (%d x %d, fmt %x, dataSpace %x): %s (%d)",
                mCameraIdStr.c_str(), streamInfo.width, streamInfo.height, streamInfo.format,
                static_cast<int>(streamInfo.dataSpace), strerror(-err), err);
    } else {
        int i = 0;
        for (auto& surfaceKey : surfaceKeys) {
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
            ALOGV("%s: mStreamMap add surfaceKey %" PRIu64 " streamId %d, surfaceId %d",
                  __FUNCTION__, surfaceKey, streamId, i);
#else
            ALOGV("%s: mStreamMap add surfaceKey %p streamId %d, surfaceId %d",
                    __FUNCTION__, surfaceKey.get(), streamId, i);
#endif
            mStreamMap.add(surfaceKey, StreamSurfaceId(streamId, surfaceIds[i]));
            i++;
        }

        mConfiguredOutputs.add(streamId, outputConfiguration);
        mStreamInfoMap[streamId] = streamInfo;

        ALOGV("%s: Camera %s: Successfully created a new stream ID %d for output surface"
                    " (%d x %d) with format 0x%x.",
                  __FUNCTION__, mCameraIdStr.c_str(), streamId, streamInfo.width,
                  streamInfo.height, streamInfo.format);

        // Fill in mHighResolutionCameraIdToStreamIdSet map
        const std::string &cameraIdUsed =
                physicalCameraId.size() != 0 ? physicalCameraId : mCameraIdStr;
        // Only needed for high resolution sensors
        if (mHighResolutionSensors.find(cameraIdUsed) !=
                mHighResolutionSensors.end()) {
            mHighResolutionCameraIdToStreamIdSet[cameraIdUsed].insert(streamId);
        }

        *newStreamId = streamId;
    }

    return res;
}

binder::Status CameraDeviceClient::createDeferredSurfaceStreamLocked(
        const hardware::camera2::params::OutputConfiguration &outputConfiguration,
        bool isShared,
        /*out*/
        int* newStreamId) {
    int width, height, format, surfaceType;
    uint64_t consumerUsage;
    android_dataspace dataSpace;
    int32_t colorSpace;
    status_t err;
    binder::Status res;

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }
    if (!flags::seamless_transitions()) {
        if (!outputConfiguration.isComplete()) {
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "OutputConfiguration isn't valid!");
        }
    }

    // Infer the surface info for deferred surface stream creation.
    width = outputConfiguration.getWidth();
    height = outputConfiguration.getHeight();
    surfaceType = outputConfiguration.getSurfaceType();
    if (flags::seamless_transitions()) {
        format = outputConfiguration.getFormat();
        dataSpace = static_cast<android_dataspace_t>(outputConfiguration.getDataspace());
    } else {
        format = HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
        dataSpace = android_dataspace_t::HAL_DATASPACE_UNKNOWN;
    }
    colorSpace = ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED;
    // Hardcode consumer usage flags: SurfaceView--0x900, SurfaceTexture--0x100.
    consumerUsage = GraphicBuffer::USAGE_HW_TEXTURE;
    if (surfaceType == OutputConfiguration::SURFACE_TYPE_SURFACE_VIEW) {
        consumerUsage |= GraphicBuffer::USAGE_HW_COMPOSER;
    } else if (flags::seamless_transitions() &&
            (surfaceType == OutputConfiguration::SURFACE_TYPE_IMAGE_READER)) {
        consumerUsage = outputConfiguration.getUsage();
    } else if (flags::seamless_transitions() &&
            (surfaceType == OutputConfiguration::SURFACE_TYPE_MEDIA_RECORDER ||
             surfaceType == OutputConfiguration::SURFACE_TYPE_MEDIA_CODEC)) {
        consumerUsage = GraphicBuffer::USAGE_HW_VIDEO_ENCODER;
    }
    int streamId = camera3::CAMERA3_STREAM_ID_INVALID;
    std::vector<SurfaceHolder> noSurface;
    std::vector<int> surfaceIds;
    const std::string &physicalCameraId = outputConfiguration.getPhysicalCameraId();
    const std::string &cameraIdUsed =
            physicalCameraId.size() != 0 ? physicalCameraId : mCameraIdStr;
    // Here, we override sensor pixel modes
    std::unordered_set<int32_t> overriddenSensorPixelModesUsed;
    const std::vector<int32_t> &sensorPixelModesUsed =
            outputConfiguration.getSensorPixelModesUsed();
    if (SessionConfigurationUtils::checkAndOverrideSensorPixelModesUsed(
            sensorPixelModesUsed, format, width, height, getStaticInfo(cameraIdUsed),
            &overriddenSensorPixelModesUsed) != OK) {
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "sensor pixel modes used not valid for deferred stream");
    }

    bool isDepthCompositeStream =
            camera3::DepthCompositeStream::isDepthCompositeStreamOutput(outputConfiguration);
    bool isHeicCompositeStream = camera3::HeicCompositeStream::isHeicCompositeStreamOutput(
            outputConfiguration, mDevice->isCompositeHeicDisabled(),
            mDevice->isCompositeHeicUltraHDRDisabled());
    bool isJpegRCompositeStream =
        camera3::JpegRCompositeStream::isJpegRCompositeStreamOutput(outputConfiguration) &&
        !mDevice->isCompositeJpegRDisabled();
    if (flags::seamless_transitions() && (isDepthCompositeStream || isHeicCompositeStream ||
                isJpegRCompositeStream)) {
        sp<CompositeStream> compositeStream;
        if (isDepthCompositeStream) {
            compositeStream = new camera3::DepthCompositeStream(mDevice, getRemoteCallback());
        } else if (isHeicCompositeStream) {
            compositeStream = new camera3::HeicCompositeStream(mDevice, getRemoteCallback());
        } else {
            compositeStream = new camera3::JpegRCompositeStream(mDevice, getRemoteCallback());
        }
        err = compositeStream->createStream(
                noSurface, true /*deferredConsumer*/, width, height, format,
                static_cast<camera_stream_rotation_t>(outputConfiguration.getRotation()), &streamId,
                physicalCameraId, overriddenSensorPixelModesUsed, &surfaceIds,
                outputConfiguration.getSurfaceSetID(), isShared,
                outputConfiguration.getMultiResMode(), colorSpace,
                outputConfiguration.getDynamicRangeProfile(),
                outputConfiguration.getStreamUseCase(), outputConfiguration.useReadoutTimestamp(),
                outputConfiguration.getDataspace());
        if (err == OK) {
            Mutex::Autolock l(mCompositeLock);
            mDeferredCompositeMap.emplace(compositeStream->getStreamId(), compositeStream);
        }
    } else {
        err = mDevice->createStream(
                noSurface, /*hasDeferredConsumer*/ true, width, height, format, dataSpace,
                static_cast<camera_stream_rotation_t>(outputConfiguration.getRotation()), &streamId,
                physicalCameraId, overriddenSensorPixelModesUsed, &surfaceIds,
                outputConfiguration.getSurfaceSetID(), isShared,
                outputConfiguration.getMultiResMode(), consumerUsage,
                outputConfiguration.getDynamicRangeProfile(),
                outputConfiguration.getStreamUseCase(), outputConfiguration.useReadoutTimestamp());
    }

    if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                               "Camera %s: Error creating output stream (%d x %d, fmt %x, "
                               "dataSpace %x): %s (%d)",
                               mCameraIdStr.c_str(), width, height, format,
                               static_cast<int>(dataSpace), strerror(-err), err);
    } else {
        // Can not add streamId to mStreamMap here, as the surface is deferred. Add it to
        // a separate list to track. Once the deferred surface is set, this id will be
        // relocated to mStreamMap.
        mDeferredStreams.push_back(streamId);
        mStreamInfoMap.emplace(
                std::piecewise_construct, std::forward_as_tuple(streamId),
                std::forward_as_tuple(width, height, format, dataSpace, consumerUsage,
                                      overriddenSensorPixelModesUsed,
                                      outputConfiguration.getDynamicRangeProfile(),
                                      outputConfiguration.getStreamUseCase(),
                                      outputConfiguration.getTimestampBase(), colorSpace));

        ALOGV("%s: Camera %s: Successfully created a new stream ID %d for a deferred surface"
              " (%d x %d) stream with format 0x%x.",
              __FUNCTION__, mCameraIdStr.c_str(), streamId, width, height, format);

        *newStreamId = streamId;
        // Fill in mHighResolutionCameraIdToStreamIdSet
        // Only needed for high resolution sensors
        if (mHighResolutionSensors.find(cameraIdUsed) != mHighResolutionSensors.end()) {
            mHighResolutionCameraIdToStreamIdSet[cameraIdUsed].insert(streamId);
        }
    }

    return res;
}

binder::Status CameraDeviceClient::createInputStream(
        int width, int height, int format, bool isMultiResolution,
        /*out*/
        int32_t* newStreamId) {
    ATRACE_CALL();
    ALOGV("%s (w = %d, h = %d, f = 0x%x, isMultiResolution %d)", __FUNCTION__,
            width, height, format, isMultiResolution);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);
    return createInputStreamLocked(width, height, format, isMultiResolution, newStreamId);
}

binder::Status CameraDeviceClient::createInputStreamLocked(
        int width, int height, int format, bool isMultiResolution,
        /*out*/
        int32_t* newStreamId) {
    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    if (mInputStream.configured) {
        std::string msg = fmt::sprintf("Camera %s: Already has an input stream "
                "configured (ID %d)", mCameraIdStr.c_str(), mInputStream.id);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str() );
        return STATUS_ERROR(CameraService::ERROR_ALREADY_EXISTS, msg.c_str());
    }

    int streamId = -1;
    status_t err = mDevice->createInputStream(width, height, format, isMultiResolution, &streamId);
    binder::Status res = binder::Status::ok();
    if (err == OK) {
        mInputStream.configured = true;
        mInputStream.width = width;
        mInputStream.height = height;
        mInputStream.format = format;
        mInputStream.id = streamId;

        ALOGV("%s: Camera %s: Successfully created a new input stream ID %d",
                __FUNCTION__, mCameraIdStr.c_str(), streamId);

        *newStreamId = streamId;
    } else {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error creating new input stream: %s (%d)", mCameraIdStr.c_str(),
                strerror(-err), err);
    }

    return res;
}

binder::Status CameraDeviceClient::getInputSurface(/*out*/ view::Surface *inputSurface) {

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    if (inputSurface == NULL) {
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, "Null input surface");
    }

    Mutex::Autolock icl(mBinderSerializationLock);
    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }
    sp<Surface> surface;
    status_t err = mDevice->getInputSurface(&surface);
    if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error getting input Surface: %s (%d)",
                mCameraIdStr.c_str(), strerror(-err), err);
    } else {
        inputSurface->name = toString16("CameraInput");
        inputSurface->graphicBufferProducer = surface->getIGraphicBufferProducer();
    }
    return res;
}

binder::Status CameraDeviceClient::updateOutputConfiguration(int streamId,
        const hardware::camera2::params::OutputConfiguration &outputConfiguration) {
    ATRACE_CALL();

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    return updateOutputConfigurationLocked(streamId, outputConfiguration);
}

binder::Status CameraDeviceClient::updateOutputConfigurationLocked(int streamId,
        const hardware::camera2::params::OutputConfiguration &outputConfiguration,
        bool replaceSurface, int64_t* lastFrameNumber) {
    ATRACE_CALL();
    binder::Status res;
    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }
    if (!flags::seamless_transitions()) {
        if (!outputConfiguration.isComplete()) {
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "OutputConfiguration isn't valid!");
        }
    }

    bool replaceEnabled = replaceSurface && flags::seamless_transitions();
    const std::vector<ParcelableSurfaceType>& surfaces = outputConfiguration.getSurfaces();
    const std::string& physicalCameraId = outputConfiguration.getPhysicalCameraId();

    if (!replaceEnabled) {
        auto producerCount = surfaces.size();
        if (producerCount == 0) {
            ALOGE("%s: surfaces must not be empty", __FUNCTION__);
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                                "surfaces must not be empty");
        }
    }

    if (!replaceEnabled) {
        // The first output is the one associated with the output configuration.
        // It should always be present, valid and the corresponding stream id should match.
        SurfaceKey surfaceKey;
        status_t ret = getSurfaceKey(surfaces[0], &surfaceKey);
        if(ret != OK) {
            ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                    mCameraIdStr.c_str());
            return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                    "Could not get the SurfaceKey");
        }
        ssize_t index = mStreamMap.indexOfKey(surfaceKey);
        if (index == NAME_NOT_FOUND) {
            ALOGE("%s: Outputconfiguration is invalid", __FUNCTION__);
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "OutputConfiguration is invalid");
        }
        if (mStreamMap.valueFor(surfaceKey).streamId() != streamId) {
            ALOGE("%s: Stream Id: %d provided doesn't match the id: %d in the stream map",
                    __FUNCTION__, streamId, mStreamMap.valueFor(surfaceKey).streamId());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                    "Stream id is invalid");
        }
    }

    std::vector<size_t> removedSurfaceIds;
    std::vector<SurfaceKey> removedOutputs;
    std::vector<SurfaceHolder> newOutputs;
    std::vector<OutputStreamInfo> streamInfos;
    KeyedVector<SurfaceKey, ParcelableSurfaceType> newOutputsMap;
    for (auto& surface : surfaces) {
        SurfaceKey surfaceKey;
        status_t ret = getSurfaceKey(surface, &surfaceKey);
        if(ret != OK) {
            ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                 mCameraIdStr.c_str());
            return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                 "Could not get the SurfaceKey");
        }
        newOutputsMap.add(surfaceKey, surface);
    }

    for (size_t i = 0; i < mStreamMap.size(); i++) {
        ssize_t idx = newOutputsMap.indexOfKey(mStreamMap.keyAt(i));
        if (idx == NAME_NOT_FOUND) {
            if (mStreamMap[i].streamId() == streamId) {
                removedSurfaceIds.push_back(mStreamMap[i].surfaceId());
                removedOutputs.push_back(mStreamMap.keyAt(i));
            }
        } else {
            if (mStreamMap[i].streamId() != streamId) {
                ALOGE("%s: Output surface already part of a different stream", __FUNCTION__);
                return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "Target Surface is invalid");
            }
            newOutputsMap.removeItemsAt(idx);
        }
    }

    const std::vector<int32_t> &sensorPixelModesUsed =
            outputConfiguration.getSensorPixelModesUsed();
    int64_t streamUseCase = outputConfiguration.getStreamUseCase();
    int timestampBase = outputConfiguration.getTimestampBase();
    int64_t dynamicRangeProfile = outputConfiguration.getDynamicRangeProfile();
    int32_t colorSpace = outputConfiguration.getColorSpace();
    int32_t multiResMode = outputConfiguration.getMultiResMode();

    for (size_t i = 0; i < newOutputsMap.size(); i++) {
        OutputStreamInfo outInfo;
        sp<Surface> outSurface;
        int mirrorMode = outputConfiguration.getMirrorMode(newOutputsMap.valueAt(i));
        res = SessionConfigurationUtils::createConfiguredSurface(
                outInfo, /*isStreamInfoValid*/ false, outputConfiguration, outSurface,
                flagtools::convertParcelableSurfaceTypeToSurface(newOutputsMap.valueAt(i)),
                mCameraIdStr, mDevice->info(), mDevice->infoPhysical(physicalCameraId),
                sensorPixelModesUsed, dynamicRangeProfile, streamUseCase, timestampBase,
                mirrorMode, colorSpace, /*respectSurfaceSize*/ false, multiResMode,
                mPrivilegedClient);
        if (!res.isOk()) return res;

        streamInfos.push_back(outInfo);
        newOutputs.push_back({outSurface, mirrorMode});
    }

    //Trivial case no changes required
    if (removedSurfaceIds.empty() && newOutputs.empty()) {
        return binder::Status::ok();
    }

    KeyedVector<sp<Surface>, size_t> outputMap;
    sp<CompositeStream> compositeStream = nullptr;
    bool deferredCompositeStream = false;
    findCompositeStream(streamId, &compositeStream, &deferredCompositeStream);

    status_t ret;
    if (compositeStream.get() == nullptr) {
        ret = mDevice->updateStream(streamId, newOutputs, streamInfos, removedSurfaceIds,
                replaceEnabled, &outputMap, lastFrameNumber);
    } else {
        ret = compositeStream->updateStream(streamId, newOutputs, &outputMap, lastFrameNumber);
    }
    if (ret != OK) {
        switch (ret) {
            case NAME_NOT_FOUND:
            case BAD_VALUE:
            case -EBUSY:
                res = STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "Camera %s: Error updating stream: %s (%d)",
                        mCameraIdStr.c_str(), strerror(ret), ret);
                break;
            default:
                res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                        "Camera %s: Error updating stream: %s (%d)",
                        mCameraIdStr.c_str(), strerror(ret), ret);
                break;
        }
    } else {
        for (const auto &it : removedOutputs) {
            mStreamMap.removeItem(it);
        }

        SurfaceKey surfaceKey;
        for (size_t i = 0; i < outputMap.size(); i++) {
            status_t ret = getSurfaceKey(outputMap.keyAt(i), &surfaceKey);
            if(ret != OK) {
                ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                     mCameraIdStr.c_str());
                return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                     "Could not get the SurfaceKey");
            }
            mStreamMap.add(surfaceKey, StreamSurfaceId(streamId, outputMap.valueAt(i)));
        }

        mConfiguredOutputs.replaceValueFor(streamId, outputConfiguration);
        updateCompositeOutputsLocked(streamId, surfaceKey, compositeStream,
                deferredCompositeStream, newOutputs.empty());


        ALOGV("%s: Camera %s: Successful stream ID %d update",
                  __FUNCTION__, mCameraIdStr.c_str(), streamId);
    }

    return res;
}

void CameraDeviceClient::findCompositeStream(int streamId,
        sp<CompositeStream> *compositeStream /*out*/, bool *deferredStream /*out*/) {
    if (compositeStream == nullptr || deferredStream == nullptr) {
        return;
    }

    if (flags::seamless_transitions()) {
        Mutex::Autolock compLock(mCompositeLock);
        for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
            if (streamId == mCompositeStreamMap.valueAt(i)->getStreamId()) {
                *compositeStream = mCompositeStreamMap.valueAt(i);
                break;
            }
        }
        if (compositeStream->get() == nullptr) {
            auto it = mDeferredCompositeMap.find(streamId);
            if (it != mDeferredCompositeMap.end()) {
                *compositeStream = it->second;
                *deferredStream = true;
            }
        }
    }
}

void CameraDeviceClient::updateCompositeOutputsLocked(int streamId, SurfaceKey surfaceKey,
        const sp<CompositeStream>& compositeStream,
        bool deferredCompositeStream, bool noNewOutputs) {
    if (compositeStream.get() != nullptr) {
        Mutex::Autolock compLock(mCompositeLock);
        if (deferredCompositeStream) {
            if (!noNewOutputs) {
                auto it = std::find(mDeferredStreams.begin(), mDeferredStreams.end(), streamId);
                if (it != mDeferredStreams.end()) {
                    mDeferredStreams.erase(it);
                }
                mStreamInfoMap[streamId].finalized = true;
                mDeferredCompositeMap.erase(streamId);
                mCompositeStreamMap.add(surfaceKey, compositeStream);
            }
        } else {
            for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
                if (streamId == mCompositeStreamMap.valueAt(i)->getStreamId()) {
                    mCompositeStreamMap.removeItemsAt(i, 1);
                    break;
                }
            }
            if (noNewOutputs)  {
                mDeferredStreams.add(streamId);
                mStreamInfoMap[streamId].finalized = false;
                mDeferredCompositeMap.emplace(streamId, compositeStream);
            } else {
                mCompositeStreamMap.add(surfaceKey, compositeStream);
            }
        }
    }
}

// Create a request object from a template.
binder::Status CameraDeviceClient::createDefaultRequest(int templateId,
        /*out*/
        hardware::camera2::impl::CameraMetadataNative* request)
{
    ATRACE_CALL();
    ALOGV("%s (templateId = 0x%x)", __FUNCTION__, templateId);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    status_t err;
    camera_request_template_t tempId = camera_request_template_t::CAMERA_TEMPLATE_COUNT;
    res = SessionConfigurationUtils::mapRequestTemplateFromClient(
            mCameraIdStr, templateId, &tempId);
    if (!res.isOk()) return res;

    CameraMetadata metadata;
    if ( (err = mDevice->createDefaultRequest(tempId, &metadata) ) == OK &&
        request != NULL) {

        request->swap(metadata);
    } else if (err == BAD_VALUE) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Camera %s: Template ID %d is invalid or not supported: %s (%d)",
                mCameraIdStr.c_str(), templateId, strerror(-err), err);

    } else {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error creating default request for template %d: %s (%d)",
                mCameraIdStr.c_str(), templateId, strerror(-err), err);
    }
    return res;
}

binder::Status CameraDeviceClient::getCameraInfo(
        /*out*/
        hardware::camera2::impl::CameraMetadataNative* info)
{
    ATRACE_CALL();
    ALOGV("%s", __FUNCTION__);

    binder::Status res;

    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    if (info != NULL) {
        *info = mDevice->info(); // static camera metadata
        // TODO: merge with device-specific camera metadata
    }

    return res;
}

binder::Status CameraDeviceClient::waitUntilIdle()
{
    ATRACE_CALL();
    ALOGV("%s", __FUNCTION__);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    // FIXME: Also need check repeating burst.
    Mutex::Autolock idLock(mStreamingRequestIdLock);
    if (mStreamingRequestId != REQUEST_ID_NONE) {
        std::string msg = fmt::sprintf(
            "Camera %s: Try to waitUntilIdle when there are active streaming requests",
            mCameraIdStr.c_str());
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, msg.c_str());
    }
    status_t err = mDevice->waitUntilDrained();
    if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error waiting to drain: %s (%d)",
                mCameraIdStr.c_str(), strerror(-err), err);
    }
    ALOGV("%s Done", __FUNCTION__);
    return res;
}

binder::Status CameraDeviceClient::flush(
        /*out*/
        int64_t* lastFrameNumber) {
    ATRACE_CALL();
    ALOGV("%s", __FUNCTION__);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    Mutex::Autolock idLock(mStreamingRequestIdLock);
    mStreamingRequestId = REQUEST_ID_NONE;
    status_t err = mDevice->flush(lastFrameNumber);
    if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error flushing device: %s (%d)", mCameraIdStr.c_str(), strerror(-err),
                err);
    }
    if (mSharedMode) {
        mSharedRequestMap.clear();
        mStreamingRequestLastFrameNumber = *lastFrameNumber;
    }
    return res;
}

binder::Status CameraDeviceClient::prepare(int streamId) {
    ATRACE_CALL();
    ALOGV("%s stream id %d", __FUNCTION__, streamId);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    // Guard against trying to prepare non-created streams
    ssize_t index = NAME_NOT_FOUND;
    for (size_t i = 0; i < mStreamMap.size(); ++i) {
        if (streamId == mStreamMap.valueAt(i).streamId()) {
            index = i;
            break;
        }
    }

    if (index == NAME_NOT_FOUND) {
        std::string msg = fmt::sprintf("Camera %s: Invalid stream ID (%d) specified, no stream "
              "with that ID exists", mCameraIdStr.c_str(), streamId);
        ALOGW("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    // Also returns BAD_VALUE if stream ID was not valid, or stream already
    // has been used
    status_t err = mDevice->prepare(streamId);
    if (err == BAD_VALUE) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Camera %s: Stream %d has already been used, and cannot be prepared",
                mCameraIdStr.c_str(), streamId);
    } else if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error preparing stream %d: %s (%d)", mCameraIdStr.c_str(), streamId,
                strerror(-err), err);
    }
    return res;
}

binder::Status CameraDeviceClient::prepare2(int maxCount, int streamId) {
    ATRACE_CALL();
    ALOGV("%s stream id %d", __FUNCTION__, streamId);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    // Guard against trying to prepare non-created streams
    ssize_t index = NAME_NOT_FOUND;
    for (size_t i = 0; i < mStreamMap.size(); ++i) {
        if (streamId == mStreamMap.valueAt(i).streamId()) {
            index = i;
            break;
        }
    }

    if (index == NAME_NOT_FOUND) {
        std::string msg = fmt::sprintf("Camera %s: Invalid stream ID (%d) specified, no stream "
              "with that ID exists", mCameraIdStr.c_str(), streamId);
        ALOGW("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    if (maxCount <= 0) {
        std::string msg = fmt::sprintf("Camera %s: maxCount (%d) must be greater than 0",
                mCameraIdStr.c_str(), maxCount);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    // Also returns BAD_VALUE if stream ID was not valid, or stream already
    // has been used
    status_t err = mDevice->prepare(maxCount, streamId);
    if (err == BAD_VALUE) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Camera %s: Stream %d has already been used, and cannot be prepared",
                mCameraIdStr.c_str(), streamId);
    } else if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error preparing stream %d: %s (%d)", mCameraIdStr.c_str(), streamId,
                strerror(-err), err);
    }

    return res;
}

binder::Status CameraDeviceClient::tearDown(int streamId) {
    ATRACE_CALL();
    ALOGV("%s", __FUNCTION__);

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    // Guard against trying to prepare non-created streams
    ssize_t index = NAME_NOT_FOUND;
    for (size_t i = 0; i < mStreamMap.size(); ++i) {
        if (streamId == mStreamMap.valueAt(i).streamId()) {
            index = i;
            break;
        }
    }

    if (index == NAME_NOT_FOUND) {
        std::string msg = fmt::sprintf("Camera %s: Invalid stream ID (%d) specified, no stream "
              "with that ID exists", mCameraIdStr.c_str(), streamId);
        ALOGW("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    // Also returns BAD_VALUE if stream ID was not valid or if the stream is in
    // use
    status_t err = mDevice->tearDown(streamId);
    if (err == BAD_VALUE) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Camera %s: Stream %d is still in use, cannot be torn down",
                mCameraIdStr.c_str(), streamId);
    } else if (err != OK) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error tearing down stream %d: %s (%d)", mCameraIdStr.c_str(), streamId,
                strerror(-err), err);
    }

    return res;
}

binder::Status CameraDeviceClient::finalizeOutputConfigurations(int32_t streamId,
        const hardware::camera2::params::OutputConfiguration &outputConfiguration) {
    ATRACE_CALL();

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!outputConfiguration.isComplete()) {
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "OutputConfiguration isn't valid!");
    }

    const std::vector<ParcelableSurfaceType>& surfaces = outputConfiguration.getSurfaces();
    const std::string& physicalId = outputConfiguration.getPhysicalCameraId();

    if (surfaces.size() == 0) {
        ALOGE("%s: surfaces must not be empty", __FUNCTION__);
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, "Target Surface is invalid");
    }

    // streamId should be in mStreamMap if this stream already has a surface attached
    // to it. Otherwise, it should be in mDeferredStreams.
    bool streamIdConfigured = false;
    ssize_t deferredStreamIndex = NAME_NOT_FOUND;
    for (size_t i = 0; i < mStreamMap.size(); i++) {
        if (mStreamMap.valueAt(i).streamId() == streamId) {
            streamIdConfigured = true;
            break;
        }
    }
    for (size_t i = 0; i < mDeferredStreams.size(); i++) {
        if (streamId == mDeferredStreams[i]) {
            deferredStreamIndex = i;
            break;
        }

    }
    if (deferredStreamIndex == NAME_NOT_FOUND && !streamIdConfigured) {
        std::string msg = fmt::sprintf("Camera %s: deferred surface is set to a unknown stream"
                "(ID %d)", mCameraIdStr.c_str(), streamId);
        ALOGW("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    if (mStreamInfoMap[streamId].finalized) {
        std::string msg = fmt::sprintf("Camera %s: finalizeOutputConfigurations has been called"
                " on stream ID %d", mCameraIdStr.c_str(), streamId);
        ALOGW("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    std::vector<SurfaceHolder> consumerSurfaceHolders;
    const std::vector<int32_t>& sensorPixelModesUsed =
            outputConfiguration.getSensorPixelModesUsed();
    int64_t dynamicRangeProfile = outputConfiguration.getDynamicRangeProfile();
    int32_t colorSpace = outputConfiguration.getColorSpace();
    int64_t streamUseCase = outputConfiguration.getStreamUseCase();
    int timestampBase = outputConfiguration.getTimestampBase();
    int32_t multiResMode = outputConfiguration.getMultiResMode();

    for (auto& surface : surfaces) {
        // Don't create multiple streams for the same target surface
        SurfaceKey surfaceKey;
        status_t ret = getSurfaceKey(surface, &surfaceKey);
        if(ret != OK) {
            ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                 mCameraIdStr.c_str());
            return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                 "Could not get the SurfaceKey");
        }
        ssize_t index = mStreamMap.indexOfKey(surfaceKey);
        if (index != NAME_NOT_FOUND) {
            ALOGV("Camera %s: Surface already has a stream created "
                  " for it (ID %zd)",
                  mCameraIdStr.c_str(), index);
            continue;
        }

        sp<Surface> outSurface;
        int mirrorMode = outputConfiguration.getMirrorMode(surface);
        res = SessionConfigurationUtils::createConfiguredSurface(
                mStreamInfoMap[streamId], true /*isStreamInfoValid*/, outputConfiguration,
                outSurface, flagtools::convertParcelableSurfaceTypeToSurface(surface),
                mCameraIdStr, mDevice->info(), mDevice->infoPhysical(physicalId),
                sensorPixelModesUsed, dynamicRangeProfile, streamUseCase, timestampBase,
                mirrorMode, colorSpace, /*respectSurfaceSize*/ false, multiResMode,
                mPrivilegedClient);

        if (!res.isOk()) return res;

        consumerSurfaceHolders.push_back({outSurface, mirrorMode});
    }
    // Gracefully handle case where finalizeOutputConfigurations is called
    // without any new surface.
    if (consumerSurfaceHolders.size() == 0) {
        mStreamInfoMap[streamId].finalized = true;
        return res;
    }

    // Finish the deferred stream configuration with the surface.
    status_t err;
    std::vector<int> consumerSurfaceIds;
    sp<CompositeStream> compositeStream;
    if (flags::seamless_transitions()) {
        Mutex::Autolock compLock(mCompositeLock);
        auto it = mDeferredCompositeMap.find(streamId);
        if (it != mDeferredCompositeMap.end()) {
            compositeStream = it->second;
        }
    }
    if (compositeStream.get() != nullptr) {
        err = compositeStream->setConsumerSurfaces(streamId, consumerSurfaceHolders,
                                                   &consumerSurfaceIds);
    } else {
        err = mDevice->setConsumerSurfaces(streamId, consumerSurfaceHolders, &consumerSurfaceIds);
    }
    if (err == OK) {
        SurfaceKey surfaceKey;
        for (size_t i = 0; i < consumerSurfaceHolders.size(); i++) {
            status_t ret = getSurfaceKey(consumerSurfaceHolders[i].mSurface, &surfaceKey);
            if (ret != OK) {
                ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                    mCameraIdStr.c_str());
                return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                                    "Could not get the SurfaceKey");
            }
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
            ALOGV("%s: mStreamMap add surface_key %" PRIu64 " streamId %d, surfaceId %d",
                  __FUNCTION__, surfaceKey, streamId, consumerSurfaceIds[i]);
#else
            ALOGV("%s: mStreamMap add surface_key %p streamId %d, surfaceId %d", __FUNCTION__,
                    surfaceKey.get(), streamId, consumerSurfaceIds[i]);
#endif
            mStreamMap.add(surfaceKey, StreamSurfaceId(streamId, consumerSurfaceIds[i]));
        }
        if (deferredStreamIndex != NAME_NOT_FOUND) {
            mDeferredStreams.removeItemsAt(deferredStreamIndex);
        }
        mStreamInfoMap[streamId].finalized = true;
        mConfiguredOutputs.replaceValueFor(streamId, outputConfiguration);

        if (compositeStream.get() != nullptr) {
            Mutex::Autolock compLock(mCompositeLock);
            mDeferredCompositeMap.erase(streamId);
            mCompositeStreamMap.add(surfaceKey, compositeStream);
        }
    } else if (err == NO_INIT) {
        res = STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Camera %s: Deferred surface is invalid: %s (%d)",
                mCameraIdStr.c_str(), strerror(-err), err);
    } else {
        res = STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                "Camera %s: Error setting output stream deferred surface: %s (%d)",
                mCameraIdStr.c_str(), strerror(-err), err);
    }

    return res;
}

binder::Status CameraDeviceClient::setCameraAudioRestriction(AudioRestriction mode) {
    ATRACE_CALL();
    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    if (!isValidAudioRestriction(mode)) {
        std::string msg = fmt::sprintf("Camera %s: invalid audio restriction mode %s",
                mCameraIdStr.c_str(), toString(mode).c_str());
        ALOGW("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    Mutex::Autolock icl(mBinderSerializationLock);
    BasicClient::setAudioRestriction(mode);
    return binder::Status::ok();
}

status_t CameraDeviceClient::CreateMetadataQueue(
        std::unique_ptr<MetadataQueue>* metadata_queue, size_t size_bytes) {
        if (metadata_queue == nullptr) {
            ALOGE("%s: metadata_queue is nullptr", __FUNCTION__);
            return BAD_VALUE;
        }

        *metadata_queue =
                std::make_unique<MetadataQueue>(size_bytes,
                        /*configureEventFlagWord*/ false);
        if (!(*metadata_queue)->isValid()) {
            ALOGE("%s: Creating metadata queue (size %zu) failed.", __FUNCTION__, size_bytes);
            return NO_INIT;
        }

        return OK;
}

binder::Status CameraDeviceClient::getCaptureResultMetadataQueue(
          android::hardware::common::fmq::MQDescriptor<
          int8_t, android::hardware::common::fmq::SynchronizedReadWrite>* aidl_return) {

    *aidl_return = mResultMetadataQueue->dupeDesc();
    return binder::Status::ok();
}

binder::Status CameraDeviceClient::getGlobalAudioRestriction(/*out*/ AudioRestriction* outMode) {
    ATRACE_CALL();
    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;
    Mutex::Autolock icl(mBinderSerializationLock);
    if (outMode != nullptr) {
        *outMode = BasicClient::getServiceAudioRestriction();
    }
    return binder::Status::ok();
}

binder::Status CameraDeviceClient::isPrimaryClient(/*out*/bool* isPrimary) {
    ATRACE_CALL();
    binder::Status res =  binder::Status::ok();
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;
    if (isPrimary != nullptr) {
        status_t ret = BasicClient::isPrimaryClient(isPrimary);
        return  binder::Status::fromStatusT(ret);
    }
    return res;
}

status_t CameraDeviceClient::setCameraServiceWatchdog(bool enabled) {
    return mDevice->setCameraServiceWatchdog(enabled);
}

status_t CameraDeviceClient::setRotateAndCropOverride(uint8_t rotateAndCrop, bool fromHal) {
    if (rotateAndCrop > ANDROID_SCALER_ROTATE_AND_CROP_AUTO) return BAD_VALUE;

    return mDevice->setRotateAndCropAutoBehavior(
        static_cast<camera_metadata_enum_android_scaler_rotate_and_crop_t>(rotateAndCrop), fromHal);
}

status_t CameraDeviceClient::setAutoframingOverride(uint8_t autoframingValue) {
    if (autoframingValue > ANDROID_CONTROL_AUTOFRAMING_AUTO) return BAD_VALUE;

    return mDevice->setAutoframingAutoBehavior(
        static_cast<camera_metadata_enum_android_control_autoframing_t>(autoframingValue));
}

bool CameraDeviceClient::supportsCameraMute() {
    return mDevice->supportsCameraMute();
}

status_t CameraDeviceClient::setCameraMute(bool enabled) {
    return mDevice->setCameraMute(enabled);
}

void CameraDeviceClient::setStreamUseCaseOverrides(
        const std::vector<int64_t>& useCaseOverrides) {
    mDevice->setStreamUseCaseOverrides(useCaseOverrides);
}

void CameraDeviceClient::clearStreamUseCaseOverrides() {
    mDevice->clearStreamUseCaseOverrides();
}

bool CameraDeviceClient::supportsZoomOverride() {
    return mDevice->supportsZoomOverride();
}

status_t CameraDeviceClient::setZoomOverride(int32_t zoomOverride) {
    return mDevice->setZoomOverride(zoomOverride);
}

binder::Status CameraDeviceClient::switchToOffline(
        const sp<hardware::camera2::ICameraDeviceCallbacks>& cameraCb,
        const std::vector<int>& offlineOutputIds,
        /*out*/
        sp<hardware::camera2::ICameraOfflineSession>* session) {
    ATRACE_CALL();

    binder::Status res;
    if (!(res = checkPidStatus(__FUNCTION__)).isOk()) return res;

    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    if (offlineOutputIds.empty()) {
        std::string msg = "Offline surfaces must not be empty";
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    if (session == nullptr) {
        std::string msg = "Invalid offline session";
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    std::vector<int32_t> offlineStreamIds;
    offlineStreamIds.reserve(offlineOutputIds.size());
    KeyedVector<SurfaceKey, sp<CompositeStream>> offlineCompositeStreamMap;
    for (const auto& streamId : offlineOutputIds) {
        ssize_t index = mConfiguredOutputs.indexOfKey(streamId);
        if (index == NAME_NOT_FOUND) {
            std::string msg = fmt::sprintf("Offline surface with id: %d is not registered",
                    streamId);
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
        }

        if (!mStreamInfoMap[streamId].supportsOffline) {
            std::string msg = fmt::sprintf("Offline surface with id: %d doesn't support "
                    "offline mode", streamId);
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
        }

        Mutex::Autolock l(mCompositeLock);
        bool isCompositeStream = false;

        for (const auto& surface : mConfiguredOutputs.valueAt(index).getSurfaces()) {
#if WB_LIBCAMERASERVICE_WITH_DEPENDENCIES
            sp<Surface> s = surface.toSurface();
#else
            sp<Surface> s = new Surface(surface, false /*controlledByApp*/);
#endif
            isCompositeStream = camera3::DepthCompositeStream::isDepthCompositeStream(s) ||
                                camera3::HeicCompositeStream::isHeicCompositeStream(
                                        s, mDevice->isCompositeHeicDisabled(),
                                        mDevice->isCompositeHeicUltraHDRDisabled()) ||
                                (camera3::JpegRCompositeStream::isJpegRCompositeStream(s) &&
                                 !mDevice->isCompositeJpegRDisabled());
            if (isCompositeStream) {
                SurfaceKey surfaceKey;
                status_t ret = getSurfaceKey(surface, &surfaceKey);
                if(ret != OK) {
                    ALOGE("%s: Camera %s: Could not get the SurfaceKey", __FUNCTION__,
                        mCameraIdStr.c_str());
                    return STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION,
                        "Could not get the SurfaceKey");
                }
                auto compositeIdx = mCompositeStreamMap.indexOfKey(surfaceKey);
                if (compositeIdx == NAME_NOT_FOUND) {
                    ALOGE("%s: Unknown composite stream", __FUNCTION__);
                    return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT,
                                        "Unknown composite stream");
                }

                mCompositeStreamMap.valueAt(compositeIdx)
                        ->insertCompositeStreamIds(&offlineStreamIds);
                offlineCompositeStreamMap.add(mCompositeStreamMap.keyAt(compositeIdx),
                                              mCompositeStreamMap.valueAt(compositeIdx));
                break;
            }
        }

        if (!isCompositeStream) {
            offlineStreamIds.push_back(streamId);
        }
    }

    sp<CameraOfflineSessionBase> offlineSession;
    auto ret = mDevice->switchToOffline(offlineStreamIds, &offlineSession);
    if (ret != OK) {
        return STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                "Camera %s: Error switching to offline mode: %s (%d)",
                mCameraIdStr.c_str(), strerror(ret), ret);
    }

    sp<CameraOfflineSessionClient> offlineClient;
    if (offlineSession.get() != nullptr) {
        offlineClient = new CameraOfflineSessionClient(
                sCameraService, offlineSession, offlineCompositeStreamMap, cameraCb,
                mAttributionAndPermissionUtils, mClientAttribution, mCallingPid, mCameraIdStr,
                mCameraFacing, mOrientation, mServicePid, /*sharedMode*/false);
        ret = sCameraService->addOfflineClient(mCameraIdStr, offlineClient);
    }

    if (ret == OK) {
        // A successful offline session switch must reset the current camera client
        // and release any resources occupied by previously configured streams.
        mStreamMap.clear();
        mConfiguredOutputs.clear();
        mDeferredStreams.clear();
        mStreamInfoMap.clear();
        Mutex::Autolock l(mCompositeLock);
        mCompositeStreamMap.clear();
        mInputStream = {false, 0, 0, 0, 0};
    } else {
        // In case we failed to register the offline client, ensure that it still initialized
        // so that all failing requests can return back correctly once the object is released.
        offlineClient->initialize(nullptr /*cameraProviderManager*/, std::string()/*monitorTags*/);

        switch(ret) {
            case BAD_VALUE:
                return STATUS_ERROR_FMT(CameraService::ERROR_ILLEGAL_ARGUMENT,
                        "Illegal argument to HAL module for camera \"%s\"", mCameraIdStr.c_str());
            case TIMED_OUT:
                return STATUS_ERROR_FMT(CameraService::ERROR_CAMERA_IN_USE,
                        "Camera \"%s\" is already open", mCameraIdStr.c_str());
            default:
                return STATUS_ERROR_FMT(CameraService::ERROR_INVALID_OPERATION,
                        "Failed to initialize camera \"%s\": %s (%d)", mCameraIdStr.c_str(),
                        strerror(-ret), ret);
        }
    }

    *session = offlineClient;

    return binder::Status::ok();
}

status_t CameraDeviceClient::dump(int fd, const Vector<String16>& args) {
    return BasicClient::dump(fd, args);
}

status_t CameraDeviceClient::dumpClient(int fd, const Vector<String16>& args, bool ignoreResult) {
    dprintf(fd, "  CameraDeviceClient[%s] (%p) dump:\n",
            mCameraIdStr.c_str(),
            (getRemoteCallback() != NULL ?
                    IInterface::asBinder(getRemoteCallback()).get() : NULL) );
    dprintf(fd, "    Current client UID %u\n", getClientUid());

    dprintf(fd, "    State:\n");
    dprintf(fd, "      Request ID counter: %d\n", mRequestIdCounter);
    if (mInputStream.configured) {
        dprintf(fd, "      Current input stream ID: %d\n", mInputStream.id);
    } else {
        dprintf(fd, "      No input stream configured.\n");
    }
    if (!mStreamMap.isEmpty()) {
        dprintf(fd, "      Current output stream/surface IDs:\n");
        for (size_t i = 0; i < mStreamMap.size(); i++) {
            dprintf(fd, "        Stream %d Surface %d\n",
                                mStreamMap.valueAt(i).streamId(),
                                mStreamMap.valueAt(i).surfaceId());
        }
    } else if (!mDeferredStreams.isEmpty()) {
        dprintf(fd, "      Current deferred surface output stream IDs:\n");
        for (auto& streamId : mDeferredStreams) {
            dprintf(fd, "        Stream %d\n", streamId);
        }
    } else {
        dprintf(fd, "      No output streams configured.\n");
    }
    // TODO: print dynamic/request section from most recent requests
    if (!ignoreResult) {
        mFrameProcessor->dump(fd, args);
    }

    return dumpDevice(fd, args);
}

status_t CameraDeviceClient::startWatchingTags(const std::string &tags, int out) {
    sp<CameraDeviceBase> device = mDevice;
    if (!device) {
        dprintf(out, "  Device is detached.");
        return OK;
    }
    device->startWatchingTags(tags);
    return OK;
}

status_t CameraDeviceClient::stopWatchingTags(int out) {
    sp<CameraDeviceBase> device = mDevice;
    if (!device) {
        dprintf(out, "  Device is detached.");
        return OK;
    }
    device->stopWatchingTags();
    return OK;
}

status_t CameraDeviceClient::dumpWatchedEventsToVector(std::vector<std::string> &out) {
    sp<CameraDeviceBase> device = mDevice;
    if (!device) {
        return OK;
    }
    device->dumpWatchedEventsToVector(out);
    return OK;
}

void CameraDeviceClient::notifyError(int32_t errorCode,
                                     const CaptureResultExtras& resultExtras) {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();
    bool skipClientNotification = false;
    if (mSharedMode && (resultExtras.requestId != -1)) {
        int clientReqId;
        bool matchStreamingRequest = matchSharedStreamingRequest(resultExtras.requestId);
        bool matchCaptureRequest = matchSharedCaptureRequest(resultExtras.requestId);
        if (matchStreamingRequest) {
            clientReqId = mSharedStreamingRequest.second;
        } else if (matchCaptureRequest) {
            clientReqId = mSharedRequestMap[resultExtras.requestId];
            mSharedRequestMap.erase(resultExtras.requestId);
        } else {
            return;
        }
        CaptureResultExtras mutableResultExtras = resultExtras;
        mutableResultExtras.requestId = clientReqId;
        if (remoteCb != 0) {
            remoteCb->onDeviceError(errorCode, mutableResultExtras);
        }
        return;
    }
    {
        // Access to the composite stream map must be synchronized
        Mutex::Autolock l(mCompositeLock);
        // Composites can have multiple internal streams. Error notifications coming from such
        // internal streams may need to remain within camera service.
        for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
            skipClientNotification |= mCompositeStreamMap.valueAt(i)->onError(errorCode,
                    resultExtras);
        }
    }

    if ((remoteCb != 0) && (!skipClientNotification)) {
        remoteCb->onDeviceError(errorCode, resultExtras);
    }
}

void CameraDeviceClient::notifyRepeatingRequestError(long lastFrameNumber) {
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();

    if (remoteCb != 0) {
        remoteCb->onRepeatingRequestError(lastFrameNumber, mStreamingRequestId);
    }

    Mutex::Autolock idLock(mStreamingRequestIdLock);
    mStreamingRequestId = REQUEST_ID_NONE;
}

void CameraDeviceClient::notifyIdle(
        int64_t requestCount, int64_t resultErrorCount, bool deviceError,
        std::pair<int32_t, int32_t> mostRequestedFpsRange,
        const std::vector<hardware::CameraStreamStats>& streamStats,
        int32_t errorState) {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();

    if (remoteCb != 0) {
        remoteCb->onDeviceIdle();
    }

    std::vector<hardware::CameraStreamStats> fullStreamStats = streamStats;
    {
        Mutex::Autolock l(mCompositeLock);
        for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
            hardware::CameraStreamStats compositeStats;
            mCompositeStreamMap.valueAt(i)->getStreamStats(&compositeStats);
            if (compositeStats.mWidth > 0) {
                fullStreamStats.push_back(compositeStats);
            }
        }
    }
    Camera2ClientBase::notifyIdleWithUserTag(requestCount, resultErrorCount, deviceError,
            mostRequestedFpsRange,
            fullStreamStats,
            mRunningSessionStats.mUserTag,
            mRunningSessionStats.mVideoStabilizationMode,
            mRunningSessionStats.mUsedUltraWide,
            mRunningSessionStats.mUsedSettingsOverrideZoom, errorState);
}

void CameraDeviceClient::notifyShutter(const CaptureResultExtras& resultExtras,
        nsecs_t timestamp) {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();
    CaptureResultExtras mutableResultExtras = resultExtras;
    if (mSharedMode) {
        int clientReqId;
        bool matchStreamingRequest = matchSharedStreamingRequest(resultExtras.requestId);
        bool matchCaptureRequest = matchSharedCaptureRequest(resultExtras.requestId);
        if (matchStreamingRequest) {
            clientReqId = mSharedStreamingRequest.second;
        } else if (matchCaptureRequest) {
            clientReqId = mSharedRequestMap[resultExtras.requestId];
        } else {
            return;
        }
        mutableResultExtras.requestId = clientReqId;
    }

    if (remoteCb != 0) {
        remoteCb->onCaptureStarted(mutableResultExtras, timestamp);
    }
    Camera2ClientBase::notifyShutter(mutableResultExtras, timestamp);
    if (mSharedMode) {
        // When camera is opened in shared mode, composite streams are not
        // supported.
        return;
    }

    // Access to the composite stream map must be synchronized
    Mutex::Autolock l(mCompositeLock);
    for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
        mCompositeStreamMap.valueAt(i)->onShutter(resultExtras, timestamp);
    }
}

void CameraDeviceClient::notifyPrepared(int streamId) {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();
    if (remoteCb != 0) {
        ALOGV("%s: stream id %d", __FUNCTION__, streamId);
        remoteCb->onPrepared(streamId);
    }
}

void CameraDeviceClient::notifyRequestQueueEmpty() {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();
    if (remoteCb != 0) {
        remoteCb->onRequestQueueEmpty();
    }
}

void CameraDeviceClient::notifyClientSharedAccessPriorityChanged(bool primaryClient) {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();
    if (remoteCb != 0) {
        remoteCb->onClientSharedAccessPriorityChanged(primaryClient);
    }
}

void CameraDeviceClient::detachDevice() {
    if (mDevice == 0) return;

    nsecs_t startTime = systemTime();
    if (mFrameProcessor.get() != nullptr) {
            mFrameProcessor->removeListener(
                    camera2::FrameProcessorBase::FRAME_PROCESSOR_LISTENER_MIN_ID,
                    camera2::FrameProcessorBase::FRAME_PROCESSOR_LISTENER_MAX_ID, /*listener*/this);
    }

    if (!mSharedMode ||
            (mSharedMode && sCameraService->isOnlyClient(this))){
        ALOGV("Camera %s: Stopping processors", mCameraIdStr.c_str());

        if (mFrameProcessor.get() != nullptr) {
            mFrameProcessor->requestExit();
            ALOGV("Camera %s: Waiting for threads", mCameraIdStr.c_str());
            mFrameProcessor->join();
            ALOGV("Camera %s: Disconnecting device", mCameraIdStr.c_str());
        }

        // WORKAROUND: HAL refuses to disconnect while there's streams in flight
        {
            int64_t lastFrameNumber;
            status_t code;
            if ((code = mDevice->flush(&lastFrameNumber)) != OK) {
                ALOGE("%s: flush failed with code 0x%x", __FUNCTION__, code);
            }

            if ((code = mDevice->waitUntilDrained()) != OK) {
                ALOGE("%s: waitUntilDrained failed with code 0x%x", __FUNCTION__,
                        code);
            }
        }

        {
            Mutex::Autolock l(mCompositeLock);
            for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
                auto ret = mCompositeStreamMap.valueAt(i)->deleteInternalStreams();
                if (ret != OK) {
                    ALOGE("%s: Failed removing composite stream  %s (%d)", __FUNCTION__,
                            strerror(-ret), ret);
                }
            }
            mCompositeStreamMap.clear();
        }
    }

    if (mSharedMode) {
        for (auto streamInfo : mStreamInfoMap) {
            int streamToDelete = streamInfo.first;
            std::vector<size_t> removedSurfaceIds;
            for (size_t i = 0; i < mStreamMap.size(); ++i) {
                if (streamToDelete == mStreamMap.valueAt(i).streamId()) {
                    removedSurfaceIds.push_back(mStreamMap.valueAt(i).surfaceId());
                }
            }
            status_t err = mDevice->removeSharedSurfaces(streamToDelete, removedSurfaceIds);
            if (err != OK) {
                std::string msg = fmt::sprintf("Camera %s: Unexpected error %s (%d) when removing"
                        "shared surfaces from stream %d", mCameraIdStr.c_str(), strerror(-err),
                        err, streamToDelete);
                ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            }
        }
    }

    bool hasDeviceError = mDevice->hasDeviceError();
    int32_t deviceErrorState = mDevice->getErrorState();
    Camera2ClientBase::detachDevice();

    int32_t closeLatencyMs = ns2ms(systemTime() - startTime);
    mCameraServiceProxyWrapper->logClose(mCameraIdStr, closeLatencyMs, hasDeviceError,
        deviceErrorState);
}

size_t CameraDeviceClient::writeResultMetadataIntoResultQueue(
        const CameraMetadata &resultMetadata) {
    ATRACE_CALL();

    const camera_metadata_t *resultMetadataP = resultMetadata.getAndLock();
    size_t resultSize = get_camera_metadata_size(resultMetadataP);
    if (mResultMetadataQueue != nullptr &&
        mResultMetadataQueue->write(reinterpret_cast<const int8_t*>(resultMetadataP),
                resultSize)) {
        resultMetadata.unlock(resultMetadataP);
        return resultSize;
    }
    resultMetadata.unlock(resultMetadataP);
    ALOGE(" %s couldn't write metadata into result queue, result size %zu, "
        "fmq availableToWrite %zu ", __FUNCTION__, resultSize,
        mResultMetadataQueue->availableToWrite());
    return 0;
}

/** Device-related methods */
std::vector<PhysicalCaptureResultInfo> CameraDeviceClient::convertToFMQ(
        const std::vector<PhysicalCaptureResultInfo> &physicalResults) {
    std::vector<PhysicalCaptureResultInfo> retVal;
    ALOGVV("%s E", __FUNCTION__);
    for (const auto &srcPhysicalResult : physicalResults) {
        size_t fmqSize = 0;
        if (!mIsVendorClient) {
            fmqSize = writeResultMetadataIntoResultQueue(
                    srcPhysicalResult.mCameraMetadataInfo.get<CameraMetadataInfo::metadata>());
        }
        ALOGVV("%s physical metadata write size is %d", __FUNCTION__, (int)fmqSize);
        if (fmqSize != 0) {
            retVal.emplace_back(srcPhysicalResult.mPhysicalCameraId, fmqSize);
        } else {
            // The flag was off / we're serving VNDK shim call or FMQ write failed.
            retVal.emplace_back(srcPhysicalResult.mPhysicalCameraId,
                    srcPhysicalResult.mCameraMetadataInfo.get<CameraMetadataInfo::metadata>());
        }
    }
    ALOGVV("%s X", __FUNCTION__);
    return retVal;
}

bool CameraDeviceClient::matchSharedStreamingRequest(int reqId) {
    if (!mSharedMode) {
        return false;
    }
    // In shared mode, check if the result req id matches the streaming request
    // sent by client.
    if (reqId == mSharedStreamingRequest.first) {
        return true;
    }
    return false;
}

bool CameraDeviceClient::matchSharedCaptureRequest(int reqId) {
    if (!mSharedMode) {
        return false;
    }
    // In shared mode, only primary clients can send the capture request. If the
    // result req id does not match the streaming request id, check against the
    // capture request ids sent by the primary client.
    if (mIsPrimaryClient) {
        auto iter = mSharedRequestMap.find(reqId);
        if (iter != mSharedRequestMap.end()) {
            return true;
        }
    }
    return false;
}

void CameraDeviceClient::onResultAvailable(const CaptureResult& result) {
    ATRACE_CALL();
    ALOGVV("%s E", __FUNCTION__);
    CaptureResult mutableResult = result;
    bool matchStreamingRequest, matchCaptureRequest, sharedStreamingLastFrame;
    if (mSharedMode) {
        int clientReqId;
        matchStreamingRequest = matchSharedStreamingRequest(result.mResultExtras.requestId);
        matchCaptureRequest = matchSharedCaptureRequest(result.mResultExtras.requestId);
        if (matchStreamingRequest) {
            clientReqId = mSharedStreamingRequest.second;
            // When a client stops streaming using cancelRequest, we still need to deliver couple
            // more capture results to the client, till the lastframe number returned by the
            // cancelRequest. Therefore, only clean the shared streaming request once all the frames for
            // the repeating request have been delivered to the client.
            sharedStreamingLastFrame = (mStreamingRequestId == REQUEST_ID_NONE)
                    && (result.mResultExtras.frameNumber >= mStreamingRequestLastFrameNumber);
            if (sharedStreamingLastFrame) {
                mSharedStreamingRequest.first = REQUEST_ID_NONE;
                mSharedStreamingRequest.second = REQUEST_ID_NONE;
            }
        } else if (matchCaptureRequest) {
            clientReqId = mSharedRequestMap[result.mResultExtras.requestId];
            mSharedRequestMap.erase(result.mResultExtras.requestId);
        } else {
            return;
        }
        mutableResult.mResultExtras.requestId = clientReqId;
        if (mutableResult.mMetadata.update(ANDROID_REQUEST_ID, &clientReqId, 1) != OK) {
            ALOGE("%s Failed to set request ID in metadata.", __FUNCTION__);
            return;
        }
    }

    // Thread-safe. No lock necessary.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = mRemoteCallback;
    if (remoteCb != NULL) {
        // Write  result metadata into metadataQueue
        size_t fmqMetadataSize = 0;
        // Vendor clients need to modify metadata and also this call is in process
        // before going through FMQ to vendor clients. So don't use FMQ here.
        if (!mIsVendorClient) {
            fmqMetadataSize = writeResultMetadataIntoResultQueue(mutableResult.mMetadata);
        }
        hardware::camera2::impl::CameraMetadataNative resultMetadata;
        CameraMetadataInfo resultInfo;
        if (fmqMetadataSize == 0) {
            // The flag was off / we're serving VNDK shim call or FMQ write failed.
            resultMetadata = mutableResult.mMetadata;
            resultInfo.set<CameraMetadataInfo::metadata>(resultMetadata);
        } else {
            resultInfo.set<CameraMetadataInfo::fmqSize>(fmqMetadataSize);
        }

        std::vector<PhysicalCaptureResultInfo> physicalMetadatas =
                convertToFMQ(mutableResult.mPhysicalMetadatas);

        remoteCb->onResultReceived(resultInfo, mutableResult.mResultExtras,
                physicalMetadatas);
        if (mSharedMode) {
            // If all the capture requests for this client has been processed,
            // send onDeviceidle callback.
            if ((mSharedStreamingRequest.first == REQUEST_ID_NONE) && mSharedRequestMap.empty() ) {
                markClientIdle();
            }
        }
    }

    // Access to the composite stream map must be synchronized
    Mutex::Autolock l(mCompositeLock);
    for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
        mCompositeStreamMap.valueAt(i)->onResultAvailable(mutableResult);
    }
    ALOGVV("%s X", __FUNCTION__);
}

void CameraDeviceClient::markClientActive() {
    Mutex::Autolock l(mDevice->mSharedDeviceActiveLock);
    if (mDeviceActive) {
        // Already in active state.
        return;
    }
    status_t res = startCameraStreamingOps();
    if (res != OK) {
        ALOGE("%s: Camera %s: Error starting camera streaming ops: %d", __FUNCTION__,
                mCameraIdStr.c_str(), res);
    }
    mDeviceActive = true;
}

void CameraDeviceClient::markClientIdle() {
    Mutex::Autolock l(mDevice->mSharedDeviceActiveLock);
    if (!mDeviceActive) {
        // Already in idle state.
        return;
    }
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = mRemoteCallback;
    if (remoteCb != NULL) {
        remoteCb->onDeviceIdle();
    }
    status_t res = finishCameraStreamingOps();
    if (res != OK) {
        ALOGE("%s: Camera %s: Error finishing streaming ops: %d", __FUNCTION__,
                mCameraIdStr.c_str(), res);
    }
    mDeviceActive = false;
}

binder::Status CameraDeviceClient::checkPidStatus(const char* checkLocation) {
    if (mDisconnected) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED,
                "The camera device has been disconnected");
    }
    status_t res = checkPid(checkLocation);
    return (res == OK) ? binder::Status::ok() :
            STATUS_ERROR(CameraService::ERROR_PERMISSION_DENIED,
                    "Attempt to use camera from a different process than original client");
}

// TODO: move to Camera2ClientBase
bool CameraDeviceClient::enforceRequestPermissions(CameraMetadata& metadata) {

    const int pid = getCallingPid();
    const int selfPid = getpid();
    camera_metadata_entry_t entry;

    /**
     * Mixin default important security values
     * - android.led.transmit = defaulted ON
     */
    CameraMetadata staticInfo = mDevice->info();
    entry = staticInfo.find(ANDROID_LED_AVAILABLE_LEDS);
    for(size_t i = 0; i < entry.count; ++i) {
        uint8_t led = entry.data.u8[i];

        switch(led) {
            case ANDROID_LED_AVAILABLE_LEDS_TRANSMIT: {
                uint8_t transmitDefault = ANDROID_LED_TRANSMIT_ON;
                if (!metadata.exists(ANDROID_LED_TRANSMIT)) {
                    metadata.update(ANDROID_LED_TRANSMIT,
                                    &transmitDefault, 1);
                }
                break;
            }
        }
    }

    // We can do anything!
    if (pid == selfPid) {
        return true;
    }

    /**
     * Permission check special fields in the request
     * - android.led.transmit = android.permission.CAMERA_DISABLE_TRANSMIT
     */
    entry = metadata.find(ANDROID_LED_TRANSMIT);
    if (entry.count > 0 && entry.data.u8[0] != ANDROID_LED_TRANSMIT_ON) {
        String16 permissionString =
            toString16("android.permission.CAMERA_DISABLE_TRANSMIT_LED");
        if (!checkCallingPermission(permissionString)) {
            const int uid = getCallingUid();
            ALOGE("Permission Denial: "
                  "can't disable transmit LED pid=%d, uid=%d", pid, uid);
            return false;
        }
    }

    return true;
}

const CameraMetadata &CameraDeviceClient::getStaticInfo(const std::string &cameraId) {
    if (mDevice->getId() == cameraId) {
        return mDevice->info();
    }
    return mDevice->infoPhysical(cameraId);
}

bool CameraDeviceClient::supportsUltraHighResolutionCapture(const std::string &cameraId) {
    const CameraMetadata &deviceInfo = getStaticInfo(cameraId);
    return SessionConfigurationUtils::supportsUltraHighResolutionCapture(deviceInfo);
}

bool CameraDeviceClient::isSensorPixelModeConsistent(
        const std::list<int> &streamIdList, const CameraMetadata &settings) {
    // First we get the sensorPixelMode from the settings metadata.
    int32_t sensorPixelMode = ANDROID_SENSOR_PIXEL_MODE_DEFAULT;
    camera_metadata_ro_entry sensorPixelModeEntry = settings.find(ANDROID_SENSOR_PIXEL_MODE);
    if (sensorPixelModeEntry.count != 0) {
        sensorPixelMode = sensorPixelModeEntry.data.u8[0];
        if (sensorPixelMode != ANDROID_SENSOR_PIXEL_MODE_DEFAULT &&
            sensorPixelMode != ANDROID_SENSOR_PIXEL_MODE_MAXIMUM_RESOLUTION) {
            ALOGE("%s: Request sensor pixel mode not is not one of the valid values %d",
                      __FUNCTION__, sensorPixelMode);
            return false;
        }
    }
    // Check whether each stream has max resolution allowed.
    bool consistent = true;
    for (auto it : streamIdList) {
        auto const streamInfoIt = mStreamInfoMap.find(it);
        if (streamInfoIt == mStreamInfoMap.end()) {
            ALOGE("%s: stream id %d not created, skipping", __FUNCTION__, it);
            return false;
        }
        consistent =
                streamInfoIt->second.sensorPixelModesUsed.find(sensorPixelMode) !=
                        streamInfoIt->second.sensorPixelModesUsed.end();
        if (!consistent) {
            ALOGE("sensorPixelMode used %i not consistent with configured modes", sensorPixelMode);
            for (auto m : streamInfoIt->second.sensorPixelModesUsed) {
                ALOGE("sensor pixel mode used list: %i", m);
            }
            break;
        }
    }

    return consistent;
}

binder::Status CameraDeviceClient::updateOutputConfigurations(
        const std::vector<int32_t>& streamIds,
        const std::vector<OutputConfiguration>& configurations) {
    ATRACE_CALL();
    binder::Status ret;
    if (!flags::seamless_transitions()) {
        ret = STATUS_ERROR(CameraService::ERROR_INVALID_OPERATION, "Unsupported operation!");
        return ret;
    }
    Mutex::Autolock icl(mBinderSerializationLock);

    if (!mDevice.get()) {
        return STATUS_ERROR(CameraService::ERROR_DISCONNECTED, "Camera device no longer alive");
    }

    if (configurations.empty()) {
        std::string msg = fmt::sprintf("Camera %s: Empty output configurations!",
                mCameraIdStr.c_str());
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    if (streamIds.size() != configurations.size()) {
        std::string msg = fmt::sprintf("Camera %s: Stream ids size: %zu doesn't match"
                " configurations size: %zu!", mCameraIdStr.c_str(), streamIds.size(),
                configurations.size());
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return STATUS_ERROR(CameraService::ERROR_ILLEGAL_ARGUMENT, msg.c_str());
    }

    for (size_t i = 0; i < streamIds.size(); i++) {
        int64_t lastRepeatingFrameNumber = -1;
        ret = updateOutputConfigurationLocked(streamIds[i], configurations[i],
                true/*replaceSurface*/, &lastRepeatingFrameNumber);
        if (!ret.isOk()) {
            return ret;
        }

        if (lastRepeatingFrameNumber >= 0) {
            Mutex::Autolock idLock(mStreamingRequestIdLock);
            if (mStreamingRequestId != REQUEST_ID_NONE) {
                mStreamingRequestId = REQUEST_ID_NONE;
            }
        }
    }

    return ret;
}

}  // namespace android
