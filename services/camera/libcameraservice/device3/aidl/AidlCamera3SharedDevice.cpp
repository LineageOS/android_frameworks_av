/*
 * Copyright (C) 2024 The Android Open Source Project
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
#define LOG_TAG "AidlCamera3-SharedDevice"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0
//#define LOG_NNDEBUG 0  // Per-frame verbose logging

#ifdef LOG_NNDEBUG
#define ALOGVV(...) ALOGV(__VA_ARGS__)
#else
#define ALOGVV(...) ((void)0)
#endif

// Convenience macro for transient errors
#define CLOGE(fmt, ...) ALOGE("Camera %s: %s: " fmt, mId.c_str(), __FUNCTION__, \
            ##__VA_ARGS__)

#define CLOGW(fmt, ...) ALOGW("Camera %s: %s: " fmt, mId.c_str(), __FUNCTION__, \
            ##__VA_ARGS__)

// Convenience macros for transitioning to the error state
#define SET_ERR(errorState, fmt, ...) setErrorState(   \
    android::framework::stats::CAMERA_ACTION_EVENT__ERROR_STATE__##errorState, \
    "%s: " fmt, __FUNCTION__,              \
    ##__VA_ARGS__)
#define SET_ERR_L(errorState, fmt, ...) setErrorStateLocked( \
    android::framework::stats::CAMERA_ACTION_EVENT__ERROR_STATE__##errorState, \
    "%s: " fmt, __FUNCTION__,                    \
    ##__VA_ARGS__)
#define DECODE_VALUE(decoder, type, var) \
  do { \
    if (decoder.get##type(var) != OK) { \
      return NOT_ENOUGH_DATA; \
    } \
  } while (0)

#include <gui/BufferItemConsumer.h>
#include <utils/Log.h>
#include <utils/Trace.h>
#include <cstring>
#include <statslog_framework.h>
#include "../../common/aidl/AidlProviderInfo.h"
#include "utils/SessionConfigurationUtils.h"

#include "AidlCamera3SharedDevice.h"

using namespace android::camera3;
using namespace android::camera3::SessionConfigurationUtils;

namespace android {

class OpaqueConsumerListener : public BufferItemConsumer::FrameAvailableListener {
public:
    OpaqueConsumerListener(const wp<BufferItemConsumer>& consumer) : mConsumer(consumer) {}

    virtual void onFrameAvailable(const BufferItem&) {
        sp<BufferItemConsumer> consumer = mConsumer.promote();
        if (consumer == nullptr) {
            return;
        }
        BufferItem item;
        consumer->acquireBuffer(&item, 0);
        consumer->releaseBuffer(item, Fence::NO_FENCE);
    }
    virtual void onFrameReplaced(const BufferItem&) {}
    virtual void onFrameDequeued(const uint64_t) {}
    virtual void onFrameCancelled(const uint64_t) {}
    virtual void onFrameDetached(const uint64_t) {}

    wp<BufferItemConsumer> mConsumer;
};

// Metadata android.info.availableSharedOutputConfigurations has list of shared output
// configurations. Each output configuration has minimum of 11 entries of size long
// followed by the physical camera id if present.
// See android.info.availableSharedOutputConfigurations for details.
static const int SHARED_OUTPUT_CONFIG_NUM_OF_ENTRIES = 11;
std::map<std::string, sp<AidlCamera3SharedDevice>> AidlCamera3SharedDevice::sSharedDevices;
std::map<std::string, std::unordered_set<int>> AidlCamera3SharedDevice::sClientsPid;
Mutex AidlCamera3SharedDevice::sSharedClientsLock;
sp<AidlCamera3SharedDevice> AidlCamera3SharedDevice::getInstance(
        std::shared_ptr<CameraServiceProxyWrapper>& cameraServiceProxyWrapper,
        std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils,
        const std::string& id, bool overrideForPerfClass,
        const CameraCompatibilityInfo& compatInfo,
        bool isVendorClient, bool legacyClient) {
    Mutex::Autolock l(sSharedClientsLock);
    if (sClientsPid[id].empty()) {
        AidlCamera3SharedDevice* sharedDevice = new AidlCamera3SharedDevice(
                cameraServiceProxyWrapper, attributionAndPermissionUtils, id, overrideForPerfClass,
                compatInfo, isVendorClient, legacyClient);
        sSharedDevices[id] = sharedDevice;
    }
    if (attributionAndPermissionUtils != nullptr) {
        sClientsPid[id].insert(attributionAndPermissionUtils->getCallingPid());
    }
    return sSharedDevices[id];
}

status_t AidlCamera3SharedDevice::initialize(sp<CameraProviderManager> manager,
        const std::string& monitorTags) {
    ATRACE_CALL();
    status_t res = OK;
    Mutex::Autolock l(mSharedDeviceLock);
    if (mStatus == STATUS_UNINITIALIZED) {
        res = AidlCamera3Device::initialize(manager, monitorTags);
        if (res == OK) {
            mSharedOutputConfigurations = getSharedOutputConfiguration();
            wp<NotificationListener> weakThis(this);
            res = AidlCamera3Device::setNotifyCallback(weakThis);
            if (res != OK) {
                ALOGE("%s: Camera %s: Unable to set notify callback: %s (%d)",
                        __FUNCTION__, mId.c_str(), strerror(-res), res);
                return res;
            }
            mFrameProcessor = new camera2::FrameProcessorBase(this);
            std::string threadName = std::string("CDU-") + mId + "-FrameProc";
            res = mFrameProcessor->run(threadName.c_str());
            if (res != OK) {
                ALOGE("%s: Unable to start frame processor thread: %s (%d)",
                        __FUNCTION__, strerror(-res), res);
                return res;
            }
        }
    }
    return res;
}

status_t AidlCamera3SharedDevice::disconnectClient(int clientPid) {
    Mutex::Autolock l1(sSharedClientsLock);
    Mutex::Autolock l2(mSharedDeviceLock);
    if (sClientsPid[mId].erase(clientPid) == 0) {
        ALOGW("%s: Camera %s: Client %d is not connected to shared device", __FUNCTION__,
                mId.c_str(), clientPid);
    }

    if (sClientsPid[mId].empty()) {
        return Camera3Device::disconnect();
    }
    return OK;
}

std::vector<OutputConfiguration> AidlCamera3SharedDevice::getSharedOutputConfiguration() {
    std::vector<OutputConfiguration> sharedConfigs;
    int32_t colorspace = ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED;
    camera_metadata_entry sharedSessionColorSpace = mDeviceInfo.find(
            ANDROID_SHARED_SESSION_COLOR_SPACE);
    if (sharedSessionColorSpace.count > 0) {
        colorspace = *sharedSessionColorSpace.data.i32;
    }
    camera_metadata_entry sharedSessionConfigs = mDeviceInfo.find(
            ANDROID_SHARED_SESSION_OUTPUT_CONFIGURATIONS);
    if (sharedSessionConfigs.count > 0) {
        int numOfEntries = sharedSessionConfigs.count;
        int i = 0;
        uint8_t physicalCameraIdLen;
        int surfaceType, width, height, format, mirrorMode, timestampBase, dataspace;
        long usage, streamUseCase;
        bool isReadOutTimestampEnabled;
        while (numOfEntries >= SHARED_OUTPUT_CONFIG_NUM_OF_ENTRIES) {
            surfaceType = (int)sharedSessionConfigs.data.i64[i];
            width = (int)sharedSessionConfigs.data.i64[i+1];
            height = (int)sharedSessionConfigs.data.i64[i+2];
            format = (int)sharedSessionConfigs.data.i64[i+3];
            mirrorMode = (int)sharedSessionConfigs.data.i64[i+4];
            isReadOutTimestampEnabled = (sharedSessionConfigs.data.i64[i+5] != 0);
            timestampBase = (int)sharedSessionConfigs.data.i64[i+6];
            dataspace = (int)sharedSessionConfigs.data.i64[i+7];
            usage = sharedSessionConfigs.data.i64[i+8];
            streamUseCase = sharedSessionConfigs.data.i64[i+9];
            physicalCameraIdLen = sharedSessionConfigs.data.i64[i+10];
            numOfEntries -= SHARED_OUTPUT_CONFIG_NUM_OF_ENTRIES;
            i += SHARED_OUTPUT_CONFIG_NUM_OF_ENTRIES;
            if (numOfEntries < physicalCameraIdLen) {
                ALOGE("%s: Camera %s: Number of remaining data (%d entries) in shared configuration"
                        " is less than physical camera id length %d. Malformed metadata"
                        " android.info.availableSharedOutputConfigurations.", __FUNCTION__,
                        mId.c_str(), numOfEntries, physicalCameraIdLen);
                break;
            }
            std::string physicalCameraId;
            long asciiValue;
            for (int j = 0; j < physicalCameraIdLen; j++) {
                asciiValue = sharedSessionConfigs.data.i64[i+j];
                if (asciiValue == 0) { // Check for null terminator
                    break;
                }
                physicalCameraId += static_cast<char>(asciiValue);
            }
            OutputConfiguration* outConfig = new OutputConfiguration(surfaceType, width, height,
                    format, colorspace, mirrorMode, isReadOutTimestampEnabled, timestampBase,
                    dataspace, usage, streamUseCase, physicalCameraId);
            sharedConfigs.push_back(*outConfig);
            i += physicalCameraIdLen;
            numOfEntries -= physicalCameraIdLen;
        }
        if (numOfEntries != 0) {
            ALOGE("%s: Camera %s: there are still %d entries left in shared output configuration."
                    " Malformed metadata android.info.availableSharedOutputConfigurations.",
                    __FUNCTION__, mId.c_str(), numOfEntries);
        }
    }
    return sharedConfigs;
}

status_t AidlCamera3SharedDevice::beginConfigure() {
    Mutex::Autolock l(mSharedDeviceLock);
    status_t res;
    int i = 0;

    if (mStatus != STATUS_UNCONFIGURED) {
        return OK;
    }

    mSharedSurfaces.clear();
    mOpaqueConsumers.clear();
    mSharedSurfaceIds.clear();
    mStreamInfoMap.clear();

    for (auto config : mSharedOutputConfigurations) {
        std::vector<SurfaceHolder> consumers;
        android_dataspace dataspace = (android_dataspace)config.getDataspace();

        if (config.getColorSpace()
                != ANDROID_REQUEST_AVAILABLE_COLOR_SPACE_PROFILES_MAP_UNSPECIFIED
                && config.getFormat() != HAL_PIXEL_FORMAT_BLOB) {
            if (!dataSpaceFromColorSpace(&dataspace, config.getColorSpace())) {
                std::string msg = fmt::sprintf("Camera %s: color space %d not supported, "
                    " failed to convert to data space", mId.c_str(), config.getColorSpace());
                ALOGE("%s: %s", __FUNCTION__, msg.c_str());
                return INVALID_OPERATION;
            }
        }
        std::unordered_set<int32_t> overriddenSensorPixelModes;
        if (checkAndOverrideSensorPixelModesUsed(config.getSensorPixelModesUsed(),
                config.getFormat(), config.getWidth(), config.getHeight(),
                mDeviceInfo, &overriddenSensorPixelModes) != OK) {
            std::string msg = fmt::sprintf("Camera %s: sensor pixel modes for stream with "
                        "format %#x are not valid",mId.c_str(), config.getFormat());
            ALOGE("%s: %s", __FUNCTION__, msg.c_str());
            return INVALID_OPERATION;
        }

        auto [consumer, surface] = BufferItemConsumer::create(AHARDWAREBUFFER_USAGE_CAMERA_READ);
        mOpaqueConsumers.push_back(consumer);
        mSharedSurfaces.push_back(surface);

        sp<OpaqueConsumerListener> consumerListener = sp<OpaqueConsumerListener>::make(
                mOpaqueConsumers[i]);
        mOpaqueConsumers[i]->setFrameAvailableListener(consumerListener);
        consumers.push_back({mSharedSurfaces[i], config.getMirrorMode()});
        sp<Camera3SharedOutputStream> newStream = new Camera3SharedOutputStream(mNextStreamId, consumers,
                config.getWidth(),config.getHeight(), config.getFormat(), config.getUsage(),
                dataspace, static_cast<camera_stream_rotation_t>(config.getRotation()),
                mTimestampOffset, config.getPhysicalCameraId(), overriddenSensorPixelModes,
                getTransportType(), config.getSurfaceSetID(), mUseHalBufManager,
                config.getDynamicRangeProfile(), config.getStreamUseCase(),
                mDeviceTimeBaseIsRealtime, config.getTimestampBase(),
                config.getColorSpace(), config.useReadoutTimestamp());
        int id = newStream->getSurfaceId(consumers[0].mSurface);
        if (id < 0) {
            SET_ERR_L(CAMERA_SERVICE_INTERNAL_ERROR,
             "Invalid surface id");
            return BAD_VALUE;
        }
        mSharedSurfaceIds.push_back(id);
        newStream->setStatusTracker(mStatusTracker);
        newStream->setBufferManager(mBufferManager);
        newStream->setImageDumpMask(mImageDumpMask);
        res = mOutputStreams.add(mNextStreamId, newStream);
        if (res < 0) {
            SET_ERR_L(CAMERA_SERVICE_INTERNAL_ERROR,
            "Can't add new stream to set: %s (%d)", strerror(-res), res);
            return res;
        }
        mSessionStatsBuilder.addStream(mNextStreamId);
        OutputStreamInfo streamInfo(config.getWidth(),config.getHeight(), config.getFormat(),
                dataspace, config.getUsage(), overriddenSensorPixelModes,
                config.getDynamicRangeProfile(), config.getStreamUseCase(),
                config.getTimestampBase(), config.getColorSpace());
        mStreamInfoMap[mNextStreamId++] = streamInfo;
        i++;
    }
    CameraMetadata sessionParams;
    res = configureStreams(sessionParams, CAMERA_STREAM_CONFIGURATION_NORMAL_MODE);
    if (res != OK) {
        std::string msg = fmt::sprintf("Camera %s: Error configuring streams: %s (%d)",
                mId.c_str(), strerror(-res), res);
        ALOGE("%s: %s", __FUNCTION__, msg.c_str());
        return res;
    }
    return OK;
}

status_t AidlCamera3SharedDevice::getSharedStreamIds(const OutputStreamInfo &config,
        std::vector<int>& streamIds) {
    Mutex::Autolock l(mSharedDeviceLock);
    streamIds.clear();

    for (const auto& streamInfo : mStreamInfoMap) {
        OutputStreamInfo info = streamInfo.second;
        if (info == config) {
            streamIds.push_back(streamInfo.first);
        }
    }

    if (streamIds.empty()) {
        return NAME_NOT_FOUND;
    } else  {
        return OK;
    }
}

status_t AidlCamera3SharedDevice::addSharedSurfaces(int streamId,
        const std::vector<android::camera3::OutputStreamInfo> &outputInfo,
        const std::vector<SurfaceHolder> &surfaces,  std::vector<int> *surfaceIds) {
    Mutex::Autolock l(mSharedDeviceLock);
    KeyedVector<sp<Surface>, size_t> outputMap;
    std::vector<size_t> removedSurfaceIds;
    status_t res;
    sp<Camera3OutputStreamInterface> stream = mOutputStreams.get(streamId);
    if (stream == nullptr) {
        CLOGE("Stream %d is unknown", streamId);
        return BAD_VALUE;
    }

    res = updateStream(streamId, surfaces, outputInfo, removedSurfaceIds, false /*replaceEnabled*/,
            &outputMap);
    if (res != OK) {
        CLOGE("Stream %d failed to update stream (error %d %s) ",
              streamId, res, strerror(-res));
        return res;
    }
    for (size_t i = 0 ; i < outputMap.size(); i++){
        if (surfaceIds != nullptr) {
            surfaceIds->push_back(outputMap.valueAt(i));
        }
    }
    return OK;
}

status_t AidlCamera3SharedDevice::removeSharedSurfaces(int streamId,
        const std::vector<size_t> &removedSurfaceIds) {
    Mutex::Autolock l(mSharedDeviceLock);
    KeyedVector<sp<Surface>, size_t> outputMap;
    std::vector<SurfaceHolder> surfaces;
    std::vector<OutputStreamInfo> outputInfo;
    status_t res;
    sp<Camera3OutputStreamInterface> stream = mOutputStreams.get(streamId);
    if (stream == nullptr) {
        CLOGE("Stream %d is unknown", streamId);
        return BAD_VALUE;
    }

    res = updateStream(streamId, surfaces, outputInfo, removedSurfaceIds, false /*replaceEnabled*/,
            &outputMap);
    if (res != OK) {
        CLOGE("Stream %d failed to update stream (error %d %s) ",
              streamId, res, strerror(-res));
        return res;
    }
    return OK;
}

SurfaceMap AidlCamera3SharedDevice::mergeSurfaceMaps(const SurfaceMap& map1,
        const SurfaceMap& map2) {
    SurfaceMap mergedMap = map1;

    for (const auto& [key, value] : map2) {
        // If the key exists in map1, append the values
        if (mergedMap.count(key) > 0) {
            mergedMap[key].insert(mergedMap[key].end(), value.begin(), value.end());
        } else {
            // Otherwise, insert the key-value pair from map2
            mergedMap[key] = value;
        }
    }
    return mergedMap;
}

SurfaceMap AidlCamera3SharedDevice::removeClientSurfaceMap(const SurfaceMap& map1,
        const SurfaceMap& map2) {
    SurfaceMap resultMap = map1;

    for (const auto& [key, value2] : map2) {
        auto it1 = resultMap.find(key);
        if (it1 != resultMap.end()) {
            // Key exists in both maps, remove matching values
            std::vector<size_t>& value1 = it1->second;
            for (size_t val2 : value2) {
                value1.erase(std::remove(value1.begin(), value1.end(), val2), value1.end());
            }

            // If the vector is empty after removing, remove the key
            if (value1.empty()) {
                resultMap.erase(it1);
            }
        }
    }
    return resultMap;
}

status_t AidlCamera3SharedDevice::setSharedStreamingRequest(
        const CameraDeviceBase::PhysicalCameraSettingsList &clientSettings,
        const SurfaceMap &surfaceMap, int32_t *sharedReqID,
        int64_t *lastFrameNumber) {
    if ((sharedReqID == nullptr) || (lastFrameNumber == nullptr)) {
        return BAD_VALUE;
    }

    Mutex::Autolock l(mSharedDeviceLock);
    auto requestIdEntry = clientSettings.begin()->metadata.find(ANDROID_REQUEST_ID);
    if (requestIdEntry.count == 0) {
        CLOGE("RequestID does not exist in metadata");
        return BAD_VALUE;
    }
    int clientRequestId = requestIdEntry.data.i32[0];
    CameraDeviceBase::PhysicalCameraSettingsList newSettings = clientSettings;
    SurfaceMap newSurfaceMap = surfaceMap;
    List<const CameraDeviceBase::PhysicalCameraSettingsList> settingsList;
    std::list<SurfaceMap> surfaceMaps;
    int32_t requestID = mRequestIdCounter;
    const sp<CaptureRequest> curRequest = getOngoingRepeatingRequestLocked();

    if (curRequest != nullptr) {
        // If there is ongoing streaming going by secondary clients, then
        // merge their surface map in the new repeating request.
        newSurfaceMap = mergeSurfaceMaps(surfaceMap, curRequest->mOutputSurfaces);
    }

    std::vector<int32_t> outputStreamIds;
    for (const auto& [key, value] : newSurfaceMap) {
        outputStreamIds.push_back(key);
    }
    surfaceMaps.push_back(newSurfaceMap);
    newSettings.begin()->metadata.update(ANDROID_REQUEST_ID, &requestID, /*size*/1);
    mRequestIdCounter++;
    newSettings.begin()->metadata.update(ANDROID_REQUEST_OUTPUT_STREAMS,
            &outputStreamIds[0], outputStreamIds.size());
    settingsList.push_back(newSettings);
    status_t  err = setStreamingRequestList(settingsList, surfaceMaps, lastFrameNumber);
    if (err != OK) {
        CLOGE("Cannot start shared streaming request");
        return err;
    }
    mStreamingRequestId = requestID;
    int clientPid = mAttributionAndPermissionUtils->getCallingPid();
    mClientRequestIds[clientPid] = clientRequestId;
    mClientSurfaces[clientPid] = surfaceMap;
    *sharedReqID = mStreamingRequestId;

    return err;
}

status_t AidlCamera3SharedDevice::clearSharedStreamingRequest(int64_t *lastFrameNumber) {
    Mutex::Autolock l(mSharedDeviceLock);
    int clientPid = mAttributionAndPermissionUtils->getCallingPid();
    const sp<CaptureRequest> curRequest = getOngoingRepeatingRequestLocked();
    if (curRequest == nullptr) {
        CLOGE("No streaming ongoing");
        return INVALID_OPERATION;
    }

    SurfaceMap newSurfaceMap;
    newSurfaceMap = removeClientSurfaceMap(curRequest->mOutputSurfaces, mClientSurfaces[clientPid]);
    mClientRequestIds.erase(clientPid);
    mClientSurfaces.erase(clientPid);
    if (newSurfaceMap.empty()) {
        status_t err = clearStreamingRequest(lastFrameNumber);
        if (err != OK) {
            CLOGE("Error clearing streaming request");
        }
        return err;
    }
    *lastFrameNumber = getRepeatingRequestLastFrameNumberLocked();
    return updateOngoingRepeatingRequestLocked(newSurfaceMap);
}

status_t AidlCamera3SharedDevice::setSharedCaptureRequest(const PhysicalCameraSettingsList &request,
        const SurfaceMap &surfaceMap, int32_t *sharedReqID, int64_t *lastFrameNumber) {
    Mutex::Autolock l(mSharedDeviceLock);
    if (sharedReqID == nullptr) {
        return BAD_VALUE;
    }
    CameraDeviceBase::PhysicalCameraSettingsList newRequest = request;
    int newReqID = mRequestIdCounter;
    List<const CameraDeviceBase::PhysicalCameraSettingsList> settingsList;
    std::list<SurfaceMap> surfaceMaps;
    surfaceMaps.push_back(surfaceMap);
    newRequest.begin()->metadata.update(ANDROID_REQUEST_ID, &newReqID, /*size*/1);
    settingsList.push_back(newRequest);
    mRequestIdCounter++;
    status_t err = captureList(settingsList, surfaceMaps, lastFrameNumber);
    if (err != OK) {
        CLOGE("Cannot start shared capture request");
        return err;
    }
    *sharedReqID = newReqID;

    return err;
}

status_t AidlCamera3SharedDevice::startStreaming(const int32_t reqId, const SurfaceMap& surfaceMap,
        int32_t* sharedReqID, int64_t* lastFrameNumber) {
    ATRACE_CALL();

    if ((sharedReqID == nullptr) || (lastFrameNumber ==  nullptr)) {
        return BAD_VALUE;
    }

    Mutex::Autolock l(mSharedDeviceLock);
    const sp<CaptureRequest> curRequest = getOngoingRepeatingRequestLocked();
    if (curRequest != nullptr) {
        // If there is already repeating request ongoing, attach the surfaces to
        // the request.
        SurfaceMap newSurfaceMap = mergeSurfaceMaps(surfaceMap, curRequest->mOutputSurfaces);
        updateOngoingRepeatingRequestLocked(newSurfaceMap);
        *lastFrameNumber = getRepeatingRequestLastFrameNumberLocked();
    } else {
        // If there is no ongoing repeating request, then send a default
        // request with template preview.
        std::vector<int32_t> outputStreamIds;
        for (const auto& [key, value] : surfaceMap) {
            outputStreamIds.push_back(key);
        }

        CameraMetadata previewTemplate;
        status_t err = createDefaultRequest(CAMERA_TEMPLATE_PREVIEW, &previewTemplate);
        if (err != OK) {
            ALOGE("%s: Failed to create default PREVIEW request: %s (%d)",
                    __FUNCTION__, strerror(-err), err);
            return err;
        }
        int32_t requestID = mRequestIdCounter;
        previewTemplate.update(ANDROID_REQUEST_ID, &requestID, /*size*/1);
        mRequestIdCounter++;
        previewTemplate.update(ANDROID_REQUEST_OUTPUT_STREAMS, &outputStreamIds[0],
                outputStreamIds.size());
        CameraDeviceBase::PhysicalCameraSettingsList previewSettings;
        previewSettings.push_back({mId, previewTemplate});

        List<const CameraDeviceBase::PhysicalCameraSettingsList> settingsList;
        std::list<SurfaceMap> surfaceMaps;
        settingsList.push_back(previewSettings);
        surfaceMaps.push_back(surfaceMap);
        err = setStreamingRequestList(settingsList, surfaceMaps, lastFrameNumber);
        if (err != OK) {
            CLOGE("Cannot start shared streaming request");
            return err;
        }
        mStreamingRequestId = requestID;
    }

    int clientPid = mAttributionAndPermissionUtils->getCallingPid();
    mClientRequestIds[clientPid] = reqId;
    mClientSurfaces[clientPid] = surfaceMap;
    *sharedReqID = mStreamingRequestId;
    return OK;
}

status_t AidlCamera3SharedDevice::setNotifyCallback(wp<NotificationListener> listener) {
    ATRACE_CALL();
    Mutex::Autolock l(mSharedDeviceLock);

    if (listener == NULL) {
        return BAD_VALUE;
    }
    mClientListeners[mAttributionAndPermissionUtils->getCallingPid()] = listener;
    return OK;
}

void AidlCamera3SharedDevice::notifyError(
        int32_t errorCode,
        const CaptureResultExtras& resultExtras) {
    for (auto clientListener : mClientListeners) {
        sp<NotificationListener> listener = clientListener.second.promote();
        if (listener != NULL) {
            listener->notifyError(errorCode, resultExtras);
        }
    }
}

status_t AidlCamera3SharedDevice::notifyActive(float maxPreviewFps) {
    Mutex::Autolock l(mSharedDeviceActiveLock);
    for (auto activeClient : mClientRequestIds) {
        sp<NotificationListener> listener =  mClientListeners[activeClient.first].promote();
        if (listener != NULL) {
            listener->notifyActive(maxPreviewFps);
        }
    }

    return OK;
}

void  AidlCamera3SharedDevice::notifyIdle(int64_t requestCount, int64_t resultErrorCount,
                                     bool deviceError,
                                     std::pair<int32_t, int32_t> mostRequestedFpsRange,
                                     const std::vector<hardware::CameraStreamStats>& stats,
                                     int32_t errorState) {
    Mutex::Autolock l(mSharedDeviceActiveLock);
    for (auto clientListener : mClientListeners) {
        sp<NotificationListener> listener =  clientListener.second.promote();
        if (listener != NULL) {
            listener->notifyIdle(requestCount, resultErrorCount, deviceError, mostRequestedFpsRange,
                    stats, errorState);
        }
    }
}

void  AidlCamera3SharedDevice::notifyShutter(const CaptureResultExtras& resultExtras,
        nsecs_t timestamp) {
    for (auto clientListener : mClientListeners) {
        sp<NotificationListener> listener =  clientListener.second.promote();
        if (listener != NULL) {
            listener->notifyShutter(resultExtras, timestamp);
        }
    }
}

}
