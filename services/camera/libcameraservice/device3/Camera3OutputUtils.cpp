/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "Camera3-OutputUtils"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0
//#define LOG_NNDEBUG 0  // Per-frame verbose logging

#ifdef LOG_NNDEBUG
#define ALOGVV(...) ALOGV(__VA_ARGS__)
#else
#define ALOGVV(...) ((void)0)
#endif

// Convenience macros for transitioning to the error state
#define SET_ERR(fmt, ...) states.setErrIntf.setErrorState(   \
    "%s: " fmt, __FUNCTION__,                         \
    ##__VA_ARGS__)

#include <inttypes.h>

#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/Trace.h>

#include <android/hardware/camera2/ICameraDeviceCallbacks.h>

#include <android/hardware/camera/device/3.4/ICameraDeviceCallback.h>
#include <android/hardware/camera/device/3.5/ICameraDeviceCallback.h>
#include <android/hardware/camera/device/3.5/ICameraDeviceSession.h>

#include <camera/CameraUtils.h>
#include <camera/StringUtils.h>
#include <camera_metadata_hidden.h>
#include <com_android_internal_camera_flags.h>

#include "device3/Camera3OutputUtils.h"
#include "utils/SessionConfigurationUtils.h"

#include "system/camera_metadata.h"

using namespace android::camera3;
using namespace android::camera3::SessionConfigurationUtils;
using namespace android::hardware::camera;
namespace flags = com::android::internal::camera::flags;

namespace android {
namespace camera3 {

status_t fixupMonochromeTags(
        CaptureOutputStates& states,
        const CameraMetadata& deviceInfo,
        CameraMetadata& resultMetadata) {
    status_t res = OK;
    if (!states.needFixupMonoChrome) {
        return res;
    }

    // Remove tags that are not applicable to monochrome camera.
    int32_t tagsToRemove[] = {
           ANDROID_SENSOR_GREEN_SPLIT,
           ANDROID_SENSOR_NEUTRAL_COLOR_POINT,
           ANDROID_COLOR_CORRECTION_MODE,
           ANDROID_COLOR_CORRECTION_TRANSFORM,
           ANDROID_COLOR_CORRECTION_GAINS,
    };
    for (auto tag : tagsToRemove) {
        res = resultMetadata.erase(tag);
        if (res != OK) {
            ALOGE("%s: Failed to remove tag %d for monochrome camera", __FUNCTION__, tag);
            return res;
        }
    }

    // ANDROID_SENSOR_DYNAMIC_BLACK_LEVEL
    camera_metadata_entry blEntry = resultMetadata.find(ANDROID_SENSOR_DYNAMIC_BLACK_LEVEL);
    for (size_t i = 1; i < blEntry.count; i++) {
        blEntry.data.f[i] = blEntry.data.f[0];
    }

    // ANDROID_SENSOR_NOISE_PROFILE
    camera_metadata_entry npEntry = resultMetadata.find(ANDROID_SENSOR_NOISE_PROFILE);
    if (npEntry.count > 0 && npEntry.count % 2 == 0) {
        double np[] = {npEntry.data.d[0], npEntry.data.d[1]};
        res = resultMetadata.update(ANDROID_SENSOR_NOISE_PROFILE, np, 2);
        if (res != OK) {
             ALOGE("%s: Failed to update SENSOR_NOISE_PROFILE: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    // ANDROID_STATISTICS_LENS_SHADING_MAP
    camera_metadata_ro_entry lsSizeEntry = deviceInfo.find(ANDROID_LENS_INFO_SHADING_MAP_SIZE);
    camera_metadata_entry lsEntry = resultMetadata.find(ANDROID_STATISTICS_LENS_SHADING_MAP);
    if (lsSizeEntry.count == 2 && lsEntry.count > 0
            && (int32_t)lsEntry.count == 4 * lsSizeEntry.data.i32[0] * lsSizeEntry.data.i32[1]) {
        for (int32_t i = 0; i < lsSizeEntry.data.i32[0] * lsSizeEntry.data.i32[1]; i++) {
            lsEntry.data.f[4*i+1] = lsEntry.data.f[4*i];
            lsEntry.data.f[4*i+2] = lsEntry.data.f[4*i];
            lsEntry.data.f[4*i+3] = lsEntry.data.f[4*i];
        }
    }

    // ANDROID_TONEMAP_CURVE_BLUE
    // ANDROID_TONEMAP_CURVE_GREEN
    // ANDROID_TONEMAP_CURVE_RED
    camera_metadata_entry tcbEntry = resultMetadata.find(ANDROID_TONEMAP_CURVE_BLUE);
    camera_metadata_entry tcgEntry = resultMetadata.find(ANDROID_TONEMAP_CURVE_GREEN);
    camera_metadata_entry tcrEntry = resultMetadata.find(ANDROID_TONEMAP_CURVE_RED);
    if (tcbEntry.count > 0
            && tcbEntry.count == tcgEntry.count
            && tcbEntry.count == tcrEntry.count) {
        for (size_t i = 0; i < tcbEntry.count; i++) {
            tcbEntry.data.f[i] = tcrEntry.data.f[i];
            tcgEntry.data.f[i] = tcrEntry.data.f[i];
        }
    }

    return res;
}

status_t fixupAutoframingTags(CameraMetadata& resultMetadata) {
    status_t res = OK;
    camera_metadata_entry autoframingEntry =
            resultMetadata.find(ANDROID_CONTROL_AUTOFRAMING);
    if (autoframingEntry.count == 0) {
        const uint8_t defaultAutoframingEntry = ANDROID_CONTROL_AUTOFRAMING_OFF;
        res = resultMetadata.update(ANDROID_CONTROL_AUTOFRAMING, &defaultAutoframingEntry, 1);
        if (res != OK) {
            ALOGE("%s: Failed to update ANDROID_CONTROL_AUTOFRAMING: %s (%d)",
                  __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    camera_metadata_entry autoframingStateEntry =
            resultMetadata.find(ANDROID_CONTROL_AUTOFRAMING_STATE);
    if (autoframingStateEntry.count == 0) {
        const uint8_t defaultAutoframingStateEntry = ANDROID_CONTROL_AUTOFRAMING_STATE_INACTIVE;
        res = resultMetadata.update(ANDROID_CONTROL_AUTOFRAMING_STATE,
                                    &defaultAutoframingStateEntry, 1);
        if (res != OK) {
            ALOGE("%s: Failed to update ANDROID_CONTROL_AUTOFRAMING_STATE: %s (%d)",
                  __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    return res;
}

status_t fixupManualFlashStrengthControlTags(CameraMetadata& resultMetadata) {
    status_t res = OK;
    camera_metadata_entry strengthLevelEntry =
            resultMetadata.find(ANDROID_FLASH_STRENGTH_LEVEL);
    if (strengthLevelEntry.count == 0) {
        const int32_t defaultStrengthLevelEntry = ANDROID_FLASH_STRENGTH_LEVEL;
        res = resultMetadata.update(ANDROID_FLASH_STRENGTH_LEVEL, &defaultStrengthLevelEntry, 1);
        if (res != OK) {
            ALOGE("%s: Failed to update ANDROID_FLASH_STRENGTH_LEVEL: %s (%d)",
                  __FUNCTION__, strerror(-res), res);
            return res;
        }
    }

    return res;
}

void correctMeteringRegions(camera_metadata_t *meta) {
    if (meta == nullptr) return;

    uint32_t meteringRegionKeys[] = {
            ANDROID_CONTROL_AE_REGIONS,
            ANDROID_CONTROL_AWB_REGIONS,
            ANDROID_CONTROL_AF_REGIONS };

    for (uint32_t key : meteringRegionKeys) {
        camera_metadata_entry_t entry;
        int res = find_camera_metadata_entry(meta, key, &entry);
        if (res != OK) continue;

        for (size_t i = 0; i < entry.count; i += 5) {
            if (entry.data.i32[0] > entry.data.i32[2]) {
                ALOGW("%s: Invalid metering region (%d): left: %d, right: %d",
                        __FUNCTION__, key, entry.data.i32[0], entry.data.i32[2]);
                entry.data.i32[2] = entry.data.i32[0];
            }
            if (entry.data.i32[1] > entry.data.i32[3]) {
                ALOGW("%s: Invalid metering region (%d): top: %d, bottom: %d",
                        __FUNCTION__, key, entry.data.i32[1], entry.data.i32[3]);
                entry.data.i32[3] = entry.data.i32[1];
            }
        }
    }
}

void insertResultLocked(CaptureOutputStates& states, CaptureResult *result, uint32_t frameNumber) {
    if (result == nullptr) return;

    camera_metadata_t *meta = const_cast<camera_metadata_t *>(
            result->mMetadata.getAndLock());
    set_camera_metadata_vendor_id(meta, states.vendorTagId);
    correctMeteringRegions(meta);
    result->mMetadata.unlock(meta);

    if (result->mMetadata.update(ANDROID_REQUEST_FRAME_COUNT,
            (int32_t*)&frameNumber, 1) != OK) {
        SET_ERR("Failed to set frame number %d in metadata", frameNumber);
        return;
    }

    if (result->mMetadata.update(ANDROID_REQUEST_ID, &result->mResultExtras.requestId, 1) != OK) {
        SET_ERR("Failed to set request ID in metadata for frame %d", frameNumber);
        return;
    }

    // Update vendor tag id for physical metadata
    for (auto& physicalMetadata : result->mPhysicalMetadatas) {
        camera_metadata_t *pmeta = const_cast<camera_metadata_t *>(
                physicalMetadata.mPhysicalCameraMetadata.getAndLock());
        set_camera_metadata_vendor_id(pmeta, states.vendorTagId);
        correctMeteringRegions(pmeta);
        physicalMetadata.mPhysicalCameraMetadata.unlock(pmeta);
    }

    // Valid result, insert into queue
    std::list<CaptureResult>::iterator queuedResult =
            states.resultQueue.insert(states.resultQueue.end(), CaptureResult(*result));
    ALOGV("%s: result requestId = %" PRId32 ", frameNumber = %" PRId64
           ", burstId = %" PRId32, __FUNCTION__,
           queuedResult->mResultExtras.requestId,
           queuedResult->mResultExtras.frameNumber,
           queuedResult->mResultExtras.burstId);

    states.resultSignal.notify_one();
}


void sendPartialCaptureResult(CaptureOutputStates& states,
        const camera_metadata_t * partialResult,
        const CaptureResultExtras &resultExtras, uint32_t frameNumber) {
    ATRACE_CALL();
    std::lock_guard<std::mutex> l(states.outputLock);

    CaptureResult captureResult;
    captureResult.mResultExtras = resultExtras;
    captureResult.mMetadata = partialResult;

    // Fix up result metadata for monochrome camera.
    status_t res = fixupMonochromeTags(states, states.deviceInfo, captureResult.mMetadata);
    if (res != OK) {
        SET_ERR("Failed to override result metadata: %s (%d)", strerror(-res), res);
        return;
    }

    // Update partial result by removing keys remapped by DistortionCorrection, ZoomRatio,
    // and RotationAndCrop mappers.
    std::set<uint32_t> keysToRemove;

    auto iter = states.distortionMappers.find(states.cameraId);
    if (iter != states.distortionMappers.end()) {
        const auto& remappedKeys = iter->second.getRemappedKeys();
        keysToRemove.insert(remappedKeys.begin(), remappedKeys.end());
    }

    const auto& remappedKeys = states.zoomRatioMappers[states.cameraId].getRemappedKeys();
    keysToRemove.insert(remappedKeys.begin(), remappedKeys.end());

    auto mapper = states.rotateAndCropMappers.find(states.cameraId);
    if (mapper != states.rotateAndCropMappers.end()) {
        const auto& remappedKeys = mapper->second.getRemappedKeys();
        keysToRemove.insert(remappedKeys.begin(), remappedKeys.end());
    }

    for (uint32_t key : keysToRemove) {
        captureResult.mMetadata.erase(key);
    }

    // Send partial result
    if (captureResult.mMetadata.entryCount() > 0) {
        insertResultLocked(states, &captureResult, frameNumber);
    }
}

void sendCaptureResult(
        CaptureOutputStates& states,
        CameraMetadata &pendingMetadata,
        CaptureResultExtras &resultExtras,
        CameraMetadata &collectedPartialResult,
        uint32_t frameNumber,
        bool reprocess, bool zslStillCapture, bool rotateAndCropAuto,
        const std::set<std::string>& cameraIdsWithZoom,
        const std::vector<PhysicalCaptureResultInfo>& physicalMetadatas) {
    ATRACE_CALL();
    if (pendingMetadata.isEmpty())
        return;

    std::lock_guard<std::mutex> l(states.outputLock);

    // TODO: need to track errors for tighter bounds on expected frame number
    if (reprocess) {
        if (frameNumber < states.nextReprocResultFrameNum) {
            SET_ERR("Out-of-order reprocess capture result metadata submitted! "
                "(got frame number %d, expecting %d)",
                frameNumber, states.nextReprocResultFrameNum);
            return;
        }
        states.nextReprocResultFrameNum = frameNumber + 1;
    } else if (zslStillCapture) {
        if (frameNumber < states.nextZslResultFrameNum) {
            SET_ERR("Out-of-order ZSL still capture result metadata submitted! "
                "(got frame number %d, expecting %d)",
                frameNumber, states.nextZslResultFrameNum);
            return;
        }
        states.nextZslResultFrameNum = frameNumber + 1;
    } else {
        if (frameNumber < states.nextResultFrameNum) {
            SET_ERR("Out-of-order capture result metadata submitted! "
                    "(got frame number %d, expecting %d)",
                    frameNumber, states.nextResultFrameNum);
            return;
        }
        states.nextResultFrameNum = frameNumber + 1;
    }

    CaptureResult captureResult;
    captureResult.mResultExtras = resultExtras;
    captureResult.mMetadata = pendingMetadata;
    captureResult.mPhysicalMetadatas = physicalMetadatas;

    // Append any previous partials to form a complete result
    if (states.usePartialResult && !collectedPartialResult.isEmpty()) {
        captureResult.mMetadata.append(collectedPartialResult);
    }

    captureResult.mMetadata.sort();

    // Check that there's a timestamp in the result metadata
    camera_metadata_entry timestamp = captureResult.mMetadata.find(ANDROID_SENSOR_TIMESTAMP);
    if (timestamp.count == 0) {
        SET_ERR("No timestamp provided by HAL for frame %d!",
                frameNumber);
        return;
    }
    nsecs_t sensorTimestamp = timestamp.data.i64[0];

    for (auto& physicalMetadata : captureResult.mPhysicalMetadatas) {
        camera_metadata_entry timestamp =
                physicalMetadata.mPhysicalCameraMetadata.find(ANDROID_SENSOR_TIMESTAMP);
        if (timestamp.count == 0) {
            SET_ERR("No timestamp provided by HAL for physical camera %s frame %d!",
                    physicalMetadata.mPhysicalCameraId.c_str(), frameNumber);
            return;
        }
    }

    // Fix up some result metadata to account for HAL-level distortion correction
    status_t res = OK;
    auto iter = states.distortionMappers.find(states.cameraId);
    if (iter != states.distortionMappers.end()) {
        res = iter->second.correctCaptureResult(&captureResult.mMetadata);
        if (res != OK) {
            SET_ERR("Unable to correct capture result metadata for frame %d: %s (%d)",
                    frameNumber, strerror(-res), res);
            return;
        }
    }

    // Fix up result metadata to account for zoom ratio availabilities between
    // HAL and app.
    bool zoomRatioIs1 = cameraIdsWithZoom.find(states.cameraId) == cameraIdsWithZoom.end();
    res = states.zoomRatioMappers[states.cameraId].updateCaptureResult(
            &captureResult.mMetadata, zoomRatioIs1);
    if (res != OK) {
        SET_ERR("Failed to update capture result zoom ratio metadata for frame %d: %s (%d)",
                frameNumber, strerror(-res), res);
        return;
    }

    // Fix up result metadata to account for rotateAndCrop in AUTO mode
    if (rotateAndCropAuto) {
        auto mapper = states.rotateAndCropMappers.find(states.cameraId);
        if (mapper != states.rotateAndCropMappers.end()) {
            res = mapper->second.updateCaptureResult(
                    &captureResult.mMetadata);
            if (res != OK) {
                SET_ERR("Unable to correct capture result rotate-and-crop for frame %d: %s (%d)",
                        frameNumber, strerror(-res), res);
                return;
            }
        }
    }

    // Fix up manual flash strength control metadata
    res = fixupManualFlashStrengthControlTags(captureResult.mMetadata);
    if (res != OK) {
        SET_ERR("Failed to set flash strength level defaults in result metadata: %s (%d)",
                strerror(-res), res);
        return;
    }
    for (auto& physicalMetadata : captureResult.mPhysicalMetadatas) {
        res = fixupManualFlashStrengthControlTags(physicalMetadata.mPhysicalCameraMetadata);
        if (res != OK) {
            SET_ERR("Failed to set flash strength level defaults in physical result"
                    " metadata: %s (%d)", strerror(-res), res);
            return;
        }
    }

    // Fix up autoframing metadata
    res = fixupAutoframingTags(captureResult.mMetadata);
    if (res != OK) {
        SET_ERR("Failed to set autoframing defaults in result metadata: %s (%d)",
                strerror(-res), res);
        return;
    }
    for (auto& physicalMetadata : captureResult.mPhysicalMetadatas) {
        res = fixupAutoframingTags(physicalMetadata.mPhysicalCameraMetadata);
        if (res != OK) {
            SET_ERR("Failed to set autoframing defaults in physical result metadata: %s (%d)",
                    strerror(-res), res);
            return;
        }
    }

    for (auto& physicalMetadata : captureResult.mPhysicalMetadatas) {
        const std::string cameraId = physicalMetadata.mPhysicalCameraId;
        auto mapper = states.distortionMappers.find(cameraId);
        if (mapper != states.distortionMappers.end()) {
            res = mapper->second.correctCaptureResult(
                    &physicalMetadata.mPhysicalCameraMetadata);
            if (res != OK) {
                SET_ERR("Unable to correct physical capture result metadata for frame %d: %s (%d)",
                        frameNumber, strerror(-res), res);
                return;
            }
        }

        zoomRatioIs1 = cameraIdsWithZoom.find(cameraId) == cameraIdsWithZoom.end();
        res = states.zoomRatioMappers[cameraId].updateCaptureResult(
                &physicalMetadata.mPhysicalCameraMetadata, zoomRatioIs1);
        if (res != OK) {
            SET_ERR("Failed to update camera %s's physical zoom ratio metadata for "
                    "frame %d: %s(%d)", cameraId.c_str(), frameNumber, strerror(-res), res);
            return;
        }
    }

    // Fix up result metadata for monochrome camera.
    res = fixupMonochromeTags(states, states.deviceInfo, captureResult.mMetadata);
    if (res != OK) {
        SET_ERR("Failed to override result metadata: %s (%d)", strerror(-res), res);
        return;
    }
    for (auto& physicalMetadata : captureResult.mPhysicalMetadatas) {
        const std::string &cameraId = physicalMetadata.mPhysicalCameraId;
        res = fixupMonochromeTags(states,
                states.physicalDeviceInfoMap.at(cameraId),
                physicalMetadata.mPhysicalCameraMetadata);
        if (res != OK) {
            SET_ERR("Failed to override result metadata: %s (%d)", strerror(-res), res);
            return;
        }
    }

    std::unordered_map<std::string, CameraMetadata> monitoredPhysicalMetadata;
    for (auto& m : physicalMetadatas) {
        monitoredPhysicalMetadata.emplace(m.mPhysicalCameraId,
                CameraMetadata(m.mPhysicalCameraMetadata));
    }
    states.tagMonitor.monitorMetadata(TagMonitor::RESULT,
            frameNumber, sensorTimestamp, captureResult.mMetadata,
            monitoredPhysicalMetadata);

    insertResultLocked(states, &captureResult, frameNumber);
}

void removeInFlightMapEntryLocked(CaptureOutputStates& states, int idx) {
    ATRACE_CALL();
    InFlightRequestMap& inflightMap = states.inflightMap;
    nsecs_t duration = inflightMap.valueAt(idx).maxExpectedDuration;
    inflightMap.removeItemsAt(idx, 1);

    states.inflightIntf.onInflightEntryRemovedLocked(duration);
}

void removeInFlightRequestIfReadyLocked(CaptureOutputStates& states, int idx,
        std::vector<BufferToReturn> *returnableBuffers) {
    InFlightRequestMap& inflightMap = states.inflightMap;
    const InFlightRequest &request = inflightMap.valueAt(idx);
    const uint32_t frameNumber = inflightMap.keyAt(idx);
    SessionStatsBuilder& sessionStatsBuilder = states.sessionStatsBuilder;

    nsecs_t sensorTimestamp = request.sensorTimestamp;
    nsecs_t shutterTimestamp = request.shutterTimestamp;

    // Check if it's okay to remove the request from InFlightMap:
    // In the case of a successful request:
    //      all input and output buffers, all result metadata, shutter callback
    //      arrived.
    // In the case of an unsuccessful request:
    //      all input and output buffers, as well as request/result error notifications, arrived.
    if (request.numBuffersLeft == 0 &&
            (request.skipResultMetadata ||
            (request.haveResultMetadata && shutterTimestamp != 0))) {
        if (request.stillCapture) {
            ATRACE_ASYNC_END("still capture", frameNumber);
        }

        ATRACE_ASYNC_END("frame capture", frameNumber);

        // Validation check - if sensor timestamp matches shutter timestamp in the
        // case of request having callback.
        if (request.hasCallback && request.requestStatus == OK &&
                sensorTimestamp != shutterTimestamp) {
            SET_ERR("sensor timestamp (%" PRId64
                ") for frame %d doesn't match shutter timestamp (%" PRId64 ")",
                sensorTimestamp, frameNumber, shutterTimestamp);
        }

        // for an unsuccessful request, it may have pending output buffers to
        // return.
        assert(request.requestStatus != OK ||
               request.pendingOutputBuffers.size() == 0);

        collectReturnableOutputBuffers(
            states.useHalBufManager, states.halBufManagedStreamIds,
            states.listener,
            request.pendingOutputBuffers.array(),
            request.pendingOutputBuffers.size(), /*timestamp*/0, /*readoutTimestamp*/0,
            /*requested*/true, request.requestTimeNs, states.sessionStatsBuilder,
            /*out*/ returnableBuffers,
            /*timestampIncreasing*/true,
            request.outputSurfaces, request.resultExtras,
            request.errorBufStrategy, request.transform);

        // Note down the just completed frame number
        if (request.hasInputBuffer) {
            states.lastCompletedReprocessFrameNumber = frameNumber;
        } else if (request.zslCapture && request.stillCapture) {
            states.lastCompletedZslFrameNumber = frameNumber;
        } else {
            states.lastCompletedRegularFrameNumber = frameNumber;
        }

        sessionStatsBuilder.incResultCounter(request.skipResultMetadata);

        removeInFlightMapEntryLocked(states, idx);
        ALOGVV("%s: removed frame %d from InFlightMap", __FUNCTION__, frameNumber);
    }

    states.inflightIntf.checkInflightMapLengthLocked();
}

// Erase the subset of physicalCameraIds that contains id
bool erasePhysicalCameraIdSet(
        std::set<std::set<std::string>>& physicalCameraIds, const std::string& id) {
    bool found = false;
    for (auto iter = physicalCameraIds.begin(); iter != physicalCameraIds.end(); iter++) {
        if (iter->count(id) == 1) {
            physicalCameraIds.erase(iter);
            found = true;
            break;
        }
    }
    return found;
}

const std::set<std::string>& getCameraIdsWithZoomLocked(
        const InFlightRequestMap& inflightMap, const CameraMetadata& metadata,
        const std::set<std::string>& cameraIdsWithZoom) {
    camera_metadata_ro_entry overrideEntry =
            metadata.find(ANDROID_CONTROL_SETTINGS_OVERRIDE);
    camera_metadata_ro_entry frameNumberEntry =
            metadata.find(ANDROID_CONTROL_SETTINGS_OVERRIDING_FRAME_NUMBER);
    if (overrideEntry.count != 1
            || overrideEntry.data.i32[0] != ANDROID_CONTROL_SETTINGS_OVERRIDE_ZOOM
            || frameNumberEntry.count != 1) {
        // No valid overriding frame number, skip
        return cameraIdsWithZoom;
    }

    uint32_t overridingFrameNumber = frameNumberEntry.data.i32[0];
    ssize_t idx = inflightMap.indexOfKey(overridingFrameNumber);
    if (idx < 0) {
        ALOGE("%s: Failed to find pending request #%d in inflight map",
                __FUNCTION__, overridingFrameNumber);
        return cameraIdsWithZoom;
    }

    const InFlightRequest &r = inflightMap.valueFor(overridingFrameNumber);
    return r.cameraIdsWithZoom;
}

void processCaptureResult(CaptureOutputStates& states, const camera_capture_result *result) {
    ATRACE_CALL();

    status_t res;

    uint32_t frameNumber = result->frame_number;
    if (result->result == NULL && result->num_output_buffers == 0 &&
            result->input_buffer == NULL) {
        SET_ERR("No result data provided by HAL for frame %d",
                frameNumber);
        return;
    }

    if (!states.usePartialResult &&
            result->result != NULL &&
            result->partial_result != 1) {
        SET_ERR("Result is malformed for frame %d: partial_result %u must be 1"
                " if partial result is not supported",
                frameNumber, result->partial_result);
        return;
    }

    bool isPartialResult = false;
    CameraMetadata collectedPartialResult;
    bool hasInputBufferInRequest = false;

    // Get shutter timestamp and resultExtras from list of in-flight requests,
    // where it was added by the shutter notification for this frame. If the
    // shutter timestamp isn't received yet, append the output buffers to the
    // in-flight request and they will be returned when the shutter timestamp
    // arrives. Update the in-flight status and remove the in-flight entry if
    // all result data and shutter timestamp have been received.
    std::vector<BufferToReturn> returnableBuffers{};
    nsecs_t shutterTimestamp = 0;
    {
        std::lock_guard<std::mutex> l(states.inflightLock);
        ssize_t idx = states.inflightMap.indexOfKey(frameNumber);
        if (idx == NAME_NOT_FOUND) {
            SET_ERR("Unknown frame number for capture result: %d",
                    frameNumber);
            return;
        }
        InFlightRequest &request = states.inflightMap.editValueAt(idx);
        ALOGVV("%s: got InFlightRequest requestId = %" PRId32
                ", frameNumber = %" PRId64 ", burstId = %" PRId32
                ", partialResultCount = %d/%d, hasCallback = %d, num_output_buffers %d"
                ", usePartialResult = %d",
                __FUNCTION__, request.resultExtras.requestId,
                request.resultExtras.frameNumber, request.resultExtras.burstId,
                result->partial_result, states.numPartialResults,
                request.hasCallback, result->num_output_buffers,
                states.usePartialResult);
        // Always update the partial count to the latest one if it's not 0
        // (buffers only). When framework aggregates adjacent partial results
        // into one, the latest partial count will be used.
        if (result->partial_result != 0)
            request.resultExtras.partialResultCount = result->partial_result;

        if (result->result != nullptr) {
            camera_metadata_ro_entry entry;
            auto ret = find_camera_metadata_ro_entry(result->result,
                    ANDROID_LOGICAL_MULTI_CAMERA_ACTIVE_PHYSICAL_ID, &entry);
            if ((ret == OK) && (entry.count > 0)) {
                std::string physicalId(reinterpret_cast<const char *>(entry.data.u8));
                if (!states.activePhysicalId.empty() && physicalId != states.activePhysicalId) {
                    states.listener->notifyPhysicalCameraChange(physicalId);
                }
                states.activePhysicalId = physicalId;

                if (!states.legacyClient && !states.overrideToPortrait) {
                    auto deviceInfo = states.physicalDeviceInfoMap.find(physicalId);
                    if (deviceInfo != states.physicalDeviceInfoMap.end()) {
                        auto orientation = deviceInfo->second.find(ANDROID_SENSOR_ORIENTATION);
                        if (orientation.count > 0) {
                            int32_t transform;
                            ret = CameraUtils::getRotationTransform(deviceInfo->second,
                                    OutputConfiguration::MIRROR_MODE_AUTO, &transform);
                            if (ret == OK) {
                                // It is possible for camera providers to return the capture
                                // results after the processed frames. In such scenario, we will
                                // not be able to set the output transformation before the frames
                                // return back to the consumer for the current capture request
                                // but we could still try and configure it for any future requests
                                // that are still in flight. The assumption is that the physical
                                // device id remains the same for the duration of the pending queue.
                                for (size_t i = 0; i < states.inflightMap.size(); i++) {
                                    auto &r = states.inflightMap.editValueAt(i);
                                    if (r.requestTimeNs >= request.requestTimeNs) {
                                        r.transform = transform;
                                    }
                                }
                            } else {
                                ALOGE("%s: Failed to calculate current stream transformation: %s "
                                        "(%d)", __FUNCTION__, strerror(-ret), ret);
                            }
                        } else {
                            ALOGE("%s: Physical device orientation absent!", __FUNCTION__);
                        }
                    } else {
                        ALOGE("%s: Physical device not found in device info map found!",
                                __FUNCTION__);
                    }
                }
            }
        }

        // Check if this result carries only partial metadata
        if (states.usePartialResult && result->result != NULL) {
            if (result->partial_result > states.numPartialResults || result->partial_result < 1) {
                SET_ERR("Result is malformed for frame %d: partial_result %u must be  in"
                        " the range of [1, %d] when metadata is included in the result",
                        frameNumber, result->partial_result, states.numPartialResults);
                return;
            }
            isPartialResult = (result->partial_result < states.numPartialResults);
            if (isPartialResult && result->num_physcam_metadata) {
                SET_ERR("Result is malformed for frame %d: partial_result not allowed for"
                        " physical camera result", frameNumber);
                return;
            }
            if (isPartialResult) {
                request.collectedPartialResult.append(result->result);
            }

            if (isPartialResult && request.hasCallback) {
                // Send partial capture result
                sendPartialCaptureResult(states, result->result, request.resultExtras,
                        frameNumber);
            }
        }

        shutterTimestamp = request.shutterTimestamp;
        hasInputBufferInRequest = request.hasInputBuffer;

        // Did we get the (final) result metadata for this capture?
        if (result->result != NULL && !isPartialResult) {
            if (request.physicalCameraIds.size() != result->num_physcam_metadata) {
                SET_ERR("Expected physical Camera metadata count %d not equal to actual count %d",
                        request.physicalCameraIds.size(), result->num_physcam_metadata);
                return;
            }
            if (request.haveResultMetadata) {
                SET_ERR("Called multiple times with metadata for frame %d",
                        frameNumber);
                return;
            }
            for (uint32_t i = 0; i < result->num_physcam_metadata; i++) {
                const std::string physicalId = result->physcam_ids[i];
                bool validPhysicalCameraMetadata =
                        erasePhysicalCameraIdSet(request.physicalCameraIds, physicalId);
                if (!validPhysicalCameraMetadata) {
                    SET_ERR("Unexpected total result for frame %d camera %s",
                            frameNumber, physicalId.c_str());
                    return;
                }
            }
            if (states.usePartialResult &&
                    !request.collectedPartialResult.isEmpty()) {
                collectedPartialResult.acquire(
                    request.collectedPartialResult);
            }
            request.haveResultMetadata = true;
            request.errorBufStrategy = ERROR_BUF_RETURN_NOTIFY;
        }

        uint32_t numBuffersReturned = result->num_output_buffers;
        if (result->input_buffer != NULL) {
            if (hasInputBufferInRequest) {
                numBuffersReturned += 1;
            } else {
                ALOGW("%s: Input buffer should be NULL if there is no input"
                        " buffer sent in the request",
                        __FUNCTION__);
            }
        }
        request.numBuffersLeft -= numBuffersReturned;
        if (request.numBuffersLeft < 0) {
            SET_ERR("Too many buffers returned for frame %d",
                    frameNumber);
            return;
        }

        camera_metadata_ro_entry_t entry;
        res = find_camera_metadata_ro_entry(result->result,
                ANDROID_SENSOR_TIMESTAMP, &entry);
        if (res == OK && entry.count == 1) {
            request.sensorTimestamp = entry.data.i64[0];
        }

        // If shutter event isn't received yet, do not return the pending output
        // buffers.
        request.pendingOutputBuffers.appendArray(result->output_buffers,
                result->num_output_buffers);
        if (shutterTimestamp != 0) {
            collectAndRemovePendingOutputBuffers(
                states.useHalBufManager, states.halBufManagedStreamIds,
                states.listener,
                request, states.sessionStatsBuilder,
                /*out*/ &returnableBuffers);
        }

        if (result->result != NULL && !isPartialResult) {
            for (uint32_t i = 0; i < result->num_physcam_metadata; i++) {
                CameraMetadata physicalMetadata;
                physicalMetadata.append(result->physcam_metadata[i]);
                request.physicalMetadatas.push_back({result->physcam_ids[i],
                        physicalMetadata});
            }
            if (shutterTimestamp == 0) {
                request.pendingMetadata = result->result;
                request.collectedPartialResult = collectedPartialResult;
            } else if (request.hasCallback) {
                CameraMetadata metadata;
                metadata = result->result;
                auto cameraIdsWithZoom = getCameraIdsWithZoomLocked(
                        states.inflightMap, metadata, request.cameraIdsWithZoom);
                sendCaptureResult(states, metadata, request.resultExtras,
                    collectedPartialResult, frameNumber,
                    hasInputBufferInRequest, request.zslCapture && request.stillCapture,
                    request.rotateAndCropAuto, cameraIdsWithZoom,
                    request.physicalMetadatas);
            }
        }
        removeInFlightRequestIfReadyLocked(states, idx, &returnableBuffers);
        if (!flags::return_buffers_outside_locks()) {
            finishReturningOutputBuffers(returnableBuffers,
                states.listener, states.sessionStatsBuilder);
        }
    } // scope for states.inFlightLock

    if (flags::return_buffers_outside_locks()) {
        finishReturningOutputBuffers(returnableBuffers,
                states.listener, states.sessionStatsBuilder);
    }

    if (result->input_buffer != NULL) {
        if (hasInputBufferInRequest) {
            Camera3Stream *stream =
                Camera3Stream::cast(result->input_buffer->stream);
            res = stream->returnInputBuffer(*(result->input_buffer));
            // Note: stream may be deallocated at this point, if this buffer was the
            // last reference to it.
            if (res != OK) {
                ALOGE("%s: RequestThread: Can't return input buffer for frame %d to"
                      "  its stream:%s (%d)",  __FUNCTION__,
                      frameNumber, strerror(-res), res);
            }
        } else {
            ALOGW("%s: Input buffer should be NULL if there is no input"
                    " buffer sent in the request, skipping input buffer return.",
                    __FUNCTION__);
        }
    }
}

void collectReturnableOutputBuffers(
        bool useHalBufManager,
        const std::set<int32_t> &halBufferManagedStreams,
        sp<NotificationListener> listener,
        const camera_stream_buffer_t *outputBuffers, size_t numBuffers,
        nsecs_t timestamp, nsecs_t readoutTimestamp, bool requested,
        nsecs_t requestTimeNs, SessionStatsBuilder& sessionStatsBuilder,
        /*out*/ std::vector<BufferToReturn> *returnableBuffers,
        bool timestampIncreasing, const SurfaceMap& outputSurfaces,
        const CaptureResultExtras &resultExtras,
        ERROR_BUF_STRATEGY errorBufStrategy, int32_t transform) {
    for (size_t i = 0; i < numBuffers; i++)
    {
        Camera3StreamInterface *stream = Camera3Stream::cast(outputBuffers[i].stream);
        int streamId = stream->getId();

        // Call notify(ERROR_BUFFER) if necessary.
        if (outputBuffers[i].status == CAMERA_BUFFER_STATUS_ERROR &&
                errorBufStrategy == ERROR_BUF_RETURN_NOTIFY) {
            if (listener != nullptr) {
                CaptureResultExtras extras = resultExtras;
                extras.errorStreamId = streamId;
                listener->notifyError(
                        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_BUFFER,
                        extras);
            }
        }

        if (outputBuffers[i].buffer == nullptr) {
            if (!useHalBufManager &&
                    !(flags::session_hal_buf_manager() &&
                            contains(halBufferManagedStreams, streamId))) {
                // With HAL buffer management API, HAL sometimes will have to return buffers that
                // has not got a output buffer handle filled yet. This is though illegal if HAL
                // buffer management API is not being used.
                ALOGE("%s: cannot return a null buffer!", __FUNCTION__);
            } else {
                if (requested) {
                    sessionStatsBuilder.incCounter(streamId, /*dropped*/true, 0);
                }
            }
            continue;
        }

        const auto& it = outputSurfaces.find(streamId);

        // Do not return the buffer if the buffer status is error, and the error
        // buffer strategy is CACHE.
        if (outputBuffers[i].status != CAMERA_BUFFER_STATUS_ERROR ||
                errorBufStrategy != ERROR_BUF_CACHE) {
            if (it != outputSurfaces.end()) {
                returnableBuffers->emplace_back(stream,
                        outputBuffers[i], timestamp, readoutTimestamp, timestampIncreasing,
                        it->second, resultExtras,
                        transform, requested ? requestTimeNs : 0);
            } else {
                returnableBuffers->emplace_back(stream,
                        outputBuffers[i], timestamp, readoutTimestamp, timestampIncreasing,
                        std::vector<size_t> (), resultExtras,
                        transform, requested ? requestTimeNs : 0 );
            }
        }
    }
}

void finishReturningOutputBuffers(const std::vector<BufferToReturn> &returnableBuffers,
        sp<NotificationListener> listener, SessionStatsBuilder& sessionStatsBuilder) {
    for (auto& b : returnableBuffers) {
        const int streamId = b.stream->getId();

        status_t res = b.stream->returnBuffer(b.buffer, b.timestamp,
                b.readoutTimestamp, b.timestampIncreasing,
                b.surfaceIds, b.resultExtras.frameNumber, b.transform);

        // Note: stream may be deallocated at this point, if this buffer was
        // the last reference to it.
        bool dropped = false;
        if (res == NO_INIT || res == DEAD_OBJECT) {
            ALOGV("Can't return buffer to its stream: %s (%d)", strerror(-res), res);
            sessionStatsBuilder.stopCounter(streamId);
        } else if (res != OK) {
            ALOGE("Can't return buffer to its stream: %s (%d)", strerror(-res), res);
            dropped = true;
        } else {
            if (b.buffer.status == CAMERA_BUFFER_STATUS_ERROR || b.timestamp == 0) {
                dropped = true;
            }
        }
        if (b.requestTimeNs > 0) {
            nsecs_t bufferTimeNs = systemTime();
            int32_t captureLatencyMs = ns2ms(bufferTimeNs - b.requestTimeNs);
            sessionStatsBuilder.incCounter(streamId, dropped, captureLatencyMs);
        }

        // Long processing consumers can cause returnBuffer timeout for shared stream
        // If that happens, cancel the buffer and send a buffer error to client
        if (b.surfaceIds.size() > 0 && res == TIMED_OUT &&
                b.buffer.status == CAMERA_BUFFER_STATUS_OK) {
            // cancel the buffer
            camera_stream_buffer_t sb = b.buffer;
            sb.status = CAMERA_BUFFER_STATUS_ERROR;
            b.stream->returnBuffer(sb, /*timestamp*/0, /*readoutTimestamp*/0,
                    b.timestampIncreasing, std::vector<size_t> (),
                    b.resultExtras.frameNumber, b.transform);

            if (listener != nullptr) {
                CaptureResultExtras extras = b.resultExtras;
                extras.errorStreamId = streamId;
                listener->notifyError(
                        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_BUFFER,
                        extras);
            }
        }

    }
}

void collectAndRemovePendingOutputBuffers(bool useHalBufManager,
        const std::set<int32_t> &halBufferManagedStreams,
        sp<NotificationListener> listener, InFlightRequest& request,
        SessionStatsBuilder& sessionStatsBuilder,
        std::vector<BufferToReturn> *returnableBuffers) {
    bool timestampIncreasing =
            !((request.zslCapture && request.stillCapture) || request.hasInputBuffer);
    nsecs_t readoutTimestamp = request.resultExtras.hasReadoutTimestamp ?
            request.resultExtras.readoutTimestamp : 0;
    collectReturnableOutputBuffers(useHalBufManager, halBufferManagedStreams, listener,
            request.pendingOutputBuffers.array(),
            request.pendingOutputBuffers.size(),
            request.shutterTimestamp, readoutTimestamp,
            /*requested*/true, request.requestTimeNs, sessionStatsBuilder,
            /*out*/ returnableBuffers,
            timestampIncreasing,
            request.outputSurfaces, request.resultExtras,
            request.errorBufStrategy, request.transform);

    // Remove error buffers that are not cached.
    for (auto iter = request.pendingOutputBuffers.begin();
            iter != request.pendingOutputBuffers.end(); ) {
        if (request.errorBufStrategy != ERROR_BUF_CACHE ||
                iter->status != CAMERA_BUFFER_STATUS_ERROR) {
            iter = request.pendingOutputBuffers.erase(iter);
        } else {
            iter++;
        }
    }
}

void notifyShutter(CaptureOutputStates& states, const camera_shutter_msg_t &msg) {
    ATRACE_CALL();
    ssize_t idx;

    std::vector<BufferToReturn> returnableBuffers{};
    CaptureResultExtras pendingNotificationResultExtras{};

    // Set timestamp for the request in the in-flight tracking
    // and get the request ID to send upstream
    {
        std::lock_guard<std::mutex> l(states.inflightLock);
        InFlightRequestMap& inflightMap = states.inflightMap;
        idx = inflightMap.indexOfKey(msg.frame_number);
        if (idx >= 0) {
            InFlightRequest &r = inflightMap.editValueAt(idx);

            // Verify ordering of shutter notifications
            {
                std::lock_guard<std::mutex> l(states.outputLock);
                // TODO: need to track errors for tighter bounds on expected frame number.
                if (r.hasInputBuffer) {
                    if (msg.frame_number < states.nextReprocShutterFrameNum) {
                        SET_ERR("Reprocess shutter notification out-of-order. Expected "
                                "notification for frame %d, got frame %d",
                                states.nextReprocShutterFrameNum, msg.frame_number);
                        return;
                    }
                    states.nextReprocShutterFrameNum = msg.frame_number + 1;
                } else if (r.zslCapture && r.stillCapture) {
                    if (msg.frame_number < states.nextZslShutterFrameNum) {
                        SET_ERR("ZSL still capture shutter notification out-of-order. Expected "
                                "notification for frame %d, got frame %d",
                                states.nextZslShutterFrameNum, msg.frame_number);
                        return;
                    }
                    states.nextZslShutterFrameNum = msg.frame_number + 1;
                } else {
                    if (msg.frame_number < states.nextShutterFrameNum) {
                        SET_ERR("Shutter notification out-of-order. Expected "
                                "notification for frame %d, got frame %d",
                                states.nextShutterFrameNum, msg.frame_number);
                        return;
                    }
                    states.nextShutterFrameNum = msg.frame_number + 1;
                }
            }

            r.shutterTimestamp = msg.timestamp;
            if (msg.readout_timestamp_valid) {
                r.resultExtras.hasReadoutTimestamp = true;
                r.resultExtras.readoutTimestamp = msg.readout_timestamp;
            }
            if (r.minExpectedDuration != states.minFrameDuration ||
                    r.isFixedFps != states.isFixedFps) {
                for (size_t i = 0; i < states.outputStreams.size(); i++) {
                    auto outputStream = states.outputStreams[i];
                    outputStream->onMinDurationChanged(r.minExpectedDuration, r.isFixedFps);
                }
                states.minFrameDuration = r.minExpectedDuration;
                states.isFixedFps = r.isFixedFps;
            }
            if (r.hasCallback) {
                ALOGVV("Camera %s: %s: Shutter fired for frame %d (id %d) at %" PRId64,
                    states.cameraId.c_str(), __FUNCTION__,
                    msg.frame_number, r.resultExtras.requestId, msg.timestamp);
                // Call listener, if any
                if (states.listener != nullptr) {
                    r.resultExtras.lastCompletedRegularFrameNumber =
                            states.lastCompletedRegularFrameNumber;
                    r.resultExtras.lastCompletedReprocessFrameNumber =
                            states.lastCompletedReprocessFrameNumber;
                    r.resultExtras.lastCompletedZslFrameNumber =
                            states.lastCompletedZslFrameNumber;
                    if (flags::return_buffers_outside_locks()) {
                        pendingNotificationResultExtras = r.resultExtras;
                    } else {
                        states.listener->notifyShutter(r.resultExtras, msg.timestamp);
                    }
                }
                // send pending result and buffers; this queues them up for delivery later
                const auto& cameraIdsWithZoom = getCameraIdsWithZoomLocked(
                        inflightMap, r.pendingMetadata, r.cameraIdsWithZoom);
                sendCaptureResult(states,
                    r.pendingMetadata, r.resultExtras,
                    r.collectedPartialResult, msg.frame_number,
                    r.hasInputBuffer, r.zslCapture && r.stillCapture,
                    r.rotateAndCropAuto, cameraIdsWithZoom, r.physicalMetadatas);
            }
            collectAndRemovePendingOutputBuffers(
                    states.useHalBufManager, states.halBufManagedStreamIds,
                    states.listener, r, states.sessionStatsBuilder, &returnableBuffers);

            if (!flags::return_buffers_outside_locks()) {
                finishReturningOutputBuffers(returnableBuffers,
                        states.listener, states.sessionStatsBuilder);
            }

            removeInFlightRequestIfReadyLocked(states, idx, &returnableBuffers);

        }
    }
    if (idx < 0) {
        SET_ERR("Shutter notification for non-existent frame number %d",
                msg.frame_number);
    }
    // Call notifyShutter outside of in-flight mutex
    if (flags::return_buffers_outside_locks() && pendingNotificationResultExtras.isValid()) {
        states.listener->notifyShutter(pendingNotificationResultExtras, msg.timestamp);
    }

    // With no locks held, finish returning buffers to streams, which may take a while since
    // binder calls are involved
    if (flags::return_buffers_outside_locks()) {
        finishReturningOutputBuffers(returnableBuffers,
                states.listener, states.sessionStatsBuilder);
    }

}

void notifyError(CaptureOutputStates& states, const camera_error_msg_t &msg) {
    ATRACE_CALL();
    // Map camera HAL error codes to ICameraDeviceCallback error codes
    // Index into this with the HAL error code
    static const int32_t halErrorMap[CAMERA_MSG_NUM_ERRORS] = {
        // 0 = Unused error code
        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_INVALID_ERROR,
        // 1 = CAMERA_MSG_ERROR_DEVICE
        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DEVICE,
        // 2 = CAMERA_MSG_ERROR_REQUEST
        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_REQUEST,
        // 3 = CAMERA_MSG_ERROR_RESULT
        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_RESULT,
        // 4 = CAMERA_MSG_ERROR_BUFFER
        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_BUFFER
    };

    int32_t errorCode =
            ((msg.error_code >= 0) &&
                    (msg.error_code < CAMERA_MSG_NUM_ERRORS)) ?
            halErrorMap[msg.error_code] :
            hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_INVALID_ERROR;

    int streamId = 0;
    std::string physicalCameraId;
    if (msg.error_stream != nullptr) {
        Camera3Stream *stream =
                Camera3Stream::cast(msg.error_stream);
        streamId = stream->getId();
        physicalCameraId = stream->physicalCameraId();
    }
    ALOGV("Camera %s: %s: HAL error, frame %d, stream %d: %d",
            states.cameraId.c_str(), __FUNCTION__, msg.frame_number,
            streamId, msg.error_code);

    CaptureResultExtras resultExtras;
    switch (errorCode) {
        case hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DEVICE:
            // SET_ERR calls into listener to notify application
            SET_ERR("Camera HAL reported serious device error");
            break;
        case hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_REQUEST:
        case hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_RESULT:
        {
            std::vector<BufferToReturn> returnableBuffers{};
            {
                std::lock_guard<std::mutex> l(states.inflightLock);
                ssize_t idx = states.inflightMap.indexOfKey(msg.frame_number);
                if (idx >= 0) {
                    InFlightRequest &r = states.inflightMap.editValueAt(idx);
                    r.requestStatus = msg.error_code;
                    resultExtras = r.resultExtras;
                    bool physicalDeviceResultError = false;
                    if (hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_RESULT ==
                            errorCode) {
                        if (physicalCameraId.size() > 0) {
                            bool validPhysicalCameraId =
                                    erasePhysicalCameraIdSet(r.physicalCameraIds, physicalCameraId);
                            if (!validPhysicalCameraId) {
                                ALOGE("%s: Reported result failure for physical camera device: %s "
                                        " which is not part of the respective request!",
                                        __FUNCTION__, physicalCameraId.c_str());
                                break;
                            }
                            resultExtras.errorPhysicalCameraId = physicalCameraId;
                            physicalDeviceResultError = true;
                        }
                    }

                    if (!physicalDeviceResultError) {
                        r.skipResultMetadata = true;
                        if (hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_RESULT
                                == errorCode) {
                            r.errorBufStrategy = ERROR_BUF_RETURN_NOTIFY;
                        } else {
                            // errorCode is ERROR_CAMERA_REQUEST
                            r.errorBufStrategy = ERROR_BUF_RETURN;
                        }

                        // Check whether the buffers returned. If they returned,
                        // remove inflight request.
                        removeInFlightRequestIfReadyLocked(states, idx, &returnableBuffers);
                        if (!flags::return_buffers_outside_locks()) {
                            finishReturningOutputBuffers(returnableBuffers,
                                    states.listener, states.sessionStatsBuilder);
                        }

                    }
                } else {
                    resultExtras.frameNumber = msg.frame_number;
                    ALOGE("Camera %s: %s: cannot find in-flight request on "
                            "frame %" PRId64 " error", states.cameraId.c_str(), __FUNCTION__,
                            resultExtras.frameNumber);
                }
            }

            if (flags::return_buffers_outside_locks()) {
                finishReturningOutputBuffers(returnableBuffers,
                        states.listener, states.sessionStatsBuilder);
            }

            resultExtras.errorStreamId = streamId;
            if (states.listener != nullptr) {
                states.listener->notifyError(errorCode, resultExtras);
            } else {
                ALOGE("Camera %s: %s: no listener available",
                        states.cameraId.c_str(), __FUNCTION__);
            }
            break;
        }
        case hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_BUFFER:
            // Do not depend on HAL ERROR_CAMERA_BUFFER to send buffer error
            // callback to the app. Rather, use STATUS_ERROR of image buffers.
            break;
        default:
            // SET_ERR calls notifyError
            SET_ERR("Unknown error message from HAL: %d", msg.error_code);
            break;
    }
}

void notify(CaptureOutputStates& states, const camera_notify_msg *msg) {
    switch (msg->type) {
        case CAMERA_MSG_ERROR: {
            notifyError(states, msg->message.error);
            break;
        }
        case CAMERA_MSG_SHUTTER: {
            notifyShutter(states, msg->message.shutter);
            break;
        }
        default:
            SET_ERR("Unknown notify message from HAL: %d",
                    msg->type);
    }
}

void flushInflightRequests(FlushInflightReqStates& states) {
    ATRACE_CALL();
    std::vector<BufferToReturn> returnableBuffers{};
    { // First return buffers cached in inFlightMap
        std::lock_guard<std::mutex> l(states.inflightLock);
        for (size_t idx = 0; idx < states.inflightMap.size(); idx++) {
            const InFlightRequest &request = states.inflightMap.valueAt(idx);
            collectReturnableOutputBuffers(
                states.useHalBufManager, states.halBufManagedStreamIds,
                states.listener,
                request.pendingOutputBuffers.array(),
                request.pendingOutputBuffers.size(), /*timestamp*/0, /*readoutTimestamp*/0,
                /*requested*/true, request.requestTimeNs, states.sessionStatsBuilder,
                /*out*/ &returnableBuffers,
                /*timestampIncreasing*/true, request.outputSurfaces, request.resultExtras,
                request.errorBufStrategy);
            if (!flags::return_buffers_outside_locks()) {
                finishReturningOutputBuffers(returnableBuffers,
                        states.listener, states.sessionStatsBuilder);
            }
            ALOGW("%s: Frame %d |  Timestamp: %" PRId64 ", metadata"
                    " arrived: %s, buffers left: %d.\n", __FUNCTION__,
                    states.inflightMap.keyAt(idx), request.shutterTimestamp,
                    request.haveResultMetadata ? "true" : "false",
                    request.numBuffersLeft);
        }

        states.inflightMap.clear();
        states.inflightIntf.onInflightMapFlushedLocked();
    }
    if (flags::return_buffers_outside_locks()) {
        finishReturningOutputBuffers(returnableBuffers,
                states.listener, states.sessionStatsBuilder);
    }

    // Then return all inflight buffers not returned by HAL
    std::vector<std::pair<int32_t, int32_t>> inflightKeys;
    states.flushBufferIntf.getInflightBufferKeys(&inflightKeys);

    // Inflight buffers for HAL buffer manager
    std::vector<uint64_t> inflightRequestBufferKeys;
    states.flushBufferIntf.getInflightRequestBufferKeys(&inflightRequestBufferKeys);

    // (streamId, frameNumber, buffer_handle_t*) tuple for all inflight buffers.
    // frameNumber will be -1 for buffers from HAL buffer manager
    std::vector<std::tuple<int32_t, int32_t, buffer_handle_t*>> inflightBuffers;
    inflightBuffers.reserve(inflightKeys.size() + inflightRequestBufferKeys.size());

    for (auto& pair : inflightKeys) {
        int32_t frameNumber = pair.first;
        int32_t streamId = pair.second;
        buffer_handle_t* buffer;
        status_t res = states.bufferRecordsIntf.popInflightBuffer(frameNumber, streamId, &buffer);
        if (res != OK) {
            ALOGE("%s: Frame %d: No in-flight buffer for stream %d",
                    __FUNCTION__, frameNumber, streamId);
            continue;
        }
        inflightBuffers.push_back(std::make_tuple(streamId, frameNumber, buffer));
    }

    for (auto& bufferId : inflightRequestBufferKeys) {
        int32_t streamId = -1;
        buffer_handle_t* buffer = nullptr;
        status_t res = states.bufferRecordsIntf.popInflightRequestBuffer(
                bufferId, &buffer, &streamId);
        if (res != OK) {
            ALOGE("%s: cannot find in-flight buffer %" PRIu64, __FUNCTION__, bufferId);
            continue;
        }
        inflightBuffers.push_back(std::make_tuple(streamId, /*frameNumber*/-1, buffer));
    }

    std::vector<sp<Camera3StreamInterface>> streams = states.flushBufferIntf.getAllStreams();

    for (auto& tuple : inflightBuffers) {
        status_t res = OK;
        int32_t streamId = std::get<0>(tuple);
        int32_t frameNumber = std::get<1>(tuple);
        buffer_handle_t* buffer = std::get<2>(tuple);

        camera_stream_buffer_t streamBuffer;
        streamBuffer.buffer = buffer;
        streamBuffer.status = CAMERA_BUFFER_STATUS_ERROR;
        streamBuffer.acquire_fence = -1;
        streamBuffer.release_fence = -1;

        for (auto& stream : streams) {
            if (streamId == stream->getId()) {
                // Return buffer to deleted stream
                camera_stream* halStream = stream->asHalStream();
                streamBuffer.stream = halStream;
                switch (halStream->stream_type) {
                    case CAMERA_STREAM_OUTPUT:
                        res = stream->returnBuffer(streamBuffer, /*timestamp*/ 0,
                                /*readoutTimestamp*/0, /*timestampIncreasing*/true,
                                std::vector<size_t> (), frameNumber);
                        if (res != OK) {
                            ALOGE("%s: Can't return output buffer for frame %d to"
                                  " stream %d: %s (%d)",  __FUNCTION__,
                                  frameNumber, streamId, strerror(-res), res);
                        }
                        break;
                    case CAMERA_STREAM_INPUT:
                        res = stream->returnInputBuffer(streamBuffer);
                        if (res != OK) {
                            ALOGE("%s: Can't return input buffer for frame %d to"
                                  " stream %d: %s (%d)",  __FUNCTION__,
                                  frameNumber, streamId, strerror(-res), res);
                        }
                        break;
                    default: // Bi-direcitonal stream is deprecated
                        ALOGE("%s: stream %d has unknown stream type %d",
                                __FUNCTION__, streamId, halStream->stream_type);
                        break;
                }
                break;
            }
        }
    }
}

} // camera3
} // namespace android
