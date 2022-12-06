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

#ifndef ANDROID_SERVERS_CAMERA3_OUTPUT_UTILS_H
#define ANDROID_SERVERS_CAMERA3_OUTPUT_UTILS_H

#include <memory>
#include <mutex>

#include <cutils/native_handle.h>

#include <fmq/MessageQueue.h>

#include <common/CameraDeviceBase.h>

#include "device3/BufferUtils.h"
#include "device3/DistortionMapper.h"
#include "device3/ZoomRatioMapper.h"
#include "device3/RotateAndCropMapper.h"
#include "device3/InFlightRequest.h"
#include "device3/Camera3Stream.h"
#include "device3/Camera3OutputStreamInterface.h"
#include "utils/SessionStatsBuilder.h"
#include "utils/TagMonitor.h"

namespace android {

namespace camera3 {

    /**
     * Helper methods shared between Camera3Device/Camera3OfflineSession for HAL callbacks
     */

    // helper function to return the output buffers to output streams. The
    // function also optionally calls notify(ERROR_BUFFER).
    void returnOutputBuffers(
            bool useHalBufManager,
            sp<NotificationListener> listener, // Only needed when outputSurfaces is not empty
            const camera_stream_buffer_t *outputBuffers,
            size_t numBuffers, nsecs_t timestamp,
            nsecs_t readoutTimestamp, bool requested, nsecs_t requestTimeNs,
            SessionStatsBuilder& sessionStatsBuilder, bool timestampIncreasing = true,
            // The following arguments are only meant for surface sharing use case
            const SurfaceMap& outputSurfaces = SurfaceMap{},
            // Used to send buffer error callback when failing to return buffer
            const CaptureResultExtras &resultExtras = CaptureResultExtras{},
            ERROR_BUF_STRATEGY errorBufStrategy = ERROR_BUF_RETURN,
            int32_t transform = -1);

    // helper function to return the output buffers to output streams, and
    // remove the returned buffers from the inflight request's pending buffers
    // vector.
    void returnAndRemovePendingOutputBuffers(
            bool useHalBufManager,
            sp<NotificationListener> listener, // Only needed when outputSurfaces is not empty
            InFlightRequest& request, SessionStatsBuilder& sessionStatsBuilder);

    // Camera3Device/Camera3OfflineSession internal states used in notify/processCaptureResult
    // callbacks
    struct CaptureOutputStates {
        const String8& cameraId;
        std::mutex& inflightLock;
        int64_t& lastCompletedRegularFrameNumber;
        int64_t& lastCompletedReprocessFrameNumber;
        int64_t& lastCompletedZslFrameNumber;
        InFlightRequestMap& inflightMap; // end of inflightLock scope
        std::mutex& outputLock;
        std::list<CaptureResult>& resultQueue;
        std::condition_variable& resultSignal;
        uint32_t& nextShutterFrameNum;
        uint32_t& nextReprocShutterFrameNum;
        uint32_t& nextZslShutterFrameNum;
        uint32_t& nextResultFrameNum;
        uint32_t& nextReprocResultFrameNum;
        uint32_t& nextZslResultFrameNum; // end of outputLock scope
        const bool useHalBufManager;
        const bool usePartialResult;
        const bool needFixupMonoChrome;
        const uint32_t numPartialResults;
        const metadata_vendor_id_t vendorTagId;
        const CameraMetadata& deviceInfo;
        const std::unordered_map<std::string, CameraMetadata>& physicalDeviceInfoMap;
        std::unordered_map<std::string, camera3::DistortionMapper>& distortionMappers;
        std::unordered_map<std::string, camera3::ZoomRatioMapper>& zoomRatioMappers;
        std::unordered_map<std::string, camera3::RotateAndCropMapper>& rotateAndCropMappers;
        TagMonitor& tagMonitor;
        sp<Camera3Stream> inputStream;
        StreamSet& outputStreams;
        SessionStatsBuilder& sessionStatsBuilder;
        sp<NotificationListener> listener;
        SetErrorInterface& setErrIntf;
        InflightRequestUpdateInterface& inflightIntf;
        BufferRecordsInterface& bufferRecordsIntf;
        bool legacyClient;
        nsecs_t& minFrameDuration;
        bool& isFixedFps;
    };

    void processCaptureResult(CaptureOutputStates& states, const camera_capture_result *result);
    void notify(CaptureOutputStates& states, const camera_notify_msg *msg);

    struct RequestBufferStates {
        const String8& cameraId;
        std::mutex& reqBufferLock; // lock to serialize request buffer calls
        const bool useHalBufManager;
        StreamSet& outputStreams;
        SessionStatsBuilder& sessionStatsBuilder;
        SetErrorInterface& setErrIntf;
        BufferRecordsInterface& bufferRecordsIntf;
        RequestBufferInterface& reqBufferIntf;
    };

    struct ReturnBufferStates {
        const String8& cameraId;
        const bool useHalBufManager;
        StreamSet& outputStreams;
        SessionStatsBuilder& sessionStatsBuilder;
        BufferRecordsInterface& bufferRecordsIntf;
    };

    struct FlushInflightReqStates {
        const String8& cameraId;
        std::mutex& inflightLock;
        InFlightRequestMap& inflightMap; // end of inflightLock scope
        const bool useHalBufManager;
        sp<NotificationListener> listener;
        InflightRequestUpdateInterface& inflightIntf;
        BufferRecordsInterface& bufferRecordsIntf;
        FlushBufferInterface& flushBufferIntf;
        SessionStatsBuilder& sessionStatsBuilder;
    };

    void flushInflightRequests(FlushInflightReqStates& states);
} // namespace camera3

} // namespace android

#endif
