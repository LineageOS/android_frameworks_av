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

#define LOG_TAG "HidlCamera3-OutputUtils"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0
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
#include <camera_metadata_hidden.h>

#include "device3/hidl/HidlCamera3OutputUtils.h"
#include "device3/Camera3OutputUtilsTemplated.h"

#include "system/camera_metadata.h"

using namespace android::camera3;
using namespace android::hardware::camera;

namespace android {
namespace camera3 {

void processOneCaptureResultLocked(
        HidlCaptureOutputStates& states,
        const hardware::camera::device::V3_2::CaptureResult& result,
        const hardware::hidl_vec<
                hardware::camera::device::V3_4::PhysicalCameraMetadata> &physicalCameraMetadata) {
    processOneCaptureResultLockedT<HidlCaptureOutputStates,
        hardware::camera::device::V3_2::CaptureResult,
        hardware::hidl_vec<hardware::camera::device::V3_4::PhysicalCameraMetadata>,
        hardware::hidl_vec<uint8_t>, ResultMetadataQueue,
        hardware::camera::device::V3_2::BufferStatus>(states, result, physicalCameraMetadata);
}

void notify(CaptureOutputStates& states,
        const hardware::camera::device::V3_8::NotifyMsg& msg) {
    using android::hardware::camera::device::V3_2::MsgType;

    hardware::camera::device::V3_2::NotifyMsg msg_3_2;
    msg_3_2.type = msg.type;
    bool hasReadoutTime = false;
    uint64_t readoutTime = 0;
    switch (msg.type) {
        case MsgType::ERROR:
            msg_3_2.msg.error = msg.msg.error;
            break;
        case MsgType::SHUTTER:
            msg_3_2.msg.shutter = msg.msg.shutter.v3_2;
            hasReadoutTime = true;
            readoutTime = msg.msg.shutter.readoutTimestamp;
            break;
    }
    notify(states, msg_3_2, hasReadoutTime, readoutTime);
}

void notify(CaptureOutputStates& states,
        const hardware::camera::device::V3_2::NotifyMsg& msg,
        bool hasReadoutTime, uint64_t readoutTime) {

    using android::hardware::camera::device::V3_2::MsgType;
    using android::hardware::camera::device::V3_2::ErrorCode;

    ATRACE_CALL();
    camera_notify_msg m;
    switch (msg.type) {
        case MsgType::ERROR:
            m.type = CAMERA_MSG_ERROR;
            m.message.error.frame_number = msg.msg.error.frameNumber;
            if (msg.msg.error.errorStreamId >= 0) {
                sp<Camera3StreamInterface> stream =
                        states.outputStreams.get(msg.msg.error.errorStreamId);
                if (stream == nullptr) {
                    ALOGE("%s: Frame %d: Invalid error stream id %d", __FUNCTION__,
                            m.message.error.frame_number, msg.msg.error.errorStreamId);
                    return;
                }
                m.message.error.error_stream = stream->asHalStream();
            } else {
                m.message.error.error_stream = nullptr;
            }
            switch (msg.msg.error.errorCode) {
                case ErrorCode::ERROR_DEVICE:
                    m.message.error.error_code = CAMERA_MSG_ERROR_DEVICE;
                    break;
                case ErrorCode::ERROR_REQUEST:
                    m.message.error.error_code = CAMERA_MSG_ERROR_REQUEST;
                    break;
                case ErrorCode::ERROR_RESULT:
                    m.message.error.error_code = CAMERA_MSG_ERROR_RESULT;
                    break;
                case ErrorCode::ERROR_BUFFER:
                    m.message.error.error_code = CAMERA_MSG_ERROR_BUFFER;
                    break;
            }
            break;
        case MsgType::SHUTTER:
            m.type = CAMERA_MSG_SHUTTER;
            m.message.shutter.frame_number = msg.msg.shutter.frameNumber;
            m.message.shutter.timestamp = msg.msg.shutter.timestamp;
            m.message.shutter.readout_timestamp = hasReadoutTime ?
                    readoutTime : m.message.shutter.timestamp;
            break;
    }
    notify(states, &m);
}



// The buffers requested through this call are not tied to any CaptureRequest in
// particular. They may used by the hal for a particular frame's output buffer
// or for its internal use as well. In the case that the hal does use any buffer
// from the requested list here, for a particular frame's output buffer, the
// buffer will be returned with the processCaptureResult call corresponding to
// the frame. The other buffers will be returned through returnStreamBuffers.
// The buffers returned via returnStreamBuffers will not have a valid
// timestamp(0) and will be dropped by the bufferqueue.
void requestStreamBuffers(RequestBufferStates& states,
        const hardware::hidl_vec<hardware::camera::device::V3_5::BufferRequest>& bufReqs,
        hardware::camera::device::V3_5::ICameraDeviceCallback::requestStreamBuffers_cb _hidl_cb) {
    using android::hardware::camera::device::V3_2::BufferStatus;
    using android::hardware::camera::device::V3_2::StreamBuffer;
    using android::hardware::camera::device::V3_5::BufferRequestStatus;
    using android::hardware::camera::device::V3_5::StreamBufferRet;
    using android::hardware::camera::device::V3_5::StreamBufferRequestError;

    std::lock_guard<std::mutex> lock(states.reqBufferLock);

    hardware::hidl_vec<StreamBufferRet> bufRets;
    if (!states.useHalBufManager) {
        ALOGE("%s: Camera %s does not support HAL buffer management",
                __FUNCTION__, states.cameraId.string());
        _hidl_cb(BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS, bufRets);
        return;
    }

    SortedVector<int32_t> streamIds;
    ssize_t sz = streamIds.setCapacity(bufReqs.size());
    if (sz < 0 || static_cast<size_t>(sz) != bufReqs.size()) {
        ALOGE("%s: failed to allocate memory for %zu buffer requests",
                __FUNCTION__, bufReqs.size());
        _hidl_cb(BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS, bufRets);
        return;
    }

    if (bufReqs.size() > states.outputStreams.size()) {
        ALOGE("%s: too many buffer requests (%zu > # of output streams %zu)",
                __FUNCTION__, bufReqs.size(), states.outputStreams.size());
        _hidl_cb(BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS, bufRets);
        return;
    }

    // Check for repeated streamId
    for (const auto& bufReq : bufReqs) {
        if (streamIds.indexOf(bufReq.streamId) != NAME_NOT_FOUND) {
            ALOGE("%s: Stream %d appear multiple times in buffer requests",
                    __FUNCTION__, bufReq.streamId);
            _hidl_cb(BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS, bufRets);
            return;
        }
        streamIds.add(bufReq.streamId);
    }

    if (!states.reqBufferIntf.startRequestBuffer()) {
        ALOGE("%s: request buffer disallowed while camera service is configuring",
                __FUNCTION__);
        _hidl_cb(BufferRequestStatus::FAILED_CONFIGURING, bufRets);
        return;
    }

    bufRets.resize(bufReqs.size());

    bool allReqsSucceeds = true;
    bool oneReqSucceeds = false;
    for (size_t i = 0; i < bufReqs.size(); i++) {
        const auto& bufReq = bufReqs[i];
        auto& bufRet = bufRets[i];
        int32_t streamId = bufReq.streamId;
        sp<Camera3OutputStreamInterface> outputStream = states.outputStreams.get(streamId);
        if (outputStream == nullptr) {
            ALOGE("%s: Output stream id %d not found!", __FUNCTION__, streamId);
            hardware::hidl_vec<StreamBufferRet> emptyBufRets;
            _hidl_cb(BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS, emptyBufRets);
            states.reqBufferIntf.endRequestBuffer();
            return;
        }

        bufRet.streamId = streamId;
        if (outputStream->isAbandoned()) {
            bufRet.val.error(StreamBufferRequestError::STREAM_DISCONNECTED);
            allReqsSucceeds = false;
            continue;
        }

        size_t handOutBufferCount = outputStream->getOutstandingBuffersCount();
        uint32_t numBuffersRequested = bufReq.numBuffersRequested;
        size_t totalHandout = handOutBufferCount + numBuffersRequested;
        uint32_t maxBuffers = outputStream->asHalStream()->max_buffers;
        if (totalHandout > maxBuffers) {
            // Not able to allocate enough buffer. Exit early for this stream
            ALOGE("%s: request too much buffers for stream %d: at HAL: %zu + requesting: %d"
                    " > max: %d", __FUNCTION__, streamId, handOutBufferCount,
                    numBuffersRequested, maxBuffers);
            bufRet.val.error(StreamBufferRequestError::MAX_BUFFER_EXCEEDED);
            allReqsSucceeds = false;
            continue;
        }

        hardware::hidl_vec<StreamBuffer> tmpRetBuffers(numBuffersRequested);
        bool currentReqSucceeds = true;
        std::vector<camera_stream_buffer_t> streamBuffers(numBuffersRequested);
        std::vector<buffer_handle_t> newBuffers;
        size_t numAllocatedBuffers = 0;
        size_t numPushedInflightBuffers = 0;
        for (size_t b = 0; b < numBuffersRequested; b++) {
            camera_stream_buffer_t& sb = streamBuffers[b];
            // Since this method can run concurrently with request thread
            // We need to update the wait duration everytime we call getbuffer
            nsecs_t waitDuration =  states.reqBufferIntf.getWaitDuration();
            status_t res = outputStream->getBuffer(&sb, waitDuration);
            if (res != OK) {
                if (res == NO_INIT || res == DEAD_OBJECT) {
                    ALOGV("%s: Can't get output buffer for stream %d: %s (%d)",
                            __FUNCTION__, streamId, strerror(-res), res);
                    bufRet.val.error(StreamBufferRequestError::STREAM_DISCONNECTED);
                    states.sessionStatsBuilder.stopCounter(streamId);
                } else {
                    ALOGE("%s: Can't get output buffer for stream %d: %s (%d)",
                            __FUNCTION__, streamId, strerror(-res), res);
                    if (res == TIMED_OUT || res == NO_MEMORY) {
                        bufRet.val.error(StreamBufferRequestError::NO_BUFFER_AVAILABLE);
                    } else {
                        bufRet.val.error(StreamBufferRequestError::UNKNOWN_ERROR);
                    }
                }
                currentReqSucceeds = false;
                break;
            }
            numAllocatedBuffers++;

            buffer_handle_t *buffer = sb.buffer;
            auto pair = states.bufferRecordsIntf.getBufferId(*buffer, streamId);
            bool isNewBuffer = pair.first;
            uint64_t bufferId = pair.second;
            StreamBuffer& hBuf = tmpRetBuffers[b];

            hBuf.streamId = streamId;
            hBuf.bufferId = bufferId;
            hBuf.buffer = (isNewBuffer) ? *buffer : nullptr;
            hBuf.status = BufferStatus::OK;
            hBuf.releaseFence = nullptr;
            if (isNewBuffer) {
                newBuffers.push_back(*buffer);
            }

            native_handle_t *acquireFence = nullptr;
            if (sb.acquire_fence != -1) {
                acquireFence = native_handle_create(1,0);
                acquireFence->data[0] = sb.acquire_fence;
            }
            hBuf.acquireFence.setTo(acquireFence, /*shouldOwn*/true);
            hBuf.releaseFence = nullptr;

            res = states.bufferRecordsIntf.pushInflightRequestBuffer(bufferId, buffer, streamId);
            if (res != OK) {
                ALOGE("%s: Can't get register request buffers for stream %d: %s (%d)",
                        __FUNCTION__, streamId, strerror(-res), res);
                bufRet.val.error(StreamBufferRequestError::UNKNOWN_ERROR);
                currentReqSucceeds = false;
                break;
            }
            numPushedInflightBuffers++;
        }
        if (currentReqSucceeds) {
            bufRet.val.buffers(std::move(tmpRetBuffers));
            oneReqSucceeds = true;
        } else {
            allReqsSucceeds = false;
            for (size_t b = 0; b < numPushedInflightBuffers; b++) {
                StreamBuffer& hBuf = tmpRetBuffers[b];
                buffer_handle_t* buffer;
                status_t res = states.bufferRecordsIntf.popInflightRequestBuffer(
                        hBuf.bufferId, &buffer);
                if (res != OK) {
                    SET_ERR("%s: popInflightRequestBuffer failed for stream %d: %s (%d)",
                            __FUNCTION__, streamId, strerror(-res), res);
                }
            }
            for (size_t b = 0; b < numAllocatedBuffers; b++) {
                camera_stream_buffer_t& sb = streamBuffers[b];
                sb.acquire_fence = -1;
                sb.status = CAMERA_BUFFER_STATUS_ERROR;
            }
            returnOutputBuffers(states.useHalBufManager, /*listener*/nullptr,
                    streamBuffers.data(), numAllocatedBuffers, /*timestamp*/0,
                    /*readoutTimestamp*/0, /*requested*/false,
                    /*requestTimeNs*/0, states.sessionStatsBuilder);
            for (auto buf : newBuffers) {
                states.bufferRecordsIntf.removeOneBufferCache(streamId, buf);
            }
        }
    }

    _hidl_cb(allReqsSucceeds ? BufferRequestStatus::OK :
            oneReqSucceeds ? BufferRequestStatus::FAILED_PARTIAL :
                             BufferRequestStatus::FAILED_UNKNOWN,
            bufRets);
    states.reqBufferIntf.endRequestBuffer();
}

void returnStreamBuffers(ReturnBufferStates& states,
        const hardware::hidl_vec<hardware::camera::device::V3_2::StreamBuffer>& buffers) {
    returnStreamBuffersT(states, buffers);
}

} // camera3
} // namespace android
