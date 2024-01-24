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

#define LOG_TAG "AidlCamera3-OutputUtils"
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
#include <aidlcommonsupport/NativeHandle.h>

#include <camera/CameraUtils.h>
#include <camera_metadata_hidden.h>

#include "device3/aidl/AidlCamera3OutputUtils.h"
#include "device3/Camera3OutputUtilsTemplated.h"

#include "system/camera_metadata.h"

using namespace android::camera3;
using namespace android::hardware::camera;

namespace android {
namespace camera3 {

void processOneCaptureResultLocked(
        AidlCaptureOutputStates& states,
        const aidl::android::hardware::camera::device::CaptureResult& result,
        const std::vector<aidl::android::hardware::camera::device::PhysicalCameraMetadata>
                &physicalCameraMetadata) {
    processOneCaptureResultLockedT<AidlCaptureOutputStates,
        aidl::android::hardware::camera::device::CaptureResult,
        std::vector<aidl::android::hardware::camera::device::PhysicalCameraMetadata>,
        std::vector<uint8_t>, AidlResultMetadataQueue,
        aidl::android::hardware::camera::device::BufferStatus, int8_t>(states, result,
                physicalCameraMetadata);
}

void notify(CaptureOutputStates& states,
            const aidl::android::hardware::camera::device::NotifyMsg& msg,
            bool hasReadoutTimestamp) {

    using ErrorCode = aidl::android::hardware::camera::device::ErrorCode;
    using Tag = aidl::android::hardware::camera::device::NotifyMsg::Tag;

    ATRACE_CALL();
    camera_notify_msg m;

    switch (msg.getTag()) {
        case Tag::error:
            m.type = CAMERA_MSG_ERROR;
            m.message.error.frame_number = msg.get<Tag::error>().frameNumber;
            if (msg.get<Tag::error>().errorStreamId >= 0) {
                sp<Camera3StreamInterface> stream =
                        states.outputStreams.get(msg.get<Tag::error>().errorStreamId);
                if (stream == nullptr) {
                    ALOGE("%s: Frame %d: Invalid error stream id %d", __FUNCTION__,
                            m.message.error.frame_number, msg.get<Tag::error>().errorStreamId);
                    return;
                }
                m.message.error.error_stream = stream->asHalStream();
            } else {
                m.message.error.error_stream = nullptr;
            }
            switch (msg.get<Tag::error>().errorCode) {
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
        case Tag::shutter:
            m.type = CAMERA_MSG_SHUTTER;
            m.message.shutter.frame_number = msg.get<Tag::shutter>().frameNumber;
            m.message.shutter.timestamp = msg.get<Tag::shutter>().timestamp;
            m.message.shutter.readout_timestamp_valid = hasReadoutTimestamp;
            m.message.shutter.readout_timestamp =
                    hasReadoutTimestamp ? msg.get<Tag::shutter>().readoutTimestamp : 0LL;
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
        const std::vector<aidl::android::hardware::camera::device::BufferRequest>& bufReqs,
        std::vector<::aidl::android::hardware::camera::device::StreamBufferRet>* outBuffers,
        ::aidl::android::hardware::camera::device::BufferRequestStatus* status) {
    using aidl::android::hardware::camera::device::BufferStatus;
    using aidl::android::hardware::camera::device::StreamBuffer;
    using aidl::android::hardware::camera::device::BufferRequestStatus;
    using aidl::android::hardware::camera::device::StreamBufferRet;
    using aidl::android::hardware::camera::device::StreamBufferRequestError;
    using Tag = aidl::android::hardware::camera::device::StreamBuffersVal::Tag;
    if (outBuffers == nullptr || status == nullptr) {
        ALOGE("%s outBuffers / buffer status nullptr", __FUNCTION__);
        return;
    }
    std::lock_guard<std::mutex> lock(states.reqBufferLock);
    std::vector<StreamBufferRet> bufRets;
    outBuffers->clear();

    SortedVector<int32_t> streamIds;
    ssize_t sz = streamIds.setCapacity(bufReqs.size());
    if (sz < 0 || static_cast<size_t>(sz) != bufReqs.size()) {
        ALOGE("%s: failed to allocate memory for %zu buffer requests",
                __FUNCTION__, bufReqs.size());
        *status = BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS;
        return;
    }

    if (bufReqs.size() > states.outputStreams.size()) {
        ALOGE("%s: too many buffer requests (%zu > # of output streams %zu)",
                __FUNCTION__, bufReqs.size(), states.outputStreams.size());
        *status = BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS;
        return;
    }

    // Check for repeated streamId
    for (const auto& bufReq : bufReqs) {
        if (streamIds.indexOf(bufReq.streamId) != NAME_NOT_FOUND) {
            ALOGE("%s: Stream %d appear multiple times in buffer requests",
                    __FUNCTION__, bufReq.streamId);
            *status = BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS;
            return;
        }
        if (!states.useHalBufManager &&
                !contains(states.halBufManagedStreamIds, bufReq.streamId)) {
            ALOGE("%s: Camera %s does not support HAL buffer management for stream id %d",
                  __FUNCTION__, states.cameraId.c_str(), bufReq.streamId);
            *status = BufferRequestStatus::FAILED_ILLEGAL_ARGUMENTS;
            return;
        }
        streamIds.add(bufReq.streamId);
    }

    if (!states.reqBufferIntf.startRequestBuffer()) {
        ALOGE("%s: request buffer disallowed while camera service is configuring",
                __FUNCTION__);
        *status = BufferRequestStatus::FAILED_CONFIGURING;
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
            std::vector<StreamBufferRet> emptyBufRets;
            *status = BufferRequestStatus::FAILED_CONFIGURING;
            states.reqBufferIntf.endRequestBuffer();
            return;
        }

        bufRet.streamId = streamId;
        if (outputStream->isAbandoned()) {
            bufRet.val.set<Tag::error>(StreamBufferRequestError::STREAM_DISCONNECTED);
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
            bufRet.val.set<Tag::error>(StreamBufferRequestError::MAX_BUFFER_EXCEEDED);
            allReqsSucceeds = false;
            continue;
        }

        std::vector<StreamBuffer> tmpRetBuffers(numBuffersRequested);
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
                    bufRet.val.set<Tag::error>(StreamBufferRequestError::STREAM_DISCONNECTED);
                    states.sessionStatsBuilder.stopCounter(streamId);
                } else {
                    ALOGE("%s: Can't get output buffer for stream %d: %s (%d)",
                            __FUNCTION__, streamId, strerror(-res), res);
                    if (res == TIMED_OUT || res == NO_MEMORY) {
                        bufRet.val.set<Tag::error>(StreamBufferRequestError::NO_BUFFER_AVAILABLE);
                    } else if (res == INVALID_OPERATION) {
                        bufRet.val.set<Tag::error>(StreamBufferRequestError::MAX_BUFFER_EXCEEDED);
                    } else {
                        bufRet.val.set<Tag::error>(StreamBufferRequestError::UNKNOWN_ERROR);
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

            hBuf.buffer = (isNewBuffer) ? camera3::dupToAidlIfNotNull(*buffer) :
                    aidl::android::hardware::common::NativeHandle();
            hBuf.status = BufferStatus::OK;
            hBuf.releaseFence =  aidl::android::hardware::common::NativeHandle();
            if (isNewBuffer) {
                newBuffers.push_back(*buffer);
            }

            native_handle_t *acquireFence = nullptr;
            if (sb.acquire_fence != -1) {
                acquireFence = native_handle_create(1,0);
                acquireFence->data[0] = sb.acquire_fence;
            }
            //makeToAidl passes ownership to aidl NativeHandle made. Ownership
            //is passed : see system/window.h : dequeueBuffer
            hBuf.acquireFence = makeToAidlIfNotNull(acquireFence);
            if (acquireFence != nullptr) {
                native_handle_delete(acquireFence);
            }
            hBuf.releaseFence =  aidl::android::hardware::common::NativeHandle();

            res = states.bufferRecordsIntf.pushInflightRequestBuffer(bufferId, buffer, streamId);
            if (res != OK) {
                ALOGE("%s: Can't get register request buffers for stream %d: %s (%d)",
                        __FUNCTION__, streamId, strerror(-res), res);
                bufRet.val.set<Tag::error>(StreamBufferRequestError::UNKNOWN_ERROR);
                currentReqSucceeds = false;
                break;
            }
            numPushedInflightBuffers++;
        }
        if (currentReqSucceeds) {
            bufRet.val.set<Tag::buffers>(std::move(tmpRetBuffers));
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
            std::vector<BufferToReturn> returnableBuffers{};
            collectReturnableOutputBuffers(states.useHalBufManager, states.halBufManagedStreamIds,
                    /*listener*/ nullptr,
                    streamBuffers.data(), numAllocatedBuffers, /*timestamp*/ 0,
                    /*readoutTimestamp*/ 0, /*requested*/ false,
                    /*requestTimeNs*/ 0, states.sessionStatsBuilder,
                    /*out*/ &returnableBuffers);
            finishReturningOutputBuffers(returnableBuffers, /*listener*/ nullptr,
                    states.sessionStatsBuilder);
            for (auto buf : newBuffers) {
                states.bufferRecordsIntf.removeOneBufferCache(streamId, buf);
            }
        }
    }

    *status = allReqsSucceeds ? BufferRequestStatus::OK :
            oneReqSucceeds ? BufferRequestStatus::FAILED_PARTIAL :
                             BufferRequestStatus::FAILED_UNKNOWN,
    // Transfer ownership of buffer fds to outBuffers
    *outBuffers = std::move(bufRets);

    states.reqBufferIntf.endRequestBuffer();
}

void returnStreamBuffers(ReturnBufferStates& states,
        const std::vector<aidl::android::hardware::camera::device::StreamBuffer>& buffers) {
    returnStreamBuffersT(states, buffers);
}

} // camera3
} // namespace android
