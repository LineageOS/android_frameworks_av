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
#include "device3/aidl/AidlCamera3OutputUtils.h"
#include "device3/Camera3Device.h"
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
        const hardware::camera::device::V3_2::NotifyMsg& msg) {

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
            m.message.shutter.readout_timestamp = 0LL;
            break;
    }
    notify(states, &m);
}

static void convertToAidl(
        const hardware::hidl_vec<hardware::camera::device::V3_5::BufferRequest>& hidlBufReqs,
        std::vector<aidl::android::hardware::camera::device::BufferRequest> &aidlBufReqs) {
    size_t i = 0;
    aidlBufReqs.resize(hidlBufReqs.size());
    for (const auto &hidlBufReq : hidlBufReqs) {
        aidlBufReqs[i].streamId = hidlBufReq.streamId;
        aidlBufReqs[i].numBuffersRequested = hidlBufReq.numBuffersRequested;
        i++;
    }
}

static hardware::camera::device::V3_5::StreamBufferRequestError
convertToHidl(aidl::android::hardware::camera::device::StreamBufferRequestError aError) {
    using AError = aidl::android::hardware::camera::device::StreamBufferRequestError;
    using HError = hardware::camera::device::V3_5::StreamBufferRequestError;

    switch(aError) {
        case AError::NO_BUFFER_AVAILABLE:
            return HError::NO_BUFFER_AVAILABLE;
        case AError::MAX_BUFFER_EXCEEDED:
            return HError::MAX_BUFFER_EXCEEDED;
        case AError::STREAM_DISCONNECTED:
            return HError::STREAM_DISCONNECTED;
        default:
            return HError::UNKNOWN_ERROR;
    }
}

static hardware::camera::device::V3_5::BufferRequestStatus
convertToHidl(const aidl::android::hardware::camera::device::BufferRequestStatus &aBufStatus) {
    using AStatus = aidl::android::hardware::camera::device::BufferRequestStatus;
    using HStatus = hardware::camera::device::V3_5::BufferRequestStatus;
    switch (aBufStatus) {
        case AStatus::OK:
            return HStatus::OK;
        case AStatus::FAILED_PARTIAL:
            return HStatus::FAILED_PARTIAL;
        case AStatus::FAILED_CONFIGURING:
            return HStatus::FAILED_CONFIGURING;
        case AStatus::FAILED_ILLEGAL_ARGUMENTS:
            return HStatus::FAILED_ILLEGAL_ARGUMENTS;
        case AStatus::FAILED_UNKNOWN:
            return HStatus::FAILED_UNKNOWN;
    }
    return HStatus::FAILED_UNKNOWN;
}

static hardware::camera::device::V3_2::BufferStatus
convertToHidl(const aidl::android::hardware::camera::device::BufferStatus &aBufStatus) {
    using AStatus = aidl::android::hardware::camera::device::BufferStatus;
    using HStatus = hardware::camera::device::V3_2::BufferStatus;
    switch (aBufStatus) {
        case AStatus::OK:
            return HStatus::OK;
        case AStatus::ERROR:
            return HStatus::ERROR;
    }
    return HStatus::ERROR;
}

static native_handle_t *convertToHidl(const aidl::android::hardware::common::NativeHandle &ah,
        std::vector<native_handle_t *> &handlesCreated) {
    if (isHandleNull(ah)) {
        return nullptr;
    }
    native_handle_t *nh = makeFromAidl(ah);
    handlesCreated.emplace_back(nh);
    return nh;
}

static void convertToHidl(
        const std::vector<aidl::android::hardware::camera::device::StreamBuffer> &aBuffers,
        hardware::camera::device::V3_5::StreamBuffersVal &hBuffersVal,
        std::vector<native_handle_t *> &handlesCreated) {
    using HStreamBuffer = hardware::camera::device::V3_2::StreamBuffer;
    hardware::hidl_vec<HStreamBuffer> tmpBuffers(aBuffers.size());
    size_t i = 0;
    for (const auto &aBuf : aBuffers) {
        tmpBuffers[i].status = convertToHidl(aBuf.status);
        tmpBuffers[i].streamId = aBuf.streamId;
        tmpBuffers[i].bufferId = aBuf.bufferId;
        tmpBuffers[i].buffer = convertToHidl(aBuf.buffer, handlesCreated);
        tmpBuffers[i].acquireFence = convertToHidl(aBuf.acquireFence, handlesCreated);
        tmpBuffers[i].releaseFence = convertToHidl(aBuf.releaseFence, handlesCreated);
        i++;
    }
    hBuffersVal.buffers(std::move(tmpBuffers));
}

static void convertToHidl(
        const std::vector<aidl::android::hardware::camera::device::StreamBufferRet> &aidlBufRets,
        hardware::hidl_vec<hardware::camera::device::V3_5::StreamBufferRet> &hidlBufRets,
        std::vector<native_handle_t *> &handlesCreated) {
    size_t i = 0;
    using Tag = aidl::android::hardware::camera::device::StreamBuffersVal::Tag;
    hidlBufRets.resize(aidlBufRets.size());
    for (const auto &aidlBufRet : aidlBufRets) {
        auto &hidlBufRet = hidlBufRets[i];
        hidlBufRet.streamId = aidlBufRet.streamId;
        switch(aidlBufRet.val.getTag()) {
          case Tag::error:
              hidlBufRet.val.error(convertToHidl(aidlBufRet.val.get<Tag::error>()));
              break;
          case Tag::buffers:
              convertToHidl(aidlBufRet.val.get<Tag::buffers>(), hidlBufRet.val, handlesCreated);
              break;
        }
        i++;
    }
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
    std::vector<aidl::android::hardware::camera::device::BufferRequest> aidlBufReqs;
    hardware::hidl_vec<hardware::camera::device::V3_5::StreamBufferRet> hidlBufRets;
    convertToAidl(bufReqs, aidlBufReqs);
    std::vector<::aidl::android::hardware::camera::device::StreamBufferRet> aidlBufRets;
    ::aidl::android::hardware::camera::device::BufferRequestStatus aidlBufRetStatus;

    requestStreamBuffers(states, aidlBufReqs, &aidlBufRets, &aidlBufRetStatus);
    std::vector<native_handle_t *> handlesCreated;
    convertToHidl(aidlBufRets, hidlBufRets, handlesCreated);
    _hidl_cb(convertToHidl(aidlBufRetStatus), hidlBufRets);
    Camera3Device::cleanupNativeHandles(&handlesCreated);
}

void returnStreamBuffers(ReturnBufferStates& states,
        const hardware::hidl_vec<hardware::camera::device::V3_2::StreamBuffer>& buffers) {
    returnStreamBuffersT(states, buffers);
}

} // camera3
} // namespace android
