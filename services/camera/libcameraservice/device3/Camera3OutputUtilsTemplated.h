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

#ifndef ANDROID_SERVERS_CAMERA3_OUTPUT_TEMPLUTILS_H
#define ANDROID_SERVERS_CAMERA3_OUTPUT_TEMPLUTILS_H

#include <inttypes.h>

#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/Trace.h>

#include <aidl/android/hardware/common/NativeHandle.h>
#include <android/hardware/camera2/ICameraDeviceCallbacks.h>

#include <android/hardware/camera/device/3.4/ICameraDeviceCallback.h>
#include <android/hardware/camera/device/3.5/ICameraDeviceCallback.h>
#include <android/hardware/camera/device/3.5/ICameraDeviceSession.h>

#include <camera/CameraUtils.h>
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

template <class BufferStatusType>
camera_buffer_status_t mapBufferStatus(BufferStatusType status) {
    switch (status) {
        case BufferStatusType::OK: return CAMERA_BUFFER_STATUS_OK;
        case BufferStatusType::ERROR: return CAMERA_BUFFER_STATUS_ERROR;
    }
    return CAMERA_BUFFER_STATUS_ERROR;
}

inline void readBufferFromVec(hardware::hidl_vec<uint8_t> &dst,
        const hardware::hidl_vec<uint8_t> &src) {
    // Not cloning here since that will be done in processCaptureResult whil
    // assigning to CameraMetadata.
    dst.setToExternal(const_cast<uint8_t *>(src.data()), src.size());
}

inline void readBufferFromVec(std::vector<uint8_t> &dst, const std::vector<uint8_t> &src) {
    dst = src;
}

// Reading one camera metadata from result argument via fmq or from the result
// Assuming the fmq is protected by a lock already
template <class FmqType, class FmqPayloadType, class MetadataType>
status_t readOneCameraMetadataLockedT(
        std::unique_ptr<FmqType>& fmq,
        uint64_t fmqResultSize,
        MetadataType& resultMetadata,
        const MetadataType& result) {
    if (fmqResultSize > 0) {
        resultMetadata.resize(fmqResultSize);
        if (fmq == nullptr) {
            return NO_MEMORY; // logged in initialize()
        }
        if (!fmq->read(reinterpret_cast<FmqPayloadType *>(resultMetadata.data()), fmqResultSize)) {
            ALOGE("%s: Cannot read camera metadata from fmq, size = %" PRIu64,
                    __FUNCTION__, fmqResultSize);
            return INVALID_OPERATION;
        }
    } else {
        readBufferFromVec(resultMetadata, result);
    }

    if (resultMetadata.size() != 0) {
        status_t res;
        const camera_metadata_t* metadata =
                reinterpret_cast<const camera_metadata_t*>(resultMetadata.data());
        size_t expected_metadata_size = resultMetadata.size();
        if ((res = validate_camera_metadata_structure(metadata, &expected_metadata_size)) != OK) {
            ALOGE("%s: Invalid camera metadata received by camera service from HAL: %s (%d)",
                    __FUNCTION__, strerror(-res), res);
            return INVALID_OPERATION;
        }
    }

    return OK;
}

inline bool isHandleNull(const hardware::hidl_handle &handle) {
    return handle == nullptr;
}

inline bool isHandleNull(const aidl::android::hardware::common::NativeHandle &handle) {
    return (handle.fds.size() == 0) && (handle.ints.size() == 0);
}

inline size_t numFdsInHandle(const hardware::hidl_handle &handle) {
    return handle->numFds;
}

inline size_t numFdsInHandle(const aidl::android::hardware::common::NativeHandle &handle) {
    return handle.fds.size();
}

inline int32_t getHandleFirstFd(const hardware::hidl_handle &handle) {
    if (handle->numFds != 1) {
        return -1;
    }
    return handle->data[0];
}

inline int32_t getHandleFirstFd(const aidl::android::hardware::common::NativeHandle &handle) {
    if (handle.fds.size() != 1) {
        return -1;
    }
    return handle.fds[0].get();
}

inline const hardware::hidl_vec<uint8_t>&
getResultMetadata(const android::hardware::camera::device::V3_2::CameraMetadata &result) {
    return result;
}

inline const std::vector<uint8_t>&
getResultMetadata(const aidl::android::hardware::camera::device::CameraMetadata &result) {
    return result.metadata;
}

// Fmqpayload type is needed since AIDL generates an fmq of payload type int8_t
// for a byte fmq vs MetadataType which is uint8_t. For HIDL, the same type is
// generated for metadata and fmq payload : uint8_t.
template <class StatesType, class CaptureResultType, class PhysMetadataType, class MetadataType,
         class FmqType, class BufferStatusType, class FmqPayloadType = uint8_t>
void processOneCaptureResultLockedT(
        StatesType& states,
        const CaptureResultType& result,
        const PhysMetadataType &physicalCameraMetadata) {
    std::unique_ptr<FmqType>& fmq = states.fmq;
    BufferRecordsInterface& bufferRecords = states.bufferRecordsIntf;
    camera_capture_result r;
    status_t res;
    r.frame_number = result.frameNumber;

    // Read and validate the result metadata.
    MetadataType resultMetadata;
    res = readOneCameraMetadataLockedT<FmqType, FmqPayloadType, MetadataType>(
            fmq, result.fmqResultSize,
            resultMetadata, getResultMetadata(result.result));
    if (res != OK) {
        ALOGE("%s: Frame %d: Failed to read capture result metadata",
                __FUNCTION__, result.frameNumber);
        return;
    }
    r.result = reinterpret_cast<const camera_metadata_t*>(resultMetadata.data());

    // Read and validate physical camera metadata
    size_t physResultCount = physicalCameraMetadata.size();
    std::vector<const char*> physCamIds(physResultCount);
    std::vector<const camera_metadata_t *> phyCamMetadatas(physResultCount);
    std::vector<MetadataType> physResultMetadata;
    physResultMetadata.resize(physResultCount);
    for (size_t i = 0; i < physicalCameraMetadata.size(); i++) {
        res = readOneCameraMetadataLockedT<FmqType, FmqPayloadType, MetadataType>(fmq,
                physicalCameraMetadata[i].fmqMetadataSize,
                physResultMetadata[i], getResultMetadata(physicalCameraMetadata[i].metadata));
        if (res != OK) {
            ALOGE("%s: Frame %d: Failed to read capture result metadata for camera %s",
                    __FUNCTION__, result.frameNumber,
                    physicalCameraMetadata[i].physicalCameraId.c_str());
            return;
        }
        physCamIds[i] = physicalCameraMetadata[i].physicalCameraId.c_str();
        phyCamMetadatas[i] =
                reinterpret_cast<const camera_metadata_t*>(physResultMetadata[i].data());
    }
    r.num_physcam_metadata = physResultCount;
    r.physcam_ids = physCamIds.data();
    r.physcam_metadata = phyCamMetadatas.data();

    std::vector<camera_stream_buffer_t> outputBuffers(result.outputBuffers.size());
    std::vector<buffer_handle_t> outputBufferHandles(result.outputBuffers.size());
    for (size_t i = 0; i < result.outputBuffers.size(); i++) {
        auto& bDst = outputBuffers[i];
        const auto &bSrc = result.outputBuffers[i];

        sp<Camera3StreamInterface> stream = states.outputStreams.get(bSrc.streamId);
        if (stream == nullptr) {
            ALOGE("%s: Frame %d: Buffer %zu: Invalid output stream id %d",
                    __FUNCTION__, result.frameNumber, i, bSrc.streamId);
            return;
        }
        bDst.stream = stream->asHalStream();

        bool noBufferReturned = false;
        buffer_handle_t *buffer = nullptr;
        if (states.useHalBufManager ||
                (flags::session_hal_buf_manager() &&
                        contains(states.halBufManagedStreamIds, bSrc.streamId))) {
            // This is suspicious most of the time but can be correct during flush where HAL
            // has to return capture result before a buffer is requested
            if (bSrc.bufferId == BUFFER_ID_NO_BUFFER) {
                if (bSrc.status == BufferStatusType::OK) {
                    ALOGE("%s: Frame %d: Buffer %zu: No bufferId for stream %d",
                            __FUNCTION__, result.frameNumber, i, bSrc.streamId);
                    // Still proceeds so other buffers can be returned
                }
                noBufferReturned = true;
            }
            if (noBufferReturned) {
                res = OK;
            } else {
                res = bufferRecords.popInflightRequestBuffer(bSrc.bufferId, &buffer);
            }
        } else {
            res = bufferRecords.popInflightBuffer(result.frameNumber, bSrc.streamId, &buffer);
        }

        if (res != OK) {
            ALOGE("%s: Frame %d: Buffer %zu: No in-flight buffer for stream %d",
                    __FUNCTION__, result.frameNumber, i, bSrc.streamId);
            return;
        }

        bDst.buffer = buffer;
        bDst.status = mapBufferStatus<BufferStatusType>(bSrc.status);
        bDst.acquire_fence = -1;
        if (isHandleNull(bSrc.releaseFence)) {
            bDst.release_fence = -1;
        } else if (numFdsInHandle(bSrc.releaseFence) == 1) {
            if (noBufferReturned) {
                ALOGE("%s: got releaseFence without output buffer!", __FUNCTION__);
            }
            bDst.release_fence = dup(getHandleFirstFd(bSrc.releaseFence));
        } else {
            ALOGE("%s: Frame %d: Invalid release fence for buffer %zu, fd count is %d, not 1",
                    __FUNCTION__, result.frameNumber, i, (int)numFdsInHandle(bSrc.releaseFence));
            return;
        }
    }
    r.num_output_buffers = outputBuffers.size();
    r.output_buffers = outputBuffers.data();

    camera_stream_buffer_t inputBuffer;
    if (result.inputBuffer.streamId == -1) {
        r.input_buffer = nullptr;
    } else {
        if (states.inputStream->getId() != result.inputBuffer.streamId) {
            ALOGE("%s: Frame %d: Invalid input stream id %d", __FUNCTION__,
                    result.frameNumber, result.inputBuffer.streamId);
            return;
        }
        inputBuffer.stream = states.inputStream->asHalStream();
        buffer_handle_t *buffer;
        res = bufferRecords.popInflightBuffer(result.frameNumber, result.inputBuffer.streamId,
                &buffer);
        if (res != OK) {
            ALOGE("%s: Frame %d: Input buffer: No in-flight buffer for stream %d",
                    __FUNCTION__, result.frameNumber, result.inputBuffer.streamId);
            return;
        }
        inputBuffer.buffer = buffer;
        inputBuffer.status = mapBufferStatus<BufferStatusType>(result.inputBuffer.status);
        inputBuffer.acquire_fence = -1;
        if (isHandleNull(result.inputBuffer.releaseFence)) {
            inputBuffer.release_fence = -1;
        } else if (numFdsInHandle(result.inputBuffer.releaseFence) == 1) {
            inputBuffer.release_fence = dup(getHandleFirstFd(result.inputBuffer.releaseFence));
        } else {
            ALOGE("%s: Frame %d: Invalid release fence for input buffer, fd count is %d, not 1",
                    __FUNCTION__, result.frameNumber,
                    (int)numFdsInHandle(result.inputBuffer.releaseFence));
            return;
        }
        r.input_buffer = &inputBuffer;
    }

    r.partial_result = result.partialResult;

    processCaptureResult(states, &r);
}

template <class VecStreamBufferType>
void returnStreamBuffersT(ReturnBufferStates& states,
        const VecStreamBufferType& buffers) {

    for (const auto& buf : buffers) {
        if (!states.useHalBufManager &&
            !(flags::session_hal_buf_manager() &&
             contains(states.halBufManagedStreamIds, buf.streamId))) {
            ALOGE("%s: Camera %s does not support HAL buffer management for stream id %d",
                  __FUNCTION__, states.cameraId.c_str(), buf.streamId);
            return;
        }
        if (buf.bufferId == BUFFER_ID_NO_BUFFER) {
            ALOGE("%s: cannot return a buffer without bufferId", __FUNCTION__);
            continue;
        }

        buffer_handle_t* buffer;
        status_t res = states.bufferRecordsIntf.popInflightRequestBuffer(buf.bufferId, &buffer);

        if (res != OK) {
            ALOGE("%s: cannot find in-flight buffer %" PRIu64 " for stream %d",
                    __FUNCTION__, buf.bufferId, buf.streamId);
            continue;
        }

        camera_stream_buffer_t streamBuffer;
        streamBuffer.buffer = buffer;
        streamBuffer.status = CAMERA_BUFFER_STATUS_ERROR;
        streamBuffer.acquire_fence = -1;
        streamBuffer.release_fence = -1;

        if (isHandleNull(buf.releaseFence)) {
            streamBuffer.release_fence = -1;
        } else if (numFdsInHandle(buf.releaseFence) == 1) {
            streamBuffer.release_fence = dup(getHandleFirstFd(buf.releaseFence));
        } else {
            ALOGE("%s: Invalid release fence, fd count is %d, not 1",
                    __FUNCTION__, (int)numFdsInHandle(buf.releaseFence));
            continue;
        }

        sp<Camera3StreamInterface> stream = states.outputStreams.get(buf.streamId);
        if (stream == nullptr) {
            ALOGE("%s: Output stream id %d not found!", __FUNCTION__, buf.streamId);
            continue;
        }
        streamBuffer.stream = stream->asHalStream();
        std::vector<BufferToReturn> returnableBuffers{};
        collectReturnableOutputBuffers(states.useHalBufManager, states.halBufManagedStreamIds,
                /*listener*/nullptr, &streamBuffer, /*size*/1, /*timestamp*/ 0,
                /*readoutTimestamp*/0, /*requested*/false, /*requestTimeNs*/0,
                states.sessionStatsBuilder,
                /*out*/&returnableBuffers);
        finishReturningOutputBuffers(returnableBuffers, /*listener*/ nullptr,
                states.sessionStatsBuilder);

    }
}

} // camera3
} // namespace android

#endif
