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

#define LOG_TAG "Camera3-OutputStream"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <algorithm>
#include <ctime>
#include <fstream>

#include <aidl/android/hardware/camera/device/CameraBlob.h>
#include <aidl/android/hardware/camera/device/CameraBlobId.h>

#include <android-base/unique_fd.h>
#include <cutils/properties.h>
#include <ui/GraphicBuffer.h>
#include <utils/Log.h>
#include <utils/Trace.h>

#include <common/CameraDeviceBase.h>
#include "api1/client2/JpegProcessor.h"
#include "Camera3OutputStream.h"
#include "utils/TraceHFR.h"

#ifndef container_of
#define container_of(ptr, type, member) \
    (type *)((char*)(ptr) - offsetof(type, member))
#endif

namespace android {

namespace camera3 {

using aidl::android::hardware::camera::device::CameraBlob;
using aidl::android::hardware::camera::device::CameraBlobId;

Camera3OutputStream::Camera3OutputStream(int id,
        sp<Surface> consumer,
        uint32_t width, uint32_t height, int format,
        android_dataspace dataSpace, camera_stream_rotation_t rotation,
        nsecs_t timestampOffset, const String8& physicalCameraId,
        const std::unordered_set<int32_t> &sensorPixelModesUsed, IPCTransport transport,
        int setId, bool isMultiResolution, int64_t dynamicRangeProfile,
        int64_t streamUseCase, bool deviceTimeBaseIsRealtime, int timestampBase,
        int mirrorMode) :
        Camera3IOStreamBase(id, CAMERA_STREAM_OUTPUT, width, height,
                            /*maxSize*/0, format, dataSpace, rotation,
                            physicalCameraId, sensorPixelModesUsed, setId, isMultiResolution,
                            dynamicRangeProfile, streamUseCase, deviceTimeBaseIsRealtime,
                            timestampBase),
        mConsumer(consumer),
        mTransform(0),
        mTraceFirstBuffer(true),
        mUseBufferManager(false),
        mTimestampOffset(timestampOffset),
        mUseReadoutTime(false),
        mConsumerUsage(0),
        mDropBuffers(false),
        mMirrorMode(mirrorMode),
        mDequeueBufferLatency(kDequeueLatencyBinSize),
        mIPCTransport(transport) {

    if (mConsumer == NULL) {
        ALOGE("%s: Consumer is NULL!", __FUNCTION__);
        mState = STATE_ERROR;
    }

    bool needsReleaseNotify = setId > CAMERA3_STREAM_SET_ID_INVALID;
    mBufferProducerListener = new BufferProducerListener(this, needsReleaseNotify);
}

Camera3OutputStream::Camera3OutputStream(int id,
        sp<Surface> consumer,
        uint32_t width, uint32_t height, size_t maxSize, int format,
        android_dataspace dataSpace, camera_stream_rotation_t rotation,
        nsecs_t timestampOffset, const String8& physicalCameraId,
        const std::unordered_set<int32_t> &sensorPixelModesUsed, IPCTransport transport,
        int setId, bool isMultiResolution, int64_t dynamicRangeProfile,
        int64_t streamUseCase, bool deviceTimeBaseIsRealtime, int timestampBase,
        int mirrorMode) :
        Camera3IOStreamBase(id, CAMERA_STREAM_OUTPUT, width, height, maxSize,
                            format, dataSpace, rotation, physicalCameraId, sensorPixelModesUsed,
                            setId, isMultiResolution, dynamicRangeProfile, streamUseCase,
                            deviceTimeBaseIsRealtime, timestampBase),
        mConsumer(consumer),
        mTransform(0),
        mTraceFirstBuffer(true),
        mUseBufferManager(false),
        mTimestampOffset(timestampOffset),
        mUseReadoutTime(false),
        mConsumerUsage(0),
        mDropBuffers(false),
        mMirrorMode(mirrorMode),
        mDequeueBufferLatency(kDequeueLatencyBinSize),
        mIPCTransport(transport) {

    if (format != HAL_PIXEL_FORMAT_BLOB && format != HAL_PIXEL_FORMAT_RAW_OPAQUE) {
        ALOGE("%s: Bad format for size-only stream: %d", __FUNCTION__,
                format);
        mState = STATE_ERROR;
    }

    if (mConsumer == NULL) {
        ALOGE("%s: Consumer is NULL!", __FUNCTION__);
        mState = STATE_ERROR;
    }

    bool needsReleaseNotify = setId > CAMERA3_STREAM_SET_ID_INVALID;
    mBufferProducerListener = new BufferProducerListener(this, needsReleaseNotify);
}

Camera3OutputStream::Camera3OutputStream(int id,
        uint32_t width, uint32_t height, int format,
        uint64_t consumerUsage, android_dataspace dataSpace,
        camera_stream_rotation_t rotation, nsecs_t timestampOffset,
        const String8& physicalCameraId,
        const std::unordered_set<int32_t> &sensorPixelModesUsed, IPCTransport transport,
        int setId, bool isMultiResolution, int64_t dynamicRangeProfile,
        int64_t streamUseCase, bool deviceTimeBaseIsRealtime, int timestampBase,
        int mirrorMode) :
        Camera3IOStreamBase(id, CAMERA_STREAM_OUTPUT, width, height,
                            /*maxSize*/0, format, dataSpace, rotation,
                            physicalCameraId, sensorPixelModesUsed, setId, isMultiResolution,
                            dynamicRangeProfile, streamUseCase, deviceTimeBaseIsRealtime,
                            timestampBase),
        mConsumer(nullptr),
        mTransform(0),
        mTraceFirstBuffer(true),
        mUseBufferManager(false),
        mTimestampOffset(timestampOffset),
        mUseReadoutTime(false),
        mConsumerUsage(consumerUsage),
        mDropBuffers(false),
        mMirrorMode(mirrorMode),
        mDequeueBufferLatency(kDequeueLatencyBinSize),
        mIPCTransport(transport) {
    // Deferred consumer only support preview surface format now.
    if (format != HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) {
        ALOGE("%s: Deferred consumer only supports IMPLEMENTATION_DEFINED format now!",
                __FUNCTION__);
        mState = STATE_ERROR;
    }

    // Validation check for the consumer usage flag.
    if ((consumerUsage & GraphicBuffer::USAGE_HW_TEXTURE) == 0 &&
            (consumerUsage & GraphicBuffer::USAGE_HW_COMPOSER) == 0) {
        ALOGE("%s: Deferred consumer usage flag is illegal %" PRIu64 "!",
              __FUNCTION__, consumerUsage);
        mState = STATE_ERROR;
    }

    mConsumerName = String8("Deferred");
    bool needsReleaseNotify = setId > CAMERA3_STREAM_SET_ID_INVALID;
    mBufferProducerListener = new BufferProducerListener(this, needsReleaseNotify);
}

Camera3OutputStream::Camera3OutputStream(int id, camera_stream_type_t type,
                                         uint32_t width, uint32_t height,
                                         int format,
                                         android_dataspace dataSpace,
                                         camera_stream_rotation_t rotation,
                                         const String8& physicalCameraId,
                                         const std::unordered_set<int32_t> &sensorPixelModesUsed,
                                         IPCTransport transport,
                                         uint64_t consumerUsage, nsecs_t timestampOffset,
                                         int setId, bool isMultiResolution,
                                         int64_t dynamicRangeProfile, int64_t streamUseCase,
                                         bool deviceTimeBaseIsRealtime, int timestampBase,
                                         int mirrorMode) :
        Camera3IOStreamBase(id, type, width, height,
                            /*maxSize*/0,
                            format, dataSpace, rotation,
                            physicalCameraId, sensorPixelModesUsed, setId, isMultiResolution,
                            dynamicRangeProfile, streamUseCase, deviceTimeBaseIsRealtime,
                            timestampBase),
        mTransform(0),
        mTraceFirstBuffer(true),
        mUseBufferManager(false),
        mTimestampOffset(timestampOffset),
        mUseReadoutTime(false),
        mConsumerUsage(consumerUsage),
        mDropBuffers(false),
        mMirrorMode(mirrorMode),
        mDequeueBufferLatency(kDequeueLatencyBinSize),
        mIPCTransport(transport) {

    bool needsReleaseNotify = setId > CAMERA3_STREAM_SET_ID_INVALID;
    mBufferProducerListener = new BufferProducerListener(this, needsReleaseNotify);

    // Subclasses expected to initialize mConsumer themselves
}


Camera3OutputStream::~Camera3OutputStream() {
    disconnectLocked();
}

status_t Camera3OutputStream::getBufferLocked(camera_stream_buffer *buffer,
        const std::vector<size_t>&) {
    ATRACE_HFR_CALL();

    ANativeWindowBuffer* anb;
    int fenceFd = -1;

    status_t res;
    res = getBufferLockedCommon(&anb, &fenceFd);
    if (res != OK) {
        return res;
    }

    /**
     * FenceFD now owned by HAL except in case of error,
     * in which case we reassign it to acquire_fence
     */
    handoutBufferLocked(*buffer, &(anb->handle), /*acquireFence*/fenceFd,
                        /*releaseFence*/-1, CAMERA_BUFFER_STATUS_OK, /*output*/true);

    return OK;
}

status_t Camera3OutputStream::getBuffersLocked(std::vector<OutstandingBuffer>* outBuffers) {
    status_t res;

    if ((res = getBufferPreconditionCheckLocked()) != OK) {
        return res;
    }

    if (mUseBufferManager) {
        ALOGE("%s: stream %d is managed by buffer manager and does not support batch operation",
                __FUNCTION__, mId);
        return INVALID_OPERATION;
    }

    sp<Surface> consumer = mConsumer;
    /**
     * Release the lock briefly to avoid deadlock for below scenario:
     * Thread 1: StreamingProcessor::startStream -> Camera3Stream::isConfiguring().
     * This thread acquired StreamingProcessor lock and try to lock Camera3Stream lock.
     * Thread 2: Camera3Stream::returnBuffer->StreamingProcessor::onFrameAvailable().
     * This thread acquired Camera3Stream lock and bufferQueue lock, and try to lock
     * StreamingProcessor lock.
     * Thread 3: Camera3Stream::getBuffer(). This thread acquired Camera3Stream lock
     * and try to lock bufferQueue lock.
     * Then there is circular locking dependency.
     */
    mLock.unlock();

    size_t numBuffersRequested = outBuffers->size();
    std::vector<Surface::BatchBuffer> buffers(numBuffersRequested);

    nsecs_t dequeueStart = systemTime(SYSTEM_TIME_MONOTONIC);
    res = consumer->dequeueBuffers(&buffers);
    nsecs_t dequeueEnd = systemTime(SYSTEM_TIME_MONOTONIC);
    mDequeueBufferLatency.add(dequeueStart, dequeueEnd);

    mLock.lock();

    if (res != OK) {
        if (shouldLogError(res, mState)) {
            ALOGE("%s: Stream %d: Can't dequeue %zu output buffers: %s (%d)",
                    __FUNCTION__, mId, numBuffersRequested, strerror(-res), res);
        }
        checkRetAndSetAbandonedLocked(res);
        return res;
    }
    checkRemovedBuffersLocked();

    /**
     * FenceFD now owned by HAL except in case of error,
     * in which case we reassign it to acquire_fence
     */
    for (size_t i = 0; i < numBuffersRequested; i++) {
        handoutBufferLocked(*(outBuffers->at(i).outBuffer),
                &(buffers[i].buffer->handle), /*acquireFence*/buffers[i].fenceFd,
                /*releaseFence*/-1, CAMERA_BUFFER_STATUS_OK, /*output*/true);
    }
    return OK;
}

status_t Camera3OutputStream::queueBufferToConsumer(sp<ANativeWindow>& consumer,
            ANativeWindowBuffer* buffer, int anwReleaseFence,
            const std::vector<size_t>&) {
    return consumer->queueBuffer(consumer.get(), buffer, anwReleaseFence);
}

status_t Camera3OutputStream::returnBufferLocked(
        const camera_stream_buffer &buffer,
        nsecs_t timestamp, nsecs_t readoutTimestamp,
        int32_t transform, const std::vector<size_t>& surface_ids) {
    ATRACE_HFR_CALL();

    if (mHandoutTotalBufferCount == 1) {
        returnPrefetchedBuffersLocked();
    }

    status_t res = returnAnyBufferLocked(buffer, timestamp, readoutTimestamp,
                                         /*output*/true, transform, surface_ids);

    if (res != OK) {
        return res;
    }

    mLastTimestamp = timestamp;
    mFrameCount++;

    return OK;
}

status_t Camera3OutputStream::fixUpHidlJpegBlobHeader(ANativeWindowBuffer* anwBuffer, int fence) {
    // Lock the JPEG buffer for CPU read
    sp<GraphicBuffer> graphicBuffer = GraphicBuffer::from(anwBuffer);
    void* mapped = nullptr;
    base::unique_fd fenceFd(dup(fence));
    // Use USAGE_SW_WRITE_RARELY since we're going to re-write the CameraBlob
    // header.
    GraphicBufferLocker gbLocker(graphicBuffer);
    status_t res =
            gbLocker.lockAsync(
                    GraphicBuffer::USAGE_SW_READ_OFTEN | GraphicBuffer::USAGE_SW_WRITE_RARELY,
                    &mapped, fenceFd.get());
    if (res != OK) {
        ALOGE("%s: Failed to lock the buffer: %s (%d)", __FUNCTION__, strerror(-res), res);
        return res;
    }

    uint8_t *hidlHeaderStart =
            static_cast<uint8_t*>(mapped) + graphicBuffer->getWidth() - sizeof(camera_jpeg_blob_t);
    // Check that the jpeg buffer is big enough to contain HIDL camera blob
    if (hidlHeaderStart < static_cast<uint8_t *>(mapped)) {
        ALOGE("%s, jpeg buffer not large enough to fit HIDL camera blob %" PRIu32, __FUNCTION__,
                graphicBuffer->getWidth());
        return BAD_VALUE;
    }
    camera_jpeg_blob_t *hidlBlobHeader = reinterpret_cast<camera_jpeg_blob_t *>(hidlHeaderStart);

    // Check that the blob is indeed the jpeg blob id.
    if (hidlBlobHeader->jpeg_blob_id != CAMERA_JPEG_BLOB_ID) {
        ALOGE("%s, jpeg blob id %d is not correct", __FUNCTION__, hidlBlobHeader->jpeg_blob_id);
        return BAD_VALUE;
    }

    // Retrieve id and blob size
    CameraBlobId blobId = static_cast<CameraBlobId>(hidlBlobHeader->jpeg_blob_id);
    uint32_t blobSizeBytes = hidlBlobHeader->jpeg_size;

    if (blobSizeBytes > (graphicBuffer->getWidth() - sizeof(camera_jpeg_blob_t))) {
        ALOGE("%s, blobSize in HIDL jpeg blob : %d is corrupt, buffer size %" PRIu32, __FUNCTION__,
                  blobSizeBytes, graphicBuffer->getWidth());
    }

    uint8_t *aidlHeaderStart =
            static_cast<uint8_t*>(mapped) + graphicBuffer->getWidth() - sizeof(CameraBlob);

    // Check that the jpeg buffer is big enough to contain AIDL camera blob
    if (aidlHeaderStart < static_cast<uint8_t *>(mapped)) {
        ALOGE("%s, jpeg buffer not large enough to fit AIDL camera blob %" PRIu32, __FUNCTION__,
                graphicBuffer->getWidth());
        return BAD_VALUE;
    }

    if (static_cast<uint8_t*>(mapped) + blobSizeBytes > aidlHeaderStart) {
        ALOGE("%s, jpeg blob with size %d , buffer size %" PRIu32 " not large enough to fit"
                " AIDL camera blob without corrupting jpeg", __FUNCTION__, blobSizeBytes,
                graphicBuffer->getWidth());
        return BAD_VALUE;
    }

    // Fill in JPEG header
    CameraBlob aidlHeader = {
            .blobId = blobId,
            .blobSizeBytes = static_cast<int32_t>(blobSizeBytes)
    };
    memcpy(aidlHeaderStart, &aidlHeader, sizeof(CameraBlob));
    graphicBuffer->unlock();
    return OK;
}

status_t Camera3OutputStream::returnBufferCheckedLocked(
            const camera_stream_buffer &buffer,
            nsecs_t timestamp,
            nsecs_t readoutTimestamp,
            bool output,
            int32_t transform,
            const std::vector<size_t>& surface_ids,
            /*out*/
            sp<Fence> *releaseFenceOut) {

    (void)output;
    ALOG_ASSERT(output, "Expected output to be true");

    status_t res;

    // Fence management - always honor release fence from HAL
    sp<Fence> releaseFence = new Fence(buffer.release_fence);
    int anwReleaseFence = releaseFence->dup();

    /**
     * Release the lock briefly to avoid deadlock with
     * StreamingProcessor::startStream -> Camera3Stream::isConfiguring (this
     * thread will go into StreamingProcessor::onFrameAvailable) during
     * queueBuffer
     */
    sp<ANativeWindow> currentConsumer = mConsumer;
    StreamState state = mState;
    mLock.unlock();

    ANativeWindowBuffer *anwBuffer = container_of(buffer.buffer, ANativeWindowBuffer, handle);
    bool bufferDeferred = false;
    /**
     * Return buffer back to ANativeWindow
     */
    if (buffer.status == CAMERA_BUFFER_STATUS_ERROR || mDropBuffers || timestamp == 0) {
        // Cancel buffer
        if (mDropBuffers) {
            ALOGV("%s: Dropping a frame for stream %d.", __FUNCTION__, mId);
        } else if (buffer.status == CAMERA_BUFFER_STATUS_ERROR) {
            ALOGV("%s: A frame is dropped for stream %d due to buffer error.", __FUNCTION__, mId);
        } else {
            ALOGE("%s: Stream %d: timestamp shouldn't be 0", __FUNCTION__, mId);
        }

        res = currentConsumer->cancelBuffer(currentConsumer.get(),
                anwBuffer,
                anwReleaseFence);
        if (shouldLogError(res, state)) {
            ALOGE("%s: Stream %d: Error cancelling buffer to native window:"
                  " %s (%d)", __FUNCTION__, mId, strerror(-res), res);
        }

        notifyBufferReleased(anwBuffer);
        if (mUseBufferManager) {
            // Return this buffer back to buffer manager.
            mBufferProducerListener->onBufferReleased();
        }
    } else {
        if (mTraceFirstBuffer && (stream_type == CAMERA_STREAM_OUTPUT)) {
            {
                char traceLog[48];
                snprintf(traceLog, sizeof(traceLog), "Stream %d: first full buffer\n", mId);
                ATRACE_NAME(traceLog);
            }
            mTraceFirstBuffer = false;
        }
        // Fix CameraBlob id type discrepancy between HIDL and AIDL, details : http://b/229688810
        if (getFormat() == HAL_PIXEL_FORMAT_BLOB && getDataSpace() == HAL_DATASPACE_V0_JFIF) {
            if (mIPCTransport == IPCTransport::HIDL) {
                fixUpHidlJpegBlobHeader(anwBuffer, anwReleaseFence);
            }
            // If this is a JPEG output, and image dump mask is set, save image to
            // disk.
            if (mImageDumpMask) {
                dumpImageToDisk(timestamp, anwBuffer, anwReleaseFence);
            }
        }

        nsecs_t captureTime = (mUseReadoutTime && readoutTimestamp != 0 ?
                readoutTimestamp : timestamp) - mTimestampOffset;
        if (mPreviewFrameSpacer != nullptr) {
            nsecs_t readoutTime = (readoutTimestamp != 0 ? readoutTimestamp : timestamp)
                    - mTimestampOffset;
            res = mPreviewFrameSpacer->queuePreviewBuffer(captureTime, readoutTime,
                    transform, anwBuffer, anwReleaseFence);
            if (res != OK) {
                ALOGE("%s: Stream %d: Error queuing buffer to preview buffer spacer: %s (%d)",
                        __FUNCTION__, mId, strerror(-res), res);
                return res;
            }
            bufferDeferred = true;
        } else {
            nsecs_t presentTime = mSyncToDisplay ?
                    syncTimestampToDisplayLocked(captureTime) : captureTime;

            setTransform(transform, true/*mayChangeMirror*/);
            res = native_window_set_buffers_timestamp(mConsumer.get(), presentTime);
            if (res != OK) {
                ALOGE("%s: Stream %d: Error setting timestamp: %s (%d)",
                      __FUNCTION__, mId, strerror(-res), res);
                return res;
            }

            queueHDRMetadata(anwBuffer->handle, currentConsumer, dynamic_range_profile);

            res = queueBufferToConsumer(currentConsumer, anwBuffer, anwReleaseFence, surface_ids);
            if (shouldLogError(res, state)) {
                ALOGE("%s: Stream %d: Error queueing buffer to native window:"
                      " %s (%d)", __FUNCTION__, mId, strerror(-res), res);
            }
        }
    }
    mLock.lock();

    if (bufferDeferred) {
        mCachedOutputBufferCount++;
    }

    // Once a valid buffer has been returned to the queue, can no longer
    // dequeue all buffers for preallocation.
    if (buffer.status != CAMERA_BUFFER_STATUS_ERROR) {
        mStreamUnpreparable = true;
    }

    if (res != OK) {
        close(anwReleaseFence);
    }

    *releaseFenceOut = releaseFence;

    return res;
}

void Camera3OutputStream::dump(int fd, const Vector<String16> &args) const {
    (void) args;
    String8 lines;
    lines.appendFormat("    Stream[%d]: Output\n", mId);
    lines.appendFormat("      Consumer name: %s\n", mConsumerName.string());
    write(fd, lines.string(), lines.size());

    Camera3IOStreamBase::dump(fd, args);

    mDequeueBufferLatency.dump(fd,
        "      DequeueBuffer latency histogram:");
}

status_t Camera3OutputStream::setTransform(int transform, bool mayChangeMirror) {
    ATRACE_CALL();
    Mutex::Autolock l(mLock);
    if (mMirrorMode != OutputConfiguration::MIRROR_MODE_AUTO && mayChangeMirror) {
        // If the mirroring mode is not AUTO, do not allow transform update
        // which may change mirror.
        return OK;
    }

    return setTransformLocked(transform);
}

status_t Camera3OutputStream::setTransformLocked(int transform) {
    status_t res = OK;

    if (transform == -1) return res;

    if (mState == STATE_ERROR) {
        ALOGE("%s: Stream in error state", __FUNCTION__);
        return INVALID_OPERATION;
    }

    mTransform = transform;
    if (mState == STATE_CONFIGURED) {
        res = native_window_set_buffers_transform(mConsumer.get(),
                transform);
        if (res != OK) {
            ALOGE("%s: Unable to configure stream transform to %x: %s (%d)",
                    __FUNCTION__, transform, strerror(-res), res);
        }
    }
    return res;
}

status_t Camera3OutputStream::configureQueueLocked() {
    status_t res;

    mTraceFirstBuffer = true;
    if ((res = Camera3IOStreamBase::configureQueueLocked()) != OK) {
        return res;
    }

    if ((res = configureConsumerQueueLocked(true /*allowPreviewRespace*/)) != OK) {
        return res;
    }

    // Set dequeueBuffer/attachBuffer timeout if the consumer is not hw composer or hw texture.
    // We need skip these cases as timeout will disable the non-blocking (async) mode.
    if (!(isConsumedByHWComposer() || isConsumedByHWTexture())) {
        if (mUseBufferManager) {
            // When buffer manager is handling the buffer, we should have available buffers in
            // buffer queue before we calls into dequeueBuffer because buffer manager is tracking
            // free buffers.
            // There are however some consumer side feature (ImageReader::discardFreeBuffers) that
            // can discard free buffers without notifying buffer manager. We want the timeout to
            // happen immediately here so buffer manager can try to update its internal state and
            // try to allocate a buffer instead of waiting.
            mConsumer->setDequeueTimeout(0);
        } else {
            mConsumer->setDequeueTimeout(kDequeueBufferTimeout);
        }
    }

    return OK;
}

status_t Camera3OutputStream::configureConsumerQueueLocked(bool allowPreviewRespace) {
    status_t res;

    mTraceFirstBuffer = true;

    ALOG_ASSERT(mConsumer != 0, "mConsumer should never be NULL");

    // Configure consumer-side ANativeWindow interface. The listener may be used
    // to notify buffer manager (if it is used) of the returned buffers.
    res = mConsumer->connect(NATIVE_WINDOW_API_CAMERA,
            /*reportBufferRemoval*/true,
            /*listener*/mBufferProducerListener);
    if (res != OK) {
        ALOGE("%s: Unable to connect to native window for stream %d",
                __FUNCTION__, mId);
        return res;
    }

    mConsumerName = mConsumer->getConsumerName();

    res = native_window_set_usage(mConsumer.get(), mUsage);
    if (res != OK) {
        ALOGE("%s: Unable to configure usage %" PRIu64 " for stream %d",
                __FUNCTION__, mUsage, mId);
        return res;
    }

    res = native_window_set_scaling_mode(mConsumer.get(),
            NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW);
    if (res != OK) {
        ALOGE("%s: Unable to configure stream scaling: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    if (mMaxSize == 0) {
        // For buffers of known size
        res = native_window_set_buffers_dimensions(mConsumer.get(),
                camera_stream::width, camera_stream::height);
    } else {
        // For buffers with bounded size
        res = native_window_set_buffers_dimensions(mConsumer.get(),
                mMaxSize, 1);
    }
    if (res != OK) {
        ALOGE("%s: Unable to configure stream buffer dimensions"
                " %d x %d (maxSize %zu) for stream %d",
                __FUNCTION__, camera_stream::width, camera_stream::height,
                mMaxSize, mId);
        return res;
    }
    res = native_window_set_buffers_format(mConsumer.get(),
            camera_stream::format);
    if (res != OK) {
        ALOGE("%s: Unable to configure stream buffer format %#x for stream %d",
                __FUNCTION__, camera_stream::format, mId);
        return res;
    }

    res = native_window_set_buffers_data_space(mConsumer.get(),
            camera_stream::data_space);
    if (res != OK) {
        ALOGE("%s: Unable to configure stream dataspace %#x for stream %d",
                __FUNCTION__, camera_stream::data_space, mId);
        return res;
    }

    int maxConsumerBuffers;
    res = static_cast<ANativeWindow*>(mConsumer.get())->query(
            mConsumer.get(),
            NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS, &maxConsumerBuffers);
    if (res != OK) {
        ALOGE("%s: Unable to query consumer undequeued"
                " buffer count for stream %d", __FUNCTION__, mId);
        return res;
    }

    ALOGV("%s: Consumer wants %d buffers, HAL wants %d", __FUNCTION__,
            maxConsumerBuffers, camera_stream::max_buffers);
    if (camera_stream::max_buffers == 0) {
        ALOGE("%s: Camera HAL requested max_buffer count: %d, requires at least 1",
                __FUNCTION__, camera_stream::max_buffers);
        return INVALID_OPERATION;
    }

    mTotalBufferCount = maxConsumerBuffers + camera_stream::max_buffers;

    int timestampBase = getTimestampBase();
    bool isDefaultTimeBase = (timestampBase ==
            OutputConfiguration::TIMESTAMP_BASE_DEFAULT);
    if (allowPreviewRespace)  {
        bool forceChoreographer = (timestampBase ==
                OutputConfiguration::TIMESTAMP_BASE_CHOREOGRAPHER_SYNCED);
        bool defaultToChoreographer = (isDefaultTimeBase &&
                isConsumedByHWComposer());
        bool defaultToSpacer = (isDefaultTimeBase &&
                isConsumedByHWTexture() &&
                !isConsumedByCPU() &&
                !isVideoStream());
        if (forceChoreographer || defaultToChoreographer) {
            mSyncToDisplay = true;
            // For choreographer synced stream, extra buffers aren't kept by
            // camera service. So no need to update mMaxCachedBufferCount.
            mTotalBufferCount += kDisplaySyncExtraBuffer;
        } else if (defaultToSpacer) {
            mPreviewFrameSpacer = new PreviewFrameSpacer(this, mConsumer);
            // For preview frame spacer, the extra buffer is kept by camera
            // service. So update mMaxCachedBufferCount.
            mMaxCachedBufferCount = 1;
            mTotalBufferCount += mMaxCachedBufferCount;
            res = mPreviewFrameSpacer->run(String8::format("PreviewSpacer-%d", mId).string());
            if (res != OK) {
                ALOGE("%s: Unable to start preview spacer", __FUNCTION__);
                return res;
            }
        }
    }
    mHandoutTotalBufferCount = 0;
    mFrameCount = 0;
    mLastTimestamp = 0;

    mUseReadoutTime =
            (timestampBase == OutputConfiguration::TIMESTAMP_BASE_READOUT_SENSOR || mSyncToDisplay);

    if (isDeviceTimeBaseRealtime()) {
        if (isDefaultTimeBase && !isConsumedByHWComposer() && !isVideoStream()) {
            // Default time base, but not hardware composer or video encoder
            mTimestampOffset = 0;
        } else if (timestampBase == OutputConfiguration::TIMESTAMP_BASE_REALTIME ||
                timestampBase == OutputConfiguration::TIMESTAMP_BASE_SENSOR ||
                timestampBase == OutputConfiguration::TIMESTAMP_BASE_READOUT_SENSOR) {
            mTimestampOffset = 0;
        }
        // If timestampBase is CHOREOGRAPHER SYNCED or MONOTONIC, leave
        // timestamp offset as bootTime - monotonicTime.
    } else {
        if (timestampBase == OutputConfiguration::TIMESTAMP_BASE_REALTIME) {
            // Reverse offset for monotonicTime -> bootTime
            mTimestampOffset = -mTimestampOffset;
        } else {
            // If timestampBase is DEFAULT, MONOTONIC, SENSOR, READOUT_SENSOR or
            // CHOREOGRAPHER_SYNCED, timestamp offset is 0.
            mTimestampOffset = 0;
        }
    }

    res = native_window_set_buffer_count(mConsumer.get(),
            mTotalBufferCount);
    if (res != OK) {
        ALOGE("%s: Unable to set buffer count for stream %d",
                __FUNCTION__, mId);
        return res;
    }

    res = native_window_set_buffers_transform(mConsumer.get(),
            mTransform);
    if (res != OK) {
        ALOGE("%s: Unable to configure stream transform to %x: %s (%d)",
                __FUNCTION__, mTransform, strerror(-res), res);
        return res;
    }

    /**
     * Camera3 Buffer manager is only supported by HAL3.3 onwards, as the older HALs requires
     * buffers to be statically allocated for internal static buffer registration, while the
     * buffers provided by buffer manager are really dynamically allocated. Camera3Device only
     * sets the mBufferManager if device version is > HAL3.2, which guarantees that the buffer
     * manager setup is skipped in below code. Note that HAL3.2 is also excluded here, as some
     * HAL3.2 devices may not support the dynamic buffer registeration.
     * Also Camera3BufferManager does not support display/texture streams as they have its own
     * buffer management logic.
     */
    if (mBufferManager != 0 && mSetId > CAMERA3_STREAM_SET_ID_INVALID &&
            !(isConsumedByHWComposer() || isConsumedByHWTexture())) {
        uint64_t consumerUsage = 0;
        getEndpointUsage(&consumerUsage);
        uint32_t width = (mMaxSize == 0) ? getWidth() : mMaxSize;
        uint32_t height = (mMaxSize == 0) ? getHeight() : 1;
        StreamInfo streamInfo(
                getId(), getStreamSetId(), width, height, getFormat(), getDataSpace(),
                mUsage | consumerUsage, mTotalBufferCount,
                /*isConfigured*/true, isMultiResolution());
        wp<Camera3OutputStream> weakThis(this);
        res = mBufferManager->registerStream(weakThis,
                streamInfo);
        if (res == OK) {
            // Disable buffer allocation for this BufferQueue, buffer manager will take over
            // the buffer allocation responsibility.
            mConsumer->getIGraphicBufferProducer()->allowAllocation(false);
            mUseBufferManager = true;
        } else {
            ALOGE("%s: Unable to register stream %d to camera3 buffer manager, "
                  "(error %d %s), fall back to BufferQueue for buffer management!",
                  __FUNCTION__, mId, res, strerror(-res));
        }
    }

    return OK;
}

status_t Camera3OutputStream::getBufferLockedCommon(ANativeWindowBuffer** anb, int* fenceFd) {
    ATRACE_HFR_CALL();
    status_t res;

    if ((res = getBufferPreconditionCheckLocked()) != OK) {
        return res;
    }

    bool gotBufferFromManager = false;

    if (mUseBufferManager) {
        sp<GraphicBuffer> gb;
        res = mBufferManager->getBufferForStream(getId(), getStreamSetId(),
                isMultiResolution(), &gb, fenceFd);
        if (res == OK) {
            // Attach this buffer to the bufferQueue: the buffer will be in dequeue state after a
            // successful return.
            *anb = gb.get();
            res = mConsumer->attachBuffer(*anb);
            if (shouldLogError(res, mState)) {
                ALOGE("%s: Stream %d: Can't attach the output buffer to this surface: %s (%d)",
                        __FUNCTION__, mId, strerror(-res), res);
            }
            if (res != OK) {
                checkRetAndSetAbandonedLocked(res);
                return res;
            }
            gotBufferFromManager = true;
            ALOGV("Stream %d: Attached new buffer", getId());
        } else if (res == ALREADY_EXISTS) {
            // Have sufficient free buffers already attached, can just
            // dequeue from buffer queue
            ALOGV("Stream %d: Reusing attached buffer", getId());
            gotBufferFromManager = false;
        } else if (res != OK) {
            ALOGE("%s: Stream %d: Can't get next output buffer from buffer manager: %s (%d)",
                    __FUNCTION__, mId, strerror(-res), res);
            return res;
        }
    }
    if (!gotBufferFromManager) {
        /**
         * Release the lock briefly to avoid deadlock for below scenario:
         * Thread 1: StreamingProcessor::startStream -> Camera3Stream::isConfiguring().
         * This thread acquired StreamingProcessor lock and try to lock Camera3Stream lock.
         * Thread 2: Camera3Stream::returnBuffer->StreamingProcessor::onFrameAvailable().
         * This thread acquired Camera3Stream lock and bufferQueue lock, and try to lock
         * StreamingProcessor lock.
         * Thread 3: Camera3Stream::getBuffer(). This thread acquired Camera3Stream lock
         * and try to lock bufferQueue lock.
         * Then there is circular locking dependency.
         */
        sp<Surface> consumer = mConsumer;
        size_t remainingBuffers = (mState == STATE_PREPARING ? mTotalBufferCount :
                                   camera_stream::max_buffers) - mHandoutTotalBufferCount;
        mLock.unlock();

        nsecs_t dequeueStart = systemTime(SYSTEM_TIME_MONOTONIC);

        size_t batchSize = mBatchSize.load();
        if (batchSize == 1) {
            sp<ANativeWindow> anw = consumer;
            res = anw->dequeueBuffer(anw.get(), anb, fenceFd);
        } else {
            std::unique_lock<std::mutex> batchLock(mBatchLock);
            res = OK;
            if (mBatchedBuffers.size() == 0) {
                if (remainingBuffers == 0) {
                    ALOGE("%s: cannot get buffer while all buffers are handed out", __FUNCTION__);
                    return INVALID_OPERATION;
                }
                if (batchSize > remainingBuffers) {
                    batchSize = remainingBuffers;
                }
                batchLock.unlock();
                // Refill batched buffers
                std::vector<Surface::BatchBuffer> batchedBuffers;
                batchedBuffers.resize(batchSize);
                res = consumer->dequeueBuffers(&batchedBuffers);
                batchLock.lock();
                if (res != OK) {
                    ALOGE("%s: batch dequeueBuffers call failed! %s (%d)",
                            __FUNCTION__, strerror(-res), res);
                } else {
                    mBatchedBuffers = std::move(batchedBuffers);
                }
            }

            if (res == OK) {
                // Dispatch batch buffers
                *anb = mBatchedBuffers.back().buffer;
                *fenceFd = mBatchedBuffers.back().fenceFd;
                mBatchedBuffers.pop_back();
            }
        }

        nsecs_t dequeueEnd = systemTime(SYSTEM_TIME_MONOTONIC);
        mDequeueBufferLatency.add(dequeueStart, dequeueEnd);

        mLock.lock();

        if (mUseBufferManager && res == TIMED_OUT) {
            checkRemovedBuffersLocked();

            sp<GraphicBuffer> gb;
            res = mBufferManager->getBufferForStream(
                    getId(), getStreamSetId(), isMultiResolution(),
                    &gb, fenceFd, /*noFreeBuffer*/true);

            if (res == OK) {
                // Attach this buffer to the bufferQueue: the buffer will be in dequeue state after
                // a successful return.
                *anb = gb.get();
                res = mConsumer->attachBuffer(*anb);
                gotBufferFromManager = true;
                ALOGV("Stream %d: Attached new buffer", getId());

                if (res != OK) {
                    if (shouldLogError(res, mState)) {
                        ALOGE("%s: Stream %d: Can't attach the output buffer to this surface:"
                                " %s (%d)", __FUNCTION__, mId, strerror(-res), res);
                    }
                    checkRetAndSetAbandonedLocked(res);
                    return res;
                }
            } else {
                ALOGE("%s: Stream %d: Can't get next output buffer from buffer manager:"
                        " %s (%d)", __FUNCTION__, mId, strerror(-res), res);
                return res;
            }
        } else if (res != OK) {
            if (shouldLogError(res, mState)) {
                ALOGE("%s: Stream %d: Can't dequeue next output buffer: %s (%d)",
                        __FUNCTION__, mId, strerror(-res), res);
            }
            checkRetAndSetAbandonedLocked(res);
            return res;
        }
    }

    if (res == OK) {
        checkRemovedBuffersLocked();
    }

    return res;
}

void Camera3OutputStream::checkRemovedBuffersLocked(bool notifyBufferManager) {
    std::vector<sp<GraphicBuffer>> removedBuffers;
    status_t res = mConsumer->getAndFlushRemovedBuffers(&removedBuffers);
    if (res == OK) {
        onBuffersRemovedLocked(removedBuffers);

        if (notifyBufferManager && mUseBufferManager && removedBuffers.size() > 0) {
            mBufferManager->onBuffersRemoved(getId(), getStreamSetId(), isMultiResolution(),
                    removedBuffers.size());
        }
    }
}

void Camera3OutputStream::checkRetAndSetAbandonedLocked(status_t res) {
    // Only transition to STATE_ABANDONED from STATE_CONFIGURED. (If it is
    // STATE_PREPARING, let prepareNextBuffer handle the error.)
    if ((res == NO_INIT || res == DEAD_OBJECT) && mState == STATE_CONFIGURED) {
        mState = STATE_ABANDONED;
    }
}

bool Camera3OutputStream::shouldLogError(status_t res, StreamState state) {
    if (res == OK) {
        return false;
    }
    if ((res == DEAD_OBJECT || res == NO_INIT) && state == STATE_ABANDONED) {
        return false;
    }
    return true;
}

void Camera3OutputStream::onCachedBufferQueued() {
    Mutex::Autolock l(mLock);
    mCachedOutputBufferCount--;
    // Signal whoever is waiting for the buffer to be returned to the buffer
    // queue.
    mOutputBufferReturnedSignal.signal();
}

status_t Camera3OutputStream::disconnectLocked() {
    status_t res;

    if ((res = Camera3IOStreamBase::disconnectLocked()) != OK) {
        return res;
    }

    // Stream configuration was not finished (can only be in STATE_IN_CONFIG or STATE_CONSTRUCTED
    // state), don't need change the stream state, return OK.
    if (mConsumer == nullptr) {
        return OK;
    }

    returnPrefetchedBuffersLocked();

    if (mPreviewFrameSpacer != nullptr) {
        mPreviewFrameSpacer->requestExit();
    }

    ALOGV("%s: disconnecting stream %d from native window", __FUNCTION__, getId());

    res = native_window_api_disconnect(mConsumer.get(),
                                       NATIVE_WINDOW_API_CAMERA);
    /**
     * This is not an error. if client calling process dies, the window will
     * also die and all calls to it will return DEAD_OBJECT, thus it's already
     * "disconnected"
     */
    if (res == DEAD_OBJECT) {
        ALOGW("%s: While disconnecting stream %d from native window, the"
                " native window died from under us", __FUNCTION__, mId);
    }
    else if (res != OK) {
        ALOGE("%s: Unable to disconnect stream %d from native window "
              "(error %d %s)",
              __FUNCTION__, mId, res, strerror(-res));
        mState = STATE_ERROR;
        return res;
    }

    // Since device is already idle, there is no getBuffer call to buffer manager, unregister the
    // stream at this point should be safe.
    if (mUseBufferManager) {
        res = mBufferManager->unregisterStream(getId(), getStreamSetId(), isMultiResolution());
        if (res != OK) {
            ALOGE("%s: Unable to unregister stream %d from buffer manager "
                    "(error %d %s)", __FUNCTION__, mId, res, strerror(-res));
            mState = STATE_ERROR;
            return res;
        }
        // Note that, to make prepare/teardown case work, we must not mBufferManager.clear(), as
        // the stream is still in usable state after this call.
        mUseBufferManager = false;
    }

    mState = (mState == STATE_IN_RECONFIG) ? STATE_IN_CONFIG
                                           : STATE_CONSTRUCTED;

    mDequeueBufferLatency.log("Stream %d dequeueBuffer latency histogram", mId);
    mDequeueBufferLatency.reset();
    return OK;
}

status_t Camera3OutputStream::getEndpointUsage(uint64_t *usage) const {

    status_t res;

    if (mConsumer == nullptr) {
        // mConsumerUsage was sanitized before the Camera3OutputStream was constructed.
        *usage = mConsumerUsage;
        return OK;
    }

    res = getEndpointUsageForSurface(usage, mConsumer);

    return res;
}

void Camera3OutputStream::applyZSLUsageQuirk(int format, uint64_t *consumerUsage /*inout*/) {
    if (consumerUsage == nullptr) {
        return;
    }

    // If an opaque output stream's endpoint is ImageReader, add
    // GRALLOC_USAGE_HW_CAMERA_ZSL to the usage so HAL knows it will be used
    // for the ZSL use case.
    // Assume it's for ImageReader if the consumer usage doesn't have any of these bits set:
    //     1. GRALLOC_USAGE_HW_TEXTURE
    //     2. GRALLOC_USAGE_HW_RENDER
    //     3. GRALLOC_USAGE_HW_COMPOSER
    //     4. GRALLOC_USAGE_HW_VIDEO_ENCODER
    if (format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED &&
            (*consumerUsage & (GRALLOC_USAGE_HW_TEXTURE | GRALLOC_USAGE_HW_RENDER |
            GRALLOC_USAGE_HW_COMPOSER | GRALLOC_USAGE_HW_VIDEO_ENCODER)) == 0) {
        *consumerUsage |= GRALLOC_USAGE_HW_CAMERA_ZSL;
    }
}

status_t Camera3OutputStream::getEndpointUsageForSurface(uint64_t *usage,
        const sp<Surface>& surface) const {
    status_t res;
    uint64_t u = 0;

    res = native_window_get_consumer_usage(static_cast<ANativeWindow*>(surface.get()), &u);
    applyZSLUsageQuirk(camera_stream::format, &u);
    *usage = u;
    return res;
}

bool Camera3OutputStream::isVideoStream() const {
    uint64_t usage = 0;
    status_t res = getEndpointUsage(&usage);
    if (res != OK) {
        ALOGE("%s: getting end point usage failed: %s (%d).", __FUNCTION__, strerror(-res), res);
        return false;
    }

    return (usage & GRALLOC_USAGE_HW_VIDEO_ENCODER) != 0;
}

status_t Camera3OutputStream::setBufferManager(sp<Camera3BufferManager> bufferManager) {
    Mutex::Autolock l(mLock);
    if (mState != STATE_CONSTRUCTED) {
        ALOGE("%s: this method can only be called when stream in CONSTRUCTED state.",
                __FUNCTION__);
        return INVALID_OPERATION;
    }
    mBufferManager = bufferManager;

    return OK;
}

status_t Camera3OutputStream::updateStream(const std::vector<sp<Surface>> &/*outputSurfaces*/,
            const std::vector<OutputStreamInfo> &/*outputInfo*/,
            const std::vector<size_t> &/*removedSurfaceIds*/,
            KeyedVector<sp<Surface>, size_t> * /*outputMapo*/) {
    ALOGE("%s: this method is not supported!", __FUNCTION__);
    return INVALID_OPERATION;
}

void Camera3OutputStream::BufferProducerListener::onBufferReleased() {
    sp<Camera3OutputStream> stream = mParent.promote();
    if (stream == nullptr) {
        ALOGV("%s: Parent camera3 output stream was destroyed", __FUNCTION__);
        return;
    }

    Mutex::Autolock l(stream->mLock);
    if (!(stream->mUseBufferManager)) {
        return;
    }

    ALOGV("Stream %d: Buffer released", stream->getId());
    bool shouldFreeBuffer = false;
    status_t res = stream->mBufferManager->onBufferReleased(
        stream->getId(), stream->getStreamSetId(), stream->isMultiResolution(),
        &shouldFreeBuffer);
    if (res != OK) {
        ALOGE("%s: signaling buffer release to buffer manager failed: %s (%d).", __FUNCTION__,
                strerror(-res), res);
        stream->mState = STATE_ERROR;
    }

    if (shouldFreeBuffer) {
        sp<GraphicBuffer> buffer;
        // Detach and free a buffer (when buffer goes out of scope)
        stream->detachBufferLocked(&buffer, /*fenceFd*/ nullptr);
        if (buffer.get() != nullptr) {
            stream->mBufferManager->notifyBufferRemoved(
                    stream->getId(), stream->getStreamSetId(), stream->isMultiResolution());
        }
    }
}

void Camera3OutputStream::BufferProducerListener::onBuffersDiscarded(
        const std::vector<sp<GraphicBuffer>>& buffers) {
    sp<Camera3OutputStream> stream = mParent.promote();
    if (stream == nullptr) {
        ALOGV("%s: Parent camera3 output stream was destroyed", __FUNCTION__);
        return;
    }

    if (buffers.size() > 0) {
        Mutex::Autolock l(stream->mLock);
        stream->onBuffersRemovedLocked(buffers);
        if (stream->mUseBufferManager) {
            stream->mBufferManager->onBuffersRemoved(stream->getId(),
                    stream->getStreamSetId(), stream->isMultiResolution(), buffers.size());
        }
        ALOGV("Stream %d: %zu Buffers discarded.", stream->getId(), buffers.size());
    }
}

void Camera3OutputStream::onBuffersRemovedLocked(
        const std::vector<sp<GraphicBuffer>>& removedBuffers) {
    sp<Camera3StreamBufferFreedListener> callback = mBufferFreedListener.promote();
    if (callback != nullptr) {
        for (const auto& gb : removedBuffers) {
            callback->onBufferFreed(mId, gb->handle);
        }
    }
}

status_t Camera3OutputStream::detachBuffer(sp<GraphicBuffer>* buffer, int* fenceFd) {
    Mutex::Autolock l(mLock);
    return detachBufferLocked(buffer, fenceFd);
}

status_t Camera3OutputStream::detachBufferLocked(sp<GraphicBuffer>* buffer, int* fenceFd) {
    ALOGV("Stream %d: detachBuffer", getId());
    if (buffer == nullptr) {
        return BAD_VALUE;
    }

    sp<Fence> fence;
    status_t res = mConsumer->detachNextBuffer(buffer, &fence);
    if (res == NO_MEMORY) {
        // This may rarely happen, which indicates that the released buffer was freed by other
        // call (e.g., attachBuffer, dequeueBuffer etc.) before reaching here. We should notify the
        // buffer manager that this buffer has been freed. It's not fatal, but should be avoided,
        // therefore log a warning.
        *buffer = 0;
        ALOGW("%s: the released buffer has already been freed by the buffer queue!", __FUNCTION__);
    } else if (res != OK) {
        // Treat other errors as abandonment
        if (shouldLogError(res, mState)) {
            ALOGE("%s: detach next buffer failed: %s (%d).", __FUNCTION__, strerror(-res), res);
        }
        mState = STATE_ABANDONED;
        return res;
    }

    if (fenceFd != nullptr) {
        if (fence!= 0 && fence->isValid()) {
            *fenceFd = fence->dup();
        } else {
            *fenceFd = -1;
        }
    }

    // Here we assume detachBuffer is called by buffer manager so it doesn't need to be notified
    checkRemovedBuffersLocked(/*notifyBufferManager*/false);
    return res;
}

status_t Camera3OutputStream::dropBuffers(bool dropping) {
    Mutex::Autolock l(mLock);
    mDropBuffers = dropping;
    return OK;
}

const String8& Camera3OutputStream::getPhysicalCameraId() const {
    Mutex::Autolock l(mLock);
    return physicalCameraId();
}

status_t Camera3OutputStream::notifyBufferReleased(ANativeWindowBuffer* /*anwBuffer*/) {
    return OK;
}

bool Camera3OutputStream::isConsumerConfigurationDeferred(size_t surface_id) const {
    Mutex::Autolock l(mLock);

    if (surface_id != 0) {
        ALOGE("%s: surface_id %zu for Camera3OutputStream should be 0!", __FUNCTION__, surface_id);
    }
    return mConsumer == nullptr;
}

status_t Camera3OutputStream::setConsumers(const std::vector<sp<Surface>>& consumers) {
    Mutex::Autolock l(mLock);
    if (consumers.size() != 1) {
        ALOGE("%s: it's illegal to set %zu consumer surfaces!",
                  __FUNCTION__, consumers.size());
        return INVALID_OPERATION;
    }
    if (consumers[0] == nullptr) {
        ALOGE("%s: it's illegal to set null consumer surface!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    if (mConsumer != nullptr) {
        ALOGE("%s: consumer surface was already set!", __FUNCTION__);
        return INVALID_OPERATION;
    }

    mConsumer = consumers[0];
    return OK;
}

bool Camera3OutputStream::isConsumedByHWComposer() const {
    uint64_t usage = 0;
    status_t res = getEndpointUsage(&usage);
    if (res != OK) {
        ALOGE("%s: getting end point usage failed: %s (%d).", __FUNCTION__, strerror(-res), res);
        return false;
    }

    return (usage & GRALLOC_USAGE_HW_COMPOSER) != 0;
}

bool Camera3OutputStream::isConsumedByHWTexture() const {
    uint64_t usage = 0;
    status_t res = getEndpointUsage(&usage);
    if (res != OK) {
        ALOGE("%s: getting end point usage failed: %s (%d).", __FUNCTION__, strerror(-res), res);
        return false;
    }

    return (usage & GRALLOC_USAGE_HW_TEXTURE) != 0;
}

bool Camera3OutputStream::isConsumedByCPU() const {
    uint64_t usage = 0;
    status_t res = getEndpointUsage(&usage);
    if (res != OK) {
        ALOGE("%s: getting end point usage failed: %s (%d).", __FUNCTION__, strerror(-res), res);
        return false;
    }

    return (usage & GRALLOC_USAGE_SW_READ_MASK) != 0;
}

void Camera3OutputStream::dumpImageToDisk(nsecs_t timestamp,
        ANativeWindowBuffer* anwBuffer, int fence) {
    // Deriver output file name
    std::string fileExtension = "jpg";
    char imageFileName[64];
    time_t now = time(0);
    tm *localTime = localtime(&now);
    snprintf(imageFileName, sizeof(imageFileName), "IMG_%4d%02d%02d_%02d%02d%02d_%" PRId64 ".%s",
            1900 + localTime->tm_year, localTime->tm_mon + 1, localTime->tm_mday,
            localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
            timestamp, fileExtension.c_str());

    // Lock the image for CPU read
    sp<GraphicBuffer> graphicBuffer = GraphicBuffer::from(anwBuffer);
    void* mapped = nullptr;
    base::unique_fd fenceFd(dup(fence));
    status_t res = graphicBuffer->lockAsync(GraphicBuffer::USAGE_SW_READ_OFTEN, &mapped,
            fenceFd.get());
    if (res != OK) {
        ALOGE("%s: Failed to lock the buffer: %s (%d)", __FUNCTION__, strerror(-res), res);
        return;
    }

    // Figure out actual file size
    auto actualJpegSize = android::camera2::JpegProcessor::findJpegSize((uint8_t*)mapped, mMaxSize);
    if (actualJpegSize == 0) {
        actualJpegSize = mMaxSize;
    }

    // Output image data to file
    std::string filePath = "/data/misc/cameraserver/";
    filePath += imageFileName;
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
        ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
        graphicBuffer->unlock();
        return;
    }
    imageFile.write((const char*)mapped, actualJpegSize);

    graphicBuffer->unlock();
}

status_t Camera3OutputStream::setBatchSize(size_t batchSize) {
    Mutex::Autolock l(mLock);
    if (batchSize == 0) {
        ALOGE("%s: invalid batch size 0", __FUNCTION__);
        return BAD_VALUE;
    }

    if (mUseBufferManager) {
        ALOGE("%s: batch operation is not supported with buffer manager", __FUNCTION__);
        return INVALID_OPERATION;
    }

    if (!isVideoStream()) {
        ALOGE("%s: batch operation is not supported with non-video stream", __FUNCTION__);
        return INVALID_OPERATION;
    }

    if (camera_stream::max_buffers < batchSize) {
        ALOGW("%s: batch size is capped by max_buffers %d", __FUNCTION__,
                camera_stream::max_buffers);
        batchSize = camera_stream::max_buffers;
    }

    size_t defaultBatchSize = 1;
    if (!mBatchSize.compare_exchange_strong(defaultBatchSize, batchSize)) {
        ALOGE("%s: change batch size from %zu to %zu dynamically is not supported",
                __FUNCTION__, defaultBatchSize, batchSize);
        return INVALID_OPERATION;
    }

    return OK;
}

void Camera3OutputStream::onMinDurationChanged(nsecs_t duration, bool fixedFps) {
    Mutex::Autolock l(mLock);
    mMinExpectedDuration = duration;
    mFixedFps = fixedFps;
}

void Camera3OutputStream::setStreamUseCase(int64_t streamUseCase) {
    Mutex::Autolock l(mLock);
    camera_stream::use_case = streamUseCase;
}

void Camera3OutputStream::returnPrefetchedBuffersLocked() {
    std::vector<Surface::BatchBuffer> batchedBuffers;

    {
        std::lock_guard<std::mutex> batchLock(mBatchLock);
        if (mBatchedBuffers.size() != 0) {
            ALOGW("%s: %zu extra prefetched buffers detected. Returning",
                   __FUNCTION__, mBatchedBuffers.size());
            batchedBuffers = std::move(mBatchedBuffers);
        }
    }

    if (batchedBuffers.size() > 0) {
        mConsumer->cancelBuffers(batchedBuffers);
    }
}

nsecs_t Camera3OutputStream::syncTimestampToDisplayLocked(nsecs_t t) {
    nsecs_t currentTime = systemTime();
    if (!mFixedFps) {
        mLastCaptureTime = t;
        mLastPresentTime = currentTime;
        return t;
    }

    ParcelableVsyncEventData parcelableVsyncEventData;
    auto res = mDisplayEventReceiver.getLatestVsyncEventData(&parcelableVsyncEventData);
    if (res != OK) {
        ALOGE("%s: Stream %d: Error getting latest vsync event data: %s (%d)",
                __FUNCTION__, mId, strerror(-res), res);
        mLastCaptureTime = t;
        mLastPresentTime = currentTime;
        return t;
    }

    const VsyncEventData& vsyncEventData = parcelableVsyncEventData.vsync;
    nsecs_t minPresentT = mLastPresentTime + vsyncEventData.frameInterval / 2;

    // Find the best presentation time without worrying about previous frame's
    // presentation time if capture interval is more than kSpacingResetIntervalNs.
    //
    // When frame interval is more than 50 ms apart (3 vsyncs for 60hz refresh rate),
    // there is little risk in starting over and finding the earliest vsync to latch onto.
    // - Update captureToPresentTime offset to be used for later frames.
    // - Example use cases:
    //   - when frame rate drops down to below 20 fps, or
    //   - A new streaming session starts (stopPreview followed by
    //   startPreview)
    //
    nsecs_t captureInterval = t - mLastCaptureTime;
    if (captureInterval > kSpacingResetIntervalNs) {
        for (size_t i = 0; i < VsyncEventData::kFrameTimelinesLength; i++) {
            const auto& timeline = vsyncEventData.frameTimelines[i];
            if (timeline.deadlineTimestamp >= currentTime &&
                    timeline.expectedPresentationTime > minPresentT) {
                nsecs_t presentT = vsyncEventData.frameTimelines[i].expectedPresentationTime;
                mCaptureToPresentOffset = presentT - t;
                mLastCaptureTime = t;
                mLastPresentTime = presentT;

                // Move the expected presentation time back by 1/3 of frame interval to
                // mitigate the time drift. Due to time drift, if we directly use the
                // expected presentation time, often times 2 expected presentation time
                // falls into the same VSYNC interval.
                return presentT - vsyncEventData.frameInterval/3;
            }
        }
    }

    nsecs_t idealPresentT = t + mCaptureToPresentOffset;
    nsecs_t expectedPresentT = mLastPresentTime;
    nsecs_t minDiff = INT64_MAX;

    // In fixed FPS case, when frame durations are close to multiples of display refresh
    // rate, derive minimum intervals between presentation times based on minimal
    // expected duration. The minimum number of Vsyncs is:
    // - 0 if minFrameDuration in (0, 1.5] * vSyncInterval,
    // - 1 if minFrameDuration in (1.5, 2.5] * vSyncInterval,
    // - and so on.
    //
    // This spaces out the displaying of the frames so that the frame
    // presentations are roughly in sync with frame captures.
    int minVsyncs = (mMinExpectedDuration - vsyncEventData.frameInterval / 2) /
            vsyncEventData.frameInterval;
    if (minVsyncs < 0) minVsyncs = 0;
    nsecs_t minInterval = minVsyncs * vsyncEventData.frameInterval;

    // In fixed FPS case, if the frame duration deviates from multiples of
    // display refresh rate, find the closest Vsync without requiring a minimum
    // number of Vsync.
    //
    // Example: (24fps camera, 60hz refresh):
    //   capture readout:  |  t1  |  t1  | .. |  t1  | .. |  t1  | .. |  t1  |
    //   display VSYNC:      | t2 | t2 | ... | t2 | ... | t2 | ... | t2 |
    //   |  : 1 frame
    //   t1 : 41.67ms
    //   t2 : 16.67ms
    //   t1/t2 = 2.5
    //
    //   24fps is a commonly used video frame rate. Because the capture
    //   interval is 2.5 times of display refresh interval, the minVsyncs
    //   calculation will directly fall at the boundary condition. In this case,
    //   we should fall back to the basic logic of finding closest vsync
    //   timestamp without worrying about minVsyncs.
    float captureToVsyncIntervalRatio = 1.0f * mMinExpectedDuration / vsyncEventData.frameInterval;
    float ratioDeviation = std::fabs(
            captureToVsyncIntervalRatio - std::roundf(captureToVsyncIntervalRatio));
    bool captureDeviateFromVsync = ratioDeviation >= kMaxIntervalRatioDeviation;
    bool cameraDisplayInSync = (mFixedFps && !captureDeviateFromVsync);

    // Find best timestamp in the vsync timelines:
    // - Only use at most kMaxTimelines timelines to avoid long latency
    // - closest to the ideal presentation time,
    // - deadline timestamp is greater than the current time, and
    // - For fixed FPS, if the capture interval doesn't deviate too much from refresh interval,
    //   the candidate presentation time is at least minInterval in the future compared to last
    //   presentation time.
    // - For variable FPS, or if the capture interval deviates from refresh
    //   interval for more than 5%, find a presentation time closest to the
    //   (lastPresentationTime + captureToPresentOffset) instead.
    int maxTimelines = std::min(kMaxTimelines, (int)VsyncEventData::kFrameTimelinesLength);
    float biasForShortDelay = 1.0f;
    for (int i = 0; i < maxTimelines; i ++) {
        const auto& vsyncTime = vsyncEventData.frameTimelines[i];
        if (minVsyncs > 0) {
            // Bias towards using smaller timeline index:
            //   i = 0:                bias = 1
            //   i = maxTimelines-1:   bias = -1
            biasForShortDelay = 1.0 - 2.0 * i / (maxTimelines - 1);
        }
        if (std::abs(vsyncTime.expectedPresentationTime - idealPresentT) < minDiff &&
                vsyncTime.deadlineTimestamp >= currentTime &&
                ((!cameraDisplayInSync && vsyncTime.expectedPresentationTime > minPresentT) ||
                 (cameraDisplayInSync && vsyncTime.expectedPresentationTime >
                mLastPresentTime + minInterval +
                    static_cast<nsecs_t>(biasForShortDelay * kTimelineThresholdNs)))) {
            expectedPresentT = vsyncTime.expectedPresentationTime;
            minDiff = std::abs(vsyncTime.expectedPresentationTime - idealPresentT);
        }
    }

    if (expectedPresentT == mLastPresentTime && expectedPresentT <
            vsyncEventData.frameTimelines[maxTimelines-1].expectedPresentationTime) {
        // Couldn't find a reasonable presentation time. Using last frame's
        // presentation time would cause a frame drop. The best option now
        // is to use the next VSync as long as the last presentation time
        // doesn't already has the maximum latency, in which case dropping the
        // buffer is more desired than increasing latency.
        //
        // Example: (60fps camera, 59.9hz refresh):
        //   capture readout:  | t1 | t1 | .. | t1 | .. | t1 | .. | t1 |
        //                      \    \    \     \    \    \    \     \   \
        //   queue to BQ:       |    |    |     |    |    |    |      |    |
        //                      \    \    \     \    \     \    \      \    \
        //   display VSYNC:      | t2 | t2 | ... | t2 | ... | t2 | ... | t2 |
        //
        //   |: 1 frame
        //   t1 : 16.67ms
        //   t2 : 16.69ms
        //
        // It takes 833 frames for capture readout count and display VSYNC count to be off
        // by 1.
        //  - At frames [0, 832], presentationTime is set to timeline[0]
        //  - At frames [833, 833*2-1], presentationTime is set to timeline[1]
        //  - At frames [833*2, 833*3-1] presentationTime is set to timeline[2]
        //  - At frame 833*3, no presentation time is found because we only
        //    search for timeline[0..2].
        //  - Drop one buffer is better than further extend the presentation
        //    time.
        //
        // However, if frame 833*2 arrives 16.67ms early (right after frame
        // 833*2-1), no presentation time can be found because
        // getLatestVsyncEventData is called early. In that case, it's better to
        // set presentation time by offseting last presentation time.
        expectedPresentT += vsyncEventData.frameInterval;
    }

    mLastCaptureTime = t;
    mLastPresentTime = expectedPresentT;

    // Move the expected presentation time back by 1/3 of frame interval to
    // mitigate the time drift. Due to time drift, if we directly use the
    // expected presentation time, often times 2 expected presentation time
    // falls into the same VSYNC interval.
    return expectedPresentT - vsyncEventData.frameInterval/3;
}

bool Camera3OutputStream::shouldLogError(status_t res) {
    Mutex::Autolock l(mLock);
    return shouldLogError(res, mState);
}

}; // namespace camera3

}; // namespace android
