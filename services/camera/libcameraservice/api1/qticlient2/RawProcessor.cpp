/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 * Not a Contribution.
 */
/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "Camera2-RawProcessor"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <netinet/in.h>
#include <inttypes.h>

#include <binder/MemoryBase.h>
#include <binder/MemoryHeapBase.h>
#include <utils/Log.h>
#include <utils/Trace.h>
#include <gui/Surface.h>

#include "common/CameraDeviceBase.h"
#include "api1/Camera2Client.h"
#include "api1/qticlient2/Camera2Heap.h"
#include "api1/qticlient2/CaptureSequencer.h"
#include "api1/qticlient2/RawProcessor.h"
#include "api1/qticlient2/QTICaptureSequencer.h"


#define QCAMERA_DUMP_FRM_LOCATION "/data/misc/camera/"

namespace android {
namespace camera2 {

RawProcessor::RawProcessor(
    sp<Camera2Client> client,
    wp<CaptureSequencer> sequencer):
        Thread(false),
        mDevice(client->getCameraDevice()),
        mSequencer(sequencer),
        mClient(client),
        mId(client->getCameraId()),
        mCaptureDone(false),
        mCaptureSuccess(false),
        mCaptureStreamId(NO_STREAM) {
}

RawProcessor::~RawProcessor() {
    ALOGV("%s: Exit", __FUNCTION__);
    deleteStream();
}

void RawProcessor::onFrameAvailable(const BufferItem& /*item*/) {
    Mutex::Autolock l(mInputMutex);
    ALOGV("%s", __FUNCTION__);
    if (!mCaptureDone) {
        mCaptureDone = true;
        mCaptureSuccess = true;
        mCaptureDoneSignal.signal();
    }
}

void RawProcessor::onBufferAcquired(const BufferInfo& /*bufferInfo*/) {
    // Intentionally left empty
}

void RawProcessor::onBufferReleased(const BufferInfo& bufferInfo) {
    ALOGV("%s", __FUNCTION__);
    if (bufferInfo.mError) {
        // Only lock in case of error, since we get one of these for each
        // onFrameAvailable as well, and scheduling may delay this call late
        // enough to run into later preview restart operations, for non-error
        // cases.
        // b/29524651
        ALOGV("%s: Raw buffer lost", __FUNCTION__);
        Mutex::Autolock l(mInputMutex);
        mCaptureDone = true;
        mCaptureSuccess = false;
        mCaptureDoneSignal.signal();
    }
}

status_t RawProcessor::updateStream(const Parameters &params) {
    ATRACE_CALL();
    ALOGV("%s", __FUNCTION__);
    status_t res;

    Mutex::Autolock l(mInputMutex);

    sp<CameraDeviceBase> device = mDevice.promote();
    if (device == 0) {
        ALOGE("%s: Camera %d: Device does not exist", __FUNCTION__, mId);
        return INVALID_OPERATION;
    }

    // Find out buffer size for Raw
    ssize_t maxRawSize = ((params.rawpictureWidth*params.rawpictureHeight*2) + 4095U) & ~4095U;
    if (maxRawSize <= 0) {
        ALOGE("%s: Camera %d: raw buffer size (%zu) is invalid ",
                __FUNCTION__, mId, maxRawSize);
        return INVALID_OPERATION;
    }

    if (mCaptureConsumer == 0) {
        // Create CPU buffer queue endpoint
        sp<IGraphicBufferProducer> producer;
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&producer, &consumer);
        mCaptureConsumer = new CpuConsumer(consumer, 1);
        mCaptureConsumer->setFrameAvailableListener(this);
        mCaptureConsumer->setName(String8("Camera2-RawConsumer"));
        mCaptureWindow = new Surface(producer);
    }

    // Since ashmem heaps are rounded up to page size, don't reallocate if
    // the capture heap isn't exactly the same size as the required Raw buffer
    const size_t HEAP_SLACK_FACTOR = 2;
    if (mCaptureHeap == 0 ||
            (mCaptureHeap->getSize() < static_cast<size_t>(maxRawSize)) ||
            (mCaptureHeap->getSize() >
                    static_cast<size_t>(maxRawSize) * HEAP_SLACK_FACTOR) ) {
        // Create memory for API consumption
        mCaptureHeap.clear();
        mCaptureHeap =
                new MemoryHeapBase(maxRawSize, 0, "Camera2Client::CaptureHeap");
        if (mCaptureHeap->getSize() == 0) {
            ALOGE("%s: Camera %d: Unable to allocate memory for capture",
                    __FUNCTION__, mId);
            return NO_MEMORY;
        }
    }
    ALOGE("%s: Camera %d: Raw capture heap now %zu bytes; requested %zd bytes",
            __FUNCTION__, mId, mCaptureHeap->getSize(), maxRawSize);

    if (mCaptureStreamId != NO_STREAM) {
        // Check if stream parameters have to change
        CameraDeviceBase::StreamInfo streamInfo;
        res = device->getStreamInfo(mCaptureStreamId, &streamInfo);
        if (res != OK) {
            ALOGE("%s: Camera %d: Error querying capture output stream info: "
                    "%s (%d)", __FUNCTION__,
                    mId, strerror(-res), res);
            return res;
        }

        if (streamInfo.width != (uint32_t)params.rawpictureWidth ||
                streamInfo.height != (uint32_t)params.rawpictureHeight) {
            ALOGV("%s: Camera %d: Deleting stream %d since the buffer dimensions changed",
                __FUNCTION__, mId, mCaptureStreamId);
            res = device->deleteStream(mCaptureStreamId);
            if (res == -EBUSY) {
                ALOGV("%s: Camera %d: Device is busy, call updateStream again "
                      " after it becomes idle", __FUNCTION__, mId);
                return res;
            } else if (res != OK) {
                ALOGE("%s: Camera %d: Unable to delete old output stream "
                        "for capture: %s (%d)", __FUNCTION__,
                        mId, strerror(-res), res);
                return res;
            }
            mCaptureStreamId = NO_STREAM;
        }
    }

    if (mCaptureStreamId == NO_STREAM) {
        // Create stream for HAL production
        res = device->createStream(mCaptureWindow,
                params.rawpictureWidth, params.rawpictureHeight,
                HAL_PIXEL_FORMAT_RAW10, HAL_DATASPACE_ARBITRARY,
                CAMERA3_STREAM_ROTATION_0, &mCaptureStreamId);
        if (res != OK) {
            ALOGE("%s: Camera %d: Can't create output stream for capture: "
                    "%s (%d)", __FUNCTION__, mId,
                    strerror(-res), res);
            return res;
        }
        res = device->addBufferListenerForStream(mCaptureStreamId, this);
        if (res != OK) {
              ALOGE("%s: Camera %d: Can't add buffer listeneri: %s (%d)",
                    __FUNCTION__, mId, strerror(-res), res);
              return res;
        }
    }
    return OK;
}

status_t RawProcessor::deleteStream() {
    ATRACE_CALL();

    Mutex::Autolock l(mInputMutex);

    if (mCaptureStreamId != NO_STREAM) {
        sp<CameraDeviceBase> device = mDevice.promote();
        if (device == 0) {
            ALOGE("%s: Camera %d: Device does not exist", __FUNCTION__, mId);
            return INVALID_OPERATION;
        }

        device->deleteStream(mCaptureStreamId);

        mCaptureHeap.clear();
        mCaptureWindow.clear();
        mCaptureConsumer.clear();

        mCaptureStreamId = NO_STREAM;
    }
    return OK;
}

int RawProcessor::getStreamId() const {
    Mutex::Autolock l(mInputMutex);
    return mCaptureStreamId;
}

bool RawProcessor::threadLoop() {
    status_t res;

    bool captureSuccess = false;
    {
        Mutex::Autolock l(mInputMutex);
        while (!mCaptureDone) {
            res = mCaptureDoneSignal.waitRelative(mInputMutex,
                    kWaitDuration);
            if (res == TIMED_OUT) return true;
        }

        captureSuccess = mCaptureSuccess;
        mCaptureDone = false;
    }

    res = processNewCapture(captureSuccess);

    return true;
}

status_t RawProcessor::processNewCapture(bool captureSuccess) {
    ATRACE_CALL();
    status_t res;
    sp<Camera2Heap> captureHeap;
    sp<MemoryBase> captureBuffer;

    CpuConsumer::LockedBuffer imgBuffer;

    if (captureSuccess) {
        Mutex::Autolock l(mInputMutex);
        if (mCaptureStreamId == NO_STREAM) {
            ALOGW("%s: Camera %d: No stream is available", __FUNCTION__, mId);
            return INVALID_OPERATION;
        }

        res = mCaptureConsumer->lockNextBuffer(&imgBuffer);
        if (res != OK) {
            if (res != BAD_VALUE) {
                ALOGE("%s: Camera %d: Error receiving still image buffer: "
                        "%s (%d)", __FUNCTION__,
                        mId, strerror(-res), res);
            }
            return res;
        }

        ALOGV("%s: Camera %d: Still capture available", __FUNCTION__,
                mId);

        if (imgBuffer.format != HAL_PIXEL_FORMAT_RAW10) {
            ALOGE("%s: Camera %d: Unexpected format for still image: "
                    "%x, expected %x", __FUNCTION__, mId,
                    imgBuffer.format,
                    HAL_PIXEL_FORMAT_RAW10);
            mCaptureConsumer->unlockBuffer(imgBuffer);
            return OK;
        }

        // Find size of Raw image
        size_t RawSize = 0;
        if (imgBuffer.format == HAL_PIXEL_FORMAT_RAW10) {
                RawSize = (imgBuffer.width*imgBuffer.height/4)*5;
        }

        size_t heapSize = mCaptureHeap->getSize();
        if (RawSize > heapSize) {
            ALOGW("%s: Raw image is larger than expected, truncating "
                    "(got %zu, expected at most %zu bytes)",
                    __FUNCTION__, RawSize, heapSize);
            RawSize = heapSize;
        }

        // TODO: Optimize this to avoid memcopy
        captureBuffer = new MemoryBase(mCaptureHeap, 0, RawSize);
        void* captureMemory = mCaptureHeap->getBase();
        memcpy(captureMemory, imgBuffer.data, RawSize);
        {
            sp<Camera2Client> client = mClient.promote();
            if (client == 0) {
                ALOGE("%s: Camera %d: Client does not exist", __FUNCTION__, mId);
                return INVALID_OPERATION;
            }
            SharedParameters::Lock l(client->getParameters());
            if(l.mParameters.qtiParams->isRawPlusYuv) {
                dumpRawSnapshot(imgBuffer,captureMemory,RawSize);
            }
        }

        mCaptureConsumer->unlockBuffer(imgBuffer);
    }

    sp<CaptureSequencer> sequencer = mSequencer.promote();
    if (sequencer != 0) {
        sequencer->mQTICaptureSequencer->onRawCaptureAvailable(imgBuffer.timestamp, captureBuffer, !captureSuccess);
    }
    return OK;
}

void RawProcessor::dumpRawSnapshot(CpuConsumer::LockedBuffer & imgBuffer,void * captureBuffer,size_t RawSize)
{
    String8 buf;
    int width=0,height=0;

    width = imgBuffer.width;
    height = imgBuffer.height;
    buf.appendFormat(QCAMERA_DUMP_FRM_LOCATION"%" PRId64 "r_%dx%d_%" PRId64 ".raw",
            imgBuffer.timestamp,width, height,imgBuffer.frameNumber);

    int file_fd = open(buf.string(), O_RDWR| O_CREAT, 0777);
    if (file_fd >= 0) {
        ssize_t written_len = write(file_fd, captureBuffer, RawSize);
        ALOGD("written number of bytes %zd", written_len);
        close(file_fd);
    } else {
        ALOGE("failed to open file to dump image");
    }
}

}; // namespace camera2
}; // namespace android
