/*
 * Copyright 2015 The Android Open Source Project
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

#include <cstring>
#include <unistd.h>

#define LOG_TAG "FifoBuffer"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "FifoControllerBase.h"
#include "FifoController.h"
#include "FifoControllerIndirect.h"
#include "FifoBuffer.h"

FifoBuffer::FifoBuffer(int32_t bytesPerFrame, fifo_frames_t capacityInFrames)
        : mFrameCapacity(capacityInFrames)
        , mBytesPerFrame(bytesPerFrame)
        , mStorage(nullptr)
        , mFramesReadCount(0)
        , mFramesUnderrunCount(0)
        , mUnderrunCount(0)
{
    // TODO Handle possible failures to allocate. Move out of constructor?
    mFifo = new FifoController(capacityInFrames, capacityInFrames);
    // allocate buffer
    int32_t bytesPerBuffer = bytesPerFrame * capacityInFrames;
    mStorage = new uint8_t[bytesPerBuffer];
    mStorageOwned = true;
    ALOGD("FifoBuffer: capacityInFrames = %d, bytesPerFrame = %d",
          capacityInFrames, bytesPerFrame);
}

FifoBuffer::FifoBuffer( int32_t   bytesPerFrame,
                        fifo_frames_t   capacityInFrames,
                        fifo_counter_t *  readIndexAddress,
                        fifo_counter_t *  writeIndexAddress,
                        void *  dataStorageAddress
                        )
        : mFrameCapacity(capacityInFrames)
        , mBytesPerFrame(bytesPerFrame)
        , mStorage(static_cast<uint8_t *>(dataStorageAddress))
        , mFramesReadCount(0)
        , mFramesUnderrunCount(0)
        , mUnderrunCount(0)
{
    // TODO Handle possible failures to allocate. Move out of constructor?
    mFifo = new FifoControllerIndirect(capacityInFrames,
                                       capacityInFrames,
                                       readIndexAddress,
                                       writeIndexAddress);
    mStorageOwned = false;
    ALOGD("FifoProcessor: capacityInFrames = %d, bytesPerFrame = %d",
          capacityInFrames, bytesPerFrame);
}

FifoBuffer::~FifoBuffer() {
    if (mStorageOwned) {
        delete[] mStorage;
    }
    delete mFifo;
}


int32_t FifoBuffer::convertFramesToBytes(fifo_frames_t frames) {
    return frames * mBytesPerFrame;
}

fifo_frames_t FifoBuffer::read(void *buffer, fifo_frames_t numFrames) {
    size_t numBytes;
    fifo_frames_t framesAvailable = mFifo->getFullFramesAvailable();
    fifo_frames_t framesToRead = numFrames;
    // Is there enough data in the FIFO
    if (framesToRead > framesAvailable) {
        framesToRead = framesAvailable;
    }
    if (framesToRead == 0) {
        return 0;
    }

    fifo_frames_t readIndex = mFifo->getReadIndex();
    uint8_t *destination = (uint8_t *) buffer;
    uint8_t *source = &mStorage[convertFramesToBytes(readIndex)];
    if ((readIndex + framesToRead) > mFrameCapacity) {
        // read in two parts, first part here
        fifo_frames_t frames1 = mFrameCapacity - readIndex;
        int32_t numBytes = convertFramesToBytes(frames1);
        memcpy(destination, source, numBytes);
        destination += numBytes;
        // read second part
        source = &mStorage[0];
        fifo_frames_t frames2 = framesToRead - frames1;
        numBytes = convertFramesToBytes(frames2);
        memcpy(destination, source, numBytes);
    } else {
        // just read in one shot
        numBytes = convertFramesToBytes(framesToRead);
        memcpy(destination, source, numBytes);
    }
    mFifo->advanceReadIndex(framesToRead);

    return framesToRead;
}

fifo_frames_t FifoBuffer::write(const void *buffer, fifo_frames_t framesToWrite) {
    fifo_frames_t framesAvailable = mFifo->getEmptyFramesAvailable();
//    ALOGD("FifoBuffer::write() framesToWrite = %d, framesAvailable = %d",
//         framesToWrite, framesAvailable);
    if (framesToWrite > framesAvailable) {
        framesToWrite = framesAvailable;
    }
    if (framesToWrite <= 0) {
        return 0;
    }

    size_t numBytes;
    fifo_frames_t writeIndex = mFifo->getWriteIndex();
    int byteIndex = convertFramesToBytes(writeIndex);
    const uint8_t *source = (const uint8_t *) buffer;
    uint8_t *destination = &mStorage[byteIndex];
    if ((writeIndex + framesToWrite) > mFrameCapacity) {
        // write in two parts, first part here
        fifo_frames_t frames1 = mFrameCapacity - writeIndex;
        numBytes = convertFramesToBytes(frames1);
        memcpy(destination, source, numBytes);
//        ALOGD("FifoBuffer::write(%p to %p, numBytes = %d", source, destination, numBytes);
        // read second part
        source += convertFramesToBytes(frames1);
        destination = &mStorage[0];
        fifo_frames_t framesLeft = framesToWrite - frames1;
        numBytes = convertFramesToBytes(framesLeft);
//        ALOGD("FifoBuffer::write(%p to %p, numBytes = %d", source, destination, numBytes);
        memcpy(destination, source, numBytes);
    } else {
        // just write in one shot
        numBytes = convertFramesToBytes(framesToWrite);
//        ALOGD("FifoBuffer::write(%p to %p, numBytes = %d", source, destination, numBytes);
        memcpy(destination, source, numBytes);
    }
    mFifo->advanceWriteIndex(framesToWrite);

    return framesToWrite;
}

fifo_frames_t FifoBuffer::readNow(void *buffer, fifo_frames_t numFrames) {
    mLastReadSize = numFrames;
    fifo_frames_t framesLeft = numFrames;
    fifo_frames_t framesRead = read(buffer, numFrames);
    framesLeft -= framesRead;
    mFramesReadCount += framesRead;
    mFramesUnderrunCount += framesLeft;
    // Zero out any samples we could not set.
    if (framesLeft > 0) {
        mUnderrunCount++;
        int32_t bytesToZero = convertFramesToBytes(framesLeft);
        memset(buffer, 0, bytesToZero);
    }

    return framesRead;
}

fifo_frames_t FifoBuffer::getThreshold() {
    return mFifo->getThreshold();
}

void FifoBuffer::setThreshold(fifo_frames_t threshold) {
    mFifo->setThreshold(threshold);
}

fifo_frames_t FifoBuffer::getBufferCapacityInFrames() {
    return mFifo->getCapacity();
}

