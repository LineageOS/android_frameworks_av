/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "SharedRingBuffer"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <iomanip>
#include <iostream>
#include <sys/mman.h>

#include "binding/RingBufferParcelable.h"
#include "binding/AudioEndpointParcelable.h"

#include "SharedRingBuffer.h"

using namespace android;
using namespace aaudio;

SharedRingBuffer::~SharedRingBuffer()
{
    mFifoBuffer.reset(); // uses mSharedMemory
    if (mSharedMemory != nullptr) {
        munmap(mSharedMemory, mSharedMemorySizeInBytes);
        mSharedMemory = nullptr;
    }
}

aaudio_result_t SharedRingBuffer::allocate(fifo_frames_t   bytesPerFrame,
                                         fifo_frames_t   capacityInFrames) {
    mCapacityInFrames = capacityInFrames;

    // Create shared memory large enough to hold the data and the read and write counters.
    mDataMemorySizeInBytes = bytesPerFrame * capacityInFrames;
    mSharedMemorySizeInBytes = mDataMemorySizeInBytes + (2 * (sizeof(fifo_counter_t)));
    mFileDescriptor.reset(ashmem_create_region("AAudioSharedRingBuffer", mSharedMemorySizeInBytes));
    if (mFileDescriptor.get() == -1) {
        ALOGE("allocate() ashmem_create_region() failed %d", errno);
        return AAUDIO_ERROR_INTERNAL;
    }
    ALOGV("allocate() mFileDescriptor = %d\n", mFileDescriptor.get());

    int err = ashmem_set_prot_region(mFileDescriptor.get(), PROT_READ|PROT_WRITE); // TODO error handling?
    if (err < 0) {
        ALOGE("allocate() ashmem_set_prot_region() failed %d", errno);
        mFileDescriptor.reset();
        return AAUDIO_ERROR_INTERNAL; // TODO convert errno to a better AAUDIO_ERROR;
    }

    // Map the fd to memory addresses. Use a temporary pointer to keep the mmap result and update
    // it to `mSharedMemory` only when mmap operate successfully.
    uint8_t* tmpPtr = (uint8_t *) mmap(0, mSharedMemorySizeInBytes,
                         PROT_READ|PROT_WRITE,
                         MAP_SHARED,
                         mFileDescriptor.get(), 0);
    if (tmpPtr == MAP_FAILED) {
        ALOGE("allocate() mmap() failed %d", errno);
        mFileDescriptor.reset();
        return AAUDIO_ERROR_INTERNAL; // TODO convert errno to a better AAUDIO_ERROR;
    }
    mSharedMemory = tmpPtr;

    // Get addresses for our counters and data from the shared memory.
    fifo_counter_t *readCounterAddress =
            (fifo_counter_t *) &mSharedMemory[SHARED_RINGBUFFER_READ_OFFSET];
    fifo_counter_t *writeCounterAddress =
            (fifo_counter_t *) &mSharedMemory[SHARED_RINGBUFFER_WRITE_OFFSET];
    uint8_t *dataAddress = &mSharedMemory[SHARED_RINGBUFFER_DATA_OFFSET];

    mFifoBuffer = std::make_shared<FifoBufferIndirect>(bytesPerFrame, capacityInFrames,
                                 readCounterAddress, writeCounterAddress, dataAddress);
    return AAUDIO_OK;
}

void SharedRingBuffer::fillParcelable(AudioEndpointParcelable &endpointParcelable,
                    RingBufferParcelable &ringBufferParcelable) {
    int fdIndex = endpointParcelable.addFileDescriptor(mFileDescriptor, mSharedMemorySizeInBytes);
    ringBufferParcelable.setupMemory(fdIndex,
                                     SHARED_RINGBUFFER_DATA_OFFSET,
                                     mDataMemorySizeInBytes,
                                     SHARED_RINGBUFFER_READ_OFFSET,
                                     SHARED_RINGBUFFER_WRITE_OFFSET,
                                     sizeof(fifo_counter_t));
    ringBufferParcelable.setBytesPerFrame(mFifoBuffer->getBytesPerFrame());
    ringBufferParcelable.setFramesPerBurst(1);
    ringBufferParcelable.setCapacityInFrames(mCapacityInFrames);
}

double SharedRingBuffer::getFractionalFullness() const {
  int32_t framesAvailable = mFifoBuffer->getFullFramesAvailable();
  int32_t capacity = mFifoBuffer->getBufferCapacityInFrames();
  return framesAvailable / (double) capacity;
}

std::string SharedRingBuffer::dump() const {
    std::stringstream result;
    int32_t readCounter = mFifoBuffer->getReadCounter();
    int32_t writeCounter = mFifoBuffer->getWriteCounter();
    result << std::setw(10) << writeCounter;
    result << std::setw(10) << readCounter;
    result << std::setw(8) << (writeCounter - readCounter);
    return result.str();
}
