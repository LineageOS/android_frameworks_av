/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "SharedMemoryWrapper"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <iomanip>
#include <iostream>
#include <sys/mman.h>

#include "SharedMemoryWrapper.h"

namespace aaudio {

constexpr int COUNTER_SIZE_IN_BYTES = sizeof(android::fifo_counter_t);
constexpr int WRAPPER_SIZE_IN_BYTES = 2 * COUNTER_SIZE_IN_BYTES;

SharedMemoryWrapper::SharedMemoryWrapper() {
    mCounterFd.reset(ashmem_create_region("AAudioSharedMemoryWrapper", WRAPPER_SIZE_IN_BYTES));
    if (mCounterFd.get() == -1) {
        ALOGE("allocate() ashmem_create_region() failed %d", errno);
        return;
    }
    int err = ashmem_set_prot_region(mCounterFd.get(), PROT_READ|PROT_WRITE);
    if (err < 0) {
        ALOGE("allocate() ashmem_set_prot_region() failed %d", errno);
        mCounterFd.reset();
        return;
    }
    auto tmpPtr = (uint8_t *) mmap(nullptr, WRAPPER_SIZE_IN_BYTES,
                                   PROT_READ|PROT_WRITE,
                                   MAP_SHARED,
                                   mCounterFd.get(), 0);
    if (tmpPtr == MAP_FAILED) {
        ALOGE("allocate() mmap() failed %d", errno);
        mCounterFd.reset();
        return;
    }
    mCounterMemoryAddress = tmpPtr;

    mReadCounterAddress = (android::fifo_counter_t*) mCounterMemoryAddress;
    mWriteCounterAddress = (android::fifo_counter_t*) &mCounterMemoryAddress[COUNTER_SIZE_IN_BYTES];
}

SharedMemoryWrapper::~SharedMemoryWrapper()
{
    reset();
    if (mCounterMemoryAddress != nullptr) {
        munmap(mCounterMemoryAddress, COUNTER_SIZE_IN_BYTES);
        mCounterMemoryAddress = nullptr;
    }
}

aaudio_result_t SharedMemoryWrapper::setupFifoBuffer(android::fifo_frames_t bytesPerFrame,
                                                     android::fifo_frames_t capacityInFrames) {
    if (mDataFd.get() == -1) {
        ALOGE("%s data file descriptor is not initialized", __func__);
        return AAUDIO_ERROR_INTERNAL;
    }
    if (mCounterMemoryAddress == nullptr) {
        ALOGE("%s the counter memory is not allocated correctly", __func__);
        return AAUDIO_ERROR_INTERNAL;
    }
    mSharedMemorySizeInBytes = bytesPerFrame * capacityInFrames;
    auto tmpPtr = (uint8_t *) mmap(nullptr, mSharedMemorySizeInBytes,
                                   PROT_READ|PROT_WRITE,
                                   MAP_SHARED,
                                   mDataFd.get(), 0);
    if (tmpPtr == MAP_FAILED) {
        ALOGE("allocate() mmap() failed %d", errno);
        return AAUDIO_ERROR_INTERNAL;
    }
    mSharedMemory = tmpPtr;

    mFifoBuffer = std::make_shared<android::FifoBufferIndirect>(
            bytesPerFrame, capacityInFrames, mReadCounterAddress,
            mWriteCounterAddress, mSharedMemory);
    return AAUDIO_OK;
}

void SharedMemoryWrapper::reset() {
    mFifoBuffer.reset();
    if (mSharedMemory != nullptr) {
        munmap(mSharedMemory, mSharedMemorySizeInBytes);
        mSharedMemory = nullptr;
    }
    mDataFd.reset();
}

void SharedMemoryWrapper::fillParcelable(
        AudioEndpointParcelable* endpointParcelable, RingBufferParcelable &ringBufferParcelable,
        int32_t bytesPerFrame, int32_t framesPerBurst, int32_t capacityInFrames,
        CounterFilling counterFilling) {
    const int capacityInBytes = bytesPerFrame * capacityInFrames;
    const int dataFdIndex =
                endpointParcelable->addFileDescriptor(mDataFd, mSharedMemorySizeInBytes);
    ringBufferParcelable.setBytesPerFrame(bytesPerFrame);
    ringBufferParcelable.setFramesPerBurst(framesPerBurst);
    ringBufferParcelable.setCapacityInFrames(capacityInFrames);
    if (mCounterFd.get() == -1 || counterFilling == NONE) {
        // Failed to create shared memory for read/write counter or requesting no filling counters.
        ALOGD("%s no counter is filled, counterFd=%d", __func__, mCounterFd.get());
        ringBufferParcelable.setupMemory(dataFdIndex, 0, capacityInBytes);
    } else {
        int counterFdIndex =
                endpointParcelable->addFileDescriptor(mCounterFd, WRAPPER_SIZE_IN_BYTES);
        const int readCounterSize = (counterFilling & READ) == NONE ? 0 : COUNTER_SIZE_IN_BYTES;
        const int writeCounterSize = (counterFilling & WRITE) == NONE ? 0 : COUNTER_SIZE_IN_BYTES;
        ALOGD("%s counterFdIndex=%d readCounterSize=%d, writeCounterSize=%d",
              __func__, counterFdIndex, readCounterSize, writeCounterSize);
        ringBufferParcelable.setupMemory(
                {dataFdIndex, 0 /*offset*/, capacityInBytes},
                {counterFdIndex, 0 /*offset*/, readCounterSize},
                {counterFdIndex, COUNTER_SIZE_IN_BYTES, writeCounterSize});
    }
}

} // namespace aaudio
