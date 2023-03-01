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

#pragma once

#include <android-base/unique_fd.h>
#include <cutils/ashmem.h>
#include <stdint.h>
#include <string>
#include <sys/mman.h>

#include "fifo/FifoBuffer.h"
#include "binding/RingBufferParcelable.h"
#include "binding/AudioEndpointParcelable.h"

namespace aaudio {

/**
 * Wrap the shared memory with read and write counters. Provide a fifo buffer to access the
 * wrapped shared memory.
 */
class SharedMemoryWrapper {
public:
    explicit SharedMemoryWrapper();

    virtual ~SharedMemoryWrapper();

    android::base::unique_fd& getDataFileDescriptor() { return mDataFd; }

    aaudio_result_t setupFifoBuffer(android::fifo_frames_t bytesPerFrame,
                                    android::fifo_frames_t capacityInFrames);

    void reset();

    enum CounterFilling {
        NONE = 0,
        READ = 1,
        WRITE = 2,
    };
    /**
     * Fill shared memory into parcelable.
     *
     * @param endpointParcelable container for ring buffers and shared memories
     * @param ringBufferParcelable the ring buffer
     * @param bytesPerFrame the bytes per frame of the data memory
     * @param framesPerBurst the frame per burst of the data memory
     * @param capacityInFrames the capacity in frames of the data memory
     * @param counterFilling a bit mask to control if the counter from the wrapper should be filled
     *                       or not.
     */
    void fillParcelable(AudioEndpointParcelable* endpointParcelable,
                        RingBufferParcelable &ringBufferParcelable,
                        int32_t bytesPerFrame,
                        int32_t framesPerBurst,
                        int32_t capacityInFrames,
                        CounterFilling counterFilling = NONE);

    std::shared_ptr<android::FifoBuffer> getFifoBuffer() {
        return mFifoBuffer;
    }

private:
    android::base::unique_fd mDataFd;
    android::base::unique_fd mCounterFd;
    uint8_t* mCounterMemoryAddress = nullptr;
    android::fifo_counter_t* mReadCounterAddress = nullptr;
    android::fifo_counter_t* mWriteCounterAddress = nullptr;
    std::shared_ptr<android::FifoBufferIndirect> mFifoBuffer;
    uint8_t* mSharedMemory = nullptr;
    int32_t mSharedMemorySizeInBytes = 0;
};

} /* namespace aaudio */
