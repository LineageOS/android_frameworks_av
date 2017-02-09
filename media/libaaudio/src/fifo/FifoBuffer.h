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

#ifndef FIFO_FIFO_BUFFER_H
#define FIFO_FIFO_BUFFER_H

#include <stdint.h>

#include "FifoControllerBase.h"

class FifoBuffer {
public:
    FifoBuffer(int32_t bytesPerFrame, fifo_frames_t capacityInFrames);

    FifoBuffer(int32_t   bytesPerFrame,
               fifo_frames_t   capacityInFrames,
               fifo_counter_t * readCounterAddress,
               fifo_counter_t * writeCounterAddress,
               void * dataStorageAddress);

    ~FifoBuffer();

    int32_t convertFramesToBytes(fifo_frames_t frames);

    fifo_frames_t read(void *destination, fifo_frames_t framesToRead);

    fifo_frames_t write(const void *source, fifo_frames_t framesToWrite);

    fifo_frames_t getThreshold();
    void setThreshold(fifo_frames_t threshold);

    fifo_frames_t getBufferCapacityInFrames();

    fifo_frames_t readNow(void *buffer, fifo_frames_t numFrames);

    int64_t getNextReadTime(int32_t frameRate);

    int32_t getUnderrunCount() const { return mUnderrunCount; }

    FifoControllerBase *getFifoControllerBase() { return mFifo; }

    int32_t getBytesPerFrame() {
        return mBytesPerFrame;
    }

    fifo_counter_t getReadCounter() {
        return mFifo->getReadCounter();
    }

    void setReadCounter(fifo_counter_t n) {
        mFifo->setReadCounter(n);
    }

    fifo_counter_t getWriteCounter() {
        return mFifo->getWriteCounter();
    }

    void setWriteCounter(fifo_counter_t n) {
        mFifo->setWriteCounter(n);
    }

private:
    const fifo_frames_t mFrameCapacity;
    const int32_t       mBytesPerFrame;
    uint8_t *           mStorage;
    bool                mStorageOwned; // did this object allocate the storage?
    FifoControllerBase *mFifo;
    fifo_counter_t      mFramesReadCount;
    fifo_counter_t      mFramesUnderrunCount;
    int32_t             mUnderrunCount; // need? just use frames
    int32_t             mLastReadSize;
};

#endif //FIFO_FIFO_BUFFER_H
