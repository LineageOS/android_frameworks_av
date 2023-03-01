/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_AAUDIO_RINGBUFFER_PARCELABLE_H
#define ANDROID_AAUDIO_RINGBUFFER_PARCELABLE_H

#include <map>
#include <stdint.h>

#include <aaudio/RingBuffer.h>
#include <binder/Parcelable.h>

#include "binding/AAudioServiceDefinitions.h"
#include "binding/SharedRegionParcelable.h"

namespace aaudio {

class RingBufferParcelable  {
public:
    RingBufferParcelable() = default;

    // Construct based on a parcelable representation.
    explicit RingBufferParcelable(const RingBuffer& parcelable);

    // TODO This assumes that all three use the same SharedMemoryParcelable
    void setupMemory(int32_t sharedMemoryIndex,
                     int32_t dataMemoryOffset,
                     int32_t dataSizeInBytes,
                     int32_t readCounterOffset,
                     int32_t writeCounterOffset,
                     int32_t counterSizeBytes);

    void setupMemory(int32_t sharedMemoryIndex,
                     int32_t dataMemoryOffset,
                     int32_t dataSizeInBytes);

    /**
     * Set up memory for the RingBufferParcelable.
     *
     * This function will take three MemoryInfoTuple as parameters to set up memory. The
     * MemoryInfoTuple contains the shared memory index, offset in the shared memory and size
     * of the object. This will allow setting up the read counter, write counter and data memory
     * that are located in different shared memory blocks.
     *
     * @param dataMemoryInfo
     * @param readCounterInfo
     * @param writeCounterInfo
     */
    void setupMemory(const SharedRegionParcelable::MemoryInfoTuple& dataMemoryInfo,
                     const SharedRegionParcelable::MemoryInfoTuple& readCounterInfo,
                     const SharedRegionParcelable::MemoryInfoTuple& writeCounterInfo);

    int32_t getBytesPerFrame() const;

    void setBytesPerFrame(int32_t bytesPerFrame);

    int32_t getFramesPerBurst() const;

    void setFramesPerBurst(int32_t framesPerBurst);

    int32_t getCapacityInFrames() const;

    void setCapacityInFrames(int32_t capacityInFrames);

    bool isFileDescriptorSafe(SharedMemoryParcelable *memoryParcels);

    aaudio_result_t resolve(SharedMemoryParcelable *memoryParcels, RingBufferDescriptor *descriptor);

    /**
     * Update this ring buffer with the given ring buffer.
     *
     * @param parcelable the ring buffer to be used to update this ring buffer.
     * @param memoryIndexMap a map from the shared memory indexes used by the given ring buffer
     *                       to the shared memory indexes used by this ring buffer.
     */
    void updateMemory(const RingBufferParcelable& parcelable,
                      const std::map<int32_t, int32_t>& memoryIndexMap);

    int32_t getReadCounterSharedMemoryIndex() const {
        return mReadCounterParcelable.getSharedMemoryIndex();
    }
    int32_t getWriteCounterSharedMemoryIndex() const {
        return mWriteCounterParcelable.getSharedMemoryIndex();
    }
    int32_t getDataSharedMemoryIndex() const {
        return mDataParcelable.getSharedMemoryIndex();
    }

    void dump();

    // Extract a parcelable representation of this object.
    RingBuffer parcelable() const;

private:
    SharedRegionParcelable  mReadCounterParcelable;
    SharedRegionParcelable  mWriteCounterParcelable;
    SharedRegionParcelable  mDataParcelable;
    int32_t                 mBytesPerFrame = 0;     // index is in frames
    int32_t                 mFramesPerBurst = 0;    // for ISOCHRONOUS queues
    int32_t                 mCapacityInFrames = 0;  // zero if unused
    RingbufferFlags         mFlags = RingbufferFlags::NONE;

    aaudio_result_t validate() const;
};

} /* namespace aaudio */

#endif //ANDROID_AAUDIO_RINGBUFFER_PARCELABLE_H
