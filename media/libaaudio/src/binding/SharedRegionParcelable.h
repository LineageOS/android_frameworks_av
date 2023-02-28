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

#ifndef ANDROID_AAUDIO_SHARED_REGION_PARCELABLE_H
#define ANDROID_AAUDIO_SHARED_REGION_PARCELABLE_H

#include <stdint.h>

#include <sys/mman.h>

#include <aaudio/AAudio.h>
#include <aaudio/SharedRegion.h>

#include "binding/SharedMemoryParcelable.h"

using android::status_t;

namespace aaudio {

class SharedRegionParcelable {
public:
    SharedRegionParcelable() = default;

    // Construct based on a parcelable representation.
    explicit SharedRegionParcelable(const SharedRegion& parcelable);

    // A tuple that contains information for setting up shared memory.
    // The information in the tuple is <shared memory index, offset, size in byte>.
    using MemoryInfoTuple = std::tuple<int, int, int>;
    // Enums to use as index to query from MemoryInfoTuple
    enum {
        MEMORY_INDEX = 0,
        OFFSET = 1,
        SIZE = 2,
    };
    void setup(MemoryInfoTuple memoryInfoTuple);

    aaudio_result_t resolve(SharedMemoryParcelable *memoryParcels, void **regionAddressPtr);

    bool isFileDescriptorSafe(SharedMemoryParcelable *memoryParcels);

    int32_t getSharedMemoryIndex() const { return mSharedMemoryIndex; }

    /**
     * Get the memory information of this SharedRegionParcelable.
     *
     * If the `memoryIndexMap` is not null, it indicates the caller has a different indexing for
     * the shared memory. In that case, the `memoryIndexMap` must contains information from the
     * shared memory indexes used by this object to the caller's shared memory indexes.
     *
     * @param memoryIndexMap a pointer to a map of memory index, which map the current shared
     *                       memory index to a new shared memory index.
     * @return
     */
    MemoryInfoTuple getMemoryInfo(const std::map<int32_t, int32_t>* memoryIndexMap) const;

    void dump();

    // Extract a parcelable representation of this object.
    SharedRegion parcelable() const;

private:
    int32_t mSharedMemoryIndex = -1;
    int32_t mOffsetInBytes     = 0;
    int32_t mSizeInBytes       = 0;

    aaudio_result_t validate() const;
};

} /* namespace aaudio */

#endif //ANDROID_AAUDIO_SHARED_REGION_PARCELABLE_H
