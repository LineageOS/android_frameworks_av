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

#ifndef ANDROID_AAUDIO_SHARED_MEMORY_PARCELABLE_H
#define ANDROID_AAUDIO_SHARED_MEMORY_PARCELABLE_H

#include <stdint.h>
#include <sys/mman.h>

#include <android-base/unique_fd.h>
#include <android/media/SharedFileRegion.h>

namespace aaudio {

// Arbitrary limits for range checks.
#define MAX_SHARED_MEMORIES (32)
#define MAX_MMAP_OFFSET_BYTES (32 * 1024 * 8)
#define MAX_MMAP_SIZE_BYTES (32 * 1024 * 8)

/**
 * This is a parcelable description of a shared memory referenced by a file descriptor.
 * It may be divided into several regions.
 * The memory can be shared using Binder or simply shared between threads.
 */
class SharedMemoryParcelable {
public:
    SharedMemoryParcelable() = default;

    // Ctor from a parcelable representation.
    // Since the parcelable object owns a unique FD, move semantics are provided to avoid the need
    // to dupe.
    explicit SharedMemoryParcelable(android::media::SharedFileRegion&& parcelable);

    /**
     * Make a dup() of the fd and store it for later use.
     *
     * @param fd
     * @param sizeInBytes
     */
    void setup(const android::base::unique_fd& fd, int32_t sizeInBytes);

    // mmap() shared memory
    aaudio_result_t resolve(int32_t offsetInBytes, int32_t sizeInBytes, void **regionAddressPtr);

    // munmap() any mapped memory
    aaudio_result_t close();

    int32_t getSizeInBytes();

    void dump();

    // Extract a parcelable representation of this object.
    // Since we own a unique FD, move semantics are provided to avoid the need to dupe.
    android::media::SharedFileRegion parcelable() &&;

    // Copy this instance. Duplicates the underlying FD.
    SharedMemoryParcelable dup() const;

private:
#define MMAP_UNRESOLVED_ADDRESS    reinterpret_cast<uint8_t*>(MAP_FAILED)

    android::base::unique_fd   mFd;
    int64_t                    mSizeInBytes = 0;
    int64_t                    mOffsetInBytes = 0;
    uint8_t                   *mResolvedAddress = MMAP_UNRESOLVED_ADDRESS;

    aaudio_result_t resolveSharedMemory(const android::base::unique_fd& fd);
    aaudio_result_t validate() const;
};

} /* namespace aaudio */

#endif //ANDROID_AAUDIO_SHARED_MEMORY_PARCELABLE_H
