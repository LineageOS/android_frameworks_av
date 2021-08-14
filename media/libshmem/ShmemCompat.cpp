/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include "media/ShmemCompat.h"

#include "binder/MemoryBase.h"
#include "binder/MemoryHeapBase.h"
#include "media/ShmemUtil.h"

namespace android {
namespace media {

bool convertSharedFileRegionToIMemory(const SharedFileRegion& shmem,
                                      sp<IMemory>* result) {
    assert(result != nullptr);

    if (!validateSharedFileRegion(shmem)) {
        return false;
    }

    // Heap offset and size must be page aligned.
    const size_t pageSize = getpagesize();
    const size_t pageMask = ~(pageSize - 1);

    // OK if this wraps.
    const uint64_t endOffset = static_cast<uint64_t>(shmem.offset) +
            static_cast<uint64_t>(shmem.size);

    // Round down to page boundary.
    const uint64_t heapStartOffset = shmem.offset & pageMask;
    // Round up to page boundary.
    const uint64_t heapEndOffset = (endOffset + pageSize - 1) & pageMask;
    const uint64_t heapSize = heapEndOffset - heapStartOffset;

    if (heapStartOffset > std::numeric_limits<size_t>::max() ||
        heapSize > std::numeric_limits<size_t>::max()) {
        return false;
    }

    uint32_t flags = !shmem.writeable ? IMemoryHeap::READ_ONLY : 0;

    const sp<MemoryHeapBase> heap =
            new MemoryHeapBase(shmem.fd.get(), heapSize, flags, heapStartOffset);
    *result = sp<MemoryBase>::make(heap,
                                   shmem.offset - heapStartOffset,
                                   shmem.size);
    return true;
}

bool convertIMemoryToSharedFileRegion(const sp<IMemory>& mem,
                                      SharedFileRegion* result) {
    assert(mem != nullptr);
    assert(result != nullptr);

    *result = SharedFileRegion();

    ssize_t offset;
    size_t size;

    sp<IMemoryHeap> heap = mem->getMemory(&offset, &size);
    if (size > 0) {
        if (heap == nullptr) {
            return false;
        }
        // Make sure the offset and size do not overflow from int64 boundaries.
        if (size > std::numeric_limits<int64_t>::max() ||
                offset > std::numeric_limits<int64_t>::max() ||
                heap->getOffset() > std::numeric_limits<int64_t>::max() ||
                static_cast<uint64_t>(heap->getOffset()) +
                static_cast<uint64_t>(offset)
                        > std::numeric_limits<int64_t>::max()) {
            return false;
        }

        const int fd = fcntl(heap->getHeapID(), F_DUPFD_CLOEXEC, 0);
        if (fd < 0) {
            return false;
        }
        result->fd.reset(base::unique_fd(fd));
        result->size = size;
        result->offset = heap->getOffset() + offset;
        result->writeable = (heap->getFlags() & IMemoryHeap::READ_ONLY) == 0;
    }
    return true;
}

bool convertNullableSharedFileRegionToIMemory(const std::optional<SharedFileRegion>& shmem,
                                              sp<IMemory>* result) {
    assert(result != nullptr);

    if (!shmem.has_value()) {
        result->clear();
        return true;
    }

    return convertSharedFileRegionToIMemory(shmem.value(), result);
}

bool convertNullableIMemoryToSharedFileRegion(const sp<IMemory>& mem,
                                              std::optional<SharedFileRegion>* result) {
    assert(result != nullptr);

    if (mem == nullptr) {
        result->reset();
        return true;
    }

    result->emplace();
    return convertIMemoryToSharedFileRegion(mem, &result->value());
}

}  // namespace media
}  // namespace android
