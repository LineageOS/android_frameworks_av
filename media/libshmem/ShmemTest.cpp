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
#include <gtest/gtest.h>

#include "binder/MemoryBase.h"
#include "binder/MemoryHeapBase.h"
#include "cutils/ashmem.h"
#include "media/ShmemCompat.h"
#include "media/ShmemUtil.h"

namespace android {
namespace media {
namespace {

// Creates a SharedFileRegion instance.
SharedFileRegion makeSharedFileRegion(int64_t offset, int64_t size) {
    SharedFileRegion shmem;
    shmem.offset = offset;
    shmem.size = size;
    int fd = ashmem_create_region("", size + offset);
    assert(fd >= 0);
    shmem.fd = os::ParcelFileDescriptor(base::unique_fd(fd));
    return shmem;
}

// Creates a SharedFileRegion instance with an invalid FD.
SharedFileRegion makeInvalidSharedFileRegion(int64_t offset, int64_t size) {
    SharedFileRegion shmem;
    shmem.offset = offset;
    shmem.size = size;
    return shmem;
}

sp<IMemory> makeIMemory(const std::vector<uint8_t>& content, bool writeable = true) {
    constexpr size_t kOffset = 19;

    sp<MemoryHeapBase> heap = new MemoryHeapBase(content.size(),
                                                 !writeable ? IMemoryHeap::READ_ONLY : 0);
    sp<IMemory> result = sp<MemoryBase>::make(heap, kOffset, content.size());
    memcpy(result->unsecurePointer(), content.data(), content.size());
    return result;
}

TEST(ShmemTest, Validate) {
    EXPECT_TRUE(validateSharedFileRegion(makeSharedFileRegion(0, 0)));
    EXPECT_TRUE(validateSharedFileRegion(makeSharedFileRegion(1, 2)));
    EXPECT_FALSE(validateSharedFileRegion(makeSharedFileRegion(-1, 2)));
    EXPECT_FALSE(validateSharedFileRegion(makeSharedFileRegion(2, -1)));
    EXPECT_FALSE(validateSharedFileRegion(makeInvalidSharedFileRegion(1, 2)));
}

TEST(ShmemTest, Conversion) {
    sp<IMemory> reconstructed;
    {
        SharedFileRegion shmem;
        sp<IMemory> imem = makeIMemory({6, 5, 3});
        ASSERT_TRUE(convertIMemoryToSharedFileRegion(imem, &shmem));
        ASSERT_EQ(3, shmem.size);
        ASSERT_GE(shmem.fd.get(), 0);
        ASSERT_TRUE(shmem.writeable);
        ASSERT_TRUE(convertSharedFileRegionToIMemory(shmem, &reconstructed));
    }
    ASSERT_EQ(3, reconstructed->size());
    ASSERT_EQ(reconstructed->getMemory()->getFlags() & IMemoryHeap::READ_ONLY,  0);
    const uint8_t* p =
            reinterpret_cast<const uint8_t*>(reconstructed->unsecurePointer());
    EXPECT_EQ(6, p[0]);
    EXPECT_EQ(5, p[1]);
    EXPECT_EQ(3, p[2]);
}

TEST(ShmemTest, ConversionReadOnly) {
    sp<IMemory> reconstructed;
    {
        SharedFileRegion shmem;
        sp<IMemory> imem = makeIMemory({6, 5, 3}, false);
        ASSERT_TRUE(convertIMemoryToSharedFileRegion(imem, &shmem));
        ASSERT_EQ(3, shmem.size);
        ASSERT_GE(shmem.fd.get(), 0);
        ASSERT_FALSE(shmem.writeable);
        ASSERT_TRUE(convertSharedFileRegionToIMemory(shmem, &reconstructed));
    }
    ASSERT_EQ(3, reconstructed->size());
    ASSERT_NE(reconstructed->getMemory()->getFlags() & IMemoryHeap::READ_ONLY,  0);
    const uint8_t* p =
            reinterpret_cast<const uint8_t*>(reconstructed->unsecurePointer());
    EXPECT_EQ(6, p[0]);
    EXPECT_EQ(5, p[1]);
    EXPECT_EQ(3, p[2]);
}

TEST(ShmemTest, NullConversion) {
    sp<IMemory> reconstructed;
    {
        std::optional<SharedFileRegion> shmem;
        sp<IMemory> imem;
        ASSERT_TRUE(convertNullableIMemoryToSharedFileRegion(imem, &shmem));
        ASSERT_FALSE(shmem.has_value());
        ASSERT_TRUE(convertNullableSharedFileRegionToIMemory(shmem, &reconstructed));
    }
    ASSERT_EQ(nullptr, reconstructed);
}

}  // namespace
}  // namespace media
}  // namespace android
