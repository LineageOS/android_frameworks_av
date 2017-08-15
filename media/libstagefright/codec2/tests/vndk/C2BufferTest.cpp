/*
 * Copyright 2017 The Android Open Source Project
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

#include <C2Buffer.h>
#include <C2BufferPriv.h>

#include <system/graphics.h>

namespace android {

class C2BufferTest : public ::testing::Test {
public:
    C2BufferTest()
        : mAllocator(std::make_shared<C2AllocatorIon>()),
          mSize(0u),
          mAddr(nullptr) {
    }

    ~C2BufferTest() = default;

    void allocate(size_t capacity) {
        C2Error err = mAllocator->allocateLinearBuffer(
                capacity,
                { C2MemoryUsage::kSoftwareRead, C2MemoryUsage::kSoftwareWrite },
                &mAllocation);
        if (err != C2_OK) {
            mAllocation.reset();
            FAIL() << "C2Allocator::allocateLinearBuffer() failed: " << err;
        }
    }

    void map(size_t offset, size_t size, uint8_t **addr) {
        ASSERT_TRUE(mAllocation);
        C2Error err = mAllocation->map(
                offset,
                size,
                { C2MemoryUsage::kSoftwareRead, C2MemoryUsage::kSoftwareWrite },
                // TODO: fence
                nullptr,
                &mAddr);
        if (err != C2_OK) {
            mAddr = nullptr;
            FAIL() << "C2LinearAllocation::map() failed: " << err;
        }
        ASSERT_NE(nullptr, mAddr);
        mSize = size;
        *addr = (uint8_t *)mAddr;
    }

    void unmap() {
        ASSERT_TRUE(mAllocation);
        ASSERT_NE(nullptr, mAddr);
        ASSERT_NE(0u, mSize);

        // TODO: fence
        ASSERT_EQ(C2_OK, mAllocation->unmap(mAddr, mSize, nullptr));
        mSize = 0u;
        mAddr = nullptr;
    }

    std::shared_ptr<C2BlockAllocator> makeBlockAllocator() {
        return std::make_shared<C2DefaultBlockAllocator>(mAllocator);
    }

private:
    std::shared_ptr<C2Allocator> mAllocator;
    std::shared_ptr<C2LinearAllocation> mAllocation;
    size_t mSize;
    void *mAddr;
};

TEST_F(C2BufferTest, LinearAllocationTest) {
    constexpr size_t kCapacity = 1024u * 1024u;

    allocate(kCapacity);

    uint8_t *addr = nullptr;
    map(0u, kCapacity, &addr);
    ASSERT_NE(nullptr, addr);

    for (size_t i = 0; i < kCapacity; ++i) {
        addr[i] = i % 100u;
    }

    unmap();
    addr = nullptr;

    map(kCapacity / 3, kCapacity / 3, &addr);
    ASSERT_NE(nullptr, addr);
    for (size_t i = 0; i < kCapacity / 3; ++i) {
        ASSERT_EQ((i + kCapacity / 3) % 100, addr[i]) << " at i = " << i;
    }
}

TEST_F(C2BufferTest, BlockAllocatorTest) {
    constexpr size_t kCapacity = 1024u * 1024u;

    std::shared_ptr<C2BlockAllocator> blockAllocator(makeBlockAllocator());

    std::shared_ptr<C2LinearBlock> block;
    ASSERT_EQ(C2_OK, blockAllocator->allocateLinearBlock(
            kCapacity,
            { C2MemoryUsage::kSoftwareRead, C2MemoryUsage::kSoftwareWrite },
            &block));
    ASSERT_TRUE(block);

    C2Acquirable<C2WriteView> writeViewHolder = block->map();
    C2WriteView writeView = writeViewHolder.get();
    ASSERT_EQ(C2_OK, writeView.error());
    ASSERT_EQ(kCapacity, writeView.capacity());
    ASSERT_EQ(0u, writeView.offset());
    ASSERT_EQ(kCapacity, writeView.size());

    uint8_t *data = writeView.data();
    ASSERT_NE(nullptr, data);
    for (size_t i = 0; i < writeView.size(); ++i) {
        data[i] = i % 100u;
    }

    C2Fence fence;
    C2ConstLinearBlock constBlock = block->share(
            kCapacity / 3, kCapacity / 3, fence);

    C2Acquirable<C2ReadView> readViewHolder = constBlock.map();
    C2ReadView readView = readViewHolder.get();
    ASSERT_EQ(C2_OK, readView.error());
    ASSERT_EQ(kCapacity / 3, readView.capacity());

    // TODO: fence
    const uint8_t *constData = readView.data();
    ASSERT_NE(nullptr, constData);
    for (size_t i = 0; i < readView.capacity(); ++i) {
        ASSERT_EQ((i + kCapacity / 3) % 100u, constData[i]) << " at i = " << i
                << "; data = " << static_cast<void *>(data)
                << "; constData = " << static_cast<const void *>(constData);
    }

    readView = readView.subView(333u, 100u);
    ASSERT_EQ(C2_OK, readView.error());
    ASSERT_EQ(100u, readView.capacity());

    constData = readView.data();
    ASSERT_NE(nullptr, constData);
    for (size_t i = 0; i < readView.capacity(); ++i) {
        ASSERT_EQ((i + 333u + kCapacity / 3) % 100u, constData[i]) << " at i = " << i;
    }
}

} // namespace android
