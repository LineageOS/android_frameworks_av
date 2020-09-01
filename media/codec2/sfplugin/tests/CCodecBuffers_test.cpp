/*
 * Copyright 2020 The Android Open Source Project
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

#include "CCodecBuffers.h"

#include <gtest/gtest.h>

#include <media/stagefright/MediaCodecConstants.h>

#include <C2PlatformSupport.h>

namespace android {

TEST(RawGraphicOutputBuffersTest, ChangeNumSlots) {
    constexpr int32_t kWidth = 3840;
    constexpr int32_t kHeight = 2160;

    std::shared_ptr<RawGraphicOutputBuffers> buffers =
        std::make_shared<RawGraphicOutputBuffers>("test");
    sp<AMessage> format{new AMessage};
    format->setInt32("width", kWidth);
    format->setInt32("height", kHeight);
    buffers->setFormat(format);

    std::shared_ptr<C2BlockPool> pool;
    ASSERT_EQ(OK, GetCodec2BlockPool(C2BlockPool::BASIC_GRAPHIC, nullptr, &pool));

    // Register 4 buffers
    std::vector<sp<MediaCodecBuffer>> clientBuffers;
    auto registerBuffer = [&buffers, &clientBuffers, &pool] {
        std::shared_ptr<C2GraphicBlock> block;
        ASSERT_EQ(OK, pool->fetchGraphicBlock(
                kWidth, kHeight, HAL_PIXEL_FORMAT_YCbCr_420_888,
                C2MemoryUsage{C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block));
        std::shared_ptr<C2Buffer> c2Buffer = C2Buffer::CreateGraphicBuffer(block->share(
                block->crop(), C2Fence{}));
        size_t index;
        sp<MediaCodecBuffer> clientBuffer;
        ASSERT_EQ(OK, buffers->registerBuffer(c2Buffer, &index, &clientBuffer));
        ASSERT_NE(nullptr, clientBuffer);
        while (clientBuffers.size() <= index) {
            clientBuffers.emplace_back();
        }
        ASSERT_EQ(nullptr, clientBuffers[index]) << "index = " << index;
        clientBuffers[index] = clientBuffer;
    };
    for (int i = 0; i < 4; ++i) {
        registerBuffer();
    }

    // Release 2 buffers
    auto releaseBuffer = [&buffers, &clientBuffers, kWidth, kHeight](int index) {
        std::shared_ptr<C2Buffer> c2Buffer;
        ASSERT_TRUE(buffers->releaseBuffer(clientBuffers[index], &c2Buffer))
                << "index = " << index;
        clientBuffers[index] = nullptr;
        // Sanity checks
        ASSERT_TRUE(c2Buffer->data().linearBlocks().empty());
        ASSERT_EQ(1u, c2Buffer->data().graphicBlocks().size());
        C2ConstGraphicBlock block = c2Buffer->data().graphicBlocks().front();
        ASSERT_EQ(kWidth, block.width());
        ASSERT_EQ(kHeight, block.height());
    };
    for (int i = 0, index = 0; i < 2 && index < clientBuffers.size(); ++index) {
        if (clientBuffers[index] == nullptr) {
            continue;
        }
        releaseBuffer(index);
        ++i;
    }

    // Simulate # of slots 4->16
    for (int i = 2; i < 16; ++i) {
        registerBuffer();
    }

    // Release everything
    for (int index = 0; index < clientBuffers.size(); ++index) {
        if (clientBuffers[index] == nullptr) {
            continue;
        }
        releaseBuffer(index);
    }
}

} // namespace android
