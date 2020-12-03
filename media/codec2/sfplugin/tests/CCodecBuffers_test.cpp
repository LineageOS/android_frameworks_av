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

#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/MediaCodecConstants.h>

#include <C2BlockInternal.h>
#include <C2PlatformSupport.h>

namespace android {

static std::shared_ptr<RawGraphicOutputBuffers> GetRawGraphicOutputBuffers(
        int32_t width, int32_t height) {
    std::shared_ptr<RawGraphicOutputBuffers> buffers =
        std::make_shared<RawGraphicOutputBuffers>("test");
    sp<AMessage> format{new AMessage};
    format->setInt32(KEY_WIDTH, width);
    format->setInt32(KEY_HEIGHT, height);
    buffers->setFormat(format);
    return buffers;
}

TEST(RawGraphicOutputBuffersTest, ChangeNumSlots) {
    constexpr int32_t kWidth = 3840;
    constexpr int32_t kHeight = 2160;

    std::shared_ptr<RawGraphicOutputBuffers> buffers =
        GetRawGraphicOutputBuffers(kWidth, kHeight);

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

class TestGraphicAllocation : public C2GraphicAllocation {
public:
    TestGraphicAllocation(
            uint32_t width,
            uint32_t height,
            const C2PlanarLayout &layout,
            size_t capacity,
            std::vector<size_t> offsets)
        : C2GraphicAllocation(width, height),
          mLayout(layout),
          mMemory(capacity, 0xAA),
          mOffsets(offsets) {
    }

    c2_status_t map(
            C2Rect rect, C2MemoryUsage usage, C2Fence *fence,
            C2PlanarLayout *layout, uint8_t **addr) override {
        (void)rect;
        (void)usage;
        (void)fence;
        *layout = mLayout;
        for (size_t i = 0; i < mLayout.numPlanes; ++i) {
            addr[i] = mMemory.data() + mOffsets[i];
        }
        return C2_OK;
    }

    c2_status_t unmap(uint8_t **, C2Rect, C2Fence *) override { return C2_OK; }

    C2Allocator::id_t getAllocatorId() const override { return -1; }

    const C2Handle *handle() const override { return nullptr; }

    bool equals(const std::shared_ptr<const C2GraphicAllocation> &other) const override {
        return other.get() == this;
    }

private:
    C2PlanarLayout mLayout;
    std::vector<uint8_t> mMemory;
    std::vector<uint8_t *> mAddr;
    std::vector<size_t> mOffsets;
};

class LayoutTest : public ::testing::TestWithParam<std::tuple<bool, std::string, bool, int32_t>> {
private:
    static C2PlanarLayout YUVPlanarLayout(int32_t stride) {
        C2PlanarLayout layout = {
            C2PlanarLayout::TYPE_YUV,
            3,  /* numPlanes */
            3,  /* rootPlanes */
            {},  /* planes --- to be filled below */
        };
        layout.planes[C2PlanarLayout::PLANE_Y] = {
            C2PlaneInfo::CHANNEL_Y,
            1,  /* colInc */
            stride,  /* rowInc */
            1,  /* colSampling */
            1,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_Y,  /* rootIx */
            0,  /* offset */
        };
        layout.planes[C2PlanarLayout::PLANE_U] = {
            C2PlaneInfo::CHANNEL_CB,
            1,  /* colInc */
            stride / 2,  /* rowInc */
            2,  /* colSampling */
            2,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_U,  /* rootIx */
            0,  /* offset */
        };
        layout.planes[C2PlanarLayout::PLANE_V] = {
            C2PlaneInfo::CHANNEL_CR,
            1,  /* colInc */
            stride / 2,  /* rowInc */
            2,  /* colSampling */
            2,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_V,  /* rootIx */
            0,  /* offset */
        };
        return layout;
    }

    static C2PlanarLayout YUVSemiPlanarLayout(int32_t stride) {
        C2PlanarLayout layout = {
            C2PlanarLayout::TYPE_YUV,
            3,  /* numPlanes */
            2,  /* rootPlanes */
            {},  /* planes --- to be filled below */
        };
        layout.planes[C2PlanarLayout::PLANE_Y] = {
            C2PlaneInfo::CHANNEL_Y,
            1,  /* colInc */
            stride,  /* rowInc */
            1,  /* colSampling */
            1,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_Y,  /* rootIx */
            0,  /* offset */
        };
        layout.planes[C2PlanarLayout::PLANE_U] = {
            C2PlaneInfo::CHANNEL_CB,
            2,  /* colInc */
            stride,  /* rowInc */
            2,  /* colSampling */
            2,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_U,  /* rootIx */
            0,  /* offset */
        };
        layout.planes[C2PlanarLayout::PLANE_V] = {
            C2PlaneInfo::CHANNEL_CR,
            2,  /* colInc */
            stride,  /* rowInc */
            2,  /* colSampling */
            2,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_U,  /* rootIx */
            1,  /* offset */
        };
        return layout;
    }

    static C2PlanarLayout YVUSemiPlanarLayout(int32_t stride) {
        C2PlanarLayout layout = {
            C2PlanarLayout::TYPE_YUV,
            3,  /* numPlanes */
            2,  /* rootPlanes */
            {},  /* planes --- to be filled below */
        };
        layout.planes[C2PlanarLayout::PLANE_Y] = {
            C2PlaneInfo::CHANNEL_Y,
            1,  /* colInc */
            stride,  /* rowInc */
            1,  /* colSampling */
            1,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_Y,  /* rootIx */
            0,  /* offset */
        };
        layout.planes[C2PlanarLayout::PLANE_U] = {
            C2PlaneInfo::CHANNEL_CB,
            2,  /* colInc */
            stride,  /* rowInc */
            2,  /* colSampling */
            2,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_V,  /* rootIx */
            1,  /* offset */
        };
        layout.planes[C2PlanarLayout::PLANE_V] = {
            C2PlaneInfo::CHANNEL_CR,
            2,  /* colInc */
            stride,  /* rowInc */
            2,  /* colSampling */
            2,  /* rowSampling */
            8,  /* allocatedDepth */
            8,  /* bitDepth */
            0,  /* rightShift */
            C2PlaneInfo::NATIVE,
            C2PlanarLayout::PLANE_V,  /* rootIx */
            0,  /* offset */
        };
        return layout;
    }

    static std::shared_ptr<C2GraphicBlock> CreateGraphicBlock(
            uint32_t width,
            uint32_t height,
            const C2PlanarLayout &layout,
            size_t capacity,
            std::vector<size_t> offsets) {
        std::shared_ptr<C2GraphicAllocation> alloc = std::make_shared<TestGraphicAllocation>(
                width,
                height,
                layout,
                capacity,
                offsets);

        return _C2BlockFactory::CreateGraphicBlock(alloc);
    }

    static constexpr uint8_t GetPixelValue(uint8_t value, uint32_t row, uint32_t col) {
        return (uint32_t(value) * row + col) & 0xFF;
    }

    static void FillPlane(C2GraphicView &view, size_t index, uint8_t value) {
        C2PlanarLayout layout = view.layout();

        uint8_t *rowPtr = view.data()[index];
        C2PlaneInfo plane = layout.planes[index];
        for (uint32_t row = 0; row < view.height() / plane.rowSampling; ++row) {
            uint8_t *colPtr = rowPtr;
            for (uint32_t col = 0; col < view.width() / plane.colSampling; ++col) {
                *colPtr = GetPixelValue(value, row, col);
                colPtr += plane.colInc;
            }
            rowPtr += plane.rowInc;
        }
    }

    static void FillBlock(const std::shared_ptr<C2GraphicBlock> &block) {
        C2GraphicView view = block->map().get();

        FillPlane(view, C2PlanarLayout::PLANE_Y, 'Y');
        FillPlane(view, C2PlanarLayout::PLANE_U, 'U');
        FillPlane(view, C2PlanarLayout::PLANE_V, 'V');
    }

    static bool VerifyPlane(
            const MediaImage2 *mediaImage,
            const uint8_t *base,
            uint32_t index,
            uint8_t value,
            std::string *errorMsg) {
        *errorMsg = "";
        MediaImage2::PlaneInfo plane = mediaImage->mPlane[index];
        const uint8_t *rowPtr = base + plane.mOffset;
        for (uint32_t row = 0; row < mediaImage->mHeight / plane.mVertSubsampling; ++row) {
            const uint8_t *colPtr = rowPtr;
            for (uint32_t col = 0; col < mediaImage->mWidth / plane.mHorizSubsampling; ++col) {
                if (GetPixelValue(value, row, col) != *colPtr) {
                    *errorMsg = AStringPrintf("row=%u col=%u expected=%02x actual=%02x",
                            row, col, GetPixelValue(value, row, col), *colPtr).c_str();
                    return false;
                }
                colPtr += plane.mColInc;
            }
            rowPtr += plane.mRowInc;
        }
        return true;
    }

public:
    static constexpr int32_t kWidth = 320;
    static constexpr int32_t kHeight = 240;
    static constexpr int32_t kGapLength = kWidth * kHeight * 10;

    static std::shared_ptr<C2Buffer> CreateAndFillBufferFromParam(const ParamType &param) {
        bool contiguous = std::get<0>(param);
        std::string planeOrderStr = std::get<1>(param);
        bool planar = std::get<2>(param);
        int32_t stride = std::get<3>(param);

        C2PlanarLayout::plane_index_t planeOrder[3];
        C2PlanarLayout layout;

        if (planeOrderStr.size() != 3) {
            return nullptr;
        }
        for (size_t i = 0; i < 3; ++i) {
            C2PlanarLayout::plane_index_t planeIndex;
            switch (planeOrderStr[i]) {
                case 'Y': planeIndex = C2PlanarLayout::PLANE_Y; break;
                case 'U': planeIndex = C2PlanarLayout::PLANE_U; break;
                case 'V': planeIndex = C2PlanarLayout::PLANE_V; break;
                default:  return nullptr;
            }
            planeOrder[i] = planeIndex;
        }

        if (planar) {
            layout = YUVPlanarLayout(stride);
        } else {  // semi-planar
            for (size_t i = 0; i < 3; ++i) {
                if (planeOrder[i] == C2PlanarLayout::PLANE_U) {
                    layout = YUVSemiPlanarLayout(stride);
                    break;
                }
                if (planeOrder[i] == C2PlanarLayout::PLANE_V) {
                    layout = YVUSemiPlanarLayout(stride);
                    break;
                }
            }
        }

        size_t yPlaneSize = stride * kHeight;
        size_t uvPlaneSize = stride * kHeight / 4;
        size_t capacity = yPlaneSize + uvPlaneSize * 2;
        std::vector<size_t> offsets(3);

        if (!contiguous) {
            if (planar) {
                capacity += kGapLength * 2;
            } else {  // semi-planar
                capacity += kGapLength;
            }
        }

        offsets[planeOrder[0]] = 0;
        size_t planeSize = (planeOrder[0] == C2PlanarLayout::PLANE_Y) ? yPlaneSize : uvPlaneSize;
        for (size_t i = 1; i < 3; ++i) {
            offsets[planeOrder[i]] = offsets[planeOrder[i - 1]] + planeSize;
            if (!contiguous) {
                offsets[planeOrder[i]] += kGapLength;
            }
            planeSize = (planeOrder[i] == C2PlanarLayout::PLANE_Y) ? yPlaneSize : uvPlaneSize;
            if (!planar  // semi-planar
                    && planeOrder[i - 1] != C2PlanarLayout::PLANE_Y
                    && planeOrder[i] != C2PlanarLayout::PLANE_Y) {
                offsets[planeOrder[i]] = offsets[planeOrder[i - 1]] + 1;
                planeSize = uvPlaneSize * 2 - 1;
            }
        }

        std::shared_ptr<C2GraphicBlock> block = CreateGraphicBlock(
                kWidth,
                kHeight,
                layout,
                capacity,
                offsets);
        FillBlock(block);
        return C2Buffer::CreateGraphicBuffer(
                block->share(block->crop(), C2Fence()));
    }

    static bool VerifyClientBuffer(
            const sp<MediaCodecBuffer> &buffer, std::string *errorMsg) {
        *errorMsg = "";
        sp<ABuffer> imageData;
        if (!buffer->format()->findBuffer("image-data", &imageData)) {
            *errorMsg = "Missing image data";
            return false;
        }
        MediaImage2 *mediaImage = (MediaImage2 *)imageData->data();
        if (mediaImage->mType != MediaImage2::MEDIA_IMAGE_TYPE_YUV) {
            *errorMsg = AStringPrintf("Unexpected type: %d", mediaImage->mType).c_str();
            return false;
        }
        std::string planeErrorMsg;
        if (!VerifyPlane(mediaImage, buffer->base(), MediaImage2::Y, 'Y', &planeErrorMsg)) {
            *errorMsg = "Y plane does not match: " + planeErrorMsg;
            return false;
        }
        if (!VerifyPlane(mediaImage, buffer->base(), MediaImage2::U, 'U', &planeErrorMsg)) {
            *errorMsg = "U plane does not match: " + planeErrorMsg;
            return false;
        }
        if (!VerifyPlane(mediaImage, buffer->base(), MediaImage2::V, 'V', &planeErrorMsg)) {
            *errorMsg = "V plane does not match: " + planeErrorMsg;
            return false;
        }

        int32_t width, height, stride;
        buffer->format()->findInt32(KEY_WIDTH, &width);
        buffer->format()->findInt32(KEY_HEIGHT, &height);
        buffer->format()->findInt32(KEY_STRIDE, &stride);

        MediaImage2 legacyYLayout = {
            MediaImage2::MEDIA_IMAGE_TYPE_Y,
            1,  // mNumPlanes
            uint32_t(width),
            uint32_t(height),
            8,
            8,
            {},  // mPlane
        };
        legacyYLayout.mPlane[MediaImage2::Y] = {
            0,  // mOffset
            1,  // mColInc
            stride,  // mRowInc
            1,  // mHorizSubsampling
            1,  // mVertSubsampling
        };
        if (!VerifyPlane(&legacyYLayout, buffer->data(), MediaImage2::Y, 'Y', &planeErrorMsg)) {
            *errorMsg = "Y plane by legacy layout does not match: " + planeErrorMsg;
            return false;
        }
        return true;
    }

};

TEST_P(LayoutTest, VerifyLayout) {
    std::shared_ptr<RawGraphicOutputBuffers> buffers =
        GetRawGraphicOutputBuffers(kWidth, kHeight);

    std::shared_ptr<C2Buffer> c2Buffer = CreateAndFillBufferFromParam(GetParam());
    ASSERT_NE(nullptr, c2Buffer);
    sp<MediaCodecBuffer> clientBuffer;
    size_t index;
    ASSERT_EQ(OK, buffers->registerBuffer(c2Buffer, &index, &clientBuffer));
    ASSERT_NE(nullptr, clientBuffer);
    std::string errorMsg;
    ASSERT_TRUE(VerifyClientBuffer(clientBuffer, &errorMsg)) << errorMsg;
}

INSTANTIATE_TEST_SUITE_P(
        RawGraphicOutputBuffersTest,
        LayoutTest,
        ::testing::Combine(
            ::testing::Bool(),  /* contiguous */
            ::testing::Values("YUV", "YVU", "UVY", "VUY"),
            ::testing::Bool(),  /* planar */
            ::testing::Values(320, 512)),
        [](const ::testing::TestParamInfo<LayoutTest::ParamType> &info) {
            std::string contiguous = std::get<0>(info.param) ? "Contiguous" : "Noncontiguous";
            std::string planar = std::get<2>(info.param) ? "Planar" : "SemiPlanar";
            return contiguous
                    + std::get<1>(info.param)
                    + planar
                    + std::to_string(std::get<3>(info.param));
        });

} // namespace android
