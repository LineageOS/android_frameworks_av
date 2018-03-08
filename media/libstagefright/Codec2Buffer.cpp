/*
 * Copyright 2018, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2Buffer"
#include <utils/Log.h>

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>

#include "include/Codec2Buffer.h"

namespace android {

// Codec2Buffer

bool Codec2Buffer::canCopyLinear(const std::shared_ptr<C2Buffer> &buffer) const {
    if (const_cast<Codec2Buffer *>(this)->base() == nullptr) {
        return false;
    }
    if (!buffer) {
        // Nothing to copy, so we can copy by doing nothing.
        return true;
    }
    if (buffer->data().type() != C2BufferData::LINEAR) {
        return false;
    }
    if (buffer->data().linearBlocks().size() == 0u) {
        // Nothing to copy, so we can copy by doing nothing.
        return true;
    } else if (buffer->data().linearBlocks().size() > 1u) {
        // We don't know how to copy more than one blocks.
        return false;
    }
    if (buffer->data().linearBlocks()[0].size() > capacity()) {
        // It won't fit.
        return false;
    }
    return true;
}

bool Codec2Buffer::copyLinear(const std::shared_ptr<C2Buffer> &buffer) {
    // We assume that all canCopyLinear() checks passed.
    if (!buffer || buffer->data().linearBlocks().size() == 0u) {
        setRange(0, 0);
        return true;
    }
    C2ReadView view = buffer->data().linearBlocks()[0].map().get();
    if (view.error() != C2_OK) {
        ALOGD("Error while mapping: %d", view.error());
        return false;
    }
    if (view.capacity() > capacity()) {
        ALOGD("C2ConstLinearBlock lied --- it actually doesn't fit: view(%u) > this(%zu)",
                view.capacity(), capacity());
        return false;
    }
    memcpy(base(), view.data(), view.capacity());
    setRange(0, view.capacity());
    return true;
}

// LocalLinearBuffer

bool LocalLinearBuffer::canCopy(const std::shared_ptr<C2Buffer> &buffer) const {
    return canCopyLinear(buffer);
}

bool LocalLinearBuffer::copy(const std::shared_ptr<C2Buffer> &buffer) {
    return copyLinear(buffer);
}

// DummyContainerBuffer

DummyContainerBuffer::DummyContainerBuffer(
        const sp<AMessage> &format, const std::shared_ptr<C2Buffer> &buffer)
    : Codec2Buffer(format, new ABuffer(nullptr, 1)),
      mBufferRef(buffer) {
    setRange(0, buffer ? 1 : 0);
}

std::shared_ptr<C2Buffer> DummyContainerBuffer::asC2Buffer() {
    return std::move(mBufferRef);
}

bool DummyContainerBuffer::canCopy(const std::shared_ptr<C2Buffer> &) const {
    return !mBufferRef;
}

bool DummyContainerBuffer::copy(const std::shared_ptr<C2Buffer> &buffer) {
    mBufferRef = buffer;
    setRange(0, mBufferRef ? 1 : 0);
    return true;
}

// LinearBlockBuffer

// static
sp<LinearBlockBuffer> LinearBlockBuffer::Allocate(
        const sp<AMessage> &format, const std::shared_ptr<C2LinearBlock> &block) {
    C2WriteView writeView(block->map().get());
    if (writeView.error() != C2_OK) {
        return nullptr;
    }
    return new LinearBlockBuffer(format, std::move(writeView), block);
}

std::shared_ptr<C2Buffer> LinearBlockBuffer::asC2Buffer() {
    return C2Buffer::CreateLinearBuffer(mBlock->share(offset(), size(), C2Fence()));
}

bool LinearBlockBuffer::canCopy(const std::shared_ptr<C2Buffer> &buffer) const {
    return canCopyLinear(buffer);
}

bool LinearBlockBuffer::copy(const std::shared_ptr<C2Buffer> &buffer) {
    return copyLinear(buffer);
}

LinearBlockBuffer::LinearBlockBuffer(
        const sp<AMessage> &format,
        C2WriteView&& writeView,
        const std::shared_ptr<C2LinearBlock> &block)
    : Codec2Buffer(format, new ABuffer(writeView.data(), writeView.size())),
      mWriteView(writeView),
      mBlock(block) {
}

// ConstLinearBlockBuffer

// static
sp<ConstLinearBlockBuffer> ConstLinearBlockBuffer::Allocate(
        const sp<AMessage> &format, const std::shared_ptr<C2Buffer> &buffer) {
    if (!buffer
            || buffer->data().type() != C2BufferData::LINEAR
            || buffer->data().linearBlocks().size() != 1u) {
        return nullptr;
    }
    C2ReadView readView(buffer->data().linearBlocks()[0].map().get());
    if (readView.error() != C2_OK) {
        return nullptr;
    }
    return new ConstLinearBlockBuffer(format, std::move(readView), buffer);
}

ConstLinearBlockBuffer::ConstLinearBlockBuffer(
        const sp<AMessage> &format,
        C2ReadView&& readView,
        const std::shared_ptr<C2Buffer> &buffer)
    : Codec2Buffer(format, new ABuffer(
            // NOTE: ABuffer only takes non-const pointer but this data is
            //       supposed to be read-only.
            const_cast<uint8_t *>(readView.data()), readView.capacity())),
      mReadView(readView),
      mBufferRef(buffer) {
}

std::shared_ptr<C2Buffer> ConstLinearBlockBuffer::asC2Buffer() {
    return std::move(mBufferRef);
}

// GraphicView2MediaImageConverter

namespace {

class GraphicView2MediaImageConverter {
public:
    explicit GraphicView2MediaImageConverter(const C2GraphicView &view)
        : mInitCheck(NO_INIT),
          mView(view),
          mWidth(view.width()),
          mHeight(view.height()),
          mAllocatedDepth(0),
          mBackBufferSize(0),
          mMediaImage(new ABuffer(sizeof(MediaImage2))) {
        if (view.error() != C2_OK) {
            ALOGD("Converter: view.error() = %d", view.error());
            mInitCheck = BAD_VALUE;
            return;
        }
        MediaImage2 *mediaImage = (MediaImage2 *)mMediaImage->base();
        const C2PlanarLayout &layout = view.layout();
        if (layout.numPlanes == 0) {
            ALOGD("Converter: 0 planes");
            mInitCheck = BAD_VALUE;
            return;
        }
        mAllocatedDepth = layout.planes[0].allocatedDepth;
        uint32_t bitDepth = layout.planes[0].bitDepth;

        switch (layout.type) {
            case C2PlanarLayout::TYPE_YUV:
                mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_YUV; break;
            case C2PlanarLayout::TYPE_YUVA:
                mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_YUVA; break;
            case C2PlanarLayout::TYPE_RGB:
                mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_RGB; break;
            case C2PlanarLayout::TYPE_RGBA:
                mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_RGBA; break;
            default:
                mediaImage->mType = MediaImage2::MEDIA_IMAGE_TYPE_UNKNOWN; break;
        }
        mediaImage->mNumPlanes = layout.numPlanes;
        mediaImage->mWidth = mWidth;
        mediaImage->mHeight = mHeight;
        mediaImage->mBitDepth = bitDepth;
        mediaImage->mBitDepthAllocated = mAllocatedDepth;

        uint32_t bufferSize = 0;
        for (uint32_t i = 0; i < layout.numPlanes; ++i) {
            const C2PlaneInfo &plane = layout.planes[i];
            if (plane.rightShift != 0) {
                ALOGV("rightShift value of %u unsupported", plane.rightShift);
                mInitCheck = BAD_VALUE;
                return;
            }
            if (plane.endianness != C2PlaneInfo::NATIVE) {
                ALOGV("endianness value of %u unsupported", plane.endianness);
                mInitCheck = BAD_VALUE;
                return;
            }
            if (plane.allocatedDepth != mAllocatedDepth || plane.bitDepth != bitDepth) {
                ALOGV("different allocatedDepth/bitDepth per plane unsupported");
                mInitCheck = BAD_VALUE;
                return;
            }
            bufferSize += mWidth * mHeight
                    / plane.rowSampling / plane.colSampling * (plane.allocatedDepth / 8);
        }

        mBackBufferSize = bufferSize;
        mInitCheck = OK;
    }

    status_t initCheck() const { return mInitCheck; }

    uint32_t backBufferSize() const { return mBackBufferSize; }

    /**
     * Convert C2GraphicView to MediaImage2. Note that if not wrapped, the content
     * is not copied over in this function --- the caller should use
     * CopyGraphicView2MediaImage() function to do that explicitly.
     *
     * \param   view[in]          source C2GraphicView object.
     * \param   alloc[in]         allocator function for ABuffer.
     * \param   mediaImage[out]   destination MediaImage2 object.
     * \param   buffer[out]       new buffer object.
     * \param   wrapped[out]      whether we wrapped around existing map or
     *                            allocated a new buffer
     *
     * \return  true              if conversion succeeds,
     *          false             otherwise; all output params should be ignored.
     */
    sp<ABuffer> wrap() {
        MediaImage2 *mediaImage = getMediaImage();
        const C2PlanarLayout &layout = mView.layout();
        if (layout.numPlanes == 1) {
            const C2PlaneInfo &plane = layout.planes[0];
            ssize_t offset = plane.minOffset(mWidth, mHeight);
            mediaImage->mPlane[0].mOffset = -offset;
            mediaImage->mPlane[0].mColInc = plane.colInc;
            mediaImage->mPlane[0].mRowInc = plane.rowInc;
            mediaImage->mPlane[0].mHorizSubsampling = plane.colSampling;
            mediaImage->mPlane[0].mVertSubsampling = plane.rowSampling;
            return new ABuffer(
                    const_cast<uint8_t *>(mView.data()[0] + offset),
                    plane.maxOffset(mWidth, mHeight) - offset + 1);
        }
        const uint8_t *minPtr = mView.data()[0];
        const uint8_t *maxPtr = mView.data()[0];
        int32_t planeSize = 0;
        for (uint32_t i = 0; i < layout.numPlanes; ++i) {
            const C2PlaneInfo &plane = layout.planes[i];
            ssize_t minOffset = plane.minOffset(mWidth, mHeight);
            ssize_t maxOffset = plane.maxOffset(mWidth, mHeight);
            if (minPtr > mView.data()[i] + minOffset) {
                minPtr = mView.data()[i] + minOffset;
            }
            if (maxPtr < mView.data()[i] + maxOffset) {
                maxPtr = mView.data()[i] + maxOffset;
            }
            planeSize += std::abs(plane.rowInc) * mHeight
                    / plane.rowSampling / plane.colSampling * (mAllocatedDepth / 8);
        }

        if ((maxPtr - minPtr + 1) <= planeSize) {
            // FIXME: this is risky as reading/writing data out of bound results in
            //        an undefined behavior.
            for (uint32_t i = 0; i < layout.numPlanes; ++i) {
                const C2PlaneInfo &plane = layout.planes[i];
                mediaImage->mPlane[i].mOffset = mView.data()[i] - minPtr;
                mediaImage->mPlane[i].mColInc = plane.colInc;
                mediaImage->mPlane[i].mRowInc = plane.rowInc;
                mediaImage->mPlane[i].mHorizSubsampling = plane.colSampling;
                mediaImage->mPlane[i].mVertSubsampling = plane.rowSampling;
            }
            return new ABuffer(const_cast<uint8_t *>(minPtr), maxPtr - minPtr + 1);
        }

        return nullptr;
    }

    bool setBackBuffer(const sp<ABuffer> &backBuffer) {
        if (backBuffer->capacity() < mBackBufferSize) {
            return false;
        }
        backBuffer->setRange(0, mBackBufferSize);

        const C2PlanarLayout &layout = mView.layout();
        MediaImage2 *mediaImage = getMediaImage();
        uint32_t offset = 0;
        // TODO: keep interleaved planes together
        for (uint32_t i = 0; i < layout.numPlanes; ++i) {
            const C2PlaneInfo &plane = layout.planes[i];
            mediaImage->mPlane[i].mOffset = offset;
            mediaImage->mPlane[i].mColInc = mAllocatedDepth / 8;
            mediaImage->mPlane[i].mRowInc =
                mediaImage->mPlane[i].mColInc * mWidth / plane.colSampling;
            mediaImage->mPlane[i].mHorizSubsampling = plane.colSampling;
            mediaImage->mPlane[i].mVertSubsampling = plane.rowSampling;
            offset += mediaImage->mPlane[i].mRowInc * mHeight / plane.rowSampling;
        }
        mBackBuffer = backBuffer;
        return true;
    }

    /**
     * Copy C2GraphicView to MediaImage2. This function assumes that |mediaImage| is
     * an output from GraphicView2MediaImage(), so it mostly skips sanity check.
     *
     * \param   view[in]          source C2GraphicView object.
     * \param   mediaImage[in]    destination MediaImage2 object.
     * \param   buffer[out]       new buffer object.
     */
    void copy() {
        // TODO: more efficient copying --- e.g. one row at a time, copying
        //       interleaved planes together, etc.
        const C2PlanarLayout &layout = mView.layout();
        MediaImage2 *mediaImage = getMediaImage();
        uint8_t *dst = mBackBuffer->base();
        for (uint32_t i = 0; i < layout.numPlanes; ++i) {
            const C2PlaneInfo &plane = layout.planes[i];
            const uint8_t *src = mView.data()[i];
            int32_t planeW = mWidth / plane.colSampling;
            int32_t planeH = mHeight / plane.rowSampling;
            for (int32_t row = 0; row < planeH; ++row) {
                for(int32_t col = 0; col < planeW; ++col) {
                    memcpy(dst, src, mAllocatedDepth / 8);
                    dst += mediaImage->mPlane[i].mColInc;
                    src += plane.colInc;
                }
                dst -= mediaImage->mPlane[i].mColInc * planeW;
                dst += mediaImage->mPlane[i].mRowInc;
                src -= plane.colInc * planeW;
                src += plane.rowInc;
            }
        }
    }

    const sp<ABuffer> &imageData() const { return mMediaImage; }

private:
    status_t mInitCheck;

    const C2GraphicView mView;
    uint32_t mWidth;
    uint32_t mHeight;
    uint32_t mAllocatedDepth;
    uint32_t mBackBufferSize;
    sp<ABuffer> mMediaImage;
    std::function<sp<ABuffer>(size_t)> mAlloc;

    sp<ABuffer> mBackBuffer;

    MediaImage2 *getMediaImage() {
        return (MediaImage2 *)mMediaImage->base();
    }
};

}  // namespace

// GraphicBlockBuffer

// static
sp<GraphicBlockBuffer> GraphicBlockBuffer::Allocate(
        const sp<AMessage> &format,
        const std::shared_ptr<C2GraphicBlock> &block,
        std::function<sp<ABuffer>(size_t)> alloc) {
    C2GraphicView view(block->map().get());
    if (view.error() != C2_OK) {
        ALOGD("C2GraphicBlock::map failed: %d", view.error());
        return nullptr;
    }
    GraphicView2MediaImageConverter converter(view);
    if (converter.initCheck() != OK) {
        ALOGD("Converter init failed: %d", converter.initCheck());
        return nullptr;
    }
    bool wrapped = true;
    sp<ABuffer> buffer = converter.wrap();
    if (buffer == nullptr) {
        buffer = alloc(converter.backBufferSize());
        if (!converter.setBackBuffer(buffer)) {
            ALOGD("Converter failed to set back buffer");
            return nullptr;
        }
        wrapped = false;
    }
    return new GraphicBlockBuffer(
            format,
            buffer,
            std::move(view),
            block,
            converter.imageData(),
            wrapped);
}

GraphicBlockBuffer::GraphicBlockBuffer(
        const sp<AMessage> &format,
        const sp<ABuffer> &buffer,
        C2GraphicView &&view,
        const std::shared_ptr<C2GraphicBlock> &block,
        const sp<ABuffer> &imageData,
        bool wrapped)
    : Codec2Buffer(format, buffer),
      mView(view),
      mBlock(block),
      mImageData(imageData),
      mWrapped(wrapped) {
    meta()->setBuffer("image-data", imageData);
}

std::shared_ptr<C2Buffer> GraphicBlockBuffer::asC2Buffer() {
    uint32_t width = mView.width();
    uint32_t height = mView.height();
    if (!mWrapped) {
        MediaImage2 *mediaImage = imageData();
        const C2PlanarLayout &layout = mView.layout();
        for (uint32_t i = 0; i < mediaImage->mNumPlanes; ++i) {
            const C2PlaneInfo &plane = layout.planes[i];
            int32_t planeW = width / plane.colSampling;
            int32_t planeH = height / plane.rowSampling;
            const uint8_t *src = base() + mediaImage->mPlane[i].mOffset;
            uint8_t *dst = mView.data()[i];
            for (int32_t row = 0; row < planeH; ++row) {
                for (int32_t col = 0; col < planeW; ++col) {
                    memcpy(dst, src, mediaImage->mBitDepthAllocated / 8);
                    src += mediaImage->mPlane[i].mColInc;
                    dst += plane.colInc;
                }
                src -= mediaImage->mPlane[i].mColInc * planeW;
                dst -= plane.colInc * planeW;
                src += mediaImage->mPlane[i].mRowInc;
                dst += plane.rowInc;
            }
        }
    }
    return C2Buffer::CreateGraphicBuffer(
            mBlock->share(C2Rect(width, height), C2Fence()));
}

// ConstGraphicBlockBuffer

// static
sp<ConstGraphicBlockBuffer> ConstGraphicBlockBuffer::Allocate(
        const sp<AMessage> &format,
        const std::shared_ptr<C2Buffer> &buffer,
        std::function<sp<ABuffer>(size_t)> alloc) {
    if (!buffer
            || buffer->data().type() != C2BufferData::GRAPHIC
            || buffer->data().graphicBlocks().size() != 1u) {
        ALOGD("C2Buffer precond fail");
        return nullptr;
    }
    std::unique_ptr<const C2GraphicView> view(std::make_unique<const C2GraphicView>(
            buffer->data().graphicBlocks()[0].map().get()));
    std::unique_ptr<const C2GraphicView> holder;

    GraphicView2MediaImageConverter converter(*view);
    if (converter.initCheck() != OK) {
        ALOGD("Converter init failed: %d", converter.initCheck());
        return nullptr;
    }
    bool wrapped = true;
    sp<ABuffer> aBuffer = converter.wrap();
    if (aBuffer == nullptr) {
        aBuffer = alloc(converter.backBufferSize());
        if (!converter.setBackBuffer(aBuffer)) {
            ALOGD("Converter failed to set back buffer");
            return nullptr;
        }
        wrapped = false;
        converter.copy();
        // We don't need the view.
        holder = std::move(view);
    }
    return new ConstGraphicBlockBuffer(
            format,
            aBuffer,
            std::move(view),
            buffer,
            converter.imageData(),
            wrapped);
}

// static
sp<ConstGraphicBlockBuffer> ConstGraphicBlockBuffer::AllocateEmpty(
        const sp<AMessage> &format,
        std::function<sp<ABuffer>(size_t)> alloc) {
    int32_t width, height;
    if (!format->findInt32("width", &width)
            || !format->findInt32("height", &height)) {
        ALOGD("format had no width / height");
        return nullptr;
    }
    sp<ABuffer> aBuffer(alloc(width * height * 4));
    return new ConstGraphicBlockBuffer(
            format,
            aBuffer,
            nullptr,
            nullptr,
            nullptr,
            false);
}

ConstGraphicBlockBuffer::ConstGraphicBlockBuffer(
        const sp<AMessage> &format,
        const sp<ABuffer> &aBuffer,
        std::unique_ptr<const C2GraphicView> &&view,
        const std::shared_ptr<C2Buffer> &buffer,
        const sp<ABuffer> &imageData,
        bool wrapped)
    : Codec2Buffer(format, aBuffer),
      mView(std::move(view)),
      mBufferRef(buffer),
      mWrapped(wrapped) {
    if (imageData != nullptr) {
        meta()->setBuffer("image-data", imageData);
    }
}

std::shared_ptr<C2Buffer> ConstGraphicBlockBuffer::asC2Buffer() {
    mView.reset();
    return std::move(mBufferRef);
}

bool ConstGraphicBlockBuffer::canCopy(const std::shared_ptr<C2Buffer> &buffer) const {
    if (mWrapped || mBufferRef) {
        ALOGD("ConstGraphicBlockBuffer::canCopy: %swrapped ; buffer ref %s",
                mWrapped ? "" : "not ", mBufferRef ? "exists" : "doesn't exist");
        return false;
    }
    if (!buffer) {
        // Nothing to copy, so we can copy by doing nothing.
        return true;
    }
    if (buffer->data().type() != C2BufferData::GRAPHIC) {
        ALOGD("ConstGraphicBlockBuffer::canCopy: buffer precondition unsatisfied");
        return false;
    }
    if (buffer->data().graphicBlocks().size() == 0) {
        return true;
    } else if (buffer->data().graphicBlocks().size() != 1u) {
        ALOGD("ConstGraphicBlockBuffer::canCopy: too many blocks");
        return false;
    }
    GraphicView2MediaImageConverter converter(
            buffer->data().graphicBlocks()[0].map().get());
    if (converter.initCheck() != OK) {
        ALOGD("ConstGraphicBlockBuffer::canCopy: converter init failed: %d", converter.initCheck());
        return false;
    }
    if (converter.backBufferSize() > capacity()) {
        ALOGD("ConstGraphicBlockBuffer::canCopy: insufficient capacity: req %u has %zu",
                converter.backBufferSize(), capacity());
        return false;
    }
    return true;
}

bool ConstGraphicBlockBuffer::copy(const std::shared_ptr<C2Buffer> &buffer) {
    if (!buffer || buffer->data().graphicBlocks().size() == 0) {
        setRange(0, 0);
        return true;
    }
    GraphicView2MediaImageConverter converter(
            buffer->data().graphicBlocks()[0].map().get());
    if (converter.initCheck() != OK) {
        ALOGD("ConstGraphicBlockBuffer::copy: converter init failed: %d", converter.initCheck());
        return false;
    }
    sp<ABuffer> aBuffer = new ABuffer(base(), capacity());
    if (!converter.setBackBuffer(aBuffer)) {
        ALOGD("ConstGraphicBlockBuffer::copy: set back buffer failed");
        return false;
    }
    converter.copy();
    meta()->setBuffer("image-data", converter.imageData());
    mBufferRef = buffer;
    return true;
}

}  // namespace android
