/*
 * Copyright 2016, The Android Open Source Project
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
#define LOG_TAG "BufferImpl"
#include <utils/Log.h>

#include <binder/IMemory.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/ICrypto.h>
#include <utils/NativeHandle.h>

#include "include/Codec2Buffer.h"
#include "include/SecureBuffer.h"
#include "include/SharedMemoryBuffer.h"

namespace android {

// SharedMemoryBuffer

SharedMemoryBuffer::SharedMemoryBuffer(const sp<AMessage> &format, const sp<IMemory> &mem)
    : MediaCodecBuffer(format, new ABuffer(mem->pointer(), mem->size())),
      mMemory(mem) {
}

SharedMemoryBuffer::SharedMemoryBuffer(const sp<AMessage> &format, const sp<TMemory> &mem)
    : MediaCodecBuffer(format, new ABuffer(mem->getPointer(), mem->getSize())),
      mTMemory(mem) {
}

// SecureBuffer

SecureBuffer::SecureBuffer(const sp<AMessage> &format, const void *ptr, size_t size)
    : MediaCodecBuffer(format, new ABuffer(nullptr, size)),
      mPointer(ptr) {
}

SecureBuffer::SecureBuffer(
        const sp<AMessage> &format, const sp<NativeHandle> &handle, size_t size)
    : MediaCodecBuffer(format, new ABuffer(nullptr, size)),
      mPointer(nullptr),
      mHandle(handle) {
}

void *SecureBuffer::getDestinationPointer() {
    return (void *)(mHandle == nullptr ? mPointer : mHandle->handle());
}

ICrypto::DestinationType SecureBuffer::getDestinationType() {
    return ICrypto::kDestinationTypeNativeHandle;
}

// Codec2Buffer

bool Codec2Buffer::canCopyLinear(const std::shared_ptr<C2Buffer> &buffer) const {
    if (const_cast<Codec2Buffer *>(this)->base() == nullptr) {
        return false;
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
    if (buffer->data().linearBlocks().size() == 0u) {
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

}  // namespace android
