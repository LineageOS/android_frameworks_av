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

// LinearBlockBuffer

// static
sp<LinearBlockBuffer> LinearBlockBuffer::allocate(
        const sp<AMessage> &format, const std::shared_ptr<C2LinearBlock> &block) {
    C2WriteView writeView(block->map().get());
    if (writeView.error() != C2_OK) {
        return nullptr;
    }
    return new LinearBlockBuffer(format, std::move(writeView), block);
}

C2ConstLinearBlock LinearBlockBuffer::share() {
    return mBlock->share(offset(), size(), C2Fence());
}

LinearBlockBuffer::LinearBlockBuffer(
        const sp<AMessage> &format,
        C2WriteView&& writeView,
        const std::shared_ptr<C2LinearBlock> &block)
    : MediaCodecBuffer(format, new ABuffer(writeView.data(), writeView.size())),
      mWriteView(writeView),
      mBlock(block) {
}

// ConstLinearBlockBuffer

// static
sp<ConstLinearBlockBuffer> ConstLinearBlockBuffer::allocate(
        const sp<AMessage> &format, const C2ConstLinearBlock &block) {
    C2ReadView readView(block.map().get());
    if (readView.error() != C2_OK) {
        return nullptr;
    }
    return new ConstLinearBlockBuffer(format, std::move(readView));
}

ConstLinearBlockBuffer::ConstLinearBlockBuffer(
        const sp<AMessage> &format,
        C2ReadView&& readView)
    : MediaCodecBuffer(format, new ABuffer(
            // NOTE: ABuffer only takes non-const pointer but this data is
            //       supposed to be read-only.
            const_cast<uint8_t *>(readView.data()), readView.capacity())),
      mReadView(readView) {
}

}  // namespace android
