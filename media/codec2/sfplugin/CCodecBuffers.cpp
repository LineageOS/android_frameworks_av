/*
 * Copyright 2019, The Android Open Source Project
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
#define LOG_TAG "CCodecBuffers"
#include <utils/Log.h>

#include <C2PlatformSupport.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/SkipCutBuffer.h>
#include <mediadrm/ICrypto.h>

#include "CCodecBuffers.h"
#include "Codec2Mapper.h"

namespace android {

namespace {

sp<GraphicBlockBuffer> AllocateGraphicBuffer(
        const std::shared_ptr<C2BlockPool> &pool,
        const sp<AMessage> &format,
        uint32_t pixelFormat,
        const C2MemoryUsage &usage,
        const std::shared_ptr<LocalBufferPool> &localBufferPool) {
    int32_t width, height;
    if (!format->findInt32("width", &width) || !format->findInt32("height", &height)) {
        ALOGD("format lacks width or height");
        return nullptr;
    }

    std::shared_ptr<C2GraphicBlock> block;
    c2_status_t err = pool->fetchGraphicBlock(
            width, height, pixelFormat, usage, &block);
    if (err != C2_OK) {
        ALOGD("fetch graphic block failed: %d", err);
        return nullptr;
    }

    return GraphicBlockBuffer::Allocate(
            format,
            block,
            [localBufferPool](size_t capacity) {
                return localBufferPool->newBuffer(capacity);
            });
}

}  // namespace

// CCodecBuffers

void CCodecBuffers::setFormat(const sp<AMessage> &format) {
    CHECK(format != nullptr);
    mFormat = format;
}

sp<AMessage> CCodecBuffers::dupFormat() {
    return mFormat != nullptr ? mFormat->dup() : nullptr;
}

void CCodecBuffers::handleImageData(const sp<Codec2Buffer> &buffer) {
    sp<ABuffer> imageDataCandidate = buffer->getImageData();
    if (imageDataCandidate == nullptr) {
        if (mFormatWithImageData) {
            // We previously sent the format with image data, so use the same format.
            buffer->setFormat(mFormatWithImageData);
        }
        return;
    }
    if (!mLastImageData
            || imageDataCandidate->size() != mLastImageData->size()
            || memcmp(imageDataCandidate->data(),
                      mLastImageData->data(),
                      mLastImageData->size()) != 0) {
        ALOGD("[%s] updating image-data", mName);
        mFormatWithImageData = dupFormat();
        mLastImageData = imageDataCandidate;
        mFormatWithImageData->setBuffer("image-data", imageDataCandidate);
        MediaImage2 *img = (MediaImage2*)imageDataCandidate->data();
        if (img->mNumPlanes > 0 && img->mType != img->MEDIA_IMAGE_TYPE_UNKNOWN) {
            int32_t stride = img->mPlane[0].mRowInc;
            mFormatWithImageData->setInt32(KEY_STRIDE, stride);
            mFormatWithImageData->setInt32(KEY_WIDTH, img->mWidth);
            mFormatWithImageData->setInt32(KEY_HEIGHT, img->mHeight);
            ALOGD("[%s] updating stride = %d, width: %d, height: %d",
                  mName, stride, img->mWidth, img->mHeight);
            if (img->mNumPlanes > 1 && stride > 0) {
                int64_t offsetDelta =
                    (int64_t)img->mPlane[1].mOffset - (int64_t)img->mPlane[0].mOffset;
                int32_t vstride = int32_t(offsetDelta / stride);
                mFormatWithImageData->setInt32(KEY_SLICE_HEIGHT, vstride);
                ALOGD("[%s] updating vstride = %d", mName, vstride);
                buffer->setRange(
                        img->mPlane[0].mOffset,
                        buffer->size() - img->mPlane[0].mOffset);
            }
        }
    }
    buffer->setFormat(mFormatWithImageData);
}

// InputBuffers

sp<Codec2Buffer> InputBuffers::cloneAndReleaseBuffer(const sp<MediaCodecBuffer> &buffer) {
    sp<Codec2Buffer> copy = createNewBuffer();
    if (copy == nullptr) {
        return nullptr;
    }
    std::shared_ptr<C2Buffer> c2buffer;
    if (!releaseBuffer(buffer, &c2buffer, true)) {
        return nullptr;
    }
    if (!copy->canCopy(c2buffer)) {
        return nullptr;
    }
    if (!copy->copy(c2buffer)) {
        return nullptr;
    }
    copy->meta()->extend(buffer->meta());
    return copy;
}

// OutputBuffers

OutputBuffers::OutputBuffers(const char *componentName, const char *name)
    : CCodecBuffers(componentName, name) { }

OutputBuffers::~OutputBuffers() = default;

void OutputBuffers::initSkipCutBuffer(
        int32_t delay, int32_t padding, int32_t sampleRate, int32_t channelCount) {
    CHECK(mSkipCutBuffer == nullptr);
    mDelay = delay;
    mPadding = padding;
    mSampleRate = sampleRate;
    mChannelCount = channelCount;
    setSkipCutBuffer(delay, padding);
}

void OutputBuffers::updateSkipCutBuffer(int32_t sampleRate, int32_t channelCount) {
    if (mSkipCutBuffer == nullptr) {
        return;
    }
    if (mSampleRate == sampleRate && mChannelCount == channelCount) {
        return;
    }
    int32_t delay = mDelay;
    int32_t padding = mPadding;
    if (sampleRate != mSampleRate) {
        delay = ((int64_t)delay * sampleRate) / mSampleRate;
        padding = ((int64_t)padding * sampleRate) / mSampleRate;
    }
    mSampleRate = sampleRate;
    mChannelCount = channelCount;
    setSkipCutBuffer(delay, padding);
}

void OutputBuffers::updateSkipCutBuffer(const sp<AMessage> &format) {
    AString mediaType;
    if (format->findString(KEY_MIME, &mediaType)
            && mediaType == MIMETYPE_AUDIO_RAW) {
        int32_t channelCount;
        int32_t sampleRate;
        if (format->findInt32(KEY_CHANNEL_COUNT, &channelCount)
                && format->findInt32(KEY_SAMPLE_RATE, &sampleRate)) {
            updateSkipCutBuffer(sampleRate, channelCount);
        }
    }
}

void OutputBuffers::submit(const sp<MediaCodecBuffer> &buffer) {
    if (mSkipCutBuffer != nullptr) {
        mSkipCutBuffer->submit(buffer);
    }
}

void OutputBuffers::setSkipCutBuffer(int32_t skip, int32_t cut) {
    if (mSkipCutBuffer != nullptr) {
        size_t prevSize = mSkipCutBuffer->size();
        if (prevSize != 0u) {
            ALOGD("[%s] Replacing SkipCutBuffer holding %zu bytes", mName, prevSize);
        }
    }
    mSkipCutBuffer = new SkipCutBuffer(skip, cut, mChannelCount);
}

bool OutputBuffers::convert(
        const std::shared_ptr<C2Buffer> &src, sp<Codec2Buffer> *dst) {
    if (!src || src->data().type() != C2BufferData::LINEAR) {
        return false;
    }
    int32_t configEncoding = kAudioEncodingPcm16bit;
    int32_t codecEncoding = kAudioEncodingPcm16bit;
    if (mFormat->findInt32("android._codec-pcm-encoding", &codecEncoding)
            && mFormat->findInt32("android._config-pcm-encoding", &configEncoding)) {
        if (mSrcEncoding != codecEncoding || mDstEncoding != configEncoding) {
            if (codecEncoding != configEncoding) {
                mDataConverter = AudioConverter::Create(
                        (AudioEncoding)codecEncoding, (AudioEncoding)configEncoding);
                ALOGD_IF(mDataConverter, "[%s] Converter created from %d to %d",
                         mName, codecEncoding, configEncoding);
                mFormatWithConverter = mFormat->dup();
                mFormatWithConverter->setInt32(KEY_PCM_ENCODING, configEncoding);
            } else {
                mDataConverter = nullptr;
                mFormatWithConverter = nullptr;
            }
            mSrcEncoding = codecEncoding;
            mDstEncoding = configEncoding;
        }
        if (int encoding; !mFormat->findInt32(KEY_PCM_ENCODING, &encoding)
                || encoding != mDstEncoding) {
        }
    }
    if (!mDataConverter) {
        return false;
    }
    sp<MediaCodecBuffer> srcBuffer = ConstLinearBlockBuffer::Allocate(mFormat, src);
    if (!srcBuffer) {
        return false;
    }
    if (!dst) {
        *dst = new Codec2Buffer(
                mFormat,
                new ABuffer(mDataConverter->targetSize(srcBuffer->size())));
    }
    sp<MediaCodecBuffer> dstBuffer = *dst;
    status_t err = mDataConverter->convert(srcBuffer, dstBuffer);
    if (err != OK) {
        ALOGD("[%s] buffer conversion failed: %d", mName, err);
        return false;
    }
    dstBuffer->setFormat(mFormatWithConverter);
    return true;
}

void OutputBuffers::clearStash() {
    mPending.clear();
    mReorderStash.clear();
    mDepth = 0;
    mKey = C2Config::ORDINAL;
}

void OutputBuffers::flushStash() {
    for (StashEntry& e : mPending) {
        e.notify = false;
    }
    for (StashEntry& e : mReorderStash) {
        e.notify = false;
    }
}

uint32_t OutputBuffers::getReorderDepth() const {
    return mDepth;
}

void OutputBuffers::setReorderDepth(uint32_t depth) {
    mPending.splice(mPending.end(), mReorderStash);
    mDepth = depth;
}

void OutputBuffers::setReorderKey(C2Config::ordinal_key_t key) {
    mPending.splice(mPending.end(), mReorderStash);
    mKey = key;
}

void OutputBuffers::pushToStash(
        const std::shared_ptr<C2Buffer>& buffer,
        bool notify,
        int64_t timestamp,
        int32_t flags,
        const sp<AMessage>& format,
        const C2WorkOrdinalStruct& ordinal) {
    bool eos = flags & MediaCodec::BUFFER_FLAG_EOS;
    if (!buffer && eos) {
        // TRICKY: we may be violating ordering of the stash here. Because we
        // don't expect any more emplace() calls after this, the ordering should
        // not matter.
        mReorderStash.emplace_back(
                buffer, notify, timestamp, flags, format, ordinal);
    } else {
        flags = flags & ~MediaCodec::BUFFER_FLAG_EOS;
        auto it = mReorderStash.begin();
        for (; it != mReorderStash.end(); ++it) {
            if (less(ordinal, it->ordinal)) {
                break;
            }
        }
        mReorderStash.emplace(it,
                buffer, notify, timestamp, flags, format, ordinal);
        if (eos) {
            mReorderStash.back().flags =
                mReorderStash.back().flags | MediaCodec::BUFFER_FLAG_EOS;
        }
    }
    while (!mReorderStash.empty() && mReorderStash.size() > mDepth) {
        mPending.push_back(mReorderStash.front());
        mReorderStash.pop_front();
    }
    ALOGV("[%s] %s: pushToStash -- pending size = %zu", mName, __func__, mPending.size());
}

OutputBuffers::BufferAction OutputBuffers::popFromStashAndRegister(
        std::shared_ptr<C2Buffer>* c2Buffer,
        size_t* index,
        sp<MediaCodecBuffer>* outBuffer) {
    if (mPending.empty()) {
        return SKIP;
    }

    // Retrieve the first entry.
    StashEntry &entry = mPending.front();

    *c2Buffer = entry.buffer;
    sp<AMessage> outputFormat = entry.format;

    if (entry.notify && mFormat != outputFormat) {
        updateSkipCutBuffer(outputFormat);
        // Trigger image data processing to the new format
        mLastImageData.clear();
        ALOGV("[%s] popFromStashAndRegister: output format reference changed: %p -> %p",
                mName, mFormat.get(), outputFormat.get());
        ALOGD("[%s] popFromStashAndRegister: at %lldus, output format changed to %s",
                mName, (long long)entry.timestamp, outputFormat->debugString().c_str());
        setFormat(outputFormat);
    }

    // Flushing mReorderStash because no other buffers should come after output
    // EOS.
    if (entry.flags & MediaCodec::BUFFER_FLAG_EOS) {
        // Flush reorder stash
        setReorderDepth(0);
    }

    if (!entry.notify) {
        mPending.pop_front();
        return DISCARD;
    }

    // Try to register the buffer.
    status_t err = registerBuffer(*c2Buffer, index, outBuffer);
    if (err != OK) {
        if (err != WOULD_BLOCK) {
            return REALLOCATE;
        }
        return RETRY;
    }

    // Append information from the front stash entry to outBuffer.
    (*outBuffer)->meta()->setInt64("timeUs", entry.timestamp);
    (*outBuffer)->meta()->setInt32("flags", entry.flags);
    (*outBuffer)->meta()->setInt64("frameIndex", entry.ordinal.frameIndex.peekll());
    ALOGV("[%s] popFromStashAndRegister: "
          "out buffer index = %zu [%p] => %p + %zu (%lld)",
          mName, *index, outBuffer->get(),
          (*outBuffer)->data(), (*outBuffer)->size(),
          (long long)entry.timestamp);

    // The front entry of mPending will be removed now that the registration
    // succeeded.
    mPending.pop_front();
    return NOTIFY_CLIENT;
}

bool OutputBuffers::popPending(StashEntry *entry) {
    if (mPending.empty()) {
        return false;
    }
    *entry = mPending.front();
    mPending.pop_front();
    return true;
}

void OutputBuffers::deferPending(const OutputBuffers::StashEntry &entry) {
    mPending.push_front(entry);
}

bool OutputBuffers::hasPending() const {
    return !mPending.empty();
}

bool OutputBuffers::less(
        const C2WorkOrdinalStruct &o1, const C2WorkOrdinalStruct &o2) const {
    switch (mKey) {
        case C2Config::ORDINAL:   return o1.frameIndex < o2.frameIndex;
        case C2Config::TIMESTAMP: return o1.timestamp < o2.timestamp;
        case C2Config::CUSTOM:    return o1.customOrdinal < o2.customOrdinal;
        default:
            ALOGD("Unrecognized key; default to timestamp");
            return o1.frameIndex < o2.frameIndex;
    }
}

// LocalBufferPool

constexpr size_t kInitialPoolCapacity = kMaxLinearBufferSize;
constexpr size_t kMaxPoolCapacity = kMaxLinearBufferSize * 32;

std::shared_ptr<LocalBufferPool> LocalBufferPool::Create() {
    return std::shared_ptr<LocalBufferPool>(new LocalBufferPool(kInitialPoolCapacity));
}

sp<ABuffer> LocalBufferPool::newBuffer(size_t capacity) {
    Mutex::Autolock lock(mMutex);
    auto it = std::find_if(
            mPool.begin(), mPool.end(),
            [capacity](const std::vector<uint8_t> &vec) {
                return vec.capacity() >= capacity;
            });
    if (it != mPool.end()) {
        sp<ABuffer> buffer = new VectorBuffer(std::move(*it), shared_from_this());
        mPool.erase(it);
        return buffer;
    }
    if (mUsedSize + capacity > mPoolCapacity) {
        while (!mPool.empty()) {
            mUsedSize -= mPool.back().capacity();
            mPool.pop_back();
        }
        while (mUsedSize + capacity > mPoolCapacity && mPoolCapacity * 2 <= kMaxPoolCapacity) {
            ALOGD("Increasing local buffer pool capacity from %zu to %zu",
                  mPoolCapacity, mPoolCapacity * 2);
            mPoolCapacity *= 2;
        }
        if (mUsedSize + capacity > mPoolCapacity) {
            ALOGD("mUsedSize = %zu, capacity = %zu, mPoolCapacity = %zu",
                    mUsedSize, capacity, mPoolCapacity);
            return nullptr;
        }
    }
    std::vector<uint8_t> vec(capacity);
    mUsedSize += vec.capacity();
    return new VectorBuffer(std::move(vec), shared_from_this());
}

LocalBufferPool::VectorBuffer::VectorBuffer(
        std::vector<uint8_t> &&vec, const std::shared_ptr<LocalBufferPool> &pool)
    : ABuffer(vec.data(), vec.capacity()),
      mVec(std::move(vec)),
      mPool(pool) {
}

LocalBufferPool::VectorBuffer::~VectorBuffer() {
    std::shared_ptr<LocalBufferPool> pool = mPool.lock();
    if (pool) {
        // If pool is alive, return the vector back to the pool so that
        // it can be recycled.
        pool->returnVector(std::move(mVec));
    }
}

void LocalBufferPool::returnVector(std::vector<uint8_t> &&vec) {
    Mutex::Autolock lock(mMutex);
    mPool.push_front(std::move(vec));
}

// FlexBuffersImpl

size_t FlexBuffersImpl::assignSlot(const sp<Codec2Buffer> &buffer) {
    for (size_t i = 0; i < mBuffers.size(); ++i) {
        if (mBuffers[i].clientBuffer == nullptr
                && mBuffers[i].compBuffer.expired()) {
            mBuffers[i].clientBuffer = buffer;
            return i;
        }
    }
    mBuffers.push_back({ buffer, std::weak_ptr<C2Buffer>() });
    return mBuffers.size() - 1;
}

bool FlexBuffersImpl::releaseSlot(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer,
        bool release) {
    sp<Codec2Buffer> clientBuffer;
    size_t index = mBuffers.size();
    for (size_t i = 0; i < mBuffers.size(); ++i) {
        if (mBuffers[i].clientBuffer == buffer) {
            clientBuffer = mBuffers[i].clientBuffer;
            if (release) {
                mBuffers[i].clientBuffer.clear();
            }
            index = i;
            break;
        }
    }
    if (clientBuffer == nullptr) {
        ALOGV("[%s] %s: No matching buffer found", mName, __func__);
        return false;
    }
    std::shared_ptr<C2Buffer> result = mBuffers[index].compBuffer.lock();
    if (!result) {
        result = clientBuffer->asC2Buffer();
        clientBuffer->clearC2BufferRefs();
        mBuffers[index].compBuffer = result;
    }
    if (c2buffer) {
        *c2buffer = result;
    }
    return true;
}

bool FlexBuffersImpl::expireComponentBuffer(const std::shared_ptr<C2Buffer> &c2buffer) {
    for (size_t i = 0; i < mBuffers.size(); ++i) {
        std::shared_ptr<C2Buffer> compBuffer =
                mBuffers[i].compBuffer.lock();
        if (!compBuffer || compBuffer != c2buffer) {
            continue;
        }
        mBuffers[i].compBuffer.reset();
        ALOGV("[%s] codec released buffer #%zu", mName, i);
        return true;
    }
    ALOGV("[%s] codec released an unknown buffer", mName);
    return false;
}

void FlexBuffersImpl::flush() {
    ALOGV("[%s] buffers are flushed %zu", mName, mBuffers.size());
    mBuffers.clear();
}

size_t FlexBuffersImpl::numActiveSlots() const {
    return std::count_if(
            mBuffers.begin(), mBuffers.end(),
            [](const Entry &entry) {
                return (entry.clientBuffer != nullptr
                        || !entry.compBuffer.expired());
            });
}

size_t FlexBuffersImpl::numComponentBuffers() const {
    return std::count_if(
            mBuffers.begin(), mBuffers.end(),
            [](const Entry &entry) {
                return !entry.compBuffer.expired();
            });
}

// BuffersArrayImpl

void BuffersArrayImpl::initialize(
        const FlexBuffersImpl &impl,
        size_t minSize,
        std::function<sp<Codec2Buffer>()> allocate) {
    mImplName = impl.mImplName + "[N]";
    mName = mImplName.c_str();
    for (size_t i = 0; i < impl.mBuffers.size(); ++i) {
        sp<Codec2Buffer> clientBuffer = impl.mBuffers[i].clientBuffer;
        bool ownedByClient = (clientBuffer != nullptr);
        if (!ownedByClient) {
            clientBuffer = allocate();
        }
        mBuffers.push_back({ clientBuffer, impl.mBuffers[i].compBuffer, ownedByClient });
    }
    ALOGV("[%s] converted %zu buffers to array mode of %zu", mName, mBuffers.size(), minSize);
    for (size_t i = impl.mBuffers.size(); i < minSize; ++i) {
        mBuffers.push_back({ allocate(), std::weak_ptr<C2Buffer>(), false });
    }
}

status_t BuffersArrayImpl::grabBuffer(
        size_t *index,
        sp<Codec2Buffer> *buffer,
        std::function<bool(const sp<Codec2Buffer> &)> match) {
    // allBuffersDontMatch remains true if all buffers are available but
    // match() returns false for every buffer.
    bool allBuffersDontMatch = true;
    for (size_t i = 0; i < mBuffers.size(); ++i) {
        if (!mBuffers[i].ownedByClient && mBuffers[i].compBuffer.expired()) {
            if (match(mBuffers[i].clientBuffer)) {
                mBuffers[i].ownedByClient = true;
                *buffer = mBuffers[i].clientBuffer;
                (*buffer)->meta()->clear();
                (*buffer)->setRange(0, (*buffer)->capacity());
                *index = i;
                return OK;
            }
        } else {
            allBuffersDontMatch = false;
        }
    }
    return allBuffersDontMatch ? NO_MEMORY : WOULD_BLOCK;
}

bool BuffersArrayImpl::returnBuffer(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer,
        bool release) {
    sp<Codec2Buffer> clientBuffer;
    size_t index = mBuffers.size();
    for (size_t i = 0; i < mBuffers.size(); ++i) {
        if (mBuffers[i].clientBuffer == buffer) {
            if (!mBuffers[i].ownedByClient) {
                ALOGD("[%s] Client returned a buffer it does not own according to our record: %zu",
                      mName, i);
            }
            clientBuffer = mBuffers[i].clientBuffer;
            if (release) {
                mBuffers[i].ownedByClient = false;
            }
            index = i;
            break;
        }
    }
    if (clientBuffer == nullptr) {
        ALOGV("[%s] %s: No matching buffer found", mName, __func__);
        return false;
    }
    ALOGV("[%s] %s: matching buffer found (index=%zu)", mName, __func__, index);
    std::shared_ptr<C2Buffer> result = mBuffers[index].compBuffer.lock();
    if (!result) {
        result = clientBuffer->asC2Buffer();
        clientBuffer->clearC2BufferRefs();
        mBuffers[index].compBuffer = result;
    }
    if (c2buffer) {
        *c2buffer = result;
    }
    return true;
}

bool BuffersArrayImpl::expireComponentBuffer(const std::shared_ptr<C2Buffer> &c2buffer) {
    for (size_t i = 0; i < mBuffers.size(); ++i) {
        std::shared_ptr<C2Buffer> compBuffer =
                mBuffers[i].compBuffer.lock();
        if (!compBuffer) {
            continue;
        }
        if (c2buffer == compBuffer) {
            if (mBuffers[i].ownedByClient) {
                // This should not happen.
                ALOGD("[%s] codec released a buffer owned by client "
                      "(index %zu)", mName, i);
            }
            mBuffers[i].compBuffer.reset();
            ALOGV("[%s] codec released buffer #%zu(array mode)", mName, i);
            return true;
        }
    }
    ALOGV("[%s] codec released an unknown buffer (array mode)", mName);
    return false;
}

void BuffersArrayImpl::getArray(Vector<sp<MediaCodecBuffer>> *array) const {
    array->clear();
    for (const Entry &entry : mBuffers) {
        array->push(entry.clientBuffer);
    }
}

void BuffersArrayImpl::flush() {
    for (Entry &entry : mBuffers) {
        entry.ownedByClient = false;
    }
}

void BuffersArrayImpl::realloc(std::function<sp<Codec2Buffer>()> alloc) {
    size_t size = mBuffers.size();
    mBuffers.clear();
    for (size_t i = 0; i < size; ++i) {
        mBuffers.push_back({ alloc(), std::weak_ptr<C2Buffer>(), false });
    }
}

void BuffersArrayImpl::grow(
        size_t newSize, std::function<sp<Codec2Buffer>()> alloc) {
    CHECK_LT(mBuffers.size(), newSize);
    while (mBuffers.size() < newSize) {
        mBuffers.push_back({ alloc(), std::weak_ptr<C2Buffer>(), false });
    }
}

size_t BuffersArrayImpl::numActiveSlots() const {
    return std::count_if(
            mBuffers.begin(), mBuffers.end(),
            [](const Entry &entry) {
                return entry.ownedByClient || !entry.compBuffer.expired();
            });
}

size_t BuffersArrayImpl::arraySize() const {
    return mBuffers.size();
}

// InputBuffersArray

void InputBuffersArray::initialize(
        const FlexBuffersImpl &impl,
        size_t minSize,
        std::function<sp<Codec2Buffer>()> allocate) {
    mAllocate = allocate;
    mImpl.initialize(impl, minSize, allocate);
}

void InputBuffersArray::getArray(Vector<sp<MediaCodecBuffer>> *array) const {
    mImpl.getArray(array);
}

bool InputBuffersArray::requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) {
    sp<Codec2Buffer> c2Buffer;
    status_t err = mImpl.grabBuffer(index, &c2Buffer);
    if (err == OK) {
        c2Buffer->setFormat(mFormat);
        handleImageData(c2Buffer);
        *buffer = c2Buffer;
        return true;
    }
    return false;
}

bool InputBuffersArray::releaseBuffer(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer,
        bool release) {
    return mImpl.returnBuffer(buffer, c2buffer, release);
}

bool InputBuffersArray::expireComponentBuffer(
        const std::shared_ptr<C2Buffer> &c2buffer) {
    return mImpl.expireComponentBuffer(c2buffer);
}

void InputBuffersArray::flush() {
    mImpl.flush();
}

size_t InputBuffersArray::numActiveSlots() const {
    return mImpl.numActiveSlots();
}

sp<Codec2Buffer> InputBuffersArray::createNewBuffer() {
    return mAllocate();
}

// SlotInputBuffers

bool SlotInputBuffers::requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) {
    sp<Codec2Buffer> newBuffer = createNewBuffer();
    *index = mImpl.assignSlot(newBuffer);
    *buffer = newBuffer;
    return true;
}

bool SlotInputBuffers::releaseBuffer(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer,
        bool release) {
    return mImpl.releaseSlot(buffer, c2buffer, release);
}

bool SlotInputBuffers::expireComponentBuffer(
        const std::shared_ptr<C2Buffer> &c2buffer) {
    return mImpl.expireComponentBuffer(c2buffer);
}

void SlotInputBuffers::flush() {
    mImpl.flush();
}

std::unique_ptr<InputBuffers> SlotInputBuffers::toArrayMode(size_t) {
    TRESPASS("Array mode should not be called at non-legacy mode");
    return nullptr;
}

size_t SlotInputBuffers::numActiveSlots() const {
    return mImpl.numActiveSlots();
}

sp<Codec2Buffer> SlotInputBuffers::createNewBuffer() {
    return new DummyContainerBuffer{mFormat, nullptr};
}

// LinearInputBuffers

bool LinearInputBuffers::requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) {
    sp<Codec2Buffer> newBuffer = createNewBuffer();
    if (newBuffer == nullptr) {
        return false;
    }
    *index = mImpl.assignSlot(newBuffer);
    *buffer = newBuffer;
    return true;
}

bool LinearInputBuffers::releaseBuffer(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer,
        bool release) {
    return mImpl.releaseSlot(buffer, c2buffer, release);
}

bool LinearInputBuffers::expireComponentBuffer(
        const std::shared_ptr<C2Buffer> &c2buffer) {
    return mImpl.expireComponentBuffer(c2buffer);
}

void LinearInputBuffers::flush() {
    // This is no-op by default unless we're in array mode where we need to keep
    // track of the flushed work.
    mImpl.flush();
}

std::unique_ptr<InputBuffers> LinearInputBuffers::toArrayMode(size_t size) {
    std::unique_ptr<InputBuffersArray> array(
            new InputBuffersArray(mComponentName.c_str(), "1D-Input[N]"));
    array->setPool(mPool);
    array->setFormat(mFormat);
    array->initialize(
            mImpl,
            size,
            [pool = mPool, format = mFormat] () -> sp<Codec2Buffer> {
                return Alloc(pool, format);
            });
    return std::move(array);
}

size_t LinearInputBuffers::numActiveSlots() const {
    return mImpl.numActiveSlots();
}

// static
sp<Codec2Buffer> LinearInputBuffers::Alloc(
        const std::shared_ptr<C2BlockPool> &pool, const sp<AMessage> &format) {
    int32_t capacity = kLinearBufferSize;
    (void)format->findInt32(KEY_MAX_INPUT_SIZE, &capacity);
    if ((size_t)capacity > kMaxLinearBufferSize) {
        ALOGD("client requested %d, capped to %zu", capacity, kMaxLinearBufferSize);
        capacity = kMaxLinearBufferSize;
    }

    int64_t usageValue = 0;
    (void)format->findInt64("android._C2MemoryUsage", &usageValue);
    C2MemoryUsage usage{usageValue | C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE};
    std::shared_ptr<C2LinearBlock> block;

    c2_status_t err = pool->fetchLinearBlock(capacity, usage, &block);
    if (err != C2_OK) {
        return nullptr;
    }

    return LinearBlockBuffer::Allocate(format, block);
}

sp<Codec2Buffer> LinearInputBuffers::createNewBuffer() {
    return Alloc(mPool, mFormat);
}

// EncryptedLinearInputBuffers

EncryptedLinearInputBuffers::EncryptedLinearInputBuffers(
        bool secure,
        const sp<MemoryDealer> &dealer,
        const sp<ICrypto> &crypto,
        int32_t heapSeqNum,
        size_t capacity,
        size_t numInputSlots,
        const char *componentName, const char *name)
    : LinearInputBuffers(componentName, name),
      mUsage({0, 0}),
      mDealer(dealer),
      mCrypto(crypto),
      mMemoryVector(new std::vector<Entry>){
    if (secure) {
        mUsage = { C2MemoryUsage::READ_PROTECTED, 0 };
    } else {
        mUsage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    }
    for (size_t i = 0; i < numInputSlots; ++i) {
        sp<IMemory> memory = mDealer->allocate(capacity);
        if (memory == nullptr) {
            ALOGD("[%s] Failed to allocate memory from dealer: only %zu slots allocated",
                  mName, i);
            break;
        }
        mMemoryVector->push_back({std::weak_ptr<C2LinearBlock>(), memory, heapSeqNum});
    }
}

std::unique_ptr<InputBuffers> EncryptedLinearInputBuffers::toArrayMode(size_t size) {
    std::unique_ptr<InputBuffersArray> array(
            new InputBuffersArray(mComponentName.c_str(), "1D-EncryptedInput[N]"));
    array->setPool(mPool);
    array->setFormat(mFormat);
    array->initialize(
            mImpl,
            size,
            [pool = mPool,
             format = mFormat,
             usage = mUsage,
             memoryVector = mMemoryVector] () -> sp<Codec2Buffer> {
                return Alloc(pool, format, usage, memoryVector);
            });
    return std::move(array);
}


// static
sp<Codec2Buffer> EncryptedLinearInputBuffers::Alloc(
        const std::shared_ptr<C2BlockPool> &pool,
        const sp<AMessage> &format,
        C2MemoryUsage usage,
        const std::shared_ptr<std::vector<EncryptedLinearInputBuffers::Entry>> &memoryVector) {
    int32_t capacity = kLinearBufferSize;
    (void)format->findInt32(KEY_MAX_INPUT_SIZE, &capacity);
    if ((size_t)capacity > kMaxLinearBufferSize) {
        ALOGD("client requested %d, capped to %zu", capacity, kMaxLinearBufferSize);
        capacity = kMaxLinearBufferSize;
    }

    sp<IMemory> memory;
    size_t slot = 0;
    int32_t heapSeqNum = -1;
    for (; slot < memoryVector->size(); ++slot) {
        if (memoryVector->at(slot).block.expired()) {
            memory = memoryVector->at(slot).memory;
            heapSeqNum = memoryVector->at(slot).heapSeqNum;
            break;
        }
    }
    if (memory == nullptr) {
        return nullptr;
    }

    std::shared_ptr<C2LinearBlock> block;
    c2_status_t err = pool->fetchLinearBlock(capacity, usage, &block);
    if (err != C2_OK || block == nullptr) {
        return nullptr;
    }

    memoryVector->at(slot).block = block;
    return new EncryptedLinearBlockBuffer(format, block, memory, heapSeqNum);
}

sp<Codec2Buffer> EncryptedLinearInputBuffers::createNewBuffer() {
    // TODO: android_2020
    return nullptr;
}

// GraphicMetadataInputBuffers

GraphicMetadataInputBuffers::GraphicMetadataInputBuffers(
        const char *componentName, const char *name)
    : InputBuffers(componentName, name),
      mImpl(mName),
      mStore(GetCodec2PlatformAllocatorStore()) { }

bool GraphicMetadataInputBuffers::requestNewBuffer(
        size_t *index, sp<MediaCodecBuffer> *buffer) {
    sp<Codec2Buffer> newBuffer = createNewBuffer();
    if (newBuffer == nullptr) {
        return false;
    }
    *index = mImpl.assignSlot(newBuffer);
    *buffer = newBuffer;
    return true;
}

bool GraphicMetadataInputBuffers::releaseBuffer(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer,
        bool release) {
    return mImpl.releaseSlot(buffer, c2buffer, release);
}

bool GraphicMetadataInputBuffers::expireComponentBuffer(
        const std::shared_ptr<C2Buffer> &c2buffer) {
    return mImpl.expireComponentBuffer(c2buffer);
}

void GraphicMetadataInputBuffers::flush() {
    // This is no-op by default unless we're in array mode where we need to keep
    // track of the flushed work.
}

std::unique_ptr<InputBuffers> GraphicMetadataInputBuffers::toArrayMode(
        size_t size) {
    std::shared_ptr<C2Allocator> alloc;
    c2_status_t err = mStore->fetchAllocator(mPool->getAllocatorId(), &alloc);
    if (err != C2_OK) {
        return nullptr;
    }
    std::unique_ptr<InputBuffersArray> array(
            new InputBuffersArray(mComponentName.c_str(), "2D-MetaInput[N]"));
    array->setPool(mPool);
    array->setFormat(mFormat);
    array->initialize(
            mImpl,
            size,
            [format = mFormat, alloc]() -> sp<Codec2Buffer> {
                return new GraphicMetadataBuffer(format, alloc);
            });
    return std::move(array);
}

size_t GraphicMetadataInputBuffers::numActiveSlots() const {
    return mImpl.numActiveSlots();
}

sp<Codec2Buffer> GraphicMetadataInputBuffers::createNewBuffer() {
    std::shared_ptr<C2Allocator> alloc;
    c2_status_t err = mStore->fetchAllocator(mPool->getAllocatorId(), &alloc);
    if (err != C2_OK) {
        return nullptr;
    }
    return new GraphicMetadataBuffer(mFormat, alloc);
}

// GraphicInputBuffers

GraphicInputBuffers::GraphicInputBuffers(
        const char *componentName, const char *name)
    : InputBuffers(componentName, name),
      mImpl(mName),
      mLocalBufferPool(LocalBufferPool::Create()) { }

bool GraphicInputBuffers::requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) {
    sp<Codec2Buffer> newBuffer = createNewBuffer();
    if (newBuffer == nullptr) {
        return false;
    }
    *index = mImpl.assignSlot(newBuffer);
    handleImageData(newBuffer);
    *buffer = newBuffer;
    return true;
}

bool GraphicInputBuffers::releaseBuffer(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer,
        bool release) {
    return mImpl.releaseSlot(buffer, c2buffer, release);
}

bool GraphicInputBuffers::expireComponentBuffer(
        const std::shared_ptr<C2Buffer> &c2buffer) {
    return mImpl.expireComponentBuffer(c2buffer);
}

void GraphicInputBuffers::flush() {
    // This is no-op by default unless we're in array mode where we need to keep
    // track of the flushed work.
}

static uint32_t extractPixelFormat(const sp<AMessage> &format) {
    int32_t frameworkColorFormat = 0;
    if (!format->findInt32("android._color-format", &frameworkColorFormat)) {
        return PIXEL_FORMAT_UNKNOWN;
    }
    uint32_t pixelFormat = PIXEL_FORMAT_UNKNOWN;
    if (C2Mapper::mapPixelFormatFrameworkToCodec(frameworkColorFormat, &pixelFormat)) {
        return pixelFormat;
    }
    return PIXEL_FORMAT_UNKNOWN;
}

std::unique_ptr<InputBuffers> GraphicInputBuffers::toArrayMode(size_t size) {
    std::unique_ptr<InputBuffersArray> array(
            new InputBuffersArray(mComponentName.c_str(), "2D-BB-Input[N]"));
    array->setPool(mPool);
    array->setFormat(mFormat);
    uint32_t pixelFormat = extractPixelFormat(mFormat);
    array->initialize(
            mImpl,
            size,
            [pool = mPool, format = mFormat, lbp = mLocalBufferPool, pixelFormat]()
                    -> sp<Codec2Buffer> {
                C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
                return AllocateGraphicBuffer(
                        pool, format, pixelFormat, usage, lbp);
            });
    return std::move(array);
}

size_t GraphicInputBuffers::numActiveSlots() const {
    return mImpl.numActiveSlots();
}

sp<Codec2Buffer> GraphicInputBuffers::createNewBuffer() {
    int64_t usageValue = 0;
    (void)mFormat->findInt64("android._C2MemoryUsage", &usageValue);
    C2MemoryUsage usage{usageValue | C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE};
    return AllocateGraphicBuffer(
            mPool, mFormat, extractPixelFormat(mFormat), usage, mLocalBufferPool);
}

// OutputBuffersArray

void OutputBuffersArray::initialize(
        const FlexBuffersImpl &impl,
        size_t minSize,
        std::function<sp<Codec2Buffer>()> allocate) {
    mAlloc = allocate;
    mImpl.initialize(impl, minSize, allocate);
}

status_t OutputBuffersArray::registerBuffer(
        const std::shared_ptr<C2Buffer> &buffer,
        size_t *index,
        sp<MediaCodecBuffer> *clientBuffer) {
    sp<Codec2Buffer> c2Buffer;
    status_t err = mImpl.grabBuffer(
            index,
            &c2Buffer,
            [buffer](const sp<Codec2Buffer> &clientBuffer) {
                return clientBuffer->canCopy(buffer);
            });
    if (err == WOULD_BLOCK) {
        ALOGV("[%s] buffers temporarily not available", mName);
        return err;
    } else if (err != OK) {
        ALOGD("[%s] grabBuffer failed: %d", mName, err);
        return err;
    }
    c2Buffer->setFormat(mFormat);
    if (!convert(buffer, &c2Buffer) && !c2Buffer->copy(buffer)) {
        ALOGD("[%s] copy buffer failed", mName);
        return WOULD_BLOCK;
    }
    submit(c2Buffer);
    handleImageData(c2Buffer);
    *clientBuffer = c2Buffer;
    ALOGV("[%s] grabbed buffer %zu", mName, *index);
    return OK;
}

status_t OutputBuffersArray::registerCsd(
        const C2StreamInitDataInfo::output *csd,
        size_t *index,
        sp<MediaCodecBuffer> *clientBuffer) {
    sp<Codec2Buffer> c2Buffer;
    status_t err = mImpl.grabBuffer(
            index,
            &c2Buffer,
            [csd](const sp<Codec2Buffer> &clientBuffer) {
                return clientBuffer->base() != nullptr
                        && clientBuffer->capacity() >= csd->flexCount();
            });
    if (err != OK) {
        return err;
    }
    memcpy(c2Buffer->base(), csd->m.value, csd->flexCount());
    c2Buffer->setRange(0, csd->flexCount());
    c2Buffer->setFormat(mFormat);
    *clientBuffer = c2Buffer;
    return OK;
}

bool OutputBuffersArray::releaseBuffer(
        const sp<MediaCodecBuffer> &buffer, std::shared_ptr<C2Buffer> *c2buffer) {
    return mImpl.returnBuffer(buffer, c2buffer, true);
}

void OutputBuffersArray::flush(const std::list<std::unique_ptr<C2Work>> &flushedWork) {
    (void)flushedWork;
    mImpl.flush();
    if (mSkipCutBuffer != nullptr) {
        mSkipCutBuffer->clear();
    }
}

void OutputBuffersArray::getArray(Vector<sp<MediaCodecBuffer>> *array) const {
    mImpl.getArray(array);
}

size_t OutputBuffersArray::numActiveSlots() const {
    return mImpl.numActiveSlots();
}

void OutputBuffersArray::realloc(const std::shared_ptr<C2Buffer> &c2buffer) {
    switch (c2buffer->data().type()) {
        case C2BufferData::LINEAR: {
            uint32_t size = kLinearBufferSize;
            const std::vector<C2ConstLinearBlock> &linear_blocks = c2buffer->data().linearBlocks();
            const uint32_t block_size = linear_blocks.front().size();
            if (block_size < kMaxLinearBufferSize / 2) {
                size = block_size * 2;
            } else {
                size = kMaxLinearBufferSize;
            }
            mAlloc = [format = mFormat, size] {
                return new LocalLinearBuffer(format, new ABuffer(size));
            };
            ALOGD("[%s] reallocating with linear buffer of size %u", mName, size);
            break;
        }

        case C2BufferData::GRAPHIC: {
            // This is only called for RawGraphicOutputBuffers.
            mAlloc = [format = mFormat,
                      lbp = LocalBufferPool::Create()] {
                return ConstGraphicBlockBuffer::AllocateEmpty(
                        format,
                        [lbp](size_t capacity) {
                            return lbp->newBuffer(capacity);
                        });
            };
            ALOGD("[%s] reallocating with graphic buffer: format = %s",
                  mName, mFormat->debugString().c_str());
            break;
        }

        case C2BufferData::INVALID:         [[fallthrough]];
        case C2BufferData::LINEAR_CHUNKS:   [[fallthrough]];
        case C2BufferData::GRAPHIC_CHUNKS:  [[fallthrough]];
        default:
            ALOGD("Unsupported type: %d", (int)c2buffer->data().type());
            return;
    }
    mImpl.realloc(mAlloc);
}

void OutputBuffersArray::grow(size_t newSize) {
    mImpl.grow(newSize, mAlloc);
}

void OutputBuffersArray::transferFrom(OutputBuffers* source) {
    mFormat = source->mFormat;
    mSkipCutBuffer = source->mSkipCutBuffer;
    mPending = std::move(source->mPending);
    mReorderStash = std::move(source->mReorderStash);
    mDepth = source->mDepth;
    mKey = source->mKey;
}

// FlexOutputBuffers

status_t FlexOutputBuffers::registerBuffer(
        const std::shared_ptr<C2Buffer> &buffer,
        size_t *index,
        sp<MediaCodecBuffer> *clientBuffer) {
    sp<Codec2Buffer> newBuffer;
    if (!convert(buffer, &newBuffer)) {
        newBuffer = wrap(buffer);
        if (newBuffer == nullptr) {
            return NO_MEMORY;
        }
    }
    newBuffer->setFormat(mFormat);
    *index = mImpl.assignSlot(newBuffer);
    handleImageData(newBuffer);
    *clientBuffer = newBuffer;
    ALOGV("[%s] registered buffer %zu", mName, *index);
    return OK;
}

status_t FlexOutputBuffers::registerCsd(
        const C2StreamInitDataInfo::output *csd,
        size_t *index,
        sp<MediaCodecBuffer> *clientBuffer) {
    sp<Codec2Buffer> newBuffer = new LocalLinearBuffer(
            mFormat, ABuffer::CreateAsCopy(csd->m.value, csd->flexCount()));
    *index = mImpl.assignSlot(newBuffer);
    *clientBuffer = newBuffer;
    return OK;
}

bool FlexOutputBuffers::releaseBuffer(
        const sp<MediaCodecBuffer> &buffer,
        std::shared_ptr<C2Buffer> *c2buffer) {
    return mImpl.releaseSlot(buffer, c2buffer, true);
}

void FlexOutputBuffers::flush(
        const std::list<std::unique_ptr<C2Work>> &flushedWork) {
    (void) flushedWork;
    // This is no-op by default unless we're in array mode where we need to keep
    // track of the flushed work.
}

std::unique_ptr<OutputBuffersArray> FlexOutputBuffers::toArrayMode(size_t size) {
    std::unique_ptr<OutputBuffersArray> array(new OutputBuffersArray(mComponentName.c_str()));
    array->transferFrom(this);
    std::function<sp<Codec2Buffer>()> alloc = getAlloc();
    array->initialize(mImpl, size, alloc);
    return array;
}

size_t FlexOutputBuffers::numActiveSlots() const {
    return mImpl.numActiveSlots();
}

// LinearOutputBuffers

void LinearOutputBuffers::flush(
        const std::list<std::unique_ptr<C2Work>> &flushedWork) {
    if (mSkipCutBuffer != nullptr) {
        mSkipCutBuffer->clear();
    }
    FlexOutputBuffers::flush(flushedWork);
}

sp<Codec2Buffer> LinearOutputBuffers::wrap(const std::shared_ptr<C2Buffer> &buffer) {
    if (buffer == nullptr) {
        ALOGV("[%s] using a dummy buffer", mName);
        return new LocalLinearBuffer(mFormat, new ABuffer(0));
    }
    if (buffer->data().type() != C2BufferData::LINEAR) {
        ALOGV("[%s] non-linear buffer %d", mName, buffer->data().type());
        // We expect linear output buffers from the component.
        return nullptr;
    }
    if (buffer->data().linearBlocks().size() != 1u) {
        ALOGV("[%s] no linear buffers", mName);
        // We expect one and only one linear block from the component.
        return nullptr;
    }
    sp<Codec2Buffer> clientBuffer = ConstLinearBlockBuffer::Allocate(mFormat, buffer);
    if (clientBuffer == nullptr) {
        ALOGD("[%s] ConstLinearBlockBuffer::Allocate failed", mName);
        return nullptr;
    }
    submit(clientBuffer);
    return clientBuffer;
}

std::function<sp<Codec2Buffer>()> LinearOutputBuffers::getAlloc() {
    return [format = mFormat]{
        // TODO: proper max output size
        return new LocalLinearBuffer(format, new ABuffer(kLinearBufferSize));
    };
}

// GraphicOutputBuffers

sp<Codec2Buffer> GraphicOutputBuffers::wrap(const std::shared_ptr<C2Buffer> &buffer) {
    return new DummyContainerBuffer(mFormat, buffer);
}

std::function<sp<Codec2Buffer>()> GraphicOutputBuffers::getAlloc() {
    return [format = mFormat]{
        return new DummyContainerBuffer(format);
    };
}

// RawGraphicOutputBuffers

RawGraphicOutputBuffers::RawGraphicOutputBuffers(
        const char *componentName, const char *name)
    : FlexOutputBuffers(componentName, name),
      mLocalBufferPool(LocalBufferPool::Create()) { }

sp<Codec2Buffer> RawGraphicOutputBuffers::wrap(const std::shared_ptr<C2Buffer> &buffer) {
    if (buffer == nullptr) {
        return new Codec2Buffer(mFormat, new ABuffer(nullptr, 0));
    } else {
        return ConstGraphicBlockBuffer::Allocate(
                mFormat,
                buffer,
                [lbp = mLocalBufferPool](size_t capacity) {
                    return lbp->newBuffer(capacity);
                });
    }
}

std::function<sp<Codec2Buffer>()> RawGraphicOutputBuffers::getAlloc() {
    return [format = mFormat, lbp = mLocalBufferPool]{
        return ConstGraphicBlockBuffer::AllocateEmpty(
                format,
                [lbp](size_t capacity) {
                    return lbp->newBuffer(capacity);
                });
    };
}

}  // namespace android
