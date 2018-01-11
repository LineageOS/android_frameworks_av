/*
 * Copyright 2017, The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "CCodecBufferChannel"
#include <utils/Log.h>

#include <numeric>
#include <thread>

#include <C2PlatformSupport.h>

#include <android/hardware/cas/native/1.0/IDescrambler.h>
#include <binder/MemoryDealer.h>
#include <gui/Surface.h>
#include <media/openmax/OMX_Core.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/MediaCodec.h>
#include <media/MediaCodecBuffer.h>
#include <system/window.h>

#include "include/CCodecBufferChannel.h"
#include "include/Codec2Buffer.h"
#include "include/SecureBuffer.h"
#include "include/SharedMemoryBuffer.h"

namespace android {

using hardware::hidl_handle;
using hardware::hidl_string;
using hardware::hidl_vec;
using namespace hardware::cas::V1_0;
using namespace hardware::cas::native::V1_0;

namespace {

// TODO: get this info from component
const static size_t kMinBufferArraySize = 16;

template <class T>
ssize_t findBufferSlot(
        std::vector<T> *buffers,
        size_t maxSize,
        std::function<bool(const T&)> pred) {
    auto it = std::find_if(buffers->begin(), buffers->end(), pred);
    if (it == buffers->end()) {
        if (buffers->size() < maxSize) {
            buffers->emplace_back();
            return buffers->size() - 1;
        } else {
            return -1;
        }
    }
    return std::distance(buffers->begin(), it);
}

sp<Codec2Buffer> allocateLinearBuffer(
        const std::shared_ptr<C2BlockPool> &pool,
        const sp<AMessage> &format,
        size_t size,
        const C2MemoryUsage &usage) {
    std::shared_ptr<C2LinearBlock> block;

    status_t err = pool->fetchLinearBlock(
            size,
            usage,
            &block);
    if (err != OK) {
        return nullptr;
    }

    return Codec2Buffer::allocate(format, block);
}

class LinearBuffer : public C2Buffer {
public:
    explicit LinearBuffer(C2ConstLinearBlock block) : C2Buffer({ block }) {}
};

class InputBuffersArray : public CCodecBufferChannel::InputBuffers {
public:
    InputBuffersArray() = default;

    void add(
            size_t index,
            const sp<MediaCodecBuffer> &clientBuffer,
            const std::shared_ptr<C2Buffer> &compBuffer,
            bool available) {
        if (mBufferArray.size() < index) {
            mBufferArray.resize(index + 1);
        }
        mBufferArray[index].clientBuffer = clientBuffer;
        mBufferArray[index].compBuffer = compBuffer;
        mBufferArray[index].available = available;
    }

    bool isArrayMode() final { return true; }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode() final {
        return nullptr;
    }

    void getArray(Vector<sp<MediaCodecBuffer>> *array) final {
        array->clear();
        for (const auto &entry : mBufferArray) {
            array->push(entry.clientBuffer);
        }
    }

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
        for (size_t i = 0; i < mBufferArray.size(); ++i) {
            if (mBufferArray[i].available) {
                mBufferArray[i].available = false;
                *index = i;
                *buffer = mBufferArray[i].clientBuffer;
                return true;
            }
        }
        return false;
    }

    std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) override {
        for (size_t i = 0; i < mBufferArray.size(); ++i) {
            if (!mBufferArray[i].available && mBufferArray[i].clientBuffer == buffer) {
                mBufferArray[i].available = true;
                return std::move(mBufferArray[i].compBuffer);
            }
        }
        return nullptr;
    }

    void flush() override {
        for (size_t i = 0; i < mBufferArray.size(); ++i) {
            mBufferArray[i].available = true;
            mBufferArray[i].compBuffer.reset();
        }
    }

private:
    struct Entry {
        sp<MediaCodecBuffer> clientBuffer;
        std::shared_ptr<C2Buffer> compBuffer;
        bool available;
    };

    std::vector<Entry> mBufferArray;
};

class LinearInputBuffers : public CCodecBufferChannel::InputBuffers {
public:
    using CCodecBufferChannel::InputBuffers::InputBuffers;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
        *buffer = nullptr;
        ssize_t ret = findBufferSlot<wp<Codec2Buffer>>(
                &mBuffers, kMinBufferArraySize,
                [] (const auto &elem) { return elem.promote() == nullptr; });
        if (ret < 0) {
            return false;
        }
        // TODO: proper max input size and usage
        // TODO: read usage from intf
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        sp<Codec2Buffer> newBuffer = allocateLinearBuffer(mPool, mFormat, 65536, usage);
        if (newBuffer == nullptr) {
            return false;
        }
        mBuffers[ret] = newBuffer;
        *index = ret;
        *buffer = newBuffer;
        return true;
    }

    std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) override {
        auto it = std::find(mBuffers.begin(), mBuffers.end(), buffer);
        if (it == mBuffers.end()) {
            return nullptr;
        }
        sp<Codec2Buffer> codecBuffer = it->promote();
        // We got sp<> reference from the caller so this should never happen..
        CHECK(codecBuffer != nullptr);
        return std::make_shared<LinearBuffer>(codecBuffer->share());
    }

    void flush() override {
    }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode() final {
        std::unique_ptr<InputBuffersArray> array(new InputBuffersArray);
        // TODO
        const size_t size = std::max(kMinBufferArraySize, mBuffers.size());
        for (size_t i = 0; i < size; ++i) {
            sp<Codec2Buffer> clientBuffer = mBuffers[i].promote();
            bool available = false;
            if (clientBuffer == nullptr) {
                // TODO: proper max input size
                // TODO: read usage from intf
                C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
                clientBuffer = allocateLinearBuffer(mPool, mFormat, 65536, usage);
                available = true;
            }
            array->add(
                    i,
                    clientBuffer,
                    std::make_shared<LinearBuffer>(clientBuffer->share()),
                    available);
        }
        return std::move(array);
    }

private:
    // Buffers we passed to the client. The index of a buffer matches what
    // was passed in BufferCallback::onInputBufferAvailable().
    std::vector<wp<Codec2Buffer>> mBuffers;
};

// TODO: stub
class GraphicInputBuffers : public CCodecBufferChannel::InputBuffers {
public:
    using CCodecBufferChannel::InputBuffers::InputBuffers;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
        (void)index;
        (void)buffer;
        return false;
    }

    std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) override {
        (void)buffer;
        return nullptr;
    }

    void flush() override {
    }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode() final {
        return nullptr;
    }
};

class OutputBuffersArray : public CCodecBufferChannel::OutputBuffers {
public:
    using CCodecBufferChannel::OutputBuffers::OutputBuffers;

    void add(
            size_t index,
            const sp<MediaCodecBuffer> &clientBuffer,
            const std::shared_ptr<C2Buffer> &compBuffer,
            bool available) {
        if (mBufferArray.size() < index) {
            mBufferArray.resize(index + 1);
        }
        mBufferArray[index].clientBuffer = clientBuffer;
        mBufferArray[index].compBuffer = compBuffer;
        mBufferArray[index].available = available;
    }

    bool isArrayMode() final { return true; }

    std::unique_ptr<CCodecBufferChannel::OutputBuffers> toArrayMode() final {
        return nullptr;
    }

    bool registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *codecBuffer) final {
        for (size_t i = 0; i < mBufferArray.size(); ++i) {
            if (mBufferArray[i].available && copy(buffer, mBufferArray[i].clientBuffer)) {
                *index = i;
                *codecBuffer = mBufferArray[i].clientBuffer;
                mBufferArray[i].compBuffer = buffer;
                mBufferArray[i].available = false;
                return true;
            }
        }
        return false;
    }

    bool registerCsd(
            const C2StreamCsdInfo::output *csd,
            size_t *index,
            sp<MediaCodecBuffer> *codecBuffer) final {
        for (size_t i = 0; i < mBufferArray.size(); ++i) {
            if (mBufferArray[i].available
                    && mBufferArray[i].clientBuffer->capacity() <= csd->flexCount()) {
                memcpy(mBufferArray[i].clientBuffer->base(), csd->m.value, csd->flexCount());
                *index = i;
                *codecBuffer = mBufferArray[i].clientBuffer;
                mBufferArray[i].available = false;
                return true;
            }
        }
        return false;
    }

    std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) final {
        for (size_t i = 0; i < mBufferArray.size(); ++i) {
            if (!mBufferArray[i].available && mBufferArray[i].clientBuffer == buffer) {
                mBufferArray[i].available = true;
                return std::move(mBufferArray[i].compBuffer);
            }
        }
        return nullptr;
    }

    void flush(
            const std::list<std::unique_ptr<C2Work>> &flushedWork) override {
        (void) flushedWork;
        for (size_t i = 0; i < mBufferArray.size(); ++i) {
            mBufferArray[i].available = true;
            mBufferArray[i].compBuffer.reset();
        }
    }

    virtual bool copy(
            const std::shared_ptr<C2Buffer> &buffer,
            const sp<MediaCodecBuffer> &clientBuffer) = 0;

    void getArray(Vector<sp<MediaCodecBuffer>> *array) final {
        array->clear();
        for (const auto &entry : mBufferArray) {
            array->push(entry.clientBuffer);
        }
    }

private:
    struct Entry {
        sp<MediaCodecBuffer> clientBuffer;
        std::shared_ptr<C2Buffer> compBuffer;
        bool available;
    };

    std::vector<Entry> mBufferArray;
};

class LinearOutputBuffersArray : public OutputBuffersArray {
public:
    using OutputBuffersArray::OutputBuffersArray;

    bool copy(
            const std::shared_ptr<C2Buffer> &buffer,
            const sp<MediaCodecBuffer> &clientBuffer) final {
        if (!buffer) {
            clientBuffer->setRange(0u, 0u);
            return true;
        }
        C2ReadView view = buffer->data().linearBlocks().front().map().get();
        if (clientBuffer->capacity() < view.capacity()) {
            return false;
        }
        clientBuffer->setRange(0u, view.capacity());
        memcpy(clientBuffer->data(), view.data(), view.capacity());
        return true;
    }
};

class GraphicOutputBuffersArray : public OutputBuffersArray {
public:
    using OutputBuffersArray::OutputBuffersArray;

    bool copy(
            const std::shared_ptr<C2Buffer> &buffer,
            const sp<MediaCodecBuffer> &clientBuffer) final {
        if (!buffer) {
            clientBuffer->setRange(0u, 0u);
            return true;
        }
        clientBuffer->setRange(0u, 1u);
        return true;
    }
};

// Flexible in a sense that it does not have fixed array size.
class FlexOutputBuffers : public CCodecBufferChannel::OutputBuffers {
public:
    using CCodecBufferChannel::OutputBuffers::OutputBuffers;

    bool registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *codecBuffer) override {
        *codecBuffer = nullptr;
        ssize_t ret = findBufferSlot<BufferInfo>(
                &mBuffers,
                std::numeric_limits<size_t>::max(),
                [] (const auto &elem) { return elem.clientBuffer.promote() == nullptr; });
        if (ret < 0) {
            return false;
        }
        sp<MediaCodecBuffer> newBuffer = new MediaCodecBuffer(
                mFormat,
                convert(buffer));
        mBuffers[ret] = { newBuffer, buffer };
        *index = ret;
        *codecBuffer = newBuffer;
        return true;
    }

    bool registerCsd(
            const C2StreamCsdInfo::output *csd,
            size_t *index,
            sp<MediaCodecBuffer> *codecBuffer) final {
        *codecBuffer = nullptr;
        ssize_t ret = findBufferSlot<BufferInfo>(
                &mBuffers,
                std::numeric_limits<size_t>::max(),
                [] (const auto &elem) { return elem.clientBuffer.promote() == nullptr; });
        if (ret < 0) {
            return false;
        }
        sp<MediaCodecBuffer> newBuffer = new MediaCodecBuffer(
                mFormat,
                ABuffer::CreateAsCopy(csd->m.value, csd->flexCount()));
        mBuffers[ret] = { newBuffer, nullptr };
        *index = ret;
        *codecBuffer = newBuffer;
        return true;
    }

    std::shared_ptr<C2Buffer> releaseBuffer(
            const sp<MediaCodecBuffer> &buffer) override {
        auto it = std::find_if(
                mBuffers.begin(), mBuffers.end(),
                [buffer] (const auto &elem) {
                    return elem.clientBuffer.promote() == buffer;
                });
        if (it == mBuffers.end()) {
            return nullptr;
        }
        return std::move(it->bufferRef);
    }

    void flush(
            const std::list<std::unique_ptr<C2Work>> &flushedWork) override {
        (void) flushedWork;
        // This is no-op by default unless we're in array mode where we need to keep
        // track of the flushed work.
    }

    virtual sp<ABuffer> convert(const std::shared_ptr<C2Buffer> &buffer) = 0;

protected:
    struct BufferInfo {
        // wp<> of MediaCodecBuffer for MediaCodec.
        wp<MediaCodecBuffer> clientBuffer;
        // Buffer reference to hold until clientBuffer is valid.
        std::shared_ptr<C2Buffer> bufferRef;
    };
    // Buffers we passed to the client. The index of a buffer matches what
    // was passed in BufferCallback::onInputBufferAvailable().
    std::vector<BufferInfo> mBuffers;
};

class LinearOutputBuffers : public FlexOutputBuffers {
public:
    using FlexOutputBuffers::FlexOutputBuffers;

    virtual sp<ABuffer> convert(const std::shared_ptr<C2Buffer> &buffer) override {
        if (buffer == nullptr) {
            return new ABuffer(nullptr, 0);
        }
        if (buffer->data().type() != C2BufferData::LINEAR) {
            // We expect linear output buffers from the component.
            return nullptr;
        }
        if (buffer->data().linearBlocks().size() != 1u) {
            // We expect one and only one linear block from the component.
            return nullptr;
        }
        C2ReadView view = buffer->data().linearBlocks().front().map().get();
        if (view.error() != C2_OK) {
            // Mapping the linear block failed
            return nullptr;
        }
        return new ABuffer(
                // XXX: the data is supposed to be read-only. We don't have
                // const equivalent of ABuffer however...
                const_cast<uint8_t *>(view.data()),
                view.capacity());
    }

    std::unique_ptr<CCodecBufferChannel::OutputBuffers> toArrayMode() override {
        std::unique_ptr<OutputBuffersArray> array(new LinearOutputBuffersArray);

        const size_t size = std::max(kMinBufferArraySize, mBuffers.size());
        for (size_t i = 0; i < size; ++i) {
            sp<MediaCodecBuffer> clientBuffer = mBuffers[i].clientBuffer.promote();
            std::shared_ptr<C2Buffer> compBuffer = mBuffers[i].bufferRef;
            bool available = false;
            if (clientBuffer == nullptr) {
                // TODO: proper max input size
                clientBuffer = new MediaCodecBuffer(mFormat, new ABuffer(65536));
                available = true;
                compBuffer.reset();
            }
            array->add(i, clientBuffer, compBuffer, available);
        }
        return std::move(array);
    }
};

class GraphicOutputBuffers : public FlexOutputBuffers {
public:
    using FlexOutputBuffers::FlexOutputBuffers;

    sp<ABuffer> convert(const std::shared_ptr<C2Buffer> &buffer) override {
        return buffer ? new ABuffer(nullptr, 1) : new ABuffer(nullptr, 0);
    }

    std::unique_ptr<CCodecBufferChannel::OutputBuffers> toArrayMode() override {
        std::unique_ptr<OutputBuffersArray> array(new GraphicOutputBuffersArray);

        const size_t size = std::max(kMinBufferArraySize, mBuffers.size());
        for (size_t i = 0; i < size; ++i) {
            sp<MediaCodecBuffer> clientBuffer = mBuffers[i].clientBuffer.promote();
            std::shared_ptr<C2Buffer> compBuffer = mBuffers[i].bufferRef;
            bool available = false;
            if (clientBuffer == nullptr) {
                clientBuffer = new MediaCodecBuffer(mFormat, new ABuffer(nullptr, 1));
                available = true;
                compBuffer.reset();
            }
            array->add(i, clientBuffer, compBuffer, available);
        }
        return std::move(array);
    }
};

}  // namespace

CCodecBufferChannel::QueueGuard::QueueGuard(
        CCodecBufferChannel::QueueSync &sync) : mSync(sync) {
    std::unique_lock<std::mutex> l(mSync.mMutex);
    // At this point it's guaranteed that mSync is not under state transition,
    // as we are holding its mutex.
    if (mSync.mCount == -1) {
        mRunning = false;
    } else {
        ++mSync.mCount;
        mRunning = true;
    }
}

CCodecBufferChannel::QueueGuard::~QueueGuard() {
    if (mRunning) {
        // We are not holding mutex at this point so that QueueSync::stop() can
        // keep holding the lock until mCount reaches zero.
        --mSync.mCount;
    }
}

void CCodecBufferChannel::QueueSync::start() {
    std::unique_lock<std::mutex> l(mMutex);
    // If stopped, it goes to running state; otherwise no-op.
    int32_t expected = -1;
    (void)mCount.compare_exchange_strong(expected, 0);
}

void CCodecBufferChannel::QueueSync::stop() {
    std::unique_lock<std::mutex> l(mMutex);
    if (mCount == -1) {
        // no-op
        return;
    }
    // Holding mutex here blocks creation of additional QueueGuard objects, so
    // mCount can only decrement. In other words, threads that acquired the lock
    // are allowed to finish execution but additional threads trying to acquire
    // the lock at this point will block, and then get QueueGuard at STOPPED
    // state.
    int32_t expected = 0;
    while (!mCount.compare_exchange_weak(expected, -1)) {
        std::this_thread::yield();
    }
}

CCodecBufferChannel::CCodecBufferChannel(
        const std::function<void(status_t, enum ActionCode)> &onError)
    : mOnError(onError),
      mFrameIndex(0u),
      mFirstValidFrameIndex(0u) {
}

CCodecBufferChannel::~CCodecBufferChannel() {
    if (mCrypto != nullptr && mDealer != nullptr && mHeapSeqNum >= 0) {
        mCrypto->unsetHeap(mHeapSeqNum);
    }
}

void CCodecBufferChannel::setComponent(const std::shared_ptr<C2Component> &component) {
    mComponent = component;
    C2StreamFormatConfig::input inputFormat(0u);
    C2StreamFormatConfig::output outputFormat(0u);
    c2_status_t err = mComponent->intf()->query_vb(
            { &inputFormat, &outputFormat },
            {},
            C2_DONT_BLOCK,
            nullptr);
    if (err != C2_OK) {
        // TODO: error
        return;
    }

    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);

        bool graphic = (inputFormat.value == C2FormatVideo);
        if (graphic) {
            buffers->reset(new GraphicInputBuffers);
        } else {
            buffers->reset(new LinearInputBuffers);
        }

        ALOGV("graphic = %s", graphic ? "true" : "false");
        std::shared_ptr<C2BlockPool> pool;
        err = GetCodec2BlockPool(
                graphic ? C2BlockPool::BASIC_GRAPHIC : C2BlockPool::BASIC_LINEAR,
                component,
                &pool);
        if (err == C2_OK) {
            (*buffers)->setPool(pool);
        } else {
            // TODO: error
        }
    }

    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);

        bool graphic = (outputFormat.value == C2FormatVideo);
        if (graphic) {
            buffers->reset(new GraphicOutputBuffers);
        } else {
            buffers->reset(new LinearOutputBuffers);
        }
    }
}

status_t CCodecBufferChannel::queueInputBuffer(const sp<MediaCodecBuffer> &buffer) {
    QueueGuard guard(mSync);
    if (!guard.isRunning()) {
        ALOGW("No more buffers should be queued at current state.");
        return -ENOSYS;
    }

    int64_t timeUs;
    CHECK(buffer->meta()->findInt64("timeUs", &timeUs));

    int32_t flags = 0;
    int32_t tmp = 0;
    if (buffer->meta()->findInt32("eos", &tmp) && tmp) {
        flags |= C2BufferPack::FLAG_END_OF_STREAM;
        ALOGV("input EOS");
    }
    if (buffer->meta()->findInt32("csd", &tmp) && tmp) {
        flags |= C2BufferPack::FLAG_CODEC_CONFIG;
    }
    std::unique_ptr<C2Work> work(new C2Work);
    work->input.flags = (C2BufferPack::flags_t)flags;
    work->input.ordinal.timestamp = timeUs;
    work->input.ordinal.frame_index = mFrameIndex++;
    work->input.buffers.clear();
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        work->input.buffers.push_back((*buffers)->releaseBuffer(buffer));
    }
    // TODO: fill info's

    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);

    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));
    return mComponent->queue_nb(&items);
}

status_t CCodecBufferChannel::queueSecureInputBuffer(
        const sp<MediaCodecBuffer> &buffer, bool secure, const uint8_t *key,
        const uint8_t *iv, CryptoPlugin::Mode mode, CryptoPlugin::Pattern pattern,
        const CryptoPlugin::SubSample *subSamples, size_t numSubSamples,
        AString *errorDetailMsg) {
    // TODO
    (void) buffer;
    (void) secure;
    (void) key;
    (void) iv;
    (void) mode;
    (void) pattern;
    (void) subSamples;
    (void) numSubSamples;
    (void) errorDetailMsg;
    return -ENOSYS;
}

status_t CCodecBufferChannel::renderOutputBuffer(
        const sp<MediaCodecBuffer> &buffer, int64_t timestampNs) {
    ALOGV("renderOutputBuffer");

    std::shared_ptr<C2Buffer> c2Buffer;
    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        c2Buffer = (*buffers)->releaseBuffer(buffer);
    }

    Mutexed<sp<Surface>>::Locked surface(mSurface);
    if (*surface == nullptr) {
        ALOGE("no surface");
        return OK;
    }

    std::list<C2ConstGraphicBlock> blocks = c2Buffer->data().graphicBlocks();
    if (blocks.size() != 1u) {
        ALOGE("# of graphic blocks expected to be 1, but %zu", blocks.size());
        return UNKNOWN_ERROR;
    }

    sp<GraphicBuffer> graphicBuffer(new GraphicBuffer(
            blocks.front().handle(),
            GraphicBuffer::CLONE_HANDLE,
            blocks.front().width(),
            blocks.front().height(),
            HAL_PIXEL_FORMAT_YV12,
            // TODO
            1,
            (uint64_t)GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
            // TODO
            blocks.front().width()));

    status_t result = (*surface)->attachBuffer(graphicBuffer.get());
    if (result != OK) {
        ALOGE("attachBuffer failed: %d", result);
        return result;
    }

    // TODO: read and set crop

    result = native_window_set_buffers_timestamp((*surface).get(), timestampNs);
    ALOGW_IF(result != OK, "failed to set buffer timestamp: %d", result);

    // TODO: fix after C2Fence implementation
#if 0
    const C2Fence &fence = blocks.front().fence();
    result = ((ANativeWindow *)(*surface).get())->queueBuffer(
            (*surface).get(), graphicBuffer.get(), fence.valid() ? fence.fd() : -1);
#else
    result = ((ANativeWindow *)(*surface).get())->queueBuffer(
            (*surface).get(), graphicBuffer.get(), -1);
#endif
    if (result != OK) {
        ALOGE("queueBuffer failed: %d", result);
        return result;
    }

    return OK;
}

status_t CCodecBufferChannel::discardBuffer(const sp<MediaCodecBuffer> &buffer) {
    ALOGV("discardBuffer: %p", buffer.get());
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        (void)(*buffers)->releaseBuffer(buffer);
    }
    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        (void)(*buffers)->releaseBuffer(buffer);
    }
    return OK;
}

void CCodecBufferChannel::getInputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    array->clear();
    Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);

    if (!(*buffers)->isArrayMode()) {
        *buffers = (*buffers)->toArrayMode();
    }

    (*buffers)->getArray(array);
}

void CCodecBufferChannel::getOutputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    array->clear();
    Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);

    if (!(*buffers)->isArrayMode()) {
        *buffers = (*buffers)->toArrayMode();
    }

    (*buffers)->getArray(array);
}

void CCodecBufferChannel::start(const sp<AMessage> &inputFormat, const sp<AMessage> &outputFormat) {
    if (inputFormat != nullptr) {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        (*buffers)->setFormat(inputFormat);
    }
    if (outputFormat != nullptr) {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        (*buffers)->setFormat(outputFormat);
    }

    mSync.start();
    // TODO: use proper buffer depth instead of this random value
    for (size_t i = 0; i < kMinBufferArraySize; ++i) {
        size_t index;
        sp<MediaCodecBuffer> buffer;
        {
            Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
            if (!(*buffers)->requestNewBuffer(&index, &buffer)) {
                buffers.unlock();
                ALOGE("start: cannot allocate memory");
                mOnError(NO_MEMORY, ACTION_CODE_FATAL);
                buffers.lock();
                return;
            }
        }
        mCallback->onInputBufferAvailable(index, buffer);
    }
}

void CCodecBufferChannel::stop() {
    mSync.stop();
    mFirstValidFrameIndex = mFrameIndex.load();
}

void CCodecBufferChannel::flush(const std::list<std::unique_ptr<C2Work>> &flushedWork) {
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        (*buffers)->flush();
    }
    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        (*buffers)->flush(flushedWork);
    }
}

void CCodecBufferChannel::onWorkDone(std::vector<std::unique_ptr<C2Work>> workItems) {
    for (const auto &work : workItems) {
        sp<MediaCodecBuffer> inBuffer;
        size_t index;
        {
            Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
            if (!(*buffers)->requestNewBuffer(&index, &inBuffer)) {
                ALOGW("no new buffer available");
                inBuffer = nullptr;
            }
        }
        if (inBuffer != nullptr) {
            mCallback->onInputBufferAvailable(index, inBuffer);
        }

        if (work->result != OK) {
            ALOGE("work failed to complete: %d", work->result);
            mOnError(work->result, ACTION_CODE_FATAL);
            return;
        }

        // NOTE: MediaCodec usage supposedly have only one worklet
        if (work->worklets.size() != 1u) {
            ALOGE("incorrect number of worklets: %zu", work->worklets.size());
            mOnError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            continue;
        }

        const std::unique_ptr<C2Worklet> &worklet = work->worklets.front();
        if (worklet->output.ordinal.frame_index < mFirstValidFrameIndex) {
            // Discard frames from previous generation.
            continue;
        }
        // NOTE: MediaCodec usage supposedly have only one output stream.
        if (worklet->output.buffers.size() != 1u) {
            ALOGE("incorrect number of output buffers: %zu", worklet->output.buffers.size());
            mOnError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            continue;
        }

        const std::shared_ptr<C2Buffer> &buffer = worklet->output.buffers[0];
        const C2StreamCsdInfo::output *csdInfo = nullptr;
        if (buffer) {
            // TODO: transfer infos() into buffer metadata
        }
        for (const auto &info : worklet->output.infos) {
            if (info->coreIndex() == C2StreamCsdInfo::output::CORE_INDEX) {
                ALOGV("csd found");
                csdInfo = static_cast<const C2StreamCsdInfo::output *>(info.get());
            }
        }

        int32_t flags = 0;
        if (worklet->output.flags & C2BufferPack::FLAG_END_OF_STREAM) {
            flags |= MediaCodec::BUFFER_FLAG_EOS;
            ALOGV("output EOS");
        }

        sp<MediaCodecBuffer> outBuffer;
        if (csdInfo != nullptr) {
            Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
            if ((*buffers)->registerCsd(csdInfo, &index, &outBuffer)) {
                outBuffer->meta()->setInt64("timeUs", worklet->output.ordinal.timestamp);
                outBuffer->meta()->setInt32("flags", flags | MediaCodec::BUFFER_FLAG_CODECCONFIG);
                ALOGV("csd index = %zu", index);

                buffers.unlock();
                mCallback->onOutputBufferAvailable(index, outBuffer);
                buffers.lock();
            } else {
                ALOGE("unable to register output buffer");
                buffers.unlock();
                mOnError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
                buffers.lock();
                continue;
            }
        }

        if (!buffer && !flags) {
            ALOGV("Not reporting output buffer");
            continue;
        }

        {
            Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
            if (!(*buffers)->registerBuffer(buffer, &index, &outBuffer)) {
                ALOGE("unable to register output buffer");

                buffers.unlock();
                mOnError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
                buffers.lock();
                continue;
            }
        }

        outBuffer->meta()->setInt64("timeUs", worklet->output.ordinal.timestamp);
        outBuffer->meta()->setInt32("flags", flags);
        ALOGV("index = %zu", index);
        mCallback->onOutputBufferAvailable(index, outBuffer);
    }
}

status_t CCodecBufferChannel::setSurface(const sp<Surface> &newSurface) {
    if (newSurface != nullptr) {
        newSurface->setScalingMode(NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW);
    }

    Mutexed<sp<Surface>>::Locked surface(mSurface);
//    if (newSurface == nullptr) {
//        if (*surface != nullptr) {
//            ALOGW("cannot unset a surface");
//            return INVALID_OPERATION;
//        }
//        return OK;
//    }
//
//    if (*surface == nullptr) {
//        ALOGW("component was not configured with a surface");
//        return INVALID_OPERATION;
//    }

    *surface = newSurface;
    return OK;
}

}  // namespace android
