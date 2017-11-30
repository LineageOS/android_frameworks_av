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

// TODO: get this info from component
const static size_t kMinBufferArraySize = 16;

void CCodecBufferChannel::OutputBuffers::flush(
        const std::list<std::unique_ptr<C2Work>> &flushedWork) {
    (void) flushedWork;
    // This is no-op by default unless we're in array mode where we need to keep
    // track of the flushed work.
}

namespace {

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

class LinearBuffer : public C2Buffer {
public:
    explicit LinearBuffer(C2ConstLinearBlock block) : C2Buffer({ block }) {}
};

class LinearInputBuffers : public CCodecBufferChannel::InputBuffers {
public:
    using CCodecBufferChannel::InputBuffers::InputBuffers;

    virtual bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
        *buffer = nullptr;
        ssize_t ret = findBufferSlot<wp<Codec2Buffer>>(
                &mBuffers, kMinBufferArraySize,
                [] (const auto &elem) { return elem.promote() == nullptr; });
        if (ret < 0) {
            return false;
        }
        std::shared_ptr<C2LinearBlock> block;

        status_t err = mAlloc->fetchLinearBlock(
                // TODO: proper max input size
                65536,
                { 0, C2MemoryUsage::kSoftwareWrite },
                &block);
        if (err != OK) {
            return false;
        }

        sp<Codec2Buffer> newBuffer = Codec2Buffer::allocate(mFormat, block);
        mBuffers[ret] = newBuffer;
        *index = ret;
        *buffer = newBuffer;
        return true;
    }

    virtual std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) override {
        auto it = std::find(mBuffers.begin(), mBuffers.end(), buffer);
        if (it == mBuffers.end()) {
            return nullptr;
        }
        sp<Codec2Buffer> codecBuffer = it->promote();
        // We got sp<> reference from the caller so this should never happen..
        CHECK(codecBuffer != nullptr);
        return std::make_shared<LinearBuffer>(codecBuffer->share());
    }

    virtual void flush() override {
    }

private:
    // Buffers we passed to the client. The index of a buffer matches what
    // was passed in BufferCallback::onInputBufferAvailable().
    std::vector<wp<Codec2Buffer>> mBuffers;

    // Buffer array we passed to the client. This only gets initialized at
    // getInput/OutputBufferArray() and when this is set we can't add more
    // buffers.
    std::vector<sp<Codec2Buffer>> mBufferArray;
};

class GraphicOutputBuffers : public CCodecBufferChannel::OutputBuffers {
public:
    using CCodecBufferChannel::OutputBuffers::OutputBuffers;

    virtual bool registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *codecBuffer) override {
        *codecBuffer = nullptr;
        ssize_t ret = findBufferSlot<BufferInfo>(
                &mBuffers,
                kMinBufferArraySize,
                [] (const auto &elem) { return elem.mClientBuffer.promote() == nullptr; });
        if (ret < 0) {
            return false;
        }
        sp<MediaCodecBuffer> newBuffer = new MediaCodecBuffer(
                mFormat,
                buffer == nullptr ? kEmptyBuffer : kDummyBuffer);
        mBuffers[ret] = { newBuffer, buffer };
        *index = ret;
        *codecBuffer = newBuffer;
        return true;
    }

    virtual std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) override {
        auto it = std::find_if(
                mBuffers.begin(), mBuffers.end(),
                [buffer] (const auto &elem) {
                    return elem.mClientBuffer.promote() == buffer;
                });
        if (it == mBuffers.end()) {
            return nullptr;
        }
        return it->mBufferRef;
    }

private:
    static const sp<ABuffer> kEmptyBuffer;
    static const sp<ABuffer> kDummyBuffer;

    struct BufferInfo {
        // wp<> of MediaCodecBuffer for MediaCodec.
        wp<MediaCodecBuffer> mClientBuffer;
        // Buffer reference to hold until mClientBuffer is valid.
        std::shared_ptr<C2Buffer> mBufferRef;
    };
    // Buffers we passed to the client. The index of a buffer matches what
    // was passed in BufferCallback::onInputBufferAvailable().
    std::vector<BufferInfo> mBuffers;
};

const sp<ABuffer> GraphicOutputBuffers::kEmptyBuffer = new ABuffer(nullptr, 0);
const sp<ABuffer> GraphicOutputBuffers::kDummyBuffer = new ABuffer(nullptr, 1);

}  // namespace

CCodecBufferChannel::QueueGuard::QueueGuard(
        CCodecBufferChannel::QueueSync &sync) : mSync(sync) {
    std::unique_lock<std::mutex> l(mSync.mMutex);
    if (mSync.mCount == -1) {
        mRunning = false;
    } else {
        ++mSync.mCount;
        mRunning = true;
    }
}

CCodecBufferChannel::QueueGuard::~QueueGuard() {
    if (mRunning) {
        --mSync.mCount;
    }
}

void CCodecBufferChannel::QueueSync::start() {
    std::unique_lock<std::mutex> l(mMutex);
    // If stopped, it goes to running state; otherwise no-op.
    int32_t expected = -1;
    mCount.compare_exchange_strong(expected, 0);
}

void CCodecBufferChannel::QueueSync::stop() {
    std::unique_lock<std::mutex> l(mMutex);
    if (mCount == -1) {
        // no-op
        return;
    }
    int32_t expected = 0;
    while (!mCount.compare_exchange_weak(expected, -1)) {
        std::this_thread::yield();
    }
}

CCodecBufferChannel::CCodecBufferChannel(
        const std::function<void(status_t, enum ActionCode)> &onError)
    : mOnError(onError),
      mInputBuffers(new LinearInputBuffers),
      mOutputBuffers(new GraphicOutputBuffers),
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
    // TODO: get pool ID from params
    std::shared_ptr<C2BlockPool> pool;
    c2_status_t err = GetCodec2BlockPool(C2BlockPool::BASIC_LINEAR, component, &pool);
    if (err == C2_OK) {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        (*buffers)->setAlloc(pool);
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
    sp<MediaCodecBuffer> inBuffer;
    size_t index;
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        if (!(*buffers)->requestNewBuffer(&index, &inBuffer)) {
            inBuffer = nullptr;
        }
    }
    if (inBuffer != nullptr) {
        mCallback->onInputBufferAvailable(index, inBuffer);
    }

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
    ALOGV("discardBuffer");
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        (void) (*buffers)->releaseBuffer(buffer);
    }
    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        (void) (*buffers)->releaseBuffer(buffer);
    }
    return OK;
}

#if 0
void fillBufferArray_l(Mutexed<Buffers>::Locked &buffers) {
    for (size_t i = 0; i < buffers->mClientBuffer.size(); ++i) {
        sp<Codec2Buffer> buffer(buffers->mClientBuffer.get(i).promote());
        if (buffer == nullptr) {
            buffer = allocateBuffer_l(buffers->mAlloc);
        }
        buffers->mBufferArray.push_back(buffer);
    }
    while (buffers->mBufferArray.size() < kMinBufferArraySize) {
        sp<Codec2Buffer> buffer = allocateBuffer_l(buffers->mAlloc);
        // allocate buffer
        buffers->mBufferArray.push_back(buffer);
    }
}
#endif

void CCodecBufferChannel::getInputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    (void) array;
    // TODO
#if 0
    array->clear();
    Mutexed<Buffers>::Locked buffers(mInputBuffers);

    if (!buffers->isArrayMode()) {
        // mBufferArray is empty.
        fillBufferArray_l(buffers);
    }

    for (const auto &buffer : buffers->mBufferArray) {
        array->push_back(buffer);
    }
#endif
}

void CCodecBufferChannel::getOutputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    (void) array;
    // TODO
#if 0
    array->clear();
    Mutexed<Buffers>::Locked buffers(mOutputBuffers);

    if (!buffers->isArrayMode()) {
        if (linear) {
            // mBufferArray is empty.
            fillBufferArray_l(buffers);

            // We need to replace the allocator so that the component only returns
            // buffer from the array.
            ArrayModeAllocator::Builder builder(buffers->mBufferArray);
            for (size_t i = 0; i < buffers->mClientBuffer.size(); ++i) {
                if (buffers->mClientBuffer.get(i).promote() != nullptr) {
                    builder.markUsing(i);
                }
            }
            buffers->mAlloc.reset(builder.build());
        } else {
            for (int i = 0; i < X; ++i) {
                buffers->mBufferArray.push_back(dummy buffer);
            }
        }
    }

    for (const auto &buffer : buffers->mBufferArray) {
        array->push_back(buffer);
    }
#endif
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
        // TODO: transfer infos() into buffer metadata

        int32_t flags = 0;
        if (worklet->output.flags & C2BufferPack::FLAG_END_OF_STREAM) {
            flags |= MediaCodec::BUFFER_FLAG_EOS;
            ALOGV("output EOS");
        }

        size_t index;
        sp<MediaCodecBuffer> outBuffer;
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        if (!(*buffers)->registerBuffer(buffer, &index, &outBuffer)) {
            ALOGE("unable to register output buffer");
            mOnError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            continue;
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
