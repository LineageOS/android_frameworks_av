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

//#define LOG_NDEBUG 0
#define LOG_TAG "CCodecBufferChannel"
#include <utils/Log.h>

#include <numeric>

#include <C2AllocatorGralloc.h>
#include <C2PlatformSupport.h>
#include <C2BlockInternal.h>
#include <C2Config.h>
#include <C2Debug.h>

#include <android/hardware/cas/native/1.0/IDescrambler.h>
#include <android-base/stringprintf.h>
#include <binder/MemoryDealer.h>
#include <gui/Surface.h>
#include <media/openmax/OMX_Core.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ALookup.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/MediaCodecBuffer.h>
#include <system/window.h>

#include "CCodecBufferChannel.h"
#include "Codec2Buffer.h"
#include "SkipCutBuffer.h"

namespace android {

using android::base::StringPrintf;
using hardware::hidl_handle;
using hardware::hidl_string;
using hardware::hidl_vec;
using namespace hardware::cas::V1_0;
using namespace hardware::cas::native::V1_0;

using CasStatus = hardware::cas::V1_0::Status;

/**
 * Base class for representation of buffers at one port.
 */
class CCodecBufferChannel::Buffers {
public:
    Buffers(const char *componentName, const char *name = "Buffers")
        : mComponentName(componentName),
          mChannelName(std::string(componentName) + ":" + name),
          mName(mChannelName.c_str()) {
    }
    virtual ~Buffers() = default;

    /**
     * Set format for MediaCodec-facing buffers.
     */
    void setFormat(const sp<AMessage> &format) {
        CHECK(format != nullptr);
        mFormat = format;
    }

    /**
     * Return a copy of current format.
     */
    sp<AMessage> dupFormat() {
        return mFormat != nullptr ? mFormat->dup() : nullptr;
    }

    /**
     * Returns true if the buffers are operating under array mode.
     */
    virtual bool isArrayMode() const { return false; }

    /**
     * Fills the vector with MediaCodecBuffer's if in array mode; otherwise,
     * no-op.
     */
    virtual void getArray(Vector<sp<MediaCodecBuffer>> *) const {}

    /**
     * Return number of buffers the client owns.
     */
    virtual size_t numClientBuffers() const = 0;

    void handleImageData(const sp<Codec2Buffer> &buffer) {
        sp<ABuffer> imageDataCandidate = buffer->getImageData();
        if (imageDataCandidate == nullptr) {
            return;
        }
        sp<ABuffer> imageData;
        if (!mFormat->findBuffer("image-data", &imageData)
                || imageDataCandidate->size() != imageData->size()
                || memcmp(imageDataCandidate->data(), imageData->data(), imageData->size()) != 0) {
            ALOGD("[%s] updating image-data", mName);
            sp<AMessage> newFormat = dupFormat();
            newFormat->setBuffer("image-data", imageDataCandidate);
            MediaImage2 *img = (MediaImage2*)imageDataCandidate->data();
            if (img->mNumPlanes > 0 && img->mType != img->MEDIA_IMAGE_TYPE_UNKNOWN) {
                int32_t stride = img->mPlane[0].mRowInc;
                newFormat->setInt32(KEY_STRIDE, stride);
                ALOGD("[%s] updating stride = %d", mName, stride);
                if (img->mNumPlanes > 1 && stride > 0) {
                    int32_t vstride = (img->mPlane[1].mOffset - img->mPlane[0].mOffset) / stride;
                    newFormat->setInt32(KEY_SLICE_HEIGHT, vstride);
                    ALOGD("[%s] updating vstride = %d", mName, vstride);
                }
            }
            setFormat(newFormat);
            buffer->setFormat(newFormat);
        }
    }

protected:
    std::string mComponentName; ///< name of component for debugging
    std::string mChannelName; ///< name of channel for debugging
    const char *mName; ///< C-string version of channel name
    // Format to be used for creating MediaCodec-facing buffers.
    sp<AMessage> mFormat;

private:
    DISALLOW_EVIL_CONSTRUCTORS(Buffers);
};

class CCodecBufferChannel::InputBuffers : public CCodecBufferChannel::Buffers {
public:
    InputBuffers(const char *componentName, const char *name = "Input[]")
        : Buffers(componentName, name) { }
    virtual ~InputBuffers() = default;

    /**
     * Set a block pool to obtain input memory blocks.
     */
    void setPool(const std::shared_ptr<C2BlockPool> &pool) { mPool = pool; }

    /**
     * Get a new MediaCodecBuffer for input and its corresponding index.
     * Returns false if no new buffer can be obtained at the moment.
     */
    virtual bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) = 0;

    /**
     * Release the buffer obtained from requestNewBuffer() and get the
     * associated C2Buffer object back. Returns true if the buffer was on file
     * and released successfully.
     */
    virtual bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) = 0;

    /**
     * Release the buffer that is no longer used by the codec process. Return
     * true if and only if the buffer was on file and released successfully.
     */
    virtual bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) = 0;

    /**
     * Flush internal state. After this call, no index or buffer previously
     * returned from requestNewBuffer() is valid.
     */
    virtual void flush() = 0;

    /**
     * Return array-backed version of input buffers. The returned object
     * shall retain the internal state so that it will honor index and
     * buffer from previous calls of requestNewBuffer().
     */
    virtual std::unique_ptr<InputBuffers> toArrayMode(size_t size) = 0;

protected:
    // Pool to obtain blocks for input buffers.
    std::shared_ptr<C2BlockPool> mPool;

private:
    DISALLOW_EVIL_CONSTRUCTORS(InputBuffers);
};

class CCodecBufferChannel::OutputBuffers : public CCodecBufferChannel::Buffers {
public:
    OutputBuffers(const char *componentName, const char *name = "Output")
        : Buffers(componentName, name) { }
    virtual ~OutputBuffers() = default;

    /**
     * Register output C2Buffer from the component and obtain corresponding
     * index and MediaCodecBuffer object. Returns false if registration
     * fails.
     */
    virtual status_t registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) = 0;

    /**
     * Register codec specific data as a buffer to be consistent with
     * MediaCodec behavior.
     */
    virtual status_t registerCsd(
            const C2StreamInitDataInfo::output * /* csd */,
            size_t * /* index */,
            sp<MediaCodecBuffer> * /* clientBuffer */) = 0;

    /**
     * Release the buffer obtained from registerBuffer() and get the
     * associated C2Buffer object back. Returns true if the buffer was on file
     * and released successfully.
     */
    virtual bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer, std::shared_ptr<C2Buffer> *c2buffer) = 0;

    /**
     * Flush internal state. After this call, no index or buffer previously
     * returned from registerBuffer() is valid.
     */
    virtual void flush(const std::list<std::unique_ptr<C2Work>> &flushedWork) = 0;

    /**
     * Return array-backed version of output buffers. The returned object
     * shall retain the internal state so that it will honor index and
     * buffer from previous calls of registerBuffer().
     */
    virtual std::unique_ptr<OutputBuffers> toArrayMode(size_t size) = 0;

    /**
     * Initialize SkipCutBuffer object.
     */
    void initSkipCutBuffer(
            int32_t delay, int32_t padding, int32_t sampleRate, int32_t channelCount) {
        CHECK(mSkipCutBuffer == nullptr);
        mDelay = delay;
        mPadding = padding;
        mSampleRate = sampleRate;
        setSkipCutBuffer(delay, padding, channelCount);
    }

    /**
     * Update the SkipCutBuffer object. No-op if it's never initialized.
     */
    void updateSkipCutBuffer(int32_t sampleRate, int32_t channelCount) {
        if (mSkipCutBuffer == nullptr) {
            return;
        }
        int32_t delay = mDelay;
        int32_t padding = mPadding;
        if (sampleRate != mSampleRate) {
            delay = ((int64_t)delay * sampleRate) / mSampleRate;
            padding = ((int64_t)padding * sampleRate) / mSampleRate;
        }
        setSkipCutBuffer(delay, padding, channelCount);
    }

    /**
     * Submit buffer to SkipCutBuffer object, if initialized.
     */
    void submit(const sp<MediaCodecBuffer> &buffer) {
        if (mSkipCutBuffer != nullptr) {
            mSkipCutBuffer->submit(buffer);
        }
    }

    /**
     * Transfer SkipCutBuffer object to the other Buffers object.
     */
    void transferSkipCutBuffer(const sp<SkipCutBuffer> &scb) {
        mSkipCutBuffer = scb;
    }

protected:
    sp<SkipCutBuffer> mSkipCutBuffer;

private:
    int32_t mDelay;
    int32_t mPadding;
    int32_t mSampleRate;

    void setSkipCutBuffer(int32_t skip, int32_t cut, int32_t channelCount) {
        if (mSkipCutBuffer != nullptr) {
            size_t prevSize = mSkipCutBuffer->size();
            if (prevSize != 0u) {
                ALOGD("[%s] Replacing SkipCutBuffer holding %zu bytes", mName, prevSize);
            }
        }
        mSkipCutBuffer = new SkipCutBuffer(skip, cut, channelCount);
    }

    DISALLOW_EVIL_CONSTRUCTORS(OutputBuffers);
};

namespace {

const static size_t kSmoothnessFactor = 4;
const static size_t kRenderingDepth = 3;
const static size_t kLinearBufferSize = 1048576;
// This can fit 4K RGBA frame, and most likely client won't need more than this.
const static size_t kMaxLinearBufferSize = 3840 * 2160 * 4;

/**
 * Simple local buffer pool backed by std::vector.
 */
class LocalBufferPool : public std::enable_shared_from_this<LocalBufferPool> {
public:
    /**
     * Create a new LocalBufferPool object.
     *
     * \param poolCapacity  max total size of buffers managed by this pool.
     *
     * \return  a newly created pool object.
     */
    static std::shared_ptr<LocalBufferPool> Create(size_t poolCapacity) {
        return std::shared_ptr<LocalBufferPool>(new LocalBufferPool(poolCapacity));
    }

    /**
     * Return an ABuffer object whose size is at least |capacity|.
     *
     * \param   capacity  requested capacity
     * \return  nullptr if the pool capacity is reached
     *          an ABuffer object otherwise.
     */
    sp<ABuffer> newBuffer(size_t capacity) {
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

private:
    /**
     * ABuffer backed by std::vector.
     */
    class VectorBuffer : public ::android::ABuffer {
    public:
        /**
         * Construct a VectorBuffer by taking the ownership of supplied vector.
         *
         * \param vec   backing vector of the buffer. this object takes
         *              ownership at construction.
         * \param pool  a LocalBufferPool object to return the vector at
         *              destruction.
         */
        VectorBuffer(std::vector<uint8_t> &&vec, const std::shared_ptr<LocalBufferPool> &pool)
            : ABuffer(vec.data(), vec.capacity()),
              mVec(std::move(vec)),
              mPool(pool) {
        }

        ~VectorBuffer() override {
            std::shared_ptr<LocalBufferPool> pool = mPool.lock();
            if (pool) {
                // If pool is alive, return the vector back to the pool so that
                // it can be recycled.
                pool->returnVector(std::move(mVec));
            }
        }

    private:
        std::vector<uint8_t> mVec;
        std::weak_ptr<LocalBufferPool> mPool;
    };

    Mutex mMutex;
    size_t mPoolCapacity;
    size_t mUsedSize;
    std::list<std::vector<uint8_t>> mPool;

    /**
     * Private constructor to prevent constructing non-managed LocalBufferPool.
     */
    explicit LocalBufferPool(size_t poolCapacity)
        : mPoolCapacity(poolCapacity), mUsedSize(0) {
    }

    /**
     * Take back the ownership of vec from the destructed VectorBuffer and put
     * it in front of the pool.
     */
    void returnVector(std::vector<uint8_t> &&vec) {
        Mutex::Autolock lock(mMutex);
        mPool.push_front(std::move(vec));
    }

    DISALLOW_EVIL_CONSTRUCTORS(LocalBufferPool);
};

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

class BuffersArrayImpl;

/**
 * Flexible buffer slots implementation.
 */
class FlexBuffersImpl {
public:
    FlexBuffersImpl(const char *name)
        : mImplName(std::string(name) + ".Impl"),
          mName(mImplName.c_str()) { }

    /**
     * Assign an empty slot for a buffer and return the index. If there's no
     * empty slot, just add one at the end and return it.
     *
     * \param buffer[in]  a new buffer to assign a slot.
     * \return            index of the assigned slot.
     */
    size_t assignSlot(const sp<Codec2Buffer> &buffer) {
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

    /**
     * Release the slot from the client, and get the C2Buffer object back from
     * the previously assigned buffer. Note that the slot is not completely free
     * until the returned C2Buffer object is freed.
     *
     * \param   buffer[in]        the buffer previously assigned a slot.
     * \param   c2buffer[in,out]  pointer to C2Buffer to be populated. Ignored
     *                            if null.
     * \return  true  if the buffer is successfully released from a slot
     *          false otherwise
     */
    bool releaseSlot(
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
            mBuffers[index].compBuffer = result;
        }
        if (c2buffer) {
            *c2buffer = result;
        }
        return true;
    }

    bool expireComponentBuffer(const std::shared_ptr<C2Buffer> &c2buffer) {
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

    void flush() {
        ALOGV("[%s] buffers are flushed %zu", mName, mBuffers.size());
        mBuffers.clear();
    }

    size_t numClientBuffers() const {
        return std::count_if(
                mBuffers.begin(), mBuffers.end(),
                [](const Entry &entry) {
                    return (entry.clientBuffer != nullptr);
                });
    }

private:
    friend class BuffersArrayImpl;

    std::string mImplName; ///< name for debugging
    const char *mName; ///< C-string version of name

    struct Entry {
        sp<Codec2Buffer> clientBuffer;
        std::weak_ptr<C2Buffer> compBuffer;
    };
    std::vector<Entry> mBuffers;
};

/**
 * Static buffer slots implementation based on a fixed-size array.
 */
class BuffersArrayImpl {
public:
    BuffersArrayImpl()
        : mImplName("BuffersArrayImpl"),
          mName(mImplName.c_str()) { }

    /**
     * Initialize buffer array from the original |impl|. The buffers known by
     * the client is preserved, and the empty slots are populated so that the
     * array size is at least |minSize|.
     *
     * \param impl[in]      FlexBuffersImpl object used so far.
     * \param minSize[in]   minimum size of the buffer array.
     * \param allocate[in]  function to allocate a client buffer for an empty slot.
     */
    void initialize(
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

    /**
     * Grab a buffer from the underlying array which matches the criteria.
     *
     * \param index[out]    index of the slot.
     * \param buffer[out]   the matching buffer.
     * \param match[in]     a function to test whether the buffer matches the
     *                      criteria or not.
     * \return OK           if successful,
     *         WOULD_BLOCK  if slots are being used,
     *         NO_MEMORY    if no slot matches the criteria, even though it's
     *                      available
     */
    status_t grabBuffer(
            size_t *index,
            sp<Codec2Buffer> *buffer,
            std::function<bool(const sp<Codec2Buffer> &)> match =
                [](const sp<Codec2Buffer> &) { return true; }) {
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

    /**
     * Return the buffer from the client, and get the C2Buffer object back from
     * the buffer. Note that the slot is not completely free until the returned
     * C2Buffer object is freed.
     *
     * \param   buffer[in]        the buffer previously grabbed.
     * \param   c2buffer[in,out]  pointer to C2Buffer to be populated. Ignored
     *                            if null.
     * \return  true  if the buffer is successfully returned
     *          false otherwise
     */
    bool returnBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) {
        sp<Codec2Buffer> clientBuffer;
        size_t index = mBuffers.size();
        for (size_t i = 0; i < mBuffers.size(); ++i) {
            if (mBuffers[i].clientBuffer == buffer) {
                if (!mBuffers[i].ownedByClient) {
                    ALOGD("[%s] Client returned a buffer it does not own according to our record: %zu", mName, i);
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
            mBuffers[index].compBuffer = result;
        }
        if (c2buffer) {
            *c2buffer = result;
        }
        return true;
    }

    bool expireComponentBuffer(const std::shared_ptr<C2Buffer> &c2buffer) {
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

    /**
     * Populate |array| with the underlying buffer array.
     *
     * \param array[out]  an array to be filled with the underlying buffer array.
     */
    void getArray(Vector<sp<MediaCodecBuffer>> *array) const {
        array->clear();
        for (const Entry &entry : mBuffers) {
            array->push(entry.clientBuffer);
        }
    }

    /**
     * The client abandoned all known buffers, so reclaim the ownership.
     */
    void flush() {
        for (Entry &entry : mBuffers) {
            entry.ownedByClient = false;
        }
    }

    void realloc(std::function<sp<Codec2Buffer>()> alloc) {
        size_t size = mBuffers.size();
        mBuffers.clear();
        for (size_t i = 0; i < size; ++i) {
            mBuffers.push_back({ alloc(), std::weak_ptr<C2Buffer>(), false });
        }
    }

    size_t numClientBuffers() const {
        return std::count_if(
                mBuffers.begin(), mBuffers.end(),
                [](const Entry &entry) {
                    return entry.ownedByClient;
                });
    }

private:
    std::string mImplName; ///< name for debugging
    const char *mName; ///< C-string version of name

    struct Entry {
        const sp<Codec2Buffer> clientBuffer;
        std::weak_ptr<C2Buffer> compBuffer;
        bool ownedByClient;
    };
    std::vector<Entry> mBuffers;
};

class InputBuffersArray : public CCodecBufferChannel::InputBuffers {
public:
    InputBuffersArray(const char *componentName, const char *name = "Input[N]")
        : InputBuffers(componentName, name) { }
    ~InputBuffersArray() override = default;

    void initialize(
            const FlexBuffersImpl &impl,
            size_t minSize,
            std::function<sp<Codec2Buffer>()> allocate) {
        mImpl.initialize(impl, minSize, allocate);
    }

    bool isArrayMode() const final { return true; }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode(
            size_t) final {
        return nullptr;
    }

    void getArray(Vector<sp<MediaCodecBuffer>> *array) const final {
        mImpl.getArray(array);
    }

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
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

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override {
        return mImpl.returnBuffer(buffer, c2buffer, release);
    }

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override {
        return mImpl.expireComponentBuffer(c2buffer);
    }

    void flush() override {
        mImpl.flush();
    }

    size_t numClientBuffers() const final {
        return mImpl.numClientBuffers();
    }

private:
    BuffersArrayImpl mImpl;
};

class LinearInputBuffers : public CCodecBufferChannel::InputBuffers {
public:
    LinearInputBuffers(const char *componentName, const char *name = "1D-Input")
        : InputBuffers(componentName, name),
          mImpl(mName) { }

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
        int32_t capacity = kLinearBufferSize;
        (void)mFormat->findInt32(KEY_MAX_INPUT_SIZE, &capacity);
        if ((size_t)capacity > kMaxLinearBufferSize) {
            ALOGD("client requested %d, capped to %zu", capacity, kMaxLinearBufferSize);
            capacity = kMaxLinearBufferSize;
        }
        // TODO: proper max input size
        // TODO: read usage from intf
        sp<Codec2Buffer> newBuffer = alloc((size_t)capacity);
        if (newBuffer == nullptr) {
            return false;
        }
        *index = mImpl.assignSlot(newBuffer);
        *buffer = newBuffer;
        return true;
    }

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override {
        return mImpl.releaseSlot(buffer, c2buffer, release);
    }

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override {
        return mImpl.expireComponentBuffer(c2buffer);
    }

    void flush() override {
        // This is no-op by default unless we're in array mode where we need to keep
        // track of the flushed work.
        mImpl.flush();
    }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode(
            size_t size) final {
        int32_t capacity = kLinearBufferSize;
        (void)mFormat->findInt32(KEY_MAX_INPUT_SIZE, &capacity);
        if ((size_t)capacity > kMaxLinearBufferSize) {
            ALOGD("client requested %d, capped to %zu", capacity, kMaxLinearBufferSize);
            capacity = kMaxLinearBufferSize;
        }
        // TODO: proper max input size
        // TODO: read usage from intf
        std::unique_ptr<InputBuffersArray> array(
                new InputBuffersArray(mComponentName.c_str(), "1D-Input[N]"));
        array->setPool(mPool);
        array->setFormat(mFormat);
        array->initialize(
                mImpl,
                size,
                [this, capacity] () -> sp<Codec2Buffer> { return alloc(capacity); });
        return std::move(array);
    }

    size_t numClientBuffers() const final {
        return mImpl.numClientBuffers();
    }

    virtual sp<Codec2Buffer> alloc(size_t size) {
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        std::shared_ptr<C2LinearBlock> block;

        c2_status_t err = mPool->fetchLinearBlock(size, usage, &block);
        if (err != C2_OK) {
            return nullptr;
        }

        return LinearBlockBuffer::Allocate(mFormat, block);
    }

private:
    FlexBuffersImpl mImpl;
};

class EncryptedLinearInputBuffers : public LinearInputBuffers {
public:
    EncryptedLinearInputBuffers(
            bool secure,
            const sp<MemoryDealer> &dealer,
            const sp<ICrypto> &crypto,
            int32_t heapSeqNum,
            size_t capacity,
            size_t numInputSlots,
            const char *componentName, const char *name = "EncryptedInput")
        : LinearInputBuffers(componentName, name),
          mUsage({0, 0}),
          mDealer(dealer),
          mCrypto(crypto),
          mHeapSeqNum(heapSeqNum) {
        if (secure) {
            mUsage = { C2MemoryUsage::READ_PROTECTED, 0 };
        } else {
            mUsage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        }
        for (size_t i = 0; i < numInputSlots; ++i) {
            sp<IMemory> memory = mDealer->allocate(capacity);
            if (memory == nullptr) {
                ALOGD("[%s] Failed to allocate memory from dealer: only %zu slots allocated", mName, i);
                break;
            }
            mMemoryVector.push_back({std::weak_ptr<C2LinearBlock>(), memory});
        }
    }

    ~EncryptedLinearInputBuffers() override {
    }

    sp<Codec2Buffer> alloc(size_t size) override {
        sp<IMemory> memory;
        size_t slot = 0;
        for (; slot < mMemoryVector.size(); ++slot) {
            if (mMemoryVector[slot].block.expired()) {
                memory = mMemoryVector[slot].memory;
                break;
            }
        }
        if (memory == nullptr) {
            return nullptr;
        }

        std::shared_ptr<C2LinearBlock> block;
        c2_status_t err = mPool->fetchLinearBlock(size, mUsage, &block);
        if (err != C2_OK || block == nullptr) {
            return nullptr;
        }

        mMemoryVector[slot].block = block;
        return new EncryptedLinearBlockBuffer(mFormat, block, memory, mHeapSeqNum);
    }

private:
    C2MemoryUsage mUsage;
    sp<MemoryDealer> mDealer;
    sp<ICrypto> mCrypto;
    int32_t mHeapSeqNum;
    struct Entry {
        std::weak_ptr<C2LinearBlock> block;
        sp<IMemory> memory;
    };
    std::vector<Entry> mMemoryVector;
};

class GraphicMetadataInputBuffers : public CCodecBufferChannel::InputBuffers {
public:
    GraphicMetadataInputBuffers(const char *componentName, const char *name = "2D-MetaInput")
        : InputBuffers(componentName, name),
          mImpl(mName),
          mStore(GetCodec2PlatformAllocatorStore()) { }
    ~GraphicMetadataInputBuffers() override = default;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
        std::shared_ptr<C2Allocator> alloc;
        c2_status_t err = mStore->fetchAllocator(mPool->getAllocatorId(), &alloc);
        if (err != C2_OK) {
            return false;
        }
        sp<GraphicMetadataBuffer> newBuffer = new GraphicMetadataBuffer(mFormat, alloc);
        if (newBuffer == nullptr) {
            return false;
        }
        *index = mImpl.assignSlot(newBuffer);
        *buffer = newBuffer;
        return true;
    }

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override {
        return mImpl.releaseSlot(buffer, c2buffer, release);
    }

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override {
        return mImpl.expireComponentBuffer(c2buffer);
    }

    void flush() override {
        // This is no-op by default unless we're in array mode where we need to keep
        // track of the flushed work.
    }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode(
            size_t size) final {
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

    size_t numClientBuffers() const final {
        return mImpl.numClientBuffers();
    }

private:
    FlexBuffersImpl mImpl;
    std::shared_ptr<C2AllocatorStore> mStore;
};

class GraphicInputBuffers : public CCodecBufferChannel::InputBuffers {
public:
    GraphicInputBuffers(
            size_t numInputSlots, const char *componentName, const char *name = "2D-BB-Input")
        : InputBuffers(componentName, name),
          mImpl(mName),
          mLocalBufferPool(LocalBufferPool::Create(
                  kMaxLinearBufferSize * numInputSlots)) { }
    ~GraphicInputBuffers() override = default;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override {
        // TODO: proper max input size
        // TODO: read usage from intf
        C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
        sp<GraphicBlockBuffer> newBuffer = AllocateGraphicBuffer(
                mPool, mFormat, HAL_PIXEL_FORMAT_YV12, usage, mLocalBufferPool);
        if (newBuffer == nullptr) {
            return false;
        }
        *index = mImpl.assignSlot(newBuffer);
        handleImageData(newBuffer);
        *buffer = newBuffer;
        return true;
    }

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override {
        return mImpl.releaseSlot(buffer, c2buffer, release);
    }

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override {
        return mImpl.expireComponentBuffer(c2buffer);
    }

    void flush() override {
        // This is no-op by default unless we're in array mode where we need to keep
        // track of the flushed work.
    }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode(
            size_t size) final {
        std::unique_ptr<InputBuffersArray> array(
                new InputBuffersArray(mComponentName.c_str(), "2D-BB-Input[N]"));
        array->setPool(mPool);
        array->setFormat(mFormat);
        array->initialize(
                mImpl,
                size,
                [pool = mPool, format = mFormat, lbp = mLocalBufferPool]() -> sp<Codec2Buffer> {
                    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
                    return AllocateGraphicBuffer(
                            pool, format, HAL_PIXEL_FORMAT_YV12, usage, lbp);
                });
        return std::move(array);
    }

    size_t numClientBuffers() const final {
        return mImpl.numClientBuffers();
    }

private:
    FlexBuffersImpl mImpl;
    std::shared_ptr<LocalBufferPool> mLocalBufferPool;
};

class DummyInputBuffers : public CCodecBufferChannel::InputBuffers {
public:
    DummyInputBuffers(const char *componentName, const char *name = "2D-Input")
        : InputBuffers(componentName, name) { }

    bool requestNewBuffer(size_t *, sp<MediaCodecBuffer> *) override {
        return false;
    }

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &, std::shared_ptr<C2Buffer> *, bool) override {
        return false;
    }

    bool expireComponentBuffer(const std::shared_ptr<C2Buffer> &) override {
        return false;
    }
    void flush() override {
    }

    std::unique_ptr<CCodecBufferChannel::InputBuffers> toArrayMode(
            size_t) final {
        return nullptr;
    }

    bool isArrayMode() const final { return true; }

    void getArray(Vector<sp<MediaCodecBuffer>> *array) const final {
        array->clear();
    }

    size_t numClientBuffers() const final {
        return 0u;
    }
};

class OutputBuffersArray : public CCodecBufferChannel::OutputBuffers {
public:
    OutputBuffersArray(const char *componentName, const char *name = "Output[N]")
        : OutputBuffers(componentName, name) { }
    ~OutputBuffersArray() override = default;

    void initialize(
            const FlexBuffersImpl &impl,
            size_t minSize,
            std::function<sp<Codec2Buffer>()> allocate) {
        mImpl.initialize(impl, minSize, allocate);
    }

    bool isArrayMode() const final { return true; }

    std::unique_ptr<CCodecBufferChannel::OutputBuffers> toArrayMode(
            size_t) final {
        return nullptr;
    }

    status_t registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) final {
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
        if (!c2Buffer->copy(buffer)) {
            ALOGD("[%s] copy buffer failed", mName);
            return WOULD_BLOCK;
        }
        submit(c2Buffer);
        handleImageData(c2Buffer);
        *clientBuffer = c2Buffer;
        ALOGV("[%s] grabbed buffer %zu", mName, *index);
        return OK;
    }

    status_t registerCsd(
            const C2StreamInitDataInfo::output *csd,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) final {
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

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer, std::shared_ptr<C2Buffer> *c2buffer) override {
        return mImpl.returnBuffer(buffer, c2buffer, true);
    }

    void flush(const std::list<std::unique_ptr<C2Work>> &flushedWork) override {
        (void)flushedWork;
        mImpl.flush();
        if (mSkipCutBuffer != nullptr) {
            mSkipCutBuffer->clear();
        }
    }

    void getArray(Vector<sp<MediaCodecBuffer>> *array) const final {
        mImpl.getArray(array);
    }

    void realloc(const std::shared_ptr<C2Buffer> &c2buffer) {
        std::function<sp<Codec2Buffer>()> alloc;
        switch (c2buffer->data().type()) {
            case C2BufferData::LINEAR: {
                uint32_t size = kLinearBufferSize;
                const C2ConstLinearBlock &block = c2buffer->data().linearBlocks().front();
                if (block.size() < kMaxLinearBufferSize / 2) {
                    size = block.size() * 2;
                } else {
                    size = kMaxLinearBufferSize;
                }
                alloc = [format = mFormat, size] {
                    return new LocalLinearBuffer(format, new ABuffer(size));
                };
                break;
            }

            // TODO: add support
            case C2BufferData::GRAPHIC:         FALLTHROUGH_INTENDED;

            case C2BufferData::INVALID:         FALLTHROUGH_INTENDED;
            case C2BufferData::LINEAR_CHUNKS:   FALLTHROUGH_INTENDED;
            case C2BufferData::GRAPHIC_CHUNKS:  FALLTHROUGH_INTENDED;
            default:
                ALOGD("Unsupported type: %d", (int)c2buffer->data().type());
                return;
        }
        mImpl.realloc(alloc);
    }

    size_t numClientBuffers() const final {
        return mImpl.numClientBuffers();
    }

private:
    BuffersArrayImpl mImpl;
};

class FlexOutputBuffers : public CCodecBufferChannel::OutputBuffers {
public:
    FlexOutputBuffers(const char *componentName, const char *name = "Output[]")
        : OutputBuffers(componentName, name),
          mImpl(mName) { }

    status_t registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) override {
        sp<Codec2Buffer> newBuffer = wrap(buffer);
        if (newBuffer == nullptr) {
            return NO_MEMORY;
        }
        newBuffer->setFormat(mFormat);
        *index = mImpl.assignSlot(newBuffer);
        handleImageData(newBuffer);
        *clientBuffer = newBuffer;
        ALOGV("[%s] registered buffer %zu", mName, *index);
        return OK;
    }

    status_t registerCsd(
            const C2StreamInitDataInfo::output *csd,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) final {
        sp<Codec2Buffer> newBuffer = new LocalLinearBuffer(
                mFormat, ABuffer::CreateAsCopy(csd->m.value, csd->flexCount()));
        *index = mImpl.assignSlot(newBuffer);
        *clientBuffer = newBuffer;
        return OK;
    }

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer) override {
        return mImpl.releaseSlot(buffer, c2buffer, true);
    }

    void flush(
            const std::list<std::unique_ptr<C2Work>> &flushedWork) override {
        (void) flushedWork;
        // This is no-op by default unless we're in array mode where we need to keep
        // track of the flushed work.
    }

    std::unique_ptr<CCodecBufferChannel::OutputBuffers> toArrayMode(
            size_t size) override {
        std::unique_ptr<OutputBuffersArray> array(new OutputBuffersArray(mComponentName.c_str()));
        array->setFormat(mFormat);
        array->transferSkipCutBuffer(mSkipCutBuffer);
        array->initialize(
                mImpl,
                size,
                [this]() { return allocateArrayBuffer(); });
        return std::move(array);
    }

    size_t numClientBuffers() const final {
        return mImpl.numClientBuffers();
    }

    /**
     * Return an appropriate Codec2Buffer object for the type of buffers.
     *
     * \param buffer  C2Buffer object to wrap.
     *
     * \return  appropriate Codec2Buffer object to wrap |buffer|.
     */
    virtual sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) = 0;

    /**
     * Return an appropriate Codec2Buffer object for the type of buffers, to be
     * used as an empty array buffer.
     *
     * \return  appropriate Codec2Buffer object which can copy() from C2Buffers.
     */
    virtual sp<Codec2Buffer> allocateArrayBuffer() = 0;

private:
    FlexBuffersImpl mImpl;
};

class LinearOutputBuffers : public FlexOutputBuffers {
public:
    LinearOutputBuffers(const char *componentName, const char *name = "1D-Output")
        : FlexOutputBuffers(componentName, name) { }

    void flush(
            const std::list<std::unique_ptr<C2Work>> &flushedWork) override {
        if (mSkipCutBuffer != nullptr) {
            mSkipCutBuffer->clear();
        }
        FlexOutputBuffers::flush(flushedWork);
    }

    sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) override {
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

    sp<Codec2Buffer> allocateArrayBuffer() override {
        // TODO: proper max output size
        return new LocalLinearBuffer(mFormat, new ABuffer(kLinearBufferSize));
    }
};

class GraphicOutputBuffers : public FlexOutputBuffers {
public:
    GraphicOutputBuffers(const char *componentName, const char *name = "2D-Output")
        : FlexOutputBuffers(componentName, name) { }

    sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) override {
        return new DummyContainerBuffer(mFormat, buffer);
    }

    sp<Codec2Buffer> allocateArrayBuffer() override {
        return new DummyContainerBuffer(mFormat);
    }
};

class RawGraphicOutputBuffers : public FlexOutputBuffers {
public:
    RawGraphicOutputBuffers(
            size_t numOutputSlots, const char *componentName, const char *name = "2D-BB-Output")
        : FlexOutputBuffers(componentName, name),
          mLocalBufferPool(LocalBufferPool::Create(
                  kMaxLinearBufferSize * numOutputSlots)) { }
    ~RawGraphicOutputBuffers() override = default;

    sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) override {
        if (buffer == nullptr) {
            sp<Codec2Buffer> c2buffer = ConstGraphicBlockBuffer::AllocateEmpty(
                    mFormat,
                    [lbp = mLocalBufferPool](size_t capacity) {
                        return lbp->newBuffer(capacity);
                    });
            if (c2buffer == nullptr) {
                ALOGD("[%s] ConstGraphicBlockBuffer::AllocateEmpty failed", mName);
                return nullptr;
            }
            c2buffer->setRange(0, 0);
            return c2buffer;
        } else {
            return ConstGraphicBlockBuffer::Allocate(
                    mFormat,
                    buffer,
                    [lbp = mLocalBufferPool](size_t capacity) {
                        return lbp->newBuffer(capacity);
                    });
        }
    }

    sp<Codec2Buffer> allocateArrayBuffer() override {
        return ConstGraphicBlockBuffer::AllocateEmpty(
                mFormat,
                [lbp = mLocalBufferPool](size_t capacity) {
                    return lbp->newBuffer(capacity);
                });
    }

private:
    std::shared_ptr<LocalBufferPool> mLocalBufferPool;
};

}  // namespace

CCodecBufferChannel::QueueGuard::QueueGuard(
        CCodecBufferChannel::QueueSync &sync) : mSync(sync) {
    Mutex::Autolock l(mSync.mGuardLock);
    // At this point it's guaranteed that mSync is not under state transition,
    // as we are holding its mutex.

    Mutexed<CCodecBufferChannel::QueueSync::Counter>::Locked count(mSync.mCount);
    if (count->value == -1) {
        mRunning = false;
    } else {
        ++count->value;
        mRunning = true;
    }
}

CCodecBufferChannel::QueueGuard::~QueueGuard() {
    if (mRunning) {
        // We are not holding mGuardLock at this point so that QueueSync::stop() can
        // keep holding the lock until mCount reaches zero.
        Mutexed<CCodecBufferChannel::QueueSync::Counter>::Locked count(mSync.mCount);
        --count->value;
        count->cond.broadcast();
    }
}

void CCodecBufferChannel::QueueSync::start() {
    Mutex::Autolock l(mGuardLock);
    // If stopped, it goes to running state; otherwise no-op.
    Mutexed<Counter>::Locked count(mCount);
    if (count->value == -1) {
        count->value = 0;
    }
}

void CCodecBufferChannel::QueueSync::stop() {
    Mutex::Autolock l(mGuardLock);
    Mutexed<Counter>::Locked count(mCount);
    if (count->value == -1) {
        // no-op
        return;
    }
    // Holding mGuardLock here blocks creation of additional QueueGuard objects, so
    // mCount can only decrement. In other words, threads that acquired the lock
    // are allowed to finish execution but additional threads trying to acquire
    // the lock at this point will block, and then get QueueGuard at STOPPED
    // state.
    while (count->value != 0) {
        count.waitForCondition(count->cond);
    }
    count->value = -1;
}

// CCodecBufferChannel::ReorderStash

CCodecBufferChannel::ReorderStash::ReorderStash() {
    clear();
}

void CCodecBufferChannel::ReorderStash::clear() {
    mPending.clear();
    mStash.clear();
    mDepth = 0;
    mKey = C2Config::ORDINAL;
}

void CCodecBufferChannel::ReorderStash::flush() {
    mPending.clear();
    mStash.clear();
}

void CCodecBufferChannel::ReorderStash::setDepth(uint32_t depth) {
    mPending.splice(mPending.end(), mStash);
    mDepth = depth;
}

void CCodecBufferChannel::ReorderStash::setKey(C2Config::ordinal_key_t key) {
    mPending.splice(mPending.end(), mStash);
    mKey = key;
}

bool CCodecBufferChannel::ReorderStash::pop(Entry *entry) {
    if (mPending.empty()) {
        return false;
    }
    entry->buffer     = mPending.front().buffer;
    entry->timestamp  = mPending.front().timestamp;
    entry->flags      = mPending.front().flags;
    entry->ordinal    = mPending.front().ordinal;
    mPending.pop_front();
    return true;
}

void CCodecBufferChannel::ReorderStash::emplace(
        const std::shared_ptr<C2Buffer> &buffer,
        int64_t timestamp,
        int32_t flags,
        const C2WorkOrdinalStruct &ordinal) {
    bool eos = flags & MediaCodec::BUFFER_FLAG_EOS;
    if (!buffer && eos) {
        // TRICKY: we may be violating ordering of the stash here. Because we
        // don't expect any more emplace() calls after this, the ordering should
        // not matter.
        mStash.emplace_back(buffer, timestamp, flags, ordinal);
    } else {
        flags = flags & ~MediaCodec::BUFFER_FLAG_EOS;
        auto it = mStash.begin();
        for (; it != mStash.end(); ++it) {
            if (less(ordinal, it->ordinal)) {
                break;
            }
        }
        mStash.emplace(it, buffer, timestamp, flags, ordinal);
        if (eos) {
            mStash.back().flags = mStash.back().flags | MediaCodec::BUFFER_FLAG_EOS;
        }
    }
    while (!mStash.empty() && mStash.size() > mDepth) {
        mPending.push_back(mStash.front());
        mStash.pop_front();
    }
}

void CCodecBufferChannel::ReorderStash::defer(
        const CCodecBufferChannel::ReorderStash::Entry &entry) {
    mPending.push_front(entry);
}

bool CCodecBufferChannel::ReorderStash::hasPending() const {
    return !mPending.empty();
}

bool CCodecBufferChannel::ReorderStash::less(
        const C2WorkOrdinalStruct &o1, const C2WorkOrdinalStruct &o2) {
    switch (mKey) {
        case C2Config::ORDINAL:   return o1.frameIndex < o2.frameIndex;
        case C2Config::TIMESTAMP: return o1.timestamp < o2.timestamp;
        case C2Config::CUSTOM:    return o1.customOrdinal < o2.customOrdinal;
        default:
            ALOGD("Unrecognized key; default to timestamp");
            return o1.frameIndex < o2.frameIndex;
    }
}

// CCodecBufferChannel

CCodecBufferChannel::CCodecBufferChannel(
        const std::shared_ptr<CCodecCallback> &callback)
    : mHeapSeqNum(-1),
      mCCodecCallback(callback),
      mNumInputSlots(kSmoothnessFactor),
      mNumOutputSlots(kSmoothnessFactor),
      mDelay(0),
      mFrameIndex(0u),
      mFirstValidFrameIndex(0u),
      mMetaMode(MODE_NONE),
      mInputMetEos(false) {
    mOutputSurface.lock()->maxDequeueBuffers = kSmoothnessFactor + kRenderingDepth;
    Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
    buffers->reset(new DummyInputBuffers(""));
}

CCodecBufferChannel::~CCodecBufferChannel() {
    if (mCrypto != nullptr && mDealer != nullptr && mHeapSeqNum >= 0) {
        mCrypto->unsetHeap(mHeapSeqNum);
    }
}

void CCodecBufferChannel::setComponent(
        const std::shared_ptr<Codec2Client::Component> &component) {
    mComponent = component;
    mComponentName = component->getName() + StringPrintf("#%d", int(uintptr_t(component.get()) % 997));
    mName = mComponentName.c_str();
}

status_t CCodecBufferChannel::setInputSurface(
        const std::shared_ptr<InputSurfaceWrapper> &surface) {
    ALOGV("[%s] setInputSurface", mName);
    mInputSurface = surface;
    return mInputSurface->connect(mComponent);
}

status_t CCodecBufferChannel::signalEndOfInputStream() {
    if (mInputSurface == nullptr) {
        return INVALID_OPERATION;
    }
    return mInputSurface->signalEndOfInputStream();
}

status_t CCodecBufferChannel::queueInputBufferInternal(const sp<MediaCodecBuffer> &buffer) {
    int64_t timeUs;
    CHECK(buffer->meta()->findInt64("timeUs", &timeUs));

    if (mInputMetEos) {
        ALOGD("[%s] buffers after EOS ignored (%lld us)", mName, (long long)timeUs);
        return OK;
    }

    int32_t flags = 0;
    int32_t tmp = 0;
    bool eos = false;
    if (buffer->meta()->findInt32("eos", &tmp) && tmp) {
        eos = true;
        mInputMetEos = true;
        ALOGV("[%s] input EOS", mName);
    }
    if (buffer->meta()->findInt32("csd", &tmp) && tmp) {
        flags |= C2FrameData::FLAG_CODEC_CONFIG;
    }
    ALOGV("[%s] queueInputBuffer: buffer->size() = %zu", mName, buffer->size());
    std::unique_ptr<C2Work> work(new C2Work);
    work->input.ordinal.timestamp = timeUs;
    work->input.ordinal.frameIndex = mFrameIndex++;
    // WORKAROUND: until codecs support handling work after EOS and max output sizing, use timestamp
    // manipulation to achieve image encoding via video codec, and to constrain encoded output.
    // Keep client timestamp in customOrdinal
    work->input.ordinal.customOrdinal = timeUs;
    work->input.buffers.clear();

    uint64_t queuedFrameIndex = work->input.ordinal.frameIndex.peeku();
    std::vector<std::shared_ptr<C2Buffer>> queuedBuffers;

    if (buffer->size() > 0u) {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        std::shared_ptr<C2Buffer> c2buffer;
        if (!(*buffers)->releaseBuffer(buffer, &c2buffer, false)) {
            return -ENOENT;
        }
        work->input.buffers.push_back(c2buffer);
        queuedBuffers.push_back(c2buffer);
    } else if (eos) {
        flags |= C2FrameData::FLAG_END_OF_STREAM;
    }
    work->input.flags = (C2FrameData::flags_t)flags;
    // TODO: fill info's

    work->input.configUpdate = std::move(mParamsToBeSet);
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);

    std::list<std::unique_ptr<C2Work>> items;
    items.push_back(std::move(work));
    mPipelineWatcher.lock()->onWorkQueued(
            queuedFrameIndex,
            std::move(queuedBuffers),
            PipelineWatcher::Clock::now());
    c2_status_t err = mComponent->queue(&items);
    if (err != C2_OK) {
        mPipelineWatcher.lock()->onWorkDone(queuedFrameIndex);
    }

    if (err == C2_OK && eos && buffer->size() > 0u) {
        work.reset(new C2Work);
        work->input.ordinal.timestamp = timeUs;
        work->input.ordinal.frameIndex = mFrameIndex++;
        // WORKAROUND: keep client timestamp in customOrdinal
        work->input.ordinal.customOrdinal = timeUs;
        work->input.buffers.clear();
        work->input.flags = C2FrameData::FLAG_END_OF_STREAM;
        work->worklets.emplace_back(new C2Worklet);

        queuedFrameIndex = work->input.ordinal.frameIndex.peeku();
        queuedBuffers.clear();

        items.clear();
        items.push_back(std::move(work));

        mPipelineWatcher.lock()->onWorkQueued(
                queuedFrameIndex,
                std::move(queuedBuffers),
                PipelineWatcher::Clock::now());
        err = mComponent->queue(&items);
        if (err != C2_OK) {
            mPipelineWatcher.lock()->onWorkDone(queuedFrameIndex);
        }
    }
    if (err == C2_OK) {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        bool released = (*buffers)->releaseBuffer(buffer, nullptr, true);
        ALOGV("[%s] queueInputBuffer: buffer %sreleased", mName, released ? "" : "not ");
    }

    feedInputBufferIfAvailableInternal();
    return err;
}

status_t CCodecBufferChannel::setParameters(std::vector<std::unique_ptr<C2Param>> &params) {
    QueueGuard guard(mSync);
    if (!guard.isRunning()) {
        ALOGD("[%s] setParameters is only supported in the running state.", mName);
        return -ENOSYS;
    }
    mParamsToBeSet.insert(mParamsToBeSet.end(),
                          std::make_move_iterator(params.begin()),
                          std::make_move_iterator(params.end()));
    params.clear();
    return OK;
}

status_t CCodecBufferChannel::queueInputBuffer(const sp<MediaCodecBuffer> &buffer) {
    QueueGuard guard(mSync);
    if (!guard.isRunning()) {
        ALOGD("[%s] No more buffers should be queued at current state.", mName);
        return -ENOSYS;
    }
    return queueInputBufferInternal(buffer);
}

status_t CCodecBufferChannel::queueSecureInputBuffer(
        const sp<MediaCodecBuffer> &buffer, bool secure, const uint8_t *key,
        const uint8_t *iv, CryptoPlugin::Mode mode, CryptoPlugin::Pattern pattern,
        const CryptoPlugin::SubSample *subSamples, size_t numSubSamples,
        AString *errorDetailMsg) {
    QueueGuard guard(mSync);
    if (!guard.isRunning()) {
        ALOGD("[%s] No more buffers should be queued at current state.", mName);
        return -ENOSYS;
    }

    if (!hasCryptoOrDescrambler()) {
        return -ENOSYS;
    }
    sp<EncryptedLinearBlockBuffer> encryptedBuffer((EncryptedLinearBlockBuffer *)buffer.get());

    ssize_t result = -1;
    ssize_t codecDataOffset = 0;
    if (mCrypto != nullptr) {
        ICrypto::DestinationBuffer destination;
        if (secure) {
            destination.mType = ICrypto::kDestinationTypeNativeHandle;
            destination.mHandle = encryptedBuffer->handle();
        } else {
            destination.mType = ICrypto::kDestinationTypeSharedMemory;
            destination.mSharedMemory = mDecryptDestination;
        }
        ICrypto::SourceBuffer source;
        encryptedBuffer->fillSourceBuffer(&source);
        result = mCrypto->decrypt(
                key, iv, mode, pattern, source, buffer->offset(),
                subSamples, numSubSamples, destination, errorDetailMsg);
        if (result < 0) {
            return result;
        }
        if (destination.mType == ICrypto::kDestinationTypeSharedMemory) {
            encryptedBuffer->copyDecryptedContent(mDecryptDestination, result);
        }
    } else {
        // Here we cast CryptoPlugin::SubSample to hardware::cas::native::V1_0::SubSample
        // directly, the structure definitions should match as checked in DescramblerImpl.cpp.
        hidl_vec<SubSample> hidlSubSamples;
        hidlSubSamples.setToExternal((SubSample *)subSamples, numSubSamples, false /*own*/);

        hardware::cas::native::V1_0::SharedBuffer srcBuffer;
        encryptedBuffer->fillSourceBuffer(&srcBuffer);

        DestinationBuffer dstBuffer;
        if (secure) {
            dstBuffer.type = BufferType::NATIVE_HANDLE;
            dstBuffer.secureMemory = hidl_handle(encryptedBuffer->handle());
        } else {
            dstBuffer.type = BufferType::SHARED_MEMORY;
            dstBuffer.nonsecureMemory = srcBuffer;
        }

        CasStatus status = CasStatus::OK;
        hidl_string detailedError;
        ScramblingControl sctrl = ScramblingControl::UNSCRAMBLED;

        if (key != nullptr) {
            sctrl = (ScramblingControl)key[0];
            // Adjust for the PES offset
            codecDataOffset = key[2] | (key[3] << 8);
        }

        auto returnVoid = mDescrambler->descramble(
                sctrl,
                hidlSubSamples,
                srcBuffer,
                0,
                dstBuffer,
                0,
                [&status, &result, &detailedError] (
                        CasStatus _status, uint32_t _bytesWritten,
                        const hidl_string& _detailedError) {
                    status = _status;
                    result = (ssize_t)_bytesWritten;
                    detailedError = _detailedError;
                });

        if (!returnVoid.isOk() || status != CasStatus::OK || result < 0) {
            ALOGI("[%s] descramble failed, trans=%s, status=%d, result=%zd",
                    mName, returnVoid.description().c_str(), status, result);
            return UNKNOWN_ERROR;
        }

        if (result < codecDataOffset) {
            ALOGD("invalid codec data offset: %zd, result %zd", codecDataOffset, result);
            return BAD_VALUE;
        }

        ALOGV("[%s] descramble succeeded, %zd bytes", mName, result);

        if (dstBuffer.type == BufferType::SHARED_MEMORY) {
            encryptedBuffer->copyDecryptedContentFromMemory(result);
        }
    }

    buffer->setRange(codecDataOffset, result - codecDataOffset);
    return queueInputBufferInternal(buffer);
}

void CCodecBufferChannel::feedInputBufferIfAvailable() {
    QueueGuard guard(mSync);
    if (!guard.isRunning()) {
        ALOGV("[%s] We're not running --- no input buffer reported", mName);
        return;
    }
    feedInputBufferIfAvailableInternal();
}

void CCodecBufferChannel::feedInputBufferIfAvailableInternal() {
    if (mInputMetEos ||
           mReorderStash.lock()->hasPending() ||
           mPipelineWatcher.lock()->pipelineFull()) {
        return;
    } else {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        if ((*buffers)->numClientBuffers() >= mNumOutputSlots) {
            return;
        }
    }
    for (size_t i = 0; i < mNumInputSlots; ++i) {
        sp<MediaCodecBuffer> inBuffer;
        size_t index;
        {
            Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
            if ((*buffers)->numClientBuffers() >= mNumInputSlots) {
                return;
            }
            if (!(*buffers)->requestNewBuffer(&index, &inBuffer)) {
                ALOGV("[%s] no new buffer available", mName);
                break;
            }
        }
        ALOGV("[%s] new input index = %zu [%p]", mName, index, inBuffer.get());
        mCallback->onInputBufferAvailable(index, inBuffer);
    }
}

status_t CCodecBufferChannel::renderOutputBuffer(
        const sp<MediaCodecBuffer> &buffer, int64_t timestampNs) {
    ALOGV("[%s] renderOutputBuffer: %p", mName, buffer.get());
    std::shared_ptr<C2Buffer> c2Buffer;
    bool released = false;
    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        if (*buffers) {
            released = (*buffers)->releaseBuffer(buffer, &c2Buffer);
        }
    }
    // NOTE: some apps try to releaseOutputBuffer() with timestamp and/or render
    //       set to true.
    sendOutputBuffers();
    // input buffer feeding may have been gated by pending output buffers
    feedInputBufferIfAvailable();
    if (!c2Buffer) {
        if (released) {
            std::call_once(mRenderWarningFlag, [this] {
                ALOGW("[%s] The app is calling releaseOutputBuffer() with "
                      "timestamp or render=true with non-video buffers. Apps should "
                      "call releaseOutputBuffer() with render=false for those.",
                      mName);
            });
        }
        return INVALID_OPERATION;
    }

#if 0
    const std::vector<std::shared_ptr<const C2Info>> infoParams = c2Buffer->info();
    ALOGV("[%s] queuing gfx buffer with %zu infos", mName, infoParams.size());
    for (const std::shared_ptr<const C2Info> &info : infoParams) {
        AString res;
        for (size_t ix = 0; ix + 3 < info->size(); ix += 4) {
            if (ix) res.append(", ");
            res.append(*((int32_t*)info.get() + (ix / 4)));
        }
        ALOGV("  [%s]", res.c_str());
    }
#endif
    std::shared_ptr<const C2StreamRotationInfo::output> rotation =
        std::static_pointer_cast<const C2StreamRotationInfo::output>(
                c2Buffer->getInfo(C2StreamRotationInfo::output::PARAM_TYPE));
    bool flip = rotation && (rotation->flip & 1);
    uint32_t quarters = ((rotation ? rotation->value : 0) / 90) & 3;
    uint32_t transform = 0;
    switch (quarters) {
        case 0: // no rotation
            transform = flip ? HAL_TRANSFORM_FLIP_H : 0;
            break;
        case 1: // 90 degrees counter-clockwise
            transform = flip ? (HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_ROT_90)
                    : HAL_TRANSFORM_ROT_270;
            break;
        case 2: // 180 degrees
            transform = flip ? HAL_TRANSFORM_FLIP_V : HAL_TRANSFORM_ROT_180;
            break;
        case 3: // 90 degrees clockwise
            transform = flip ? (HAL_TRANSFORM_FLIP_H | HAL_TRANSFORM_ROT_90)
                    : HAL_TRANSFORM_ROT_90;
            break;
    }

    std::shared_ptr<const C2StreamSurfaceScalingInfo::output> surfaceScaling =
        std::static_pointer_cast<const C2StreamSurfaceScalingInfo::output>(
                c2Buffer->getInfo(C2StreamSurfaceScalingInfo::output::PARAM_TYPE));
    uint32_t videoScalingMode = NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW;
    if (surfaceScaling) {
        videoScalingMode = surfaceScaling->value;
    }

    // Use dataspace from format as it has the default aspects already applied
    android_dataspace_t dataSpace = HAL_DATASPACE_UNKNOWN; // this is 0
    (void)buffer->format()->findInt32("android._dataspace", (int32_t *)&dataSpace);

    // HDR static info
    std::shared_ptr<const C2StreamHdrStaticInfo::output> hdrStaticInfo =
        std::static_pointer_cast<const C2StreamHdrStaticInfo::output>(
                c2Buffer->getInfo(C2StreamHdrStaticInfo::output::PARAM_TYPE));

    // HDR10 plus info
    std::shared_ptr<const C2StreamHdr10PlusInfo::output> hdr10PlusInfo =
        std::static_pointer_cast<const C2StreamHdr10PlusInfo::output>(
                c2Buffer->getInfo(C2StreamHdr10PlusInfo::output::PARAM_TYPE));

    {
        Mutexed<OutputSurface>::Locked output(mOutputSurface);
        if (output->surface == nullptr) {
            ALOGI("[%s] cannot render buffer without surface", mName);
            return OK;
        }
    }

    std::vector<C2ConstGraphicBlock> blocks = c2Buffer->data().graphicBlocks();
    if (blocks.size() != 1u) {
        ALOGD("[%s] expected 1 graphic block, but got %zu", mName, blocks.size());
        return UNKNOWN_ERROR;
    }
    const C2ConstGraphicBlock &block = blocks.front();

    // TODO: revisit this after C2Fence implementation.
    android::IGraphicBufferProducer::QueueBufferInput qbi(
            timestampNs,
            false, // droppable
            dataSpace,
            Rect(blocks.front().crop().left,
                 blocks.front().crop().top,
                 blocks.front().crop().right(),
                 blocks.front().crop().bottom()),
            videoScalingMode,
            transform,
            Fence::NO_FENCE, 0);
    if (hdrStaticInfo || hdr10PlusInfo) {
        HdrMetadata hdr;
        if (hdrStaticInfo) {
            struct android_smpte2086_metadata smpte2086_meta = {
                .displayPrimaryRed = {
                    hdrStaticInfo->mastering.red.x, hdrStaticInfo->mastering.red.y
                },
                .displayPrimaryGreen = {
                    hdrStaticInfo->mastering.green.x, hdrStaticInfo->mastering.green.y
                },
                .displayPrimaryBlue = {
                    hdrStaticInfo->mastering.blue.x, hdrStaticInfo->mastering.blue.y
                },
                .whitePoint = {
                    hdrStaticInfo->mastering.white.x, hdrStaticInfo->mastering.white.y
                },
                .maxLuminance = hdrStaticInfo->mastering.maxLuminance,
                .minLuminance = hdrStaticInfo->mastering.minLuminance,
            };

            struct android_cta861_3_metadata cta861_meta = {
                .maxContentLightLevel = hdrStaticInfo->maxCll,
                .maxFrameAverageLightLevel = hdrStaticInfo->maxFall,
            };

            hdr.validTypes = HdrMetadata::SMPTE2086 | HdrMetadata::CTA861_3;
            hdr.smpte2086 = smpte2086_meta;
            hdr.cta8613 = cta861_meta;
        }
        if (hdr10PlusInfo) {
            hdr.validTypes |= HdrMetadata::HDR10PLUS;
            hdr.hdr10plus.assign(
                    hdr10PlusInfo->m.value,
                    hdr10PlusInfo->m.value + hdr10PlusInfo->flexCount());
        }
        qbi.setHdrMetadata(hdr);
    }
    // we don't have dirty regions
    qbi.setSurfaceDamage(Region::INVALID_REGION);
    android::IGraphicBufferProducer::QueueBufferOutput qbo;
    status_t result = mComponent->queueToOutputSurface(block, qbi, &qbo);
    if (result != OK) {
        ALOGI("[%s] queueBuffer failed: %d", mName, result);
        return result;
    }
    ALOGV("[%s] queue buffer successful", mName);

    int64_t mediaTimeUs = 0;
    (void)buffer->meta()->findInt64("timeUs", &mediaTimeUs);
    mCCodecCallback->onOutputFramesRendered(mediaTimeUs, timestampNs);

    return OK;
}

status_t CCodecBufferChannel::discardBuffer(const sp<MediaCodecBuffer> &buffer) {
    ALOGV("[%s] discardBuffer: %p", mName, buffer.get());
    bool released = false;
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        if (*buffers && (*buffers)->releaseBuffer(buffer, nullptr, true)) {
            released = true;
        }
    }
    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        if (*buffers && (*buffers)->releaseBuffer(buffer, nullptr)) {
            released = true;
        }
    }
    if (released) {
        sendOutputBuffers();
        feedInputBufferIfAvailable();
    } else {
        ALOGD("[%s] MediaCodec discarded an unknown buffer", mName);
    }
    return OK;
}

void CCodecBufferChannel::getInputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    array->clear();
    Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);

    if (!(*buffers)->isArrayMode()) {
        *buffers = (*buffers)->toArrayMode(mNumInputSlots);
    }

    (*buffers)->getArray(array);
}

void CCodecBufferChannel::getOutputBufferArray(Vector<sp<MediaCodecBuffer>> *array) {
    array->clear();
    Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);

    if (!(*buffers)->isArrayMode()) {
        *buffers = (*buffers)->toArrayMode(mNumOutputSlots);
    }

    (*buffers)->getArray(array);
}

status_t CCodecBufferChannel::start(
        const sp<AMessage> &inputFormat, const sp<AMessage> &outputFormat) {
    C2StreamBufferTypeSetting::input iStreamFormat(0u);
    C2StreamBufferTypeSetting::output oStreamFormat(0u);
    C2PortReorderBufferDepthTuning::output reorderDepth;
    C2PortReorderKeySetting::output reorderKey;
    C2PortActualDelayTuning::input inputDelay(0);
    C2PortActualDelayTuning::output outputDelay(0);
    C2ActualPipelineDelayTuning pipelineDelay(0);

    c2_status_t err = mComponent->query(
            {
                &iStreamFormat,
                &oStreamFormat,
                &reorderDepth,
                &reorderKey,
                &inputDelay,
                &pipelineDelay,
                &outputDelay,
            },
            {},
            C2_DONT_BLOCK,
            nullptr);
    if (err == C2_BAD_INDEX) {
        if (!iStreamFormat || !oStreamFormat) {
            return UNKNOWN_ERROR;
        }
    } else if (err != C2_OK) {
        return UNKNOWN_ERROR;
    }

    {
        Mutexed<ReorderStash>::Locked reorder(mReorderStash);
        reorder->clear();
        if (reorderDepth) {
            reorder->setDepth(reorderDepth.value);
        }
        if (reorderKey) {
            reorder->setKey(reorderKey.value);
        }
    }

    uint32_t inputDelayValue = inputDelay ? inputDelay.value : 0;
    uint32_t pipelineDelayValue = pipelineDelay ? pipelineDelay.value : 0;
    uint32_t outputDelayValue = outputDelay ? outputDelay.value : 0;

    mNumInputSlots = inputDelayValue + pipelineDelayValue + kSmoothnessFactor;
    mNumOutputSlots = outputDelayValue + kSmoothnessFactor;
    mDelay = inputDelayValue + pipelineDelayValue + outputDelayValue;

    // TODO: get this from input format
    bool secure = mComponent->getName().find(".secure") != std::string::npos;

    std::shared_ptr<C2AllocatorStore> allocatorStore = GetCodec2PlatformAllocatorStore();
    int poolMask = property_get_int32(
            "debug.stagefright.c2-poolmask",
            1 << C2PlatformAllocatorStore::ION |
            1 << C2PlatformAllocatorStore::BUFFERQUEUE);

    if (inputFormat != nullptr) {
        bool graphic = (iStreamFormat.value == C2BufferData::GRAPHIC);
        std::shared_ptr<C2BlockPool> pool;
        {
            Mutexed<BlockPools>::Locked pools(mBlockPools);

            // set default allocator ID.
            pools->inputAllocatorId = (graphic) ? C2PlatformAllocatorStore::GRALLOC
                                                : C2PlatformAllocatorStore::ION;

            // query C2PortAllocatorsTuning::input from component. If an allocator ID is obtained
            // from component, create the input block pool with given ID. Otherwise, use default IDs.
            std::vector<std::unique_ptr<C2Param>> params;
            err = mComponent->query({ },
                                    { C2PortAllocatorsTuning::input::PARAM_TYPE },
                                    C2_DONT_BLOCK,
                                    &params);
            if ((err != C2_OK && err != C2_BAD_INDEX) || params.size() != 1) {
                ALOGD("[%s] Query input allocators returned %zu params => %s (%u)",
                        mName, params.size(), asString(err), err);
            } else if (err == C2_OK && params.size() == 1) {
                C2PortAllocatorsTuning::input *inputAllocators =
                    C2PortAllocatorsTuning::input::From(params[0].get());
                if (inputAllocators && inputAllocators->flexCount() > 0) {
                    std::shared_ptr<C2Allocator> allocator;
                    // verify allocator IDs and resolve default allocator
                    allocatorStore->fetchAllocator(inputAllocators->m.values[0], &allocator);
                    if (allocator) {
                        pools->inputAllocatorId = allocator->getId();
                    } else {
                        ALOGD("[%s] component requested invalid input allocator ID %u",
                                mName, inputAllocators->m.values[0]);
                    }
                }
            }

            // TODO: use C2Component wrapper to associate this pool with ourselves
            if ((poolMask >> pools->inputAllocatorId) & 1) {
                err = CreateCodec2BlockPool(pools->inputAllocatorId, nullptr, &pool);
                ALOGD("[%s] Created input block pool with allocatorID %u => poolID %llu - %s (%d)",
                        mName, pools->inputAllocatorId,
                        (unsigned long long)(pool ? pool->getLocalId() : 111000111),
                        asString(err), err);
            } else {
                err = C2_NOT_FOUND;
            }
            if (err != C2_OK) {
                C2BlockPool::local_id_t inputPoolId =
                    graphic ? C2BlockPool::BASIC_GRAPHIC : C2BlockPool::BASIC_LINEAR;
                err = GetCodec2BlockPool(inputPoolId, nullptr, &pool);
                ALOGD("[%s] Using basic input block pool with poolID %llu => got %llu - %s (%d)",
                        mName, (unsigned long long)inputPoolId,
                        (unsigned long long)(pool ? pool->getLocalId() : 111000111),
                        asString(err), err);
                if (err != C2_OK) {
                    return NO_MEMORY;
                }
            }
            pools->inputPool = pool;
        }

        bool forceArrayMode = false;
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        if (graphic) {
            if (mInputSurface) {
                buffers->reset(new DummyInputBuffers(mName));
            } else if (mMetaMode == MODE_ANW) {
                buffers->reset(new GraphicMetadataInputBuffers(mName));
            } else {
                buffers->reset(new GraphicInputBuffers(mNumInputSlots, mName));
            }
        } else {
            if (hasCryptoOrDescrambler()) {
                int32_t capacity = kLinearBufferSize;
                (void)inputFormat->findInt32(KEY_MAX_INPUT_SIZE, &capacity);
                if ((size_t)capacity > kMaxLinearBufferSize) {
                    ALOGD("client requested %d, capped to %zu", capacity, kMaxLinearBufferSize);
                    capacity = kMaxLinearBufferSize;
                }
                if (mDealer == nullptr) {
                    mDealer = new MemoryDealer(
                            align(capacity, MemoryDealer::getAllocationAlignment())
                                * (mNumInputSlots + 1),
                            "EncryptedLinearInputBuffers");
                    mDecryptDestination = mDealer->allocate((size_t)capacity);
                }
                if (mCrypto != nullptr && mHeapSeqNum < 0) {
                    mHeapSeqNum = mCrypto->setHeap(mDealer->getMemoryHeap());
                } else {
                    mHeapSeqNum = -1;
                }
                buffers->reset(new EncryptedLinearInputBuffers(
                        secure, mDealer, mCrypto, mHeapSeqNum, (size_t)capacity,
                        mNumInputSlots, mName));
                forceArrayMode = true;
            } else {
                buffers->reset(new LinearInputBuffers(mName));
            }
        }
        (*buffers)->setFormat(inputFormat);

        if (err == C2_OK) {
            (*buffers)->setPool(pool);
        } else {
            // TODO: error
        }

        if (forceArrayMode) {
            *buffers = (*buffers)->toArrayMode(mNumInputSlots);
        }
    }

    if (outputFormat != nullptr) {
        sp<IGraphicBufferProducer> outputSurface;
        uint32_t outputGeneration;
        {
            Mutexed<OutputSurface>::Locked output(mOutputSurface);
            output->maxDequeueBuffers = mNumOutputSlots + reorderDepth.value + kRenderingDepth;
            outputSurface = output->surface ?
                    output->surface->getIGraphicBufferProducer() : nullptr;
            if (outputSurface) {
                output->surface->setMaxDequeuedBufferCount(output->maxDequeueBuffers);
            }
            outputGeneration = output->generation;
        }

        bool graphic = (oStreamFormat.value == C2BufferData::GRAPHIC);
        C2BlockPool::local_id_t outputPoolId_;

        {
            Mutexed<BlockPools>::Locked pools(mBlockPools);

            // set default allocator ID.
            pools->outputAllocatorId = (graphic) ? C2PlatformAllocatorStore::GRALLOC
                                                 : C2PlatformAllocatorStore::ION;

            // query C2PortAllocatorsTuning::output from component, or use default allocator if
            // unsuccessful.
            std::vector<std::unique_ptr<C2Param>> params;
            err = mComponent->query({ },
                                    { C2PortAllocatorsTuning::output::PARAM_TYPE },
                                    C2_DONT_BLOCK,
                                    &params);
            if ((err != C2_OK && err != C2_BAD_INDEX) || params.size() != 1) {
                ALOGD("[%s] Query output allocators returned %zu params => %s (%u)",
                        mName, params.size(), asString(err), err);
            } else if (err == C2_OK && params.size() == 1) {
                C2PortAllocatorsTuning::output *outputAllocators =
                    C2PortAllocatorsTuning::output::From(params[0].get());
                if (outputAllocators && outputAllocators->flexCount() > 0) {
                    std::shared_ptr<C2Allocator> allocator;
                    // verify allocator IDs and resolve default allocator
                    allocatorStore->fetchAllocator(outputAllocators->m.values[0], &allocator);
                    if (allocator) {
                        pools->outputAllocatorId = allocator->getId();
                    } else {
                        ALOGD("[%s] component requested invalid output allocator ID %u",
                                mName, outputAllocators->m.values[0]);
                    }
                }
            }

            // use bufferqueue if outputting to a surface.
            // query C2PortSurfaceAllocatorTuning::output from component, or use default allocator
            // if unsuccessful.
            if (outputSurface) {
                params.clear();
                err = mComponent->query({ },
                                        { C2PortSurfaceAllocatorTuning::output::PARAM_TYPE },
                                        C2_DONT_BLOCK,
                                        &params);
                if ((err != C2_OK && err != C2_BAD_INDEX) || params.size() != 1) {
                    ALOGD("[%s] Query output surface allocator returned %zu params => %s (%u)",
                            mName, params.size(), asString(err), err);
                } else if (err == C2_OK && params.size() == 1) {
                    C2PortSurfaceAllocatorTuning::output *surfaceAllocator =
                        C2PortSurfaceAllocatorTuning::output::From(params[0].get());
                    if (surfaceAllocator) {
                        std::shared_ptr<C2Allocator> allocator;
                        // verify allocator IDs and resolve default allocator
                        allocatorStore->fetchAllocator(surfaceAllocator->value, &allocator);
                        if (allocator) {
                            pools->outputAllocatorId = allocator->getId();
                        } else {
                            ALOGD("[%s] component requested invalid surface output allocator ID %u",
                                    mName, surfaceAllocator->value);
                            err = C2_BAD_VALUE;
                        }
                    }
                }
                if (pools->outputAllocatorId == C2PlatformAllocatorStore::GRALLOC
                        && err != C2_OK
                        && ((poolMask >> C2PlatformAllocatorStore::BUFFERQUEUE) & 1)) {
                    pools->outputAllocatorId = C2PlatformAllocatorStore::BUFFERQUEUE;
                }
            }

            if ((poolMask >> pools->outputAllocatorId) & 1) {
                err = mComponent->createBlockPool(
                        pools->outputAllocatorId, &pools->outputPoolId, &pools->outputPoolIntf);
                ALOGI("[%s] Created output block pool with allocatorID %u => poolID %llu - %s",
                        mName, pools->outputAllocatorId,
                        (unsigned long long)pools->outputPoolId,
                        asString(err));
            } else {
                err = C2_NOT_FOUND;
            }
            if (err != C2_OK) {
                // use basic pool instead
                pools->outputPoolId =
                    graphic ? C2BlockPool::BASIC_GRAPHIC : C2BlockPool::BASIC_LINEAR;
            }

            // Configure output block pool ID as parameter C2PortBlockPoolsTuning::output to
            // component.
            std::unique_ptr<C2PortBlockPoolsTuning::output> poolIdsTuning =
                    C2PortBlockPoolsTuning::output::AllocUnique({ pools->outputPoolId });

            std::vector<std::unique_ptr<C2SettingResult>> failures;
            err = mComponent->config({ poolIdsTuning.get() }, C2_MAY_BLOCK, &failures);
            ALOGD("[%s] Configured output block pool ids %llu => %s",
                    mName, (unsigned long long)poolIdsTuning->m.values[0], asString(err));
            outputPoolId_ = pools->outputPoolId;
        }

        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);

        if (graphic) {
            if (outputSurface) {
                buffers->reset(new GraphicOutputBuffers(mName));
            } else {
                buffers->reset(new RawGraphicOutputBuffers(mNumOutputSlots, mName));
            }
        } else {
            buffers->reset(new LinearOutputBuffers(mName));
        }
        (*buffers)->setFormat(outputFormat->dup());


        // Try to set output surface to created block pool if given.
        if (outputSurface) {
            mComponent->setOutputSurface(
                    outputPoolId_,
                    outputSurface,
                    outputGeneration);
        }

        if (oStreamFormat.value == C2BufferData::LINEAR
                && mComponentName.find("c2.qti.") == std::string::npos) {
            // WORKAROUND: if we're using early CSD workaround we convert to
            //             array mode, to appease apps assuming the output
            //             buffers to be of the same size.
            (*buffers) = (*buffers)->toArrayMode(mNumOutputSlots);

            int32_t channelCount;
            int32_t sampleRate;
            if (outputFormat->findInt32(KEY_CHANNEL_COUNT, &channelCount)
                    && outputFormat->findInt32(KEY_SAMPLE_RATE, &sampleRate)) {
                int32_t delay = 0;
                int32_t padding = 0;;
                if (!outputFormat->findInt32("encoder-delay", &delay)) {
                    delay = 0;
                }
                if (!outputFormat->findInt32("encoder-padding", &padding)) {
                    padding = 0;
                }
                if (delay || padding) {
                    // We need write access to the buffers, and we're already in
                    // array mode.
                    (*buffers)->initSkipCutBuffer(delay, padding, sampleRate, channelCount);
                }
            }
        }
    }

    // Set up pipeline control. This has to be done after mInputBuffers and
    // mOutputBuffers are initialized to make sure that lingering callbacks
    // about buffers from the previous generation do not interfere with the
    // newly initialized pipeline capacity.

    {
        Mutexed<PipelineWatcher>::Locked watcher(mPipelineWatcher);
        watcher->inputDelay(inputDelayValue)
                .pipelineDelay(pipelineDelayValue)
                .outputDelay(outputDelayValue)
                .smoothnessFactor(kSmoothnessFactor);
        watcher->flush();
    }

    mInputMetEos = false;
    mSync.start();
    return OK;
}

status_t CCodecBufferChannel::requestInitialInputBuffers() {
    if (mInputSurface) {
        return OK;
    }

    C2StreamBufferTypeSetting::output oStreamFormat(0u);
    c2_status_t err = mComponent->query({ &oStreamFormat }, {}, C2_DONT_BLOCK, nullptr);
    if (err != C2_OK) {
        return UNKNOWN_ERROR;
    }
    std::vector<sp<MediaCodecBuffer>> toBeQueued;
    // TODO: use proper buffer depth instead of this random value
    for (size_t i = 0; i < mNumInputSlots; ++i) {
        size_t index;
        sp<MediaCodecBuffer> buffer;
        {
            Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
            if (!(*buffers)->requestNewBuffer(&index, &buffer)) {
                if (i == 0) {
                    ALOGW("[%s] start: cannot allocate memory at all", mName);
                    return NO_MEMORY;
                } else {
                    ALOGV("[%s] start: cannot allocate memory, only %zu buffers allocated",
                            mName, i);
                }
                break;
            }
        }
        if (buffer) {
            Mutexed<std::list<sp<ABuffer>>>::Locked configs(mFlushedConfigs);
            ALOGV("[%s] input buffer %zu available", mName, index);
            bool post = true;
            if (!configs->empty()) {
                sp<ABuffer> config = configs->front();
                configs->pop_front();
                if (buffer->capacity() >= config->size()) {
                    memcpy(buffer->base(), config->data(), config->size());
                    buffer->setRange(0, config->size());
                    buffer->meta()->clear();
                    buffer->meta()->setInt64("timeUs", 0);
                    buffer->meta()->setInt32("csd", 1);
                    post = false;
                } else {
                    ALOGD("[%s] buffer capacity too small for the config (%zu < %zu)",
                            mName, buffer->capacity(), config->size());
                }
            } else if (oStreamFormat.value == C2BufferData::LINEAR && i == 0
                    && mComponentName.find("c2.qti.") == std::string::npos) {
                // WORKAROUND: Some apps expect CSD available without queueing
                //             any input. Queue an empty buffer to get the CSD.
                buffer->setRange(0, 0);
                buffer->meta()->clear();
                buffer->meta()->setInt64("timeUs", 0);
                post = false;
            }
            if (post) {
                mCallback->onInputBufferAvailable(index, buffer);
            } else {
                toBeQueued.emplace_back(buffer);
            }
        }
    }
    for (const sp<MediaCodecBuffer> &buffer : toBeQueued) {
        if (queueInputBufferInternal(buffer) != OK) {
            ALOGV("[%s] Error while queueing initial buffers", mName);
        }
    }
    return OK;
}

void CCodecBufferChannel::stop() {
    mSync.stop();
    mFirstValidFrameIndex = mFrameIndex.load(std::memory_order_relaxed);
    if (mInputSurface != nullptr) {
        mInputSurface.reset();
    }
}

void CCodecBufferChannel::flush(const std::list<std::unique_ptr<C2Work>> &flushedWork) {
    ALOGV("[%s] flush", mName);
    {
        Mutexed<std::list<sp<ABuffer>>>::Locked configs(mFlushedConfigs);
        for (const std::unique_ptr<C2Work> &work : flushedWork) {
            if (!(work->input.flags & C2FrameData::FLAG_CODEC_CONFIG)) {
                continue;
            }
            if (work->input.buffers.empty()
                    || work->input.buffers.front()->data().linearBlocks().empty()) {
                ALOGD("[%s] no linear codec config data found", mName);
                continue;
            }
            C2ReadView view =
                    work->input.buffers.front()->data().linearBlocks().front().map().get();
            if (view.error() != C2_OK) {
                ALOGD("[%s] failed to map flushed codec config data: %d", mName, view.error());
                continue;
            }
            configs->push_back(ABuffer::CreateAsCopy(view.data(), view.capacity()));
            ALOGV("[%s] stashed flushed codec config data (size=%u)", mName, view.capacity());
        }
    }
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        (*buffers)->flush();
    }
    {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        (*buffers)->flush(flushedWork);
    }
    mReorderStash.lock()->flush();
    mPipelineWatcher.lock()->flush();
}

void CCodecBufferChannel::onWorkDone(
        std::unique_ptr<C2Work> work, const sp<AMessage> &outputFormat,
        const C2StreamInitDataInfo::output *initData) {
    if (handleWork(std::move(work), outputFormat, initData)) {
        feedInputBufferIfAvailable();
    }
}

void CCodecBufferChannel::onInputBufferDone(
        uint64_t frameIndex, size_t arrayIndex) {
    std::shared_ptr<C2Buffer> buffer =
            mPipelineWatcher.lock()->onInputBufferReleased(frameIndex, arrayIndex);
    bool newInputSlotAvailable;
    {
        Mutexed<std::unique_ptr<InputBuffers>>::Locked buffers(mInputBuffers);
        newInputSlotAvailable = (*buffers)->expireComponentBuffer(buffer);
    }
    if (newInputSlotAvailable) {
        feedInputBufferIfAvailable();
    }
}

bool CCodecBufferChannel::handleWork(
        std::unique_ptr<C2Work> work,
        const sp<AMessage> &outputFormat,
        const C2StreamInitDataInfo::output *initData) {
    if ((work->input.ordinal.frameIndex - mFirstValidFrameIndex.load()).peek() < 0) {
        // Discard frames from previous generation.
        ALOGD("[%s] Discard frames from previous generation.", mName);
        return false;
    }

    if (mInputSurface == nullptr && (work->worklets.size() != 1u
            || !work->worklets.front()
            || !(work->worklets.front()->output.flags & C2FrameData::FLAG_INCOMPLETE))) {
        mPipelineWatcher.lock()->onWorkDone(work->input.ordinal.frameIndex.peeku());
    }

    if (work->result == C2_NOT_FOUND) {
        ALOGD("[%s] flushed work; ignored.", mName);
        return true;
    }

    if (work->result != C2_OK) {
        ALOGD("[%s] work failed to complete: %d", mName, work->result);
        mCCodecCallback->onError(work->result, ACTION_CODE_FATAL);
        return false;
    }

    // NOTE: MediaCodec usage supposedly have only one worklet
    if (work->worklets.size() != 1u) {
        ALOGI("[%s] onWorkDone: incorrect number of worklets: %zu",
                mName, work->worklets.size());
        mCCodecCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
        return false;
    }

    const std::unique_ptr<C2Worklet> &worklet = work->worklets.front();

    std::shared_ptr<C2Buffer> buffer;
    // NOTE: MediaCodec usage supposedly have only one output stream.
    if (worklet->output.buffers.size() > 1u) {
        ALOGI("[%s] onWorkDone: incorrect number of output buffers: %zu",
                mName, worklet->output.buffers.size());
        mCCodecCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
        return false;
    } else if (worklet->output.buffers.size() == 1u) {
        buffer = worklet->output.buffers[0];
        if (!buffer) {
            ALOGD("[%s] onWorkDone: nullptr found in buffers; ignored.", mName);
        }
    }

    while (!worklet->output.configUpdate.empty()) {
        std::unique_ptr<C2Param> param;
        worklet->output.configUpdate.back().swap(param);
        worklet->output.configUpdate.pop_back();
        switch (param->coreIndex().coreIndex()) {
            case C2PortReorderBufferDepthTuning::CORE_INDEX: {
                C2PortReorderBufferDepthTuning::output reorderDepth;
                if (reorderDepth.updateFrom(*param)) {
                    mReorderStash.lock()->setDepth(reorderDepth.value);
                    ALOGV("[%s] onWorkDone: updated reorder depth to %u",
                          mName, reorderDepth.value);
                    Mutexed<OutputSurface>::Locked output(mOutputSurface);
                    output->maxDequeueBuffers = mNumOutputSlots + reorderDepth.value + kRenderingDepth;
                    if (output->surface) {
                        output->surface->setMaxDequeuedBufferCount(output->maxDequeueBuffers);
                    }
                } else {
                    ALOGD("[%s] onWorkDone: failed to read reorder depth", mName);
                }
                break;
            }
            case C2PortReorderKeySetting::CORE_INDEX: {
                C2PortReorderKeySetting::output reorderKey;
                if (reorderKey.updateFrom(*param)) {
                    mReorderStash.lock()->setKey(reorderKey.value);
                    ALOGV("[%s] onWorkDone: updated reorder key to %u",
                          mName, reorderKey.value);
                } else {
                    ALOGD("[%s] onWorkDone: failed to read reorder key", mName);
                }
                break;
            }
            default:
                ALOGV("[%s] onWorkDone: unrecognized config update (%08X)",
                      mName, param->index());
                break;
        }
    }

    if (outputFormat != nullptr) {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        ALOGD("[%s] onWorkDone: output format changed to %s",
                mName, outputFormat->debugString().c_str());
        (*buffers)->setFormat(outputFormat);

        AString mediaType;
        if (outputFormat->findString(KEY_MIME, &mediaType)
                && mediaType == MIMETYPE_AUDIO_RAW) {
            int32_t channelCount;
            int32_t sampleRate;
            if (outputFormat->findInt32(KEY_CHANNEL_COUNT, &channelCount)
                    && outputFormat->findInt32(KEY_SAMPLE_RATE, &sampleRate)) {
                (*buffers)->updateSkipCutBuffer(sampleRate, channelCount);
            }
        }
    }

    int32_t flags = 0;
    if (worklet->output.flags & C2FrameData::FLAG_END_OF_STREAM) {
        flags |= MediaCodec::BUFFER_FLAG_EOS;
        ALOGV("[%s] onWorkDone: output EOS", mName);
    }

    sp<MediaCodecBuffer> outBuffer;
    size_t index;

    // WORKAROUND: adjust output timestamp based on client input timestamp and codec
    // input timestamp. Codec output timestamp (in the timestamp field) shall correspond to
    // the codec input timestamp, but client output timestamp should (reported in timeUs)
    // shall correspond to the client input timesamp (in customOrdinal). By using the
    // delta between the two, this allows for some timestamp deviation - e.g. if one input
    // produces multiple output.
    c2_cntr64_t timestamp =
        worklet->output.ordinal.timestamp + work->input.ordinal.customOrdinal
                - work->input.ordinal.timestamp;
    if (mInputSurface != nullptr) {
        // When using input surface we need to restore the original input timestamp.
        timestamp = work->input.ordinal.customOrdinal;
    }
    ALOGV("[%s] onWorkDone: input %lld, codec %lld => output %lld => %lld",
          mName,
          work->input.ordinal.customOrdinal.peekll(),
          work->input.ordinal.timestamp.peekll(),
          worklet->output.ordinal.timestamp.peekll(),
          timestamp.peekll());

    if (initData != nullptr) {
        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        if ((*buffers)->registerCsd(initData, &index, &outBuffer) == OK) {
            outBuffer->meta()->setInt64("timeUs", timestamp.peek());
            outBuffer->meta()->setInt32("flags", MediaCodec::BUFFER_FLAG_CODECCONFIG);
            ALOGV("[%s] onWorkDone: csd index = %zu [%p]", mName, index, outBuffer.get());

            buffers.unlock();
            mCallback->onOutputBufferAvailable(index, outBuffer);
            buffers.lock();
        } else {
            ALOGD("[%s] onWorkDone: unable to register csd", mName);
            buffers.unlock();
            mCCodecCallback->onError(UNKNOWN_ERROR, ACTION_CODE_FATAL);
            buffers.lock();
            return false;
        }
    }

    if (!buffer && !flags) {
        ALOGV("[%s] onWorkDone: Not reporting output buffer (%lld)",
              mName, work->input.ordinal.frameIndex.peekull());
        return true;
    }

    if (buffer) {
        for (const std::shared_ptr<const C2Info> &info : buffer->info()) {
            // TODO: properly translate these to metadata
            switch (info->coreIndex().coreIndex()) {
                case C2StreamPictureTypeMaskInfo::CORE_INDEX:
                    if (((C2StreamPictureTypeMaskInfo *)info.get())->value & C2Config::SYNC_FRAME) {
                        flags |= MediaCodec::BUFFER_FLAG_SYNCFRAME;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    {
        Mutexed<ReorderStash>::Locked reorder(mReorderStash);
        reorder->emplace(buffer, timestamp.peek(), flags, worklet->output.ordinal);
        if (flags & MediaCodec::BUFFER_FLAG_EOS) {
            // Flush reorder stash
            reorder->setDepth(0);
        }
    }
    sendOutputBuffers();
    return true;
}

void CCodecBufferChannel::sendOutputBuffers() {
    ReorderStash::Entry entry;
    sp<MediaCodecBuffer> outBuffer;
    size_t index;

    while (true) {
        Mutexed<ReorderStash>::Locked reorder(mReorderStash);
        if (!reorder->hasPending()) {
            break;
        }
        if (!reorder->pop(&entry)) {
            break;
        }

        Mutexed<std::unique_ptr<OutputBuffers>>::Locked buffers(mOutputBuffers);
        status_t err = (*buffers)->registerBuffer(entry.buffer, &index, &outBuffer);
        if (err != OK) {
            bool outputBuffersChanged = false;
            if (err != WOULD_BLOCK) {
                if (!(*buffers)->isArrayMode()) {
                    *buffers = (*buffers)->toArrayMode(mNumOutputSlots);
                }
                OutputBuffersArray *array = (OutputBuffersArray *)buffers->get();
                array->realloc(entry.buffer);
                outputBuffersChanged = true;
            }
            ALOGV("[%s] sendOutputBuffers: unable to register output buffer", mName);
            reorder->defer(entry);

            buffers.unlock();
            reorder.unlock();

            if (outputBuffersChanged) {
                mCCodecCallback->onOutputBuffersChanged();
            }
            return;
        }
        buffers.unlock();
        reorder.unlock();

        outBuffer->meta()->setInt64("timeUs", entry.timestamp);
        outBuffer->meta()->setInt32("flags", entry.flags);
        ALOGV("[%s] sendOutputBuffers: out buffer index = %zu [%p] => %p + %zu (%lld)",
                mName, index, outBuffer.get(), outBuffer->data(), outBuffer->size(),
                (long long)entry.timestamp);
        mCallback->onOutputBufferAvailable(index, outBuffer);
    }
}

status_t CCodecBufferChannel::setSurface(const sp<Surface> &newSurface) {
    static std::atomic_uint32_t surfaceGeneration{0};
    uint32_t generation = (getpid() << 10) |
            ((surfaceGeneration.fetch_add(1, std::memory_order_relaxed) + 1)
                & ((1 << 10) - 1));

    sp<IGraphicBufferProducer> producer;
    if (newSurface) {
        newSurface->setScalingMode(NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW);
        producer = newSurface->getIGraphicBufferProducer();
        producer->setGenerationNumber(generation);
    } else {
        ALOGE("[%s] setting output surface to null", mName);
        return INVALID_OPERATION;
    }

    std::shared_ptr<Codec2Client::Configurable> outputPoolIntf;
    C2BlockPool::local_id_t outputPoolId;
    {
        Mutexed<BlockPools>::Locked pools(mBlockPools);
        outputPoolId = pools->outputPoolId;
        outputPoolIntf = pools->outputPoolIntf;
    }

    if (outputPoolIntf) {
        if (mComponent->setOutputSurface(
                outputPoolId,
                producer,
                generation) != C2_OK) {
            ALOGI("[%s] setSurface: component setOutputSurface failed", mName);
            return INVALID_OPERATION;
        }
    }

    {
        Mutexed<OutputSurface>::Locked output(mOutputSurface);
        newSurface->setMaxDequeuedBufferCount(output->maxDequeueBuffers);
        output->surface = newSurface;
        output->generation = generation;
    }

    return OK;
}

PipelineWatcher::Clock::duration CCodecBufferChannel::elapsed() {
    // When client pushed EOS, we want all the work to be done quickly.
    // Otherwise, component may have stalled work due to input starvation up to
    // the sum of the delay in the pipeline.
    size_t n = mInputMetEos ? 0 : mDelay;
    return mPipelineWatcher.lock()->elapsed(PipelineWatcher::Clock::now(), n);
}

void CCodecBufferChannel::setMetaMode(MetaMode mode) {
    mMetaMode = mode;
}

status_t toStatusT(c2_status_t c2s, c2_operation_t c2op) {
    // C2_OK is always translated to OK.
    if (c2s == C2_OK) {
        return OK;
    }

    // Operation-dependent translation
    // TODO: Add as necessary
    switch (c2op) {
    case C2_OPERATION_Component_start:
        switch (c2s) {
        case C2_NO_MEMORY:
            return NO_MEMORY;
        default:
            return UNKNOWN_ERROR;
        }
    default:
        break;
    }

    // Backup operation-agnostic translation
    switch (c2s) {
    case C2_BAD_INDEX:
        return BAD_INDEX;
    case C2_BAD_VALUE:
        return BAD_VALUE;
    case C2_BLOCKING:
        return WOULD_BLOCK;
    case C2_DUPLICATE:
        return ALREADY_EXISTS;
    case C2_NO_INIT:
        return NO_INIT;
    case C2_NO_MEMORY:
        return NO_MEMORY;
    case C2_NOT_FOUND:
        return NAME_NOT_FOUND;
    case C2_TIMED_OUT:
        return TIMED_OUT;
    case C2_BAD_STATE:
    case C2_CANCELED:
    case C2_CANNOT_DO:
    case C2_CORRUPTED:
    case C2_OMITTED:
    case C2_REFUSED:
        return UNKNOWN_ERROR;
    default:
        return -static_cast<status_t>(c2s);
    }
}

}  // namespace android
