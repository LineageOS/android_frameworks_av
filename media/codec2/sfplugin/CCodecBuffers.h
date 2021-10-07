/*
 * Copyright 2019, The Android Open Source Project
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

#ifndef CCODEC_BUFFERS_H_

#define CCODEC_BUFFERS_H_

#include <optional>
#include <string>

#include <C2Config.h>
#include <DataConverter.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/MediaCodecBuffer.h>

#include "Codec2Buffer.h"

namespace android {

struct ICrypto;
class MemoryDealer;
class SkipCutBuffer;

constexpr size_t kLinearBufferSize = 1048576;
// This can fit an 8K frame.
constexpr size_t kMaxLinearBufferSize = 7680 * 4320 * 2;

/**
 * Base class for representation of buffers at one port.
 */
class CCodecBuffers {
public:
    CCodecBuffers(const char *componentName, const char *name = "Buffers")
        : mComponentName(componentName),
          mChannelName(std::string(componentName) + ":" + name),
          mName(mChannelName.c_str()) {
    }
    virtual ~CCodecBuffers() = default;

    /**
     * Set format for MediaCodec-facing buffers.
     */
    void setFormat(const sp<AMessage> &format);

    /**
     * Return a copy of current format.
     */
    sp<AMessage> dupFormat();

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
    virtual size_t numActiveSlots() const = 0;

    /**
     * Examine image data from the buffer and update the format if necessary.
     */
    void handleImageData(const sp<Codec2Buffer> &buffer);

protected:
    std::string mComponentName; ///< name of component for debugging
    std::string mChannelName; ///< name of channel for debugging
    const char *mName; ///< C-string version of channel name
    // Format to be used for creating MediaCodec-facing buffers.
    sp<AMessage> mFormat;

    sp<ABuffer> mLastImageData;
    sp<AMessage> mFormatWithImageData;

private:
    DISALLOW_EVIL_CONSTRUCTORS(CCodecBuffers);
};

class InputBuffers : public CCodecBuffers {
public:
    InputBuffers(const char *componentName, const char *name = "Input[]")
        : CCodecBuffers(componentName, name) { }
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

    /**
     * Release the buffer obtained from requestNewBuffer(), and create a deep
     * copy clone of the buffer.
     *
     * \return  the deep copy clone of the buffer; nullptr if cloning is not
     *          possible.
     */
    sp<Codec2Buffer> cloneAndReleaseBuffer(const sp<MediaCodecBuffer> &buffer);

protected:
    virtual sp<Codec2Buffer> createNewBuffer() = 0;

    // Pool to obtain blocks for input buffers.
    std::shared_ptr<C2BlockPool> mPool;

private:
    DISALLOW_EVIL_CONSTRUCTORS(InputBuffers);
};

class OutputBuffersArray;

class OutputBuffers : public CCodecBuffers {
public:
    OutputBuffers(const char *componentName, const char *name = "Output");
    virtual ~OutputBuffers();

    /**
     * Register output C2Buffer from the component and obtain corresponding
     * index and MediaCodecBuffer object.
     *
     * Returns:
     *   OK if registration succeeds.
     *   NO_MEMORY if all buffers are available but not compatible.
     *   WOULD_BLOCK if there are compatible buffers, but they are all in use.
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
    virtual std::unique_ptr<OutputBuffersArray> toArrayMode(size_t size) = 0;

    /**
     * Initialize SkipCutBuffer object.
     */
    void initSkipCutBuffer(
            int32_t delay, int32_t padding, int32_t sampleRate, int32_t channelCount);

    /**
     * Update SkipCutBuffer from format. The @p format must not be null.
     */
    void updateSkipCutBuffer(const sp<AMessage> &format);

    /**
     * Output Stash
     * ============
     *
     * The output stash is a place to hold output buffers temporarily before
     * they are registered to output slots. It has 2 main functions:
     * 1. Allow reordering of output frames as the codec may produce frames in a
     *    different order.
     * 2. Act as a "buffer" between the codec and the client because the codec
     *    may produce more buffers than available slots. This excess of codec's
     *    output buffers should be registered to slots later, after the client
     *    has released some slots.
     *
     * The stash consists of 2 lists of buffers: mPending and mReorderStash.
     * mPending is a normal FIFO queue with not size limit, while mReorderStash
     * is a sorted list with size limit mDepth.
     *
     * The normal flow of a non-csd output buffer is as follows:
     *
     *           |----------------OutputBuffers---------------|
     *           |----------Output stash----------|           |
     *   Codec --|-> mReorderStash --> mPending --|-> slots --|-> client
     *           |                                |           |
     *     pushToStash()                    popFromStashAndRegister()
     *
     * The buffer that comes from the codec first enters mReorderStash. The
     * first buffer in mReorderStash gets moved to mPending when mReorderStash
     * overflows. Buffers in mPending are registered to slots and given to the
     * client as soon as slots are available.
     *
     * Every output buffer that is not a csd buffer should be put on the stash
     * by calling pushToStash(), then later registered to a slot by calling
     * popFromStashAndRegister() before notifying the client with
     * onOutputBufferAvailable().
     *
     * Reordering
     * ==========
     *
     * mReorderStash is a sorted list with a specified size limit. The size
     * limit can be set by calling setReorderDepth().
     *
     * Every buffer in mReorderStash has a C2WorkOrdinalStruct, which contains 3
     * members, all of which are comparable. Which member of C2WorkOrdinalStruct
     * should be used for reordering can be chosen by calling setReorderKey().
     */

    /**
     * Return the reorder depth---the size of mReorderStash.
     */
    uint32_t getReorderDepth() const;

    /**
     * Set the reorder depth.
     */
    void setReorderDepth(uint32_t depth);

    /**
     * Set the type of "key" to use in comparisons.
     */
    void setReorderKey(C2Config::ordinal_key_t key);

    /**
     * Return whether the output stash has any pending buffers.
     */
    bool hasPending() const;

    /**
     * Flush the stash and reset the depth and the key to their default values.
     */
    void clearStash();

    /**
     * Flush the stash.
     */
    void flushStash();

    /**
     * Push a buffer to the reorder stash.
     *
     * @param buffer    C2Buffer object from the returned work.
     * @param notify    Whether the returned work contains a buffer that should
     *                  be reported to the client. This may be false if the
     *                  caller wants to process the buffer without notifying the
     *                  client.
     * @param timestamp Buffer timestamp to report to the client.
     * @param flags     Buffer flags to report to the client.
     * @param format    Buffer format to report to the client.
     * @param ordinal   Ordinal used in reordering. This determines when the
     *                  buffer will be popped from the output stash by
     *                  `popFromStashAndRegister()`.
     */
    void pushToStash(
            const std::shared_ptr<C2Buffer>& buffer,
            bool notify,
            int64_t timestamp,
            int32_t flags,
            const sp<AMessage>& format,
            const C2WorkOrdinalStruct& ordinal);

    enum BufferAction : int {
        SKIP,
        DISCARD,
        NOTIFY_CLIENT,
        REALLOCATE,
        RETRY,
    };

    /**
     * Try to atomically pop the first buffer from the reorder stash and
     * register it to an output slot. The function returns a value that
     * indicates a recommended course of action for the caller.
     *
     * If the stash is empty, the function will return `SKIP`.
     *
     * If the stash is not empty, the function will peek at the first (oldest)
     * entry in mPending process the buffer in the entry as follows:
     * - If the buffer should not be sent to the client, the function will
     *   return `DISCARD`. The stash entry will be removed.
     * - If the buffer should be sent to the client, the function will attempt
     *   to register the buffer to a slot. The registration may have 3 outcomes
     *   corresponding to the following return values:
     *   - `NOTIFY_CLIENT`: The buffer is successfully registered to a slot. The
     *     output arguments @p index and @p outBuffer will contain valid values
     *     that the caller can use to call onOutputBufferAvailable(). The stash
     *     entry will be removed.
     *   - `REALLOCATE`: The buffer is not registered because it is not
     *     compatible with the current slots (which are available). The caller
     *     should reallocate the OutputBuffers with slots that can fit the
     *     returned @p c2Buffer. The stash entry will not be removed
     *   - `RETRY`: All slots are currently occupied by the client. The caller
     *     should try to call this function again after the client has released
     *     some slots.
     *
     * @return What the caller should do afterwards.
     *
     * @param[out] c2Buffer   Underlying C2Buffer associated to the first buffer
     *                        on the stash. This value is guaranteed to be valid
     *                        unless the return value is `SKIP`.
     * @param[out] index      Slot index. This value is valid only if the return
     *                        value is `NOTIFY_CLIENT`.
     * @param[out] outBuffer  Registered buffer. This value is valid only if the
     *                        return valu is `NOTIFY_CLIENT`.
     */
    BufferAction popFromStashAndRegister(
            std::shared_ptr<C2Buffer>* c2Buffer,
            size_t* index,
            sp<MediaCodecBuffer>* outBuffer);

protected:
    sp<SkipCutBuffer> mSkipCutBuffer;

    /**
     * Update the SkipCutBuffer object. No-op if it's never initialized.
     */
    void updateSkipCutBuffer(int32_t sampleRate, int32_t channelCount);

    /**
     * Submit buffer to SkipCutBuffer object, if initialized.
     */
    void submit(const sp<MediaCodecBuffer> &buffer);

    /**
     * Apply DataConverter from |src| to |*dst| if needed. If |dst| is nullptr,
     * a new buffer is allocated.
     *
     * Returns true if conversion was needed and executed; false otherwise.
     */
    bool convert(const std::shared_ptr<C2Buffer> &src, sp<Codec2Buffer> *dst);

private:
    // SkipCutBuffer
    int32_t mDelay;
    int32_t mPadding;
    int32_t mSampleRate;
    int32_t mChannelCount;

    void setSkipCutBuffer(int32_t skip, int32_t cut);

    // DataConverter
    sp<DataConverter> mDataConverter;
    sp<AMessage> mFormatWithConverter;
    std::optional<int32_t> mSrcEncoding;
    std::optional<int32_t> mDstEncoding;

    // Output stash

    // Struct for an entry in the output stash (mPending and mReorderStash)
    struct StashEntry {
        inline StashEntry()
            : buffer(nullptr),
              notify(false),
              timestamp(0),
              flags(0),
              format(),
              ordinal({0, 0, 0}) {}
        inline StashEntry(
                const std::shared_ptr<C2Buffer> &b,
                bool n,
                int64_t t,
                int32_t f,
                const sp<AMessage> &fmt,
                const C2WorkOrdinalStruct &o)
            : buffer(b),
              notify(n),
              timestamp(t),
              flags(f),
              format(fmt),
              ordinal(o) {}
        std::shared_ptr<C2Buffer> buffer;
        bool notify;
        int64_t timestamp;
        int32_t flags;
        sp<AMessage> format;
        C2WorkOrdinalStruct ordinal;
    };

    /**
     * FIFO queue of stash entries.
     */
    std::list<StashEntry> mPending;
    /**
     * Sorted list of stash entries.
     */
    std::list<StashEntry> mReorderStash;
    /**
     * Size limit of mReorderStash.
     */
    uint32_t mDepth{0};
    /**
     * Choice of key to use in ordering of stash entries in mReorderStash.
     */
    C2Config::ordinal_key_t mKey{C2Config::ORDINAL};

    /**
     * Return false if mPending is empty; otherwise, pop the first entry from
     * mPending and return true.
     */
    bool popPending(StashEntry *entry);

    /**
     * Push an entry as the first entry of mPending.
     */
    void deferPending(const StashEntry &entry);

    /**
     * Comparison of C2WorkOrdinalStruct based on mKey.
     */
    bool less(const C2WorkOrdinalStruct &o1,
              const C2WorkOrdinalStruct &o2) const;

    DISALLOW_EVIL_CONSTRUCTORS(OutputBuffers);

    friend OutputBuffersArray;
};

/**
 * Simple local buffer pool backed by std::vector.
 */
class LocalBufferPool : public std::enable_shared_from_this<LocalBufferPool> {
public:
    /**
     * Create a new LocalBufferPool object.
     *
     * \return  a newly created pool object.
     */
    static std::shared_ptr<LocalBufferPool> Create();

    /**
     * Return an ABuffer object whose size is at least |capacity|.
     *
     * \param   capacity  requested capacity
     * \return  nullptr if the pool capacity is reached
     *          an ABuffer object otherwise.
     */
    sp<ABuffer> newBuffer(size_t capacity);

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
        VectorBuffer(std::vector<uint8_t> &&vec, const std::shared_ptr<LocalBufferPool> &pool);

        ~VectorBuffer() override;

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
    void returnVector(std::vector<uint8_t> &&vec);

    DISALLOW_EVIL_CONSTRUCTORS(LocalBufferPool);
};

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
    size_t assignSlot(const sp<Codec2Buffer> &buffer);

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
            bool release);

    /**
     * Expire the C2Buffer object in the slot.
     *
     * \param   c2buffer[in]  C2Buffer object which the component released.
     * \return  true  if the buffer is found in one of the slots and
     *                successfully released
     *          false otherwise
     */
    bool expireComponentBuffer(const std::shared_ptr<C2Buffer> &c2buffer);

    /**
     * The client abandoned all known buffers, so reclaim the ownership.
     */
    void flush();

    /**
     * Return the number of buffers that are sent to the client but not released
     * yet.
     */
    size_t numActiveSlots() const;

    /**
     * Return the number of buffers that are sent to the component but not
     * returned back yet.
     */
    size_t numComponentBuffers() const;

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
            std::function<sp<Codec2Buffer>()> allocate);

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
                [](const sp<Codec2Buffer> &buffer) { return (buffer != nullptr); });

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
            bool release);

    /**
     * Expire the C2Buffer object in the slot.
     *
     * \param   c2buffer[in]  C2Buffer object which the component released.
     * \return  true  if the buffer is found in one of the slots and
     *                successfully released
     *          false otherwise
     */
    bool expireComponentBuffer(const std::shared_ptr<C2Buffer> &c2buffer);

    /**
     * Populate |array| with the underlying buffer array.
     *
     * \param array[out]  an array to be filled with the underlying buffer array.
     */
    void getArray(Vector<sp<MediaCodecBuffer>> *array) const;

    /**
     * The client abandoned all known buffers, so reclaim the ownership.
     */
    void flush();

    /**
     * Reallocate the array with the given allocation function.
     *
     * \param alloc[in] the allocation function for client buffers.
     */
    void realloc(std::function<sp<Codec2Buffer>()> alloc);

    /**
     * Grow the array to the new size. It is a programming error to supply
     * smaller size as the new size.
     *
     * \param newSize[in] new size of the array.
     * \param alloc[in]   the alllocation function for client buffers to fill
     *                    the new empty slots.
     */
    void grow(size_t newSize, std::function<sp<Codec2Buffer>()> alloc);

    /**
     * Return the number of buffers that are sent to the client but not released
     * yet.
     */
    size_t numActiveSlots() const;

    /**
     * Return the size of the array.
     */
    size_t arraySize() const;

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

class InputBuffersArray : public InputBuffers {
public:
    InputBuffersArray(const char *componentName, const char *name = "Input[N]")
        : InputBuffers(componentName, name) { }
    ~InputBuffersArray() override = default;

    /**
     * Initialize this object from the non-array state. We keep existing slots
     * at the same index, and for empty slots we allocate client buffers with
     * the given allocate function. If the number of slots is less than minSize,
     * we fill the array to the minimum size.
     *
     * \param impl[in]      existing non-array state
     * \param minSize[in]   minimum size of the array
     * \param allocate[in]  allocate function to fill empty slots
     */
    void initialize(
            const FlexBuffersImpl &impl,
            size_t minSize,
            std::function<sp<Codec2Buffer>()> allocate);

    bool isArrayMode() const final { return true; }

    std::unique_ptr<InputBuffers> toArrayMode(size_t) final {
        return nullptr;
    }

    void getArray(Vector<sp<MediaCodecBuffer>> *array) const final;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override;

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override;

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override;

    void flush() override;

    size_t numActiveSlots() const final;

protected:
    sp<Codec2Buffer> createNewBuffer() override;

private:
    BuffersArrayImpl mImpl;
    std::function<sp<Codec2Buffer>()> mAllocate;
};

class SlotInputBuffers : public InputBuffers {
public:
    SlotInputBuffers(const char *componentName, const char *name = "Slot-Input")
        : InputBuffers(componentName, name),
          mImpl(mName) { }
    ~SlotInputBuffers() override = default;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) final;

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) final;

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) final;

    void flush() final;

    std::unique_ptr<InputBuffers> toArrayMode(size_t size) final;

    size_t numActiveSlots() const final;

protected:
    sp<Codec2Buffer> createNewBuffer() final;

private:
    FlexBuffersImpl mImpl;
};

class LinearInputBuffers : public InputBuffers {
public:
    LinearInputBuffers(const char *componentName, const char *name = "1D-Input")
        : InputBuffers(componentName, name),
          mImpl(mName) { }
    ~LinearInputBuffers() override = default;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override;

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override;

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override;

    void flush() override;

    std::unique_ptr<InputBuffers> toArrayMode(size_t size) override;

    size_t numActiveSlots() const final;

protected:
    sp<Codec2Buffer> createNewBuffer() override;

    FlexBuffersImpl mImpl;

private:
    static sp<Codec2Buffer> Alloc(
            const std::shared_ptr<C2BlockPool> &pool, const sp<AMessage> &format);
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
            const char *componentName, const char *name = "EncryptedInput");

    ~EncryptedLinearInputBuffers() override = default;

    std::unique_ptr<InputBuffers> toArrayMode(size_t size) override;

protected:
    sp<Codec2Buffer> createNewBuffer() override;

private:
    struct Entry {
        std::weak_ptr<C2LinearBlock> block;
        sp<IMemory> memory;
        int32_t heapSeqNum;
    };

    static sp<Codec2Buffer> Alloc(
            const std::shared_ptr<C2BlockPool> &pool,
            const sp<AMessage> &format,
            C2MemoryUsage usage,
            const std::shared_ptr<std::vector<Entry>> &memoryVector);

    C2MemoryUsage mUsage;
    sp<MemoryDealer> mDealer;
    sp<ICrypto> mCrypto;
    std::shared_ptr<std::vector<Entry>> mMemoryVector;
};

class GraphicMetadataInputBuffers : public InputBuffers {
public:
    GraphicMetadataInputBuffers(const char *componentName, const char *name = "2D-MetaInput");
    ~GraphicMetadataInputBuffers() override = default;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override;

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override;

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override;

    void flush() override;

    std::unique_ptr<InputBuffers> toArrayMode(size_t size) final;

    size_t numActiveSlots() const final;

protected:
    sp<Codec2Buffer> createNewBuffer() override;

private:
    FlexBuffersImpl mImpl;
    std::shared_ptr<C2AllocatorStore> mStore;
};

class GraphicInputBuffers : public InputBuffers {
public:
    GraphicInputBuffers(const char *componentName, const char *name = "2D-BB-Input");
    ~GraphicInputBuffers() override = default;

    bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) override;

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer,
            bool release) override;

    bool expireComponentBuffer(
            const std::shared_ptr<C2Buffer> &c2buffer) override;

    void flush() override;

    std::unique_ptr<InputBuffers> toArrayMode(
            size_t size) final;

    size_t numActiveSlots() const final;

protected:
    sp<Codec2Buffer> createNewBuffer() override;

private:
    FlexBuffersImpl mImpl;
    std::shared_ptr<LocalBufferPool> mLocalBufferPool;
};

class DummyInputBuffers : public InputBuffers {
public:
    DummyInputBuffers(const char *componentName, const char *name = "2D-Input")
        : InputBuffers(componentName, name) { }
    ~DummyInputBuffers() override = default;

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

    std::unique_ptr<InputBuffers> toArrayMode(size_t) final {
        return nullptr;
    }

    bool isArrayMode() const final { return true; }

    void getArray(Vector<sp<MediaCodecBuffer>> *array) const final {
        array->clear();
    }

    size_t numActiveSlots() const final {
        return 0u;
    }

protected:
    sp<Codec2Buffer> createNewBuffer() override {
        return nullptr;
    }
};

class OutputBuffersArray : public OutputBuffers {
public:
    OutputBuffersArray(const char *componentName, const char *name = "Output[N]")
        : OutputBuffers(componentName, name) { }
    ~OutputBuffersArray() override = default;

    /**
     * Initialize this object from the non-array state. We keep existing slots
     * at the same index, and for empty slots we allocate client buffers with
     * the given allocate function. If the number of slots is less than minSize,
     * we fill the array to the minimum size.
     *
     * \param impl[in]      existing non-array state
     * \param minSize[in]   minimum size of the array
     * \param allocate[in]  allocate function to fill empty slots
     */
    void initialize(
            const FlexBuffersImpl &impl,
            size_t minSize,
            std::function<sp<Codec2Buffer>()> allocate);

    bool isArrayMode() const final { return true; }

    std::unique_ptr<OutputBuffersArray> toArrayMode(size_t) final {
        return nullptr;
    }

    status_t registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) final;

    status_t registerCsd(
            const C2StreamInitDataInfo::output *csd,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) final;

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer, std::shared_ptr<C2Buffer> *c2buffer) override;

    void flush(const std::list<std::unique_ptr<C2Work>> &flushedWork) override;

    void getArray(Vector<sp<MediaCodecBuffer>> *array) const final;

    size_t numActiveSlots() const final;

    /**
     * Reallocate the array, filled with buffers with the same size as given
     * buffer.
     *
     * \param c2buffer[in] the reference buffer
     */
    void realloc(const std::shared_ptr<C2Buffer> &c2buffer);

    /**
     * Grow the array to the new size. It is a programming error to supply
     * smaller size as the new size.
     *
     * \param newSize[in] new size of the array.
     */
    void grow(size_t newSize);

    /**
     * Transfer the SkipCutBuffer and the output stash from another
     * OutputBuffers.
     */
    void transferFrom(OutputBuffers* source);

private:
    BuffersArrayImpl mImpl;
    std::function<sp<Codec2Buffer>()> mAlloc;
};

class FlexOutputBuffers : public OutputBuffers {
public:
    FlexOutputBuffers(const char *componentName, const char *name = "Output[]")
        : OutputBuffers(componentName, name),
          mImpl(mName) { }

    status_t registerBuffer(
            const std::shared_ptr<C2Buffer> &buffer,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) override;

    status_t registerCsd(
            const C2StreamInitDataInfo::output *csd,
            size_t *index,
            sp<MediaCodecBuffer> *clientBuffer) final;

    bool releaseBuffer(
            const sp<MediaCodecBuffer> &buffer,
            std::shared_ptr<C2Buffer> *c2buffer) override;

    void flush(
            const std::list<std::unique_ptr<C2Work>> &flushedWork) override;

    std::unique_ptr<OutputBuffersArray> toArrayMode(size_t size) override;

    size_t numActiveSlots() const final;

    /**
     * Return an appropriate Codec2Buffer object for the type of buffers.
     *
     * \param buffer  C2Buffer object to wrap.
     *
     * \return  appropriate Codec2Buffer object to wrap |buffer|.
     */
    virtual sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) = 0;

    /**
     * Return a function that allocates an appropriate Codec2Buffer object for
     * the type of buffers, to be used as an empty array buffer. The function
     * must not refer to this pointer, since it may be used after this object
     * destructs.
     *
     * \return  a function that allocates appropriate Codec2Buffer object,
     *          which can copy() from C2Buffers.
     */
    virtual std::function<sp<Codec2Buffer>()> getAlloc() = 0;

private:
    FlexBuffersImpl mImpl;
};

class LinearOutputBuffers : public FlexOutputBuffers {
public:
    LinearOutputBuffers(const char *componentName, const char *name = "1D-Output")
        : FlexOutputBuffers(componentName, name) { }

    void flush(
            const std::list<std::unique_ptr<C2Work>> &flushedWork) override;

    sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) override;

    std::function<sp<Codec2Buffer>()> getAlloc() override;
};

class GraphicOutputBuffers : public FlexOutputBuffers {
public:
    GraphicOutputBuffers(const char *componentName, const char *name = "2D-Output")
        : FlexOutputBuffers(componentName, name) { }

    sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) override;

    std::function<sp<Codec2Buffer>()> getAlloc() override;
};

class RawGraphicOutputBuffers : public FlexOutputBuffers {
public:
    RawGraphicOutputBuffers(const char *componentName, const char *name = "2D-BB-Output");
    ~RawGraphicOutputBuffers() override = default;

    sp<Codec2Buffer> wrap(const std::shared_ptr<C2Buffer> &buffer) override;

    std::function<sp<Codec2Buffer>()> getAlloc() override;

private:
    std::shared_ptr<LocalBufferPool> mLocalBufferPool;
};

}  // namespace android

#endif  // CCODEC_BUFFERS_H_
