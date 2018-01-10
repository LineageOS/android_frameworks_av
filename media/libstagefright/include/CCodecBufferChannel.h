/*
 * Copyright 2017, The Android Open Source Project
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

#ifndef A_BUFFER_CHANNEL_H_

#define A_BUFFER_CHANNEL_H_

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include <C2Buffer.h>
#include <C2Component.h>

#include <media/stagefright/foundation/Mutexed.h>
#include <media/stagefright/CodecBase.h>
#include <media/ICrypto.h>

namespace android {

/**
 * BufferChannelBase implementation for CCodec.
 */
class CCodecBufferChannel : public BufferChannelBase {
public:
    /**
     * Base class for representation of buffers at one port.
     */
    class Buffers {
    public:
        Buffers() = default;
        virtual ~Buffers() = default;

        /**
         * Set format for MediaCodec-facing buffers.
         */
        inline void setFormat(const sp<AMessage> &format) { mFormat = format; }

        /**
         * Returns true if the buffers are operating under array mode.
         */
        virtual bool isArrayMode() { return false; }

        /**
         * Fills the vector with MediaCodecBuffer's if in array mode; otherwise,
         * no-op.
         */
        virtual void getArray(Vector<sp<MediaCodecBuffer>> *) {}

    protected:
        // Format to be used for creating MediaCodec-facing buffers.
        sp<AMessage> mFormat;

    private:
        DISALLOW_EVIL_CONSTRUCTORS(Buffers);
    };

    class InputBuffers : public Buffers {
    public:
        using Buffers::Buffers;
        virtual ~InputBuffers() = default;

        /**
         * Set a block pool to obtain input memory blocks.
         */
        inline void setPool(const std::shared_ptr<C2BlockPool> &pool) { mPool = pool; }

        /**
         * Get a new MediaCodecBuffer for input and its corresponding index.
         * Returns false if no new buffer can be obtained at the moment.
         */
        virtual bool requestNewBuffer(size_t *index, sp<MediaCodecBuffer> *buffer) = 0;

        /**
         * Release the buffer obtained from requestNewBuffer() and get the
         * associated C2Buffer object back. Returns empty shared_ptr if the
         * buffer is not on file.
         */
        virtual std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) = 0;

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
        virtual std::unique_ptr<InputBuffers> toArrayMode() = 0;

    protected:
        // Pool to obtain blocks for input buffers.
        std::shared_ptr<C2BlockPool> mPool;

    private:
        DISALLOW_EVIL_CONSTRUCTORS(InputBuffers);
    };

    class OutputBuffers : public Buffers {
    public:
        using Buffers::Buffers;
        virtual ~OutputBuffers() = default;

        /**
         * Register output C2Buffer from the component and obtain corresponding
         * index and MediaCodecBuffer object. Returns false if registration
         * fails.
         */
        virtual bool registerBuffer(
                const std::shared_ptr<C2Buffer> &buffer,
                size_t *index,
                sp<MediaCodecBuffer> *codecBuffer) = 0;

        /**
         * Register codec specific data as a buffer to be consistent with
         * MediaCodec behavior.
         */
        virtual bool registerCsd(
                const C2StreamCsdInfo::output * /* csd */,
                size_t * /* index */,
                sp<MediaCodecBuffer> * /* codecBuffer */) {
            return false;
        }

        /**
         * Release the buffer obtained from registerBuffer() and get the
         * associated C2Buffer object back. Returns empty shared_ptr if the
         * buffer is not on file.
         */
        virtual std::shared_ptr<C2Buffer> releaseBuffer(const sp<MediaCodecBuffer> &buffer) = 0;

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
        virtual std::unique_ptr<OutputBuffers> toArrayMode() = 0;

    private:
        DISALLOW_EVIL_CONSTRUCTORS(OutputBuffers);
    };

    CCodecBufferChannel(const std::function<void(status_t, enum ActionCode)> &onError);
    virtual ~CCodecBufferChannel();

    // BufferChannelBase interface
    virtual status_t queueInputBuffer(const sp<MediaCodecBuffer> &buffer) override;
    virtual status_t queueSecureInputBuffer(
            const sp<MediaCodecBuffer> &buffer,
            bool secure,
            const uint8_t *key,
            const uint8_t *iv,
            CryptoPlugin::Mode mode,
            CryptoPlugin::Pattern pattern,
            const CryptoPlugin::SubSample *subSamples,
            size_t numSubSamples,
            AString *errorDetailMsg) override;
    virtual status_t renderOutputBuffer(
            const sp<MediaCodecBuffer> &buffer, int64_t timestampNs) override;
    virtual status_t discardBuffer(const sp<MediaCodecBuffer> &buffer) override;
    virtual void getInputBufferArray(Vector<sp<MediaCodecBuffer>> *array) override;
    virtual void getOutputBufferArray(Vector<sp<MediaCodecBuffer>> *array) override;

    // Methods below are interface for CCodec to use.

    void setComponent(const std::shared_ptr<C2Component> &component);
    status_t setSurface(const sp<Surface> &surface);

    /**
     * Set C2BlockPool for input buffers.
     *
     * TODO: start timestamp?
     */
    void setInputBufferAllocator(const sp<C2BlockPool> &inAlloc);

    /**
     * Set C2BlockPool for output buffers. This object shall never use the
     * allocator itself; it's just passed
     *
     * TODO: start timestamp?
     */
    void setOutputBufferAllocator(const sp<C2BlockPool> &outAlloc);

    /**
     * Start queueing buffers to the component. This object should never queue
     * buffers before this call.
     */
    void start(const sp<AMessage> &inputFormat, const sp<AMessage> &outputFormat);

    /**
     * Stop queueing buffers to the component. This object should never queue
     * buffers after this call, until start() is called.
     */
    void stop();

    void flush(const std::list<std::unique_ptr<C2Work>> &flushedWork);

    /**
     * Notify MediaCodec about work done.
     *
     * @param workItems   finished work items.
     */
    void onWorkDone(std::vector<std::unique_ptr<C2Work>> workItems);

private:
    class QueueGuard;

    /**
     * Special mutex-like object with the following properties:
     *
     * - At STOPPED state (initial, or after stop())
     *   - QueueGuard object gets created at STOPPED state, and the client is
     *     supposed to return immediately.
     * - At RUNNING state (after start())
     *   - Each QueueGuard object
     */
    class QueueSync {
    public:
        /**
         * At construction the sync object is in STOPPED state.
         */
        inline QueueSync() : mCount(-1) {}
        ~QueueSync() = default;

        /**
         * Transition to RUNNING state when stopped. No-op if already in RUNNING
         * state.
         */
        void start();

        /**
         * At RUNNING state, wait until all QueueGuard object created during
         * RUNNING state are destroyed, and then transition to STOPPED state.
         * No-op if already in STOPPED state.
         */
        void stop();

    private:
        std::mutex mMutex;
        std::atomic_int32_t mCount;

        friend class CCodecBufferChannel::QueueGuard;
    };

    class QueueGuard {
    public:
        QueueGuard(QueueSync &sync);
        ~QueueGuard();
        inline bool isRunning() { return mRunning; }

    private:
        QueueSync &mSync;
        bool mRunning;
    };

    QueueSync mSync;
    sp<MemoryDealer> mDealer;
    sp<IMemory> mDecryptDestination;
    int32_t mHeapSeqNum;

    std::shared_ptr<C2Component> mComponent;
    std::function<void(status_t, enum ActionCode)> mOnError;
    std::shared_ptr<C2BlockPool> mInputAllocator;
    QueueSync mQueueSync;

    Mutexed<std::unique_ptr<InputBuffers>> mInputBuffers;
    Mutexed<std::unique_ptr<OutputBuffers>> mOutputBuffers;

    std::atomic_uint64_t mFrameIndex;
    std::atomic_uint64_t mFirstValidFrameIndex;

    sp<MemoryDealer> makeMemoryDealer(size_t heapSize);
    Mutexed<sp<Surface>> mSurface;

    inline bool hasCryptoOrDescrambler() {
        return mCrypto != NULL || mDescrambler != NULL;
    }
};

}  // namespace android

#endif  // A_BUFFER_CHANNEL_H_
