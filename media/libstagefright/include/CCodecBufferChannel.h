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

#ifndef CCODEC_BUFFER_CHANNEL_H_

#define CCODEC_BUFFER_CHANNEL_H_

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include <C2Buffer.h>
#include <C2Component.h>

#include <media/stagefright/bqhelper/GraphicBufferSource.h>
#include <media/stagefright/codec2/1.0/InputSurface.h>
#include <media/stagefright/foundation/Mutexed.h>
#include <media/stagefright/CodecBase.h>
#include <media/ICrypto.h>

#include "InputSurfaceWrapper.h"

namespace android {

using ::android::hardware::media::c2::V1_0::implementation::InputSurface;
using ::android::hardware::media::c2::V1_0::implementation::InputSurfaceConnection;

/**
 * BufferChannelBase implementation for CCodec.
 */
class CCodecBufferChannel
    : public BufferChannelBase, public std::enable_shared_from_this<CCodecBufferChannel> {
public:
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

    /**
     * Set the component object for buffer processing.
     */
    void setComponent(const std::shared_ptr<C2Component> &component);

    /**
     * Set output graphic surface for rendering.
     */
    status_t setSurface(const sp<Surface> &surface);

    /**
     * Set GraphicBufferSource object from which the component extracts input
     * buffers.
     */
    status_t setInputSurface(const std::shared_ptr<InputSurfaceWrapper> &surface);

    /**
     * Start queueing buffers to the component. This object should never queue
     * buffers before this call.
     */
    status_t start(const sp<AMessage> &inputFormat, const sp<AMessage> &outputFormat);

    /**
     * Stop queueing buffers to the component. This object should never queue
     * buffers after this call, until start() is called.
     */
    void stop();

    void flush(const std::list<std::unique_ptr<C2Work>> &flushedWork);

    /**
     * Notify input client about work done.
     *
     * @param workItems   finished work item.
     */
    void onWorkDone(const std::unique_ptr<C2Work> &work);

    // Internal classes
    class Buffers;
    class InputBuffers;
    class OutputBuffers;

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

    void feedInputBufferIfAvailable();
    status_t queueInputBufferInternal(const sp<MediaCodecBuffer> &buffer);

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

    struct OutputSurface {
        sp<Surface> surface;
        std::list<std::shared_ptr<C2Buffer>> bufferRefs;
        size_t maxBufferCount;
    };
    Mutexed<OutputSurface> mOutputSurface;

    std::shared_ptr<InputSurfaceWrapper> mInputSurface;

    inline bool hasCryptoOrDescrambler() {
        return mCrypto != NULL || mDescrambler != NULL;
    }
};

}  // namespace android

#endif  // CCODEC_BUFFER_CHANNEL_H_
