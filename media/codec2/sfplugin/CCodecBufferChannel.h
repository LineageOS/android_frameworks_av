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

#include <deque>
#include <map>
#include <memory>
#include <vector>
#include <mutex>

#include <C2Buffer.h>
#include <C2Component.h>
#include <Codec2Mapper.h>

#include <codec2/hidl/client.h>
#include <media/stagefright/foundation/Mutexed.h>
#include <media/stagefright/CodecBase.h>

#include "CCodecBuffers.h"
#include "FrameReassembler.h"
#include "InputSurfaceWrapper.h"
#include "PipelineWatcher.h"

namespace android {

class MemoryDealer;

class CCodecCallback {
public:
    virtual ~CCodecCallback() = default;
    virtual void onError(status_t err, enum ActionCode actionCode) = 0;
    virtual void onOutputFramesRendered(int64_t mediaTimeUs, nsecs_t renderTimeNs) = 0;
    virtual void onOutputBuffersChanged() = 0;
    virtual void onFirstTunnelFrameReady() = 0;
};

/**
 * BufferChannelBase implementation for CCodec.
 */
class CCodecBufferChannel
    : public BufferChannelBase, public std::enable_shared_from_this<CCodecBufferChannel> {
public:
    explicit CCodecBufferChannel(const std::shared_ptr<CCodecCallback> &callback);
    virtual ~CCodecBufferChannel();

    // BufferChannelBase interface
    void setCrypto(const sp<ICrypto> &crypto) override;
    void setDescrambler(const sp<IDescrambler> &descrambler) override;

    status_t queueInputBuffer(const sp<MediaCodecBuffer> &buffer) override;
    status_t queueSecureInputBuffer(
            const sp<MediaCodecBuffer> &buffer,
            bool secure,
            const uint8_t *key,
            const uint8_t *iv,
            CryptoPlugin::Mode mode,
            CryptoPlugin::Pattern pattern,
            const CryptoPlugin::SubSample *subSamples,
            size_t numSubSamples,
            AString *errorDetailMsg) override;
    status_t queueSecureInputBuffers(
            const sp<MediaCodecBuffer> &buffer,
            bool secure,
            AString *errorDetailMsg) override;
    status_t attachBuffer(
            const std::shared_ptr<C2Buffer> &c2Buffer,
            const sp<MediaCodecBuffer> &buffer) override;
    status_t attachEncryptedBuffer(
            const sp<hardware::HidlMemory> &memory,
            bool secure,
            const uint8_t *key,
            const uint8_t *iv,
            CryptoPlugin::Mode mode,
            CryptoPlugin::Pattern pattern,
            size_t offset,
            const CryptoPlugin::SubSample *subSamples,
            size_t numSubSamples,
            const sp<MediaCodecBuffer> &buffer,
            AString* errorDetailMsg) override;
    status_t attachEncryptedBuffers(
            const sp<hardware::HidlMemory> &memory,
            size_t offset,
            const sp<MediaCodecBuffer> &buffer,
            bool secure,
            AString* errorDetailMsg) override;
    status_t renderOutputBuffer(
            const sp<MediaCodecBuffer> &buffer, int64_t timestampNs) override;
    void pollForRenderedBuffers() override;
    void onBufferReleasedFromOutputSurface(uint32_t generation) override;
    status_t discardBuffer(const sp<MediaCodecBuffer> &buffer) override;
    void getInputBufferArray(Vector<sp<MediaCodecBuffer>> *array) override;
    void getOutputBufferArray(Vector<sp<MediaCodecBuffer>> *array) override;

    // Methods below are interface for CCodec to use.

    /**
     * Set the component object for buffer processing.
     */
    void setComponent(const std::shared_ptr<Codec2Client::Component> &component);

    /**
     * Set output graphic surface for rendering.
     */
    status_t setSurface(const sp<Surface> &surface, uint32_t generation, bool pushBlankBuffer);

    /**
     * Set GraphicBufferSource object from which the component extracts input
     * buffers.
     */
    status_t setInputSurface(const std::shared_ptr<InputSurfaceWrapper> &surface);

    /**
     * Signal EOS to input surface.
     */
    status_t signalEndOfInputStream();

    /**
     * Set parameters.
     */
    status_t setParameters(std::vector<std::unique_ptr<C2Param>> &params);

    /**
     * Start queueing buffers to the component. This object should never queue
     * buffers before this call has completed.
     */
    status_t start(
            const sp<AMessage> &inputFormat,
            const sp<AMessage> &outputFormat,
            bool buffersBoundToCodec);

    /**
     * Prepare initial input buffers to be filled by client.
     *
     * \param clientInputBuffers[out]   pointer to slot index -> buffer map.
     *                                  On success, it contains prepared
     *                                  initial input buffers.
     */
    status_t prepareInitialInputBuffers(
            std::map<size_t, sp<MediaCodecBuffer>> *clientInputBuffers,
            bool retry = false);

    /**
     * Request initial input buffers as prepared in clientInputBuffers.
     *
     * \param clientInputBuffers[in]    slot index -> buffer map with prepared
     *                                  initial input buffers.
     */
    status_t requestInitialInputBuffers(
            std::map<size_t, sp<MediaCodecBuffer>> &&clientInputBuffers);

    /**
     * Stop using buffers of the current output surface for other Codec
     * instances to use the surface safely.
     *
     * \param pushBlankBuffer[in]       push a blank buffer at the end if true
     */
    void stopUseOutputSurface(bool pushBlankBuffer);

    /**
     * Stop queueing buffers to the component. This object should never queue
     * buffers after this call, until start() is called.
     */
    void stop();

    /**
     * Stop queueing buffers to the component and release all buffers.
     */
    void reset();

    /**
     * Release all resources.
     */
    void release();

    void flush(const std::list<std::unique_ptr<C2Work>> &flushedWork);

    /**
     * Notify input client about work done.
     *
     * @param workItems   finished work item.
     * @param outputFormat new output format if it has changed, otherwise nullptr
     * @param initData    new init data (CSD) if it has changed, otherwise nullptr
     */
    void onWorkDone(
            std::unique_ptr<C2Work> work, const sp<AMessage> &outputFormat,
            const C2StreamInitDataInfo::output *initData);

    /**
     * Make an input buffer available for the client as it is no longer needed
     * by the codec.
     *
     * @param frameIndex The index of input work
     * @param arrayIndex The index of buffer in the input work buffers.
     */
    void onInputBufferDone(uint64_t frameIndex, size_t arrayIndex);

    PipelineWatcher::Clock::duration elapsed();

    enum MetaMode {
        MODE_NONE,
        MODE_ANW,
    };

    void setMetaMode(MetaMode mode);

    /**
     * get pixel format from output buffers.
     *
     * @return 0 if no valid pixel format found.
     */
    uint32_t getBuffersPixelFormat(bool isEncoder);

    void resetBuffersPixelFormat(bool isEncoder);

    /**
     * Queue a C2 info buffer that will be sent to codec in the subsequent
     * queueInputBuffer
     *
     * @param buffer C2 info buffer
     */
    void setInfoBuffer(const std::shared_ptr<C2InfoBuffer> &buffer);

private:
    uint32_t getInputBuffersPixelFormat();

    uint32_t getOutputBuffersPixelFormat();

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
        inline QueueSync() {}
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
        Mutex mGuardLock;

        struct Counter {
            inline Counter() : value(-1) {}
            int32_t value;
            Condition cond;
        };
        Mutexed<Counter> mCount;

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

    struct TrackedFrame {
        uint64_t number;
        int64_t mediaTimeUs;
        int64_t desiredRenderTimeNs;
        nsecs_t latchTime;
        sp<Fence> presentFence;
    };

    void feedInputBufferIfAvailable();
    void feedInputBufferIfAvailableInternal();
    void queueDummyWork();
    status_t queueInputBufferInternal(sp<MediaCodecBuffer> buffer,
                                      std::shared_ptr<C2LinearBlock> encryptedBlock = nullptr,
                                      size_t blockSize = 0);
    bool handleWork(
            std::unique_ptr<C2Work> work, const sp<AMessage> &outputFormat,
            const C2StreamInitDataInfo::output *initData);
    void sendOutputBuffers();
    void ensureDecryptDestination(size_t size);
    int32_t getHeapSeqNum(const sp<hardware::HidlMemory> &memory);

    void initializeFrameTrackingFor(ANativeWindow * window);
    void trackReleasedFrame(const IGraphicBufferProducer::QueueBufferOutput& qbo,
                            int64_t mediaTimeUs, int64_t desiredRenderTimeNs);
    void processRenderedFrames(const FrameEventHistoryDelta& delta);
    int64_t getRenderTimeNs(const TrackedFrame& frame);

    QueueSync mSync;
    sp<MemoryDealer> mDealer;
    sp<IMemory> mDecryptDestination;
    int32_t mHeapSeqNum;
    std::map<wp<hardware::HidlMemory>, int32_t> mHeapSeqNumMap;

    std::shared_ptr<Codec2Client::Component> mComponent;
    std::string mComponentName; ///< component name for debugging
    const char *mName; ///< C-string version of component name
    std::shared_ptr<CCodecCallback> mCCodecCallback;
    std::shared_ptr<C2BlockPool> mInputAllocator;
    QueueSync mQueueSync;
    std::vector<std::unique_ptr<C2Param>> mParamsToBeSet;
    sp<AMessage> mOutputFormat;

    struct Input {
        Input();

        std::unique_ptr<InputBuffers> buffers;
        size_t numSlots;
        FlexBuffersImpl extraBuffers;
        size_t numExtraSlots;
        uint32_t inputDelay;
        uint32_t pipelineDelay;
        c2_cntr64_t lastFlushIndex;

        FrameReassembler frameReassembler;
    };
    Mutexed<Input> mInput;
    struct Output {
        std::unique_ptr<OutputBuffers> buffers;
        size_t numSlots;
        uint32_t outputDelay;
        // true iff the underlying block pool is bounded --- for example,
        // a BufferQueue-based block pool would be bounded by the BufferQueue.
        bool bounded;
    };
    Mutexed<Output> mOutput;
    Mutexed<std::list<std::unique_ptr<C2Work>>> mFlushedConfigs;

    std::atomic_uint64_t mFrameIndex;
    std::atomic_uint64_t mFirstValidFrameIndex;

    sp<MemoryDealer> makeMemoryDealer(size_t heapSize);

    std::deque<TrackedFrame> mTrackedFrames;
    bool mAreRenderMetricsEnabled;
    bool mIsSurfaceToDisplay;
    bool mHasPresentFenceTimes;

    struct OutputSurface {
        sp<Surface> surface;
        uint32_t generation;
        int maxDequeueBuffers;
        std::map<uint64_t, int> rotation;
    };
    Mutexed<OutputSurface> mOutputSurface;
    int mRenderingDepth;

    struct BlockPools {
        C2Allocator::id_t inputAllocatorId;
        std::shared_ptr<C2BlockPool> inputPool;
        C2Allocator::id_t outputAllocatorId;
        C2BlockPool::local_id_t outputPoolId;
        std::shared_ptr<Codec2Client::Configurable> outputPoolIntf;
    };
    Mutexed<BlockPools> mBlockPools;

    std::shared_ptr<InputSurfaceWrapper> mInputSurface;

    MetaMode mMetaMode;

    Mutexed<PipelineWatcher> mPipelineWatcher;

    std::atomic_bool mInputMetEos;
    std::once_flag mRenderWarningFlag;

    uint64_t mLastInputBufferAvailableTs;
    std::mutex mTsLock;
    bool mIsHWDecoder;

    sp<ICrypto> mCrypto;
    sp<IDescrambler> mDescrambler;

    inline bool hasCryptoOrDescrambler() {
        return mCrypto != nullptr || mDescrambler != nullptr;
    }
    std::atomic_bool mSendEncryptedInfoBuffer;

    std::atomic_bool mTunneled;

    std::vector<std::shared_ptr<C2InfoBuffer>> mInfoBuffers;
};

// Conversion of a c2_status_t value to a status_t value may depend on the
// operation that returns the c2_status_t value.
enum c2_operation_t {
    C2_OPERATION_NONE,
    C2_OPERATION_Component_connectToOmxInputSurface,
    C2_OPERATION_Component_createBlockPool,
    C2_OPERATION_Component_destroyBlockPool,
    C2_OPERATION_Component_disconnectFromInputSurface,
    C2_OPERATION_Component_drain,
    C2_OPERATION_Component_flush,
    C2_OPERATION_Component_queue,
    C2_OPERATION_Component_release,
    C2_OPERATION_Component_reset,
    C2_OPERATION_Component_setOutputSurface,
    C2_OPERATION_Component_start,
    C2_OPERATION_Component_stop,
    C2_OPERATION_ComponentStore_copyBuffer,
    C2_OPERATION_ComponentStore_createComponent,
    C2_OPERATION_ComponentStore_createInputSurface,
    C2_OPERATION_ComponentStore_createInterface,
    C2_OPERATION_Configurable_config,
    C2_OPERATION_Configurable_query,
    C2_OPERATION_Configurable_querySupportedParams,
    C2_OPERATION_Configurable_querySupportedValues,
    C2_OPERATION_InputSurface_connectToComponent,
    C2_OPERATION_InputSurfaceConnection_disconnect,
};

status_t toStatusT(c2_status_t c2s, c2_operation_t c2op = C2_OPERATION_NONE);

}  // namespace android

#endif  // CCODEC_BUFFER_CHANNEL_H_
