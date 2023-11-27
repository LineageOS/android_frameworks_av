/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <android/hardware_buffer.h>
#include <android-base/unique_fd.h>
#include <gui/IGraphicBufferProducer.h>

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <optional>

#include <C2Buffer.h>

namespace aidl::android::hardware::media::c2::implementation {

using ::android::IGraphicBufferProducer;
using ::android::GraphicBuffer;
using ::android::Fence;
using ::android::PixelFormat;
using ::android::sp;
/**
 * The class allocates AHardwareBuffer(GraphicBuffer)s using BufferQueue.
 *
 * The class tracks and manages outstanding # of allocations for buffer
 * recycling. So Graphics operations which affects # of outstanding allocation
 * should be done via the class. (e.g. rendering a buffer to display)
 *
 * The class is supposed to be wrapped into IGraphicBufferAllocator AIDL interface,
 * and the interface will be passed to HAL for a specific BlockPool instance.
 *
 * The class has one to one relation with HAL side Graphic C2BlockPool.
 * The life cycle of the class is tied to a HAL side BlockPool object.
 *
 * So, reset()/stop() of HAL which related to blokcpool destruction will terminate the
 * use of the class. And a new instance should be created in order for start()
 * of HAL.
 */
class GraphicsTracker {
public:
    static std::shared_ptr<GraphicsTracker> CreateGraphicsTracker(int maxDequeueCount) {
        GraphicsTracker *p = new GraphicsTracker(maxDequeueCount);
        std::shared_ptr<GraphicsTracker> sp(p);
        return sp;
    }

    ~GraphicsTracker();

    /**
     * Configure a new surface to render/allocate graphic blocks.
     *
     * Graphic  blocks from the old surface will be migrated to the new surface,
     * if possible. Configuring to a null surface is possible in the case,
     * an allocation request will be fulfilled by a direct allocation(not using
     * BQ). generation should be different to the previous generations.
     *
     * @param[in] igbp        the new surface to configure
     * @param[in] generation  identifier for each configured surface
     */
    c2_status_t configureGraphics(const sp<IGraphicBufferProducer>& igbp, uint32_t generation);

    /**
     * Configure max # of outstanding allocations at any given time.
     *
     * @param[in] maxDequeueCount    max # of outstanding allocation to configure
     */
    c2_status_t configureMaxDequeueCount(int maxDequeueCount);

    /**
     * Allocates a AHardwareBuffer.
     *
     * @param[in] width       width
     * @param[in] height      height
     * @param[in] PixelFormat pixel format which describes color format and etc
     * @param[in] usage       gralloc usage bits
     * @param[out] buf        the allocated buffer
     * @param[out] fence      fence for the allocated buffer
     * @return  C2_OK         the buffer is allocated
     *          C2_BAD_STATE  stop() is called and in stopped state
     *          C2_BLOCKING   should be waited to allocate
     *          C2_NO_MEMORY  out of memory
     *          C2_CORRUPTED
     */
    c2_status_t allocate(uint32_t width, uint32_t height, PixelFormat format, uint64_t usage,
                         AHardwareBuffer **buf, sp<Fence> *fence);

    /**
     * Deallocates a AHardwareBuffer
     *
     * @param[in] bufId         id of the buffer to deallocate
     * @param[in] fence         i/o fence for the buffer
     * @return  C2_OK           the buffer is successfully deallocated.
     *          C2_DUPLICATE    deallocation/render request is pending already.
     *          C2_NOT_FOUND    the buffer with the id is not allocated.
     */
    c2_status_t deallocate(uint64_t bufId, const sp<Fence> &fence);

    /**
     * Render a GraphicBlock which is associated to a pending allocated buffer
     *
     * @param[in] block         GraphicBlock
     * @param[in] input         render input params to Graphics
     * @param[out] output       render output params from Graphics
     * @return  C2_OK           the buffer is now ready to render
     *          C2_BAD_STATE    there is no surface to render.
     *                          (null surface mode or life cycle ends)
     *          C2_DUPLICATE    deallocation/render request is pending already.
     *          C2_NOT_FOUND    the buffer with the id is not allocated.
     *          C2_REFUSED      the buffer is refused to render from Graphics
     *          C2_CORRUPTED
     */
    c2_status_t render(const C2ConstGraphicBlock& block,
                       const IGraphicBufferProducer::QueueBufferInput& input,
                       IGraphicBufferProducer::QueueBufferOutput *output);

    /**
     * Notifies when a Buffer is ready to allocate from Graphics.
     * If generation does not match to the current, notifications via the interface
     * will be ignored. (In the case, the notifications are from one of the old surfaces
     * which is no longer used.)
     *
     * @param[in] generation    generation id for specifying Graphics(BQ)
     */
    void onReleased(uint32_t generation);

    /**
     * Get waitable fd for events.(allocate is ready, end of life cycle)
     *
     * @param[out]  pipeFd      a file descriptor created from pipe2()
     *                          in order for notifying being ready to allocate
     *
     * @return  C2_OK
     *          C2_NO_MEMORY    Max # of fd reached.(not really a memory issue)
     */
    c2_status_t getWaitableFd(int *pipeFd);

    /**
     * Get the current max allocatable/dequeueable buffer count without de-allocating.
     */
    int getCurDequeueable();

    /**
     *  Ends to use the class. after the call, allocate will fail.
     */
    void stop();

private:
    struct BufferCache;

    struct BufferItem {
        bool mInit;
        uint64_t mId;
        uint32_t mGeneration;
        int mSlot;
        AHardwareBuffer *mBuf;
        uint64_t mUsage; // Gralloc usage format, not AHB
        sp<Fence> mFence;

        // Create from a GraphicBuffer
        BufferItem(uint32_t generation, int slot,
                   const sp<GraphicBuffer>& buf,
                   const sp<Fence> &fence);

        // Create from an AHB (no slot information)
        // Should be attached to IGBP for rendering
        BufferItem(uint32_t generation,
                   AHardwareBuffer *pBuf,
                   uint64_t usage);

        ~BufferItem();

        std::shared_ptr<BufferItem> migrateBuffer(uint64_t newUsage, uint32_t newGeneration);

        sp<GraphicBuffer> getGraphicBuffer();

    };

    struct BufferCache {
        static constexpr int kNumSlots = ::android::BufferQueueDefs::NUM_BUFFER_SLOTS;

        uint64_t mBqId;
        uint32_t mGeneration;
        ::android::sp<IGraphicBufferProducer> mIgbp;

        // Maps slotId to buffer
        // IGBP::dequeueBuffer(), IGBP::queueBuffer() and IGBP::cancelBuffer()
        // require slotId.
        std::map<int, std::shared_ptr<BufferItem>> mBuffers;

        // block slot use, while deallocating(cancel, render and etc)
        struct BlockedSlot {
            std::mutex l;
            std::condition_variable cv;
            bool blocked;
            BlockedSlot() : blocked{false} {}
            ~BlockedSlot() = default;
        };

        BlockedSlot mBlockedSlots[kNumSlots];

        BufferCache() : mBqId{0ULL}, mGeneration{0}, mIgbp{nullptr} {}
        BufferCache(uint64_t bqId, uint32_t generation, const sp<IGraphicBufferProducer>& igbp) :
            mBqId{bqId}, mGeneration{generation}, mIgbp{igbp} {}

        ~BufferCache();

        void waitOnSlot(int slot);

        void blockSlot(int slot);

        void unblockSlot(int slot);
    };

    std::shared_ptr<BufferCache> mBufferCache;
    // Maps bufferId to buffer
    std::map<uint64_t, std::shared_ptr<BufferItem>> mDequeued;
    std::set<uint64_t> mDeallocating;

    // These member variables are read and modified accessed as follows.
    // 1. mConfigLock being held
    //    Set mInConfig true with mLock in the beginning
    //    Clear mInConfig with mLock in the end
    // 2. mLock is held and mInConfig is false.
    int mMaxDequeue;
    int mMaxDequeueCommitted;
    std::optional<int> mMaxDequeueRequested;

    int mDequeueable;

    // TODO: statistics
    uint64_t mTotalDequeued;
    //uint64_t mTotalQueued;
    uint64_t mTotalCancelled;
    uint64_t mTotalDropped;
    uint64_t mTotalReleased;

    bool mInConfig;
    std::mutex mLock; // locks for data synchronization
    std::mutex mConfigLock; // locks for configuration change.

    // NOTE: pipe2() creates two file descriptors for allocatable events
    // and irrecoverable error events notification.
    //
    // A byte will be written to the writing end whenever a buffer is ready to
    // dequeue/allocate. A byte will be read from the reading end whenever
    // an allocate/dequeue event happens.
    //
    // The writing end will be closed when the end-of-lifecycle event was met.
    //
    // The reading end will be shared to the remote processes. Remote processes
    // use ::poll() to check whether a buffer is ready to allocate/ready.
    // Also ::poll() will let remote processes know the end-of-lifecycle event
    // by returning POLLHUP event from the reading end.
    ::android::base::unique_fd mReadPipeFd;   // The reading end file descriptor
    ::android::base::unique_fd mWritePipeFd;  // The writing end file descriptor

    std::atomic<bool> mStopped;

private:
    explicit GraphicsTracker(int maxDequeueCount);

    // return {@code true} only when dequeue config adjust happened.
    // {@code updateDequeueConf} is an output parameter, and returns
    // {@code true} only when the current dequeue conf is required to be
    // updated to IGBP(BQ) as a result of the adjust.
    bool adjustDequeueConfLocked(bool *updateDequeueConf);

    void updateDequeueConf();
    void clearCacheIfNecessaryLocked(
            const std::shared_ptr<BufferCache> &cache,
            int maxDequeueCommitted);

    c2_status_t requestAllocate(std::shared_ptr<BufferCache> *cache);
    c2_status_t requestDeallocate(uint64_t bid, const sp<Fence> &fence,
                                  bool *completed, bool *updateDequeue,
                                  std::shared_ptr<BufferCache> *cache, int *slotId,
                                  sp<Fence> *rFence);
    c2_status_t requestRender(uint64_t bid, std::shared_ptr<BufferCache> *cache,
                              std::shared_ptr<BufferItem> *pBuffer,
                              bool *fromCache,
                              bool *updateDequeue);

    void commitAllocate(c2_status_t res,
                        const std::shared_ptr<BufferCache> &cache,
                        bool cached, int slotId, const sp<Fence> &fence,
                        std::shared_ptr<BufferItem> *buffer,
                        bool *updateDequeue);
    void commitDeallocate(std::shared_ptr<BufferCache> &cache,
                          int slotId, uint64_t bid,
                          bool *updateDequeue);
    void commitRender(const std::shared_ptr<BufferCache> &cache,
                      const std::shared_ptr<BufferItem> &buffer,
                      const std::shared_ptr<BufferItem> &oldBuffer,
                      bool bufferReplaced,
                      bool *updateDequeue);

    c2_status_t _allocate(
            const std::shared_ptr<BufferCache> &cache,
            uint32_t width, uint32_t height, PixelFormat format, uint64_t usage,
            bool *cached, int *rSlotId, sp<Fence> *rFence,
            std::shared_ptr<BufferItem> *buffer);

    void writeIncDequeueableLocked(int inc);
    void drainDequeueableLocked(int dec);
};

} // namespace aidl::android::hardware::media::c2::implementation
