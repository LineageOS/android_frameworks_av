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
//#define LOG_NDEBUG 0
#define LOG_TAG "GraphicsTracker"
#include <fcntl.h>
#include <unistd.h>

#include <media/stagefright/foundation/ADebug.h>
#include <private/android/AHardwareBufferHelpers.h>
#include <vndk/hardware_buffer.h>

#include <C2BlockInternal.h>
#include <codec2/aidl/GraphicsTracker.h>

namespace aidl::android::hardware::media::c2::implementation {

namespace {

static constexpr int kMaxDequeueMin = 1;
static constexpr int kMaxDequeueMax = ::android::BufferQueueDefs::NUM_BUFFER_SLOTS - 2;

c2_status_t retrieveAHardwareBufferId(const C2ConstGraphicBlock &blk, uint64_t *bid) {
    std::shared_ptr<const _C2BlockPoolData> bpData = _C2BlockFactory::GetGraphicBlockPoolData(blk);
    if (bpData->getType() != _C2BlockPoolData::TYPE_AHWBUFFER) {
        return C2_BAD_VALUE;
    }
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        AHardwareBuffer *pBuf;
        if (!_C2BlockFactory::GetAHardwareBuffer(bpData, &pBuf)) {
            return C2_CORRUPTED;
        }
        int ret = AHardwareBuffer_getId(pBuf, bid);
        if (ret != ::android::OK) {
            return C2_CORRUPTED;
        }
        return C2_OK;
    } else {
        return C2_OMITTED;
    }
}

} // anonymous namespace

GraphicsTracker::BufferItem::BufferItem(
        uint32_t generation, int slot, const sp<GraphicBuffer>& buf, const sp<Fence>& fence) :
        mInit{false}, mGeneration{generation}, mSlot{slot} {
    if (!buf) {
        return;
    }
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        AHardwareBuffer *pBuf = AHardwareBuffer_from_GraphicBuffer(buf.get());
        int ret = AHardwareBuffer_getId(pBuf, &mId);
        if (ret != ::android::OK) {
            return;
        }
        mUsage = buf->getUsage();
        AHardwareBuffer_acquire(pBuf);
        mBuf = pBuf;
        mFence = fence;
        mInit = true;
    }
}

GraphicsTracker::BufferItem::BufferItem(
        uint32_t generation, AHardwareBuffer *pBuf, uint64_t usage) :
        mInit{true}, mGeneration{generation}, mSlot{-1},
        mBuf{pBuf}, mUsage{usage},
        mFence{Fence::NO_FENCE} {
    if (__builtin_available(android __ANDROID_API_T__, *)) {
        int ret = AHardwareBuffer_getId(mBuf, &mId);
        if (ret != ::android::OK) {
            mInit = false;
            mBuf = nullptr;
            return;
        }
    }
    AHardwareBuffer_acquire(mBuf);
}

GraphicsTracker::BufferItem::~BufferItem() {
    if (mInit) {
        AHardwareBuffer_release(mBuf);
    }
}


std::shared_ptr<GraphicsTracker::BufferItem> GraphicsTracker::BufferItem::migrateBuffer(
        uint64_t newUsage, uint32_t newGeneration) {
    if (!mInit) {
        return nullptr;
    }
    newUsage |= mUsage;
    uint64_t ahbUsage = ::android::AHardwareBuffer_convertFromGrallocUsageBits(newUsage);
    AHardwareBuffer_Desc desc;
    AHardwareBuffer_describe(mBuf, &desc);
    // TODO: we need well-established buffer migration features from graphics.
    // (b/273776738)
    desc.usage = ahbUsage;
    const native_handle_t *handle = AHardwareBuffer_getNativeHandle(mBuf);
    if (!handle) {
        return nullptr;
    }

    AHardwareBuffer *newBuf;
    int err = AHardwareBuffer_createFromHandle(&desc, handle,
                                     AHARDWAREBUFFER_CREATE_FROM_HANDLE_METHOD_CLONE,
                                     &newBuf);
    if (err != ::android::NO_ERROR) {
        return nullptr;
    }

    std::shared_ptr<BufferItem> newBuffer =
            std::make_shared<BufferItem>(newGeneration, newBuf, newUsage);
    AHardwareBuffer_release(newBuf);
    return newBuffer;
}

sp<GraphicBuffer> GraphicsTracker::BufferItem::getGraphicBuffer() {
    if (!mInit) {
        return nullptr;
    }
    GraphicBuffer *gb = ::android::AHardwareBuffer_to_GraphicBuffer(mBuf);
    if (!gb) {
        return nullptr;
    }
    gb->setGenerationNumber(mGeneration);
    return gb;
}

GraphicsTracker::BufferCache::~BufferCache() {
    ALOGV("BufferCache destruction: generation(%d), igbp(%d)", mGeneration, (bool)mIgbp);
}

void GraphicsTracker::BufferCache::waitOnSlot(int slot) {
    // TODO: log
    CHECK(0 <= slot && slot < kNumSlots);
    BlockedSlot *p = &mBlockedSlots[slot];
    std::unique_lock<std::mutex> l(p->l);
    while (p->blocked) {
        p->cv.wait(l);
    }
}

void GraphicsTracker::BufferCache::blockSlot(int slot) {
    CHECK(0 <= slot && slot < kNumSlots);
    ALOGV("block slot %d", slot);
    BlockedSlot *p = &mBlockedSlots[slot];
    std::unique_lock<std::mutex> l(p->l);
    p->blocked = true;
}

void GraphicsTracker::BufferCache::unblockSlot(int slot) {
    CHECK(0 <= slot && slot < kNumSlots);
    ALOGV("unblock slot %d", slot);
    BlockedSlot *p = &mBlockedSlots[slot];
    std::unique_lock<std::mutex> l(p->l);
    p->blocked = false;
    l.unlock();
    p->cv.notify_one();
}

GraphicsTracker::GraphicsTracker(int maxDequeueCount)
    : mBufferCache(new BufferCache()), mMaxDequeue{maxDequeueCount},
    mMaxDequeueCommitted{maxDequeueCount},
    mDequeueable{maxDequeueCount},
    mTotalDequeued{0}, mTotalCancelled{0}, mTotalDropped{0}, mTotalReleased{0},
    mInConfig{false}, mStopped{false} {
    if (maxDequeueCount < kMaxDequeueMin) {
        mMaxDequeue = kMaxDequeueMin;
        mMaxDequeueCommitted = kMaxDequeueMin;
        mDequeueable = kMaxDequeueMin;
    } else if(maxDequeueCount > kMaxDequeueMax) {
        mMaxDequeue = kMaxDequeueMax;
        mMaxDequeueCommitted = kMaxDequeueMax;
        mDequeueable = kMaxDequeueMax;
    }
    int pipefd[2] = { -1, -1};
    int ret = ::pipe2(pipefd, O_CLOEXEC | O_NONBLOCK);

    mReadPipeFd.reset(pipefd[0]);
    mWritePipeFd.reset(pipefd[1]);

    // ctor does not require lock to be held.
    writeIncDequeueableLocked(mDequeueable);

    CHECK(ret >= 0);
}

GraphicsTracker::~GraphicsTracker() {
    stop();
}

bool GraphicsTracker::adjustDequeueConfLocked(bool *updateDequeue) {
    // TODO: can't we adjust during config? not committing it may safe?
    *updateDequeue = false;
    if (!mInConfig && mMaxDequeueRequested.has_value() && mMaxDequeueRequested < mMaxDequeue) {
        int delta = mMaxDequeue - mMaxDequeueRequested.value();
        int drained = 0;
        // Since we are supposed to increase mDequeuable by one already
        int adjustable = mDequeueable + 1;
        if (adjustable >= delta) {
            mMaxDequeue = mMaxDequeueRequested.value();
            mDequeueable -= (delta - 1);
            drained = delta - 1;
        } else {
            mMaxDequeue -= adjustable;
            drained = mDequeueable;
            mDequeueable = 0;
        }
        if (drained > 0) {
            drainDequeueableLocked(drained);
        }
        if (mMaxDequeueRequested == mMaxDequeue && mMaxDequeueRequested != mMaxDequeueCommitted) {
            *updateDequeue = true;
        }
        return true;
    }
    return false;
}

c2_status_t GraphicsTracker::configureGraphics(
        const sp<IGraphicBufferProducer>& igbp, uint32_t generation) {
    // TODO: wait until operations to previous IGBP is completed.
    std::shared_ptr<BufferCache> prevCache;
    int prevDequeueCommitted;

    std::unique_lock<std::mutex> cl(mConfigLock);
    {
        std::unique_lock<std::mutex> l(mLock);
        mInConfig = true;
        prevCache = mBufferCache;
        prevDequeueCommitted = mMaxDequeueCommitted;
    }
    // NOTE: Switching to the same surface is blocked from MediaCodec.
    // Switching to the same surface might not work if tried, since disconnect()
    // to the old surface in MediaCodec and allocate from the new surface from
    // GraphicsTracker cannot be synchronized properly.
    uint64_t bqId{0ULL};
    ::android::status_t ret = ::android::OK;
    if (igbp) {
        ret = igbp->getUniqueId(&bqId);
    }
    if (ret != ::android::OK ||
            prevCache->mGeneration == generation) {
        ALOGE("new surface configure fail due to wrong or same bqId or same generation:"
              "igbp(%d:%llu -> %llu), gen(%lu -> %lu)", (bool)igbp,
              (unsigned long long)prevCache->mBqId, (unsigned long long)bqId,
              (unsigned long)prevCache->mGeneration, (unsigned long)generation);
        std::unique_lock<std::mutex> l(mLock);
        mInConfig = false;
        return C2_BAD_VALUE;
    }
    if (igbp) {
        ret = igbp->setMaxDequeuedBufferCount(prevDequeueCommitted);
        if (ret != ::android::OK) {
            ALOGE("new surface maxDequeueBufferCount configure fail");
            // TODO: sort out the error from igbp and return an error accordingly.
            std::unique_lock<std::mutex> l(mLock);
            mInConfig = false;
            return C2_CORRUPTED;
        }
    }
    ALOGD("new surface configured with id:%llu gen:%lu maxDequeue:%d",
          (unsigned long long)bqId, (unsigned long)generation, prevDequeueCommitted);
    std::shared_ptr<BufferCache> newCache = std::make_shared<BufferCache>(bqId, generation, igbp);
    {
        std::unique_lock<std::mutex> l(mLock);
        mInConfig = false;
        mBufferCache = newCache;
    }
    return C2_OK;
}

c2_status_t GraphicsTracker::configureMaxDequeueCount(int maxDequeueCount) {
    std::shared_ptr<BufferCache> cache;

    if (maxDequeueCount < kMaxDequeueMin || maxDequeueCount > kMaxDequeueMax) {
        ALOGE("max dequeue count %d is not valid", maxDequeueCount);
        return C2_BAD_VALUE;
    }

    // max dequeue count which can be committed to IGBP.
    // (Sometimes maxDequeueCount cannot be committed if the number of
    // dequeued buffer count is bigger.)
    int maxDequeueToCommit;
    std::unique_lock<std::mutex> cl(mConfigLock);
    {
        std::unique_lock<std::mutex> l(mLock);
        if (mMaxDequeueRequested.has_value()) {
            if (mMaxDequeueRequested == maxDequeueCount) {
                ALOGD("maxDequeueCount requested with %d already", maxDequeueCount);
                return C2_OK;
            }
        } else if (mMaxDequeue == maxDequeueCount) {
            ALOGD("maxDequeueCount is already %d", maxDequeueCount);
            return C2_OK;
        }
        mInConfig = true;
        mMaxDequeueRequested = maxDequeueCount;
        cache = mBufferCache;
        if (mMaxDequeue <= maxDequeueCount) {
            maxDequeueToCommit = maxDequeueCount;
        } else {
            // Since mDequeuable is decreasing,
            // a delievered ready to allocate event may not be fulfilled.
            // Another waiting via a waitable object may be necessary in the case.
            int delta = std::min(mMaxDequeue - maxDequeueCount, mDequeueable);
            maxDequeueToCommit = mMaxDequeue - delta;
            mDequeueable -= delta;
            if (delta > 0) {
                drainDequeueableLocked(delta);
            }
        }
    }

    bool committed = true;
    if (cache->mIgbp && maxDequeueToCommit != mMaxDequeueCommitted) {
        ::android::status_t ret = cache->mIgbp->setMaxDequeuedBufferCount(maxDequeueToCommit);
        committed = (ret == ::android::OK);
        if (committed) {
            ALOGD("maxDequeueCount committed to IGBP: %d", maxDequeueToCommit);
        } else {
            // This should not happen.
            ALOGE("maxdequeueCount update to IGBP failed with error(%d)", (int)ret);
        }
    }

    int oldMaxDequeue = 0;
    int requested = 0;
    {
        std::unique_lock<std::mutex> l(mLock);
        mInConfig = false;
        oldMaxDequeue = mMaxDequeue;
        mMaxDequeue = maxDequeueToCommit; // we already drained dequeueable
        if (committed) {
            clearCacheIfNecessaryLocked(cache, maxDequeueToCommit);
            mMaxDequeueCommitted = maxDequeueToCommit;
            if (mMaxDequeueRequested == mMaxDequeueCommitted &&
                  mMaxDequeueRequested == mMaxDequeue) {
                mMaxDequeueRequested.reset();
            }
            if (mMaxDequeueRequested.has_value()) {
                requested = mMaxDequeueRequested.value();
            }
            int delta = mMaxDequeueCommitted - oldMaxDequeue;
            if (delta > 0) {
                mDequeueable += delta;
                writeIncDequeueableLocked(delta);
            }
        }
    }
    ALOGD("maxDqueueCount change %d -> %d: pending: %d",
          oldMaxDequeue, maxDequeueToCommit, requested);

    if (!committed) {
        return C2_CORRUPTED;
    }
    return C2_OK;
}

void GraphicsTracker::updateDequeueConf() {
    std::shared_ptr<BufferCache> cache;
    int dequeueCommit;
    ALOGV("trying to update max dequeue count");
    std::unique_lock<std::mutex> cl(mConfigLock);
    {
        std::unique_lock<std::mutex> l(mLock);
        if (!mMaxDequeueRequested.has_value() || mMaxDequeue != mMaxDequeueRequested) {
            return;
        }
        if (mMaxDequeueCommitted == mMaxDequeueRequested) {
            // already committed. may not happen.
            mMaxDequeueRequested.reset();
            return;
        }
        dequeueCommit = mMaxDequeue;
        mInConfig = true;
        cache = mBufferCache;
    }
    bool committed = true;
    if (cache->mIgbp) {
        ::android::status_t ret = cache->mIgbp->setMaxDequeuedBufferCount(dequeueCommit);
        committed = (ret == ::android::OK);
        if (committed) {
            ALOGD("delayed maxDequeueCount update to IGBP: %d", dequeueCommit);
        } else {
            // This should not happen.
            ALOGE("delayed maxdequeueCount update to IGBP failed with error(%d)", (int)ret);
        }
    }
    {
        // cache == mCache here, since we locked config.
        std::unique_lock<std::mutex> l(mLock);
        mInConfig = false;
        if (committed) {
            clearCacheIfNecessaryLocked(cache, dequeueCommit);
            mMaxDequeueCommitted = dequeueCommit;
        }
        mMaxDequeueRequested.reset();
    }
}

void GraphicsTracker::clearCacheIfNecessaryLocked(const std::shared_ptr<BufferCache> &cache,
                                            int maxDequeueCommitted) {
    int cleared = 0;
    size_t origCacheSize = cache->mBuffers.size();
    if (cache->mIgbp && maxDequeueCommitted < mMaxDequeueCommitted) {
        // we are shrinking # of buffers in the case, so evict the previous
        // cached buffers.
        for (auto it = cache->mBuffers.begin(); it != cache->mBuffers.end();) {
            uint64_t bid = it->second->mId;
            if (mDequeued.count(bid) == 0 || mDeallocating.count(bid) > 0) {
                ++cleared;
                it = cache->mBuffers.erase(it);
            } else {
                ++it;
            }
        }
    }
    ALOGD("Cache size %zu -> %zu: maybe_cleared(%d), dequeued(%zu)",
          origCacheSize, cache->mBuffers.size(), cleared, mDequeued.size());
}

int GraphicsTracker::getCurDequeueable() {
    std::unique_lock<std::mutex> l(mLock);
    return mDequeueable;
}

void GraphicsTracker::stop() {
   // TODO: wait until all operation to current IGBP
   // being completed.
    std::unique_lock<std::mutex> l(mLock);
    if (mStopped) {
        return;
    }
    mStopped = true;
    int writeFd = mWritePipeFd.release();
    if (writeFd >= 0) {
        ::close(writeFd);
    }
}

void GraphicsTracker::writeIncDequeueableLocked(int inc) {
    CHECK(inc > 0 && inc < kMaxDequeueMax);
    thread_local char buf[kMaxDequeueMax];
    if (mStopped) { // reading end closed;
        return;
    }
    int writeFd = mWritePipeFd.get();
    if (writeFd < 0) {
        // initialization fail and not valid though.
        return;
    }
    int ret = ::write(writeFd, buf, inc);
    // Since this is non-blocking i/o, it never returns EINTR.
    //
    // ::write() to pipe guarantee to succeed atomically if it writes less than
    // the given PIPE_BUF. And the buffer size in pipe/fifo is at least 4K and our total
    // max pending buffer size is 64. So it never returns EAGAIN here either.
    // See pipe(7) for further information.
    //
    // Other errors are serious errors and we cannot synchronize mDequeueable to
    // length of pending buffer in pipe/fifo anymore. So better to abort here.
    // TODO: do not abort here. (b/318717399)
    CHECK(ret == inc);
}

void GraphicsTracker::drainDequeueableLocked(int dec) {
    CHECK(dec > 0 && dec < kMaxDequeueMax);
    thread_local char buf[kMaxDequeueMax];
    if (mStopped) {
        return;
    }
    int readFd = mReadPipeFd.get();
    if (readFd < 0) {
        // initializationf fail and not valid though.
        return;
    }
    int ret = ::read(readFd, buf, dec);
    // TODO: no dot abort here. (b/318717399)
    CHECK(ret == dec);
}

c2_status_t GraphicsTracker::getWaitableFd(int *pipeFd) {
    *pipeFd = ::dup(mReadPipeFd.get());
    if (*pipeFd < 0) {
        if (mReadPipeFd.get() < 0) {
            return C2_BAD_STATE;
        }
        // dup error
        ALOGE("dup() for the reading end failed %d", errno);
        return C2_NO_MEMORY;
    }
    return C2_OK;
}

c2_status_t GraphicsTracker::requestAllocate(std::shared_ptr<BufferCache> *cache) {
    std::lock_guard<std::mutex> l(mLock);
    if (mDequeueable > 0) {
        char buf[1];
        int ret = ::read(mReadPipeFd.get(), buf, 1);
        if (ret < 0) {
            if (errno == EINTR) {
                // Do we really need to care for cancel due to signal handling?
                return C2_CANCELED;
            }
            if (errno == EAGAIN) {
                // proper usage of waitable object should not return this.
                // but there could be alloc requests from HAL ignoring the internal status.
                return C2_BLOCKING;
            }
            CHECK(errno != 0);
        }
        if (ret == 0) {
            // writing end is closed
            ALOGE("writing end for the waitable object seems to be closed");
            return C2_BAD_STATE;
        }
        mDequeueable--;
        *cache = mBufferCache;
        return C2_OK;
    }
    return C2_BLOCKING;
}

// If {@code cached} is {@code true}, {@code pBuffer} should be read from the
// current cached status. Otherwise, {@code pBuffer} should be written to
// current caches status.
void GraphicsTracker::commitAllocate(c2_status_t res, const std::shared_ptr<BufferCache> &cache,
                    bool cached, int slot, const sp<Fence> &fence,
                    std::shared_ptr<BufferItem> *pBuffer, bool *updateDequeue) {
    std::unique_lock<std::mutex> l(mLock);
    if (res == C2_OK) {
        if (cached) {
            auto it = cache->mBuffers.find(slot);
            CHECK(it != cache->mBuffers.end());
            it->second->mFence = fence;
            *pBuffer = it->second;
            ALOGV("an allocated buffer already cached, updated Fence");
        } else if (cache.get() == mBufferCache.get() && mBufferCache->mIgbp) {
            // Cache the buffer if it is allocated from the current IGBP
            CHECK(slot >= 0);
            auto ret = mBufferCache->mBuffers.emplace(slot, *pBuffer);
            if (!ret.second) {
                ret.first->second = *pBuffer;
            }
            ALOGV("an allocated buffer not cached from the current IGBP");
        }
        uint64_t bid = (*pBuffer)->mId;
        auto mapRet = mDequeued.emplace(bid, *pBuffer);
        CHECK(mapRet.second);
    } else {
        if (adjustDequeueConfLocked(updateDequeue)) {
            return;
        }
        mDequeueable++;
        writeIncDequeueableLocked(1);
    }
}


// if a buffer is newly allocated, {@code cached} is {@code false},
// and the buffer is in the {@code buffer}
// otherwise, {@code cached} is {@code false} and the buffer should be
// retrieved by commitAllocate();
c2_status_t GraphicsTracker::_allocate(const std::shared_ptr<BufferCache> &cache,
                                      uint32_t width, uint32_t height, PixelFormat format,
                                      uint64_t usage,
                                      bool *cached,
                                      int *rSlotId,
                                      sp<Fence> *rFence,
                                      std::shared_ptr<BufferItem> *buffer) {
    ::android::sp<IGraphicBufferProducer> igbp = cache->mIgbp;
    uint32_t generation = cache->mGeneration;
    if (!igbp) {
        // allocate directly
        AHardwareBuffer_Desc desc;
        desc.width = width;
        desc.height = height;
        desc.layers = 1u;
        desc.format = ::android::AHardwareBuffer_convertFromPixelFormat(format);
        desc.usage = ::android::AHardwareBuffer_convertFromGrallocUsageBits(usage);
        desc.rfu0 = 0;
        desc.rfu1 = 0;

        AHardwareBuffer *buf;
        int ret = AHardwareBuffer_allocate(&desc, &buf);
        if (ret != ::android::OK) {
            ALOGE("direct allocation of AHB failed(%d)", ret);
            return ret == ::android::NO_MEMORY ? C2_NO_MEMORY : C2_CORRUPTED;
        }
        *cached = false;
        *rSlotId = -1;
        *rFence = Fence::NO_FENCE;
        *buffer = std::make_shared<BufferItem>(generation, buf, usage);
        AHardwareBuffer_release(buf); // remove an acquire count from
                                      // AHwb_allocate().
        if (!*buffer) {
            ALOGE("direct allocation of AHB successful, but failed to create BufferItem");
            return C2_NO_MEMORY;
        }
        if (!(*buffer)->mInit) {
            ALOGE("direct allocation of AHB successful, but BufferItem init failed");
            buffer->reset();
            return C2_CORRUPTED;
        }
        ALOGV("allocate: direct allocate without igbp");
        return C2_OK;
    }

    int slotId;
    uint64_t outBufferAge;
    ::android::FrameEventHistoryDelta outTimestamps;
    sp<Fence> fence;

    ::android::status_t status = igbp->dequeueBuffer(
            &slotId, &fence, width, height, format, usage, &outBufferAge, &outTimestamps);
    if (status < ::android::OK) {
        ALOGE("dequeueBuffer() error %d", (int)status);
        return C2_CORRUPTED;
    }
    cache->waitOnSlot(slotId);
    bool exists = false;
    {
        std::unique_lock<std::mutex> l(mLock);
        if (cache.get() == mBufferCache.get() &&
            cache->mBuffers.find(slotId) != cache->mBuffers.end()) {
            exists = true;
        }
    }
    bool needsRealloc = status & IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION;
    if (needsRealloc || !exists) {
        sp<GraphicBuffer> realloced;
        status = igbp->requestBuffer(slotId, &realloced);
        if (status != ::android::OK) {
            ALOGE("allocate by dequeueBuffer() successful, but requestBuffer() failed %d",
                  status);
            igbp->cancelBuffer(slotId, fence);
            return C2_CORRUPTED;
        }
        *buffer = std::make_shared<BufferItem>(generation, slotId, realloced, fence);
        if (!*buffer) {
            ALOGE("allocate by dequeueBuffer() successful, but creating BufferItem failed");
            igbp->cancelBuffer(slotId, fence);
            return C2_NO_MEMORY;
        }
        if (!(*buffer)->mInit) {
            ALOGE("allocate by dequeueBuffer() successful, but BufferItem init failed");
            buffer->reset();
            igbp->cancelBuffer(slotId, fence);
            return C2_CORRUPTED;
        }
        *cached = false;
    } else {
        *cached = true;
    }
    ALOGV("allocate: a new allocated buffer from igbp cached %d, slot: %d",
          *cached, slotId);
    *rSlotId = slotId;
    *rFence = fence;
    return C2_OK;
}

c2_status_t GraphicsTracker::allocate(
        uint32_t width, uint32_t height, PixelFormat format, uint64_t usage,
        AHardwareBuffer **buf, sp<Fence> *rFence) {
    if (mStopped.load() == true) {
        ALOGE("cannot allocate due to being stopped");
        return C2_BAD_STATE;
    }
    std::shared_ptr<BufferCache> cache;
    c2_status_t res = requestAllocate(&cache);
    if (res != C2_OK) {
        return res;
    }
    ALOGV("allocatable or dequeueable");

    bool cached = false;
    int slotId;
    sp<Fence> fence;
    std::shared_ptr<BufferItem> buffer;
    bool updateDequeue;
    res = _allocate(cache, width, height, format, usage, &cached, &slotId, &fence, &buffer);
    commitAllocate(res, cache, cached, slotId, fence, &buffer, &updateDequeue);
    if (res == C2_OK) {
        ALOGV("allocated a buffer width:%u height:%u pixelformat:%d usage:%llu",
              width, height, format, (unsigned long long)usage);
        *buf = buffer->mBuf;
        *rFence = buffer->mFence;
        // *buf should be valid even if buffer is dtor-ed.
        AHardwareBuffer_acquire(*buf);
    }
    if (updateDequeue) {
        updateDequeueConf();
    }
    return res;
}

c2_status_t GraphicsTracker::requestDeallocate(uint64_t bid, const sp<Fence> &fence,
                                              bool *completed, bool *updateDequeue,
                                              std::shared_ptr<BufferCache> *cache, int *slotId,
                                              sp<Fence> *rFence) {
    std::unique_lock<std::mutex> l(mLock);
    if (mDeallocating.find(bid) != mDeallocating.end()) {
        ALOGE("Tries to deallocate a buffer which is already deallocating or rendering");
        return C2_DUPLICATE;
    }
    auto it = mDequeued.find(bid);
    if (it == mDequeued.end()) {
        ALOGE("Tried to deallocate non dequeued buffer");
        return C2_NOT_FOUND;
    }

    std::shared_ptr<BufferItem> buffer = it->second;
    if (buffer->mGeneration == mBufferCache->mGeneration && mBufferCache->mIgbp) {
        auto it = mBufferCache->mBuffers.find(buffer->mSlot);
        CHECK(it != mBufferCache->mBuffers.end() && it->second.get() == buffer.get());
        *cache = mBufferCache;
        *slotId = buffer->mSlot;
        *rFence = ( fence == Fence::NO_FENCE) ? buffer->mFence : fence;
        // mark this deallocating
        mDeallocating.emplace(bid);
        mBufferCache->blockSlot(buffer->mSlot);
        *completed = false;
    } else { // buffer is not from the current underlying Graphics.
        mDequeued.erase(bid);
        *completed = true;
        if (adjustDequeueConfLocked(updateDequeue)) {
            return C2_OK;
        }
        mDequeueable++;
        writeIncDequeueableLocked(1);
    }
    return C2_OK;
}

void GraphicsTracker::commitDeallocate(
        std::shared_ptr<BufferCache> &cache, int slotId, uint64_t bid, bool *updateDequeue) {
    std::unique_lock<std::mutex> l(mLock);
    size_t del1 = mDequeued.erase(bid);
    size_t del2 = mDeallocating.erase(bid);
    CHECK(del1 > 0 && del2 > 0);
    if (cache) {
        cache->unblockSlot(slotId);
    }
    if (adjustDequeueConfLocked(updateDequeue)) {
        return;
    }
    mDequeueable++;
    writeIncDequeueableLocked(1);
}


c2_status_t GraphicsTracker::deallocate(uint64_t bid, const sp<Fence> &fence) {
    bool completed;
    bool updateDequeue;
    std::shared_ptr<BufferCache> cache;
    int slotId;
    sp<Fence> rFence;
    c2_status_t res = requestDeallocate(bid, fence, &completed, &updateDequeue,
                                        &cache, &slotId, &rFence);
    if (res != C2_OK) {
        return res;
    }
    if (completed == true) {
        if (updateDequeue) {
            updateDequeueConf();
        }
        return C2_OK;
    }

    // ignore return value since IGBP could be already stale.
    // cache->mIgbp is not null, if completed is false.
    (void)cache->mIgbp->cancelBuffer(slotId, rFence);

    commitDeallocate(cache, slotId, bid, &updateDequeue);
    if (updateDequeue) {
        updateDequeueConf();
    }
    return C2_OK;
}

c2_status_t GraphicsTracker::requestRender(uint64_t bid, std::shared_ptr<BufferCache> *cache,
                                          std::shared_ptr<BufferItem> *pBuffer,
                                          bool *fromCache,
                                          bool *updateDequeue) {
    std::unique_lock<std::mutex> l(mLock);
    if (mDeallocating.find(bid) != mDeallocating.end()) {
        ALOGE("Tries to render a buffer which is already deallocating or rendering");
        return C2_DUPLICATE;
    }
    auto it = mDequeued.find(bid);
    if (it == mDequeued.end()) {
        ALOGE("Tried to render non dequeued buffer");
        return C2_NOT_FOUND;
    }
    if (!mBufferCache->mIgbp) {
        // Render requested without surface.
        // reclaim the buffer for dequeue.
        // TODO: is this correct for API wise?
        mDequeued.erase(it);
        if (adjustDequeueConfLocked(updateDequeue)) {
            return C2_BAD_STATE;
        }
        mDequeueable++;
        writeIncDequeueableLocked(1);
        return C2_BAD_STATE;
    }
    std::shared_ptr<BufferItem> buffer = it->second;
    *cache = mBufferCache;
    if (buffer->mGeneration == mBufferCache->mGeneration) {
        auto it = mBufferCache->mBuffers.find(buffer->mSlot);
        CHECK(it != mBufferCache->mBuffers.end() && it->second.get() == buffer.get());
        mBufferCache->blockSlot(buffer->mSlot);
        *fromCache = true;
    } else {
        *fromCache = false;
    }
    *pBuffer = buffer;
    mDeallocating.emplace(bid);
    return C2_OK;
}

void GraphicsTracker::commitRender(const std::shared_ptr<BufferCache> &cache,
                                  const std::shared_ptr<BufferItem> &buffer,
                                  const std::shared_ptr<BufferItem> &oldBuffer,
                                  bool bufferReplaced,
                                  bool *updateDequeue) {
    std::unique_lock<std::mutex> l(mLock);
    uint64_t origBid = oldBuffer ? oldBuffer->mId : buffer->mId;

    if (cache) {
        cache->unblockSlot(buffer->mSlot);
        if (oldBuffer) {
            // migrated, register the new buffer to the cache.
            cache->mBuffers.emplace(buffer->mSlot, buffer);
        }
    }
    mDeallocating.erase(origBid);
    mDequeued.erase(origBid);

    if (cache.get() != mBufferCache.get() || bufferReplaced) {
        // Surface changed, no need to wait for buffer being released.
        if (adjustDequeueConfLocked(updateDequeue)) {
            return;
        }
        mDequeueable++;
        writeIncDequeueableLocked(1);
        return;
    }
}

c2_status_t GraphicsTracker::render(const C2ConstGraphicBlock& blk,
                                   const IGraphicBufferProducer::QueueBufferInput &input,
                                   IGraphicBufferProducer::QueueBufferOutput *output) {
    uint64_t bid;
    c2_status_t res = retrieveAHardwareBufferId(blk, &bid);
    if (res != C2_OK) {
        ALOGE("retrieving AHB-ID for GraphicBlock failed");
        return C2_CORRUPTED;
    }
    std::shared_ptr<_C2BlockPoolData> poolData =
            _C2BlockFactory::GetGraphicBlockPoolData(blk);
    _C2BlockFactory::DisownIgbaBlock(poolData);
    std::shared_ptr<BufferCache> cache;
    std::shared_ptr<BufferItem> buffer;
    std::shared_ptr<BufferItem> oldBuffer;
    bool updateDequeue = false;
    bool fromCache = false;
    res = requestRender(bid, &cache, &buffer, &fromCache, &updateDequeue);
    if (res != C2_OK) {
        if (updateDequeue) {
            updateDequeueConf();
        }
        return res;
    }
    int cacheSlotId = fromCache ? buffer->mSlot : -1;
    ALOGV("render prepared: igbp(%d) slot(%d)", bool(cache->mIgbp), cacheSlotId);
    if (!fromCache) {
        // The buffer does not come from the current cache.
        // The buffer is needed to be migrated(attached).
        uint64_t newUsage = 0ULL;

        (void) cache->mIgbp->getConsumerUsage(&newUsage);
        std::shared_ptr<BufferItem> newBuffer =
                buffer->migrateBuffer(newUsage, cache->mGeneration);
        sp<GraphicBuffer> gb = newBuffer ? newBuffer->getGraphicBuffer() : nullptr;

        if (!gb) {
            ALOGE("render: realloc-ing a new buffer for migration failed");
            std::shared_ptr<BufferCache> nullCache;
            commitDeallocate(nullCache, -1, bid, &updateDequeue);
            if (updateDequeue) {
                updateDequeueConf();
            }
            return C2_REFUSED;
        }
        if (cache->mIgbp->attachBuffer(&(newBuffer->mSlot), gb) != ::android::OK) {
            ALOGE("render: attaching a new buffer to IGBP failed");
            std::shared_ptr<BufferCache> nullCache;
            commitDeallocate(nullCache, -1, bid, &updateDequeue);
            if (updateDequeue) {
                updateDequeueConf();
            }
            return C2_REFUSED;
        }
        cache->waitOnSlot(newBuffer->mSlot);
        cache->blockSlot(newBuffer->mSlot);
        oldBuffer = buffer;
        buffer = newBuffer;
    }
    ::android::status_t renderRes = cache->mIgbp->queueBuffer(buffer->mSlot, input, output);
    ALOGV("render done: migration(%d), render(err = %d)", !fromCache, renderRes);
    if (renderRes != ::android::OK) {
        CHECK(renderRes != ::android::BAD_VALUE);
        ALOGE("render: failed to queueBuffer() err = %d", renderRes);
        (void) cache->mIgbp->cancelBuffer(buffer->mSlot, input.fence);
        commitDeallocate(cache, buffer->mSlot, bid, &updateDequeue);
        if (updateDequeue) {
            updateDequeueConf();
        }
        return C2_REFUSED;
    }

    commitRender(cache, buffer, oldBuffer, output->bufferReplaced, &updateDequeue);
    if (updateDequeue) {
        updateDequeueConf();
    }
    return C2_OK;
}

void GraphicsTracker::onReleased(uint32_t generation) {
    bool updateDequeue = false;
    {
        std::unique_lock<std::mutex> l(mLock);
        if (mBufferCache->mGeneration == generation) {
            if (!adjustDequeueConfLocked(&updateDequeue)) {
                mDequeueable++;
                writeIncDequeueableLocked(1);
            }
        }
    }
    if (updateDequeue) {
        updateDequeueConf();
    }
}

} // namespace aidl::android::hardware::media::c2::implementation
