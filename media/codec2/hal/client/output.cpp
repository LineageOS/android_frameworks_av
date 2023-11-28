/*
 * Copyright 2018 The Android Open Source Project
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
#define LOG_TAG "Codec2-OutputBufferQueue"
#define ATRACE_TAG  ATRACE_TAG_VIDEO
#include <android-base/logging.h>
#include <utils/Trace.h>

#include <android/hardware/graphics/bufferqueue/2.0/IGraphicBufferProducer.h>
#include <codec2/hidl/output.h>
#include <cutils/ashmem.h>
#include <gui/bufferqueue/2.0/B2HGraphicBufferProducer.h>
#include <sys/mman.h>

#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2PlatformSupport.h>
#include <C2SurfaceSyncObj.h>

#include <iomanip>

namespace android {
namespace hardware {
namespace media {
namespace c2 {

using HGraphicBufferProducer = ::android::hardware::graphics::bufferqueue::
        V2_0::IGraphicBufferProducer;
using B2HGraphicBufferProducer = ::android::hardware::graphics::bufferqueue::
        V2_0::utils::B2HGraphicBufferProducer;

namespace /* unnamed */ {

// Create a GraphicBuffer object from a graphic block.
sp<GraphicBuffer> createGraphicBuffer(const C2ConstGraphicBlock& block) {
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint64_t usage;
    uint32_t stride;
    uint32_t generation;
    uint64_t bqId;
    int32_t bqSlot;
    _UnwrapNativeCodec2GrallocMetadata(
            block.handle(), &width, &height, &format, &usage,
            &stride, &generation, &bqId, reinterpret_cast<uint32_t*>(&bqSlot));
    native_handle_t *grallocHandle =
            UnwrapNativeCodec2GrallocHandle(block.handle());
    sp<GraphicBuffer> graphicBuffer =
            new GraphicBuffer(grallocHandle,
                              GraphicBuffer::CLONE_HANDLE,
                              width, height, format,
                              1, usage, stride);
    native_handle_delete(grallocHandle);
    return graphicBuffer;
}

template <typename BlockProcessor>
void forEachBlock(C2FrameData& frameData,
                  BlockProcessor process) {
    for (const std::shared_ptr<C2Buffer>& buffer : frameData.buffers) {
        if (buffer) {
            for (const C2ConstGraphicBlock& block :
                    buffer->data().graphicBlocks()) {
                process(block);
            }
        }
    }
}

template <typename BlockProcessor>
void forEachBlock(const std::list<std::unique_ptr<C2Work>>& workList,
                  BlockProcessor process) {
    for (const std::unique_ptr<C2Work>& work : workList) {
        if (!work) {
            continue;
        }
        for (const std::unique_ptr<C2Worklet>& worklet : work->worklets) {
            if (worklet) {
                forEachBlock(worklet->output, process);
            }
        }
    }
}

sp<HGraphicBufferProducer> getHgbp(const sp<IGraphicBufferProducer>& igbp) {
    sp<HGraphicBufferProducer> hgbp =
            igbp->getHalInterface<HGraphicBufferProducer>();
    return hgbp ? hgbp :
            new B2HGraphicBufferProducer(igbp);
}

status_t attachToBufferQueue(const C2ConstGraphicBlock& block,
                             const sp<IGraphicBufferProducer>& igbp,
                             uint32_t generation,
                             int32_t* bqSlot,
                             std::shared_ptr<C2SurfaceSyncMemory> syncMem) {
    if (!igbp) {
        LOG(WARNING) << "attachToBufferQueue -- null producer.";
        return NO_INIT;
    }

    sp<GraphicBuffer> graphicBuffer = createGraphicBuffer(block);
    graphicBuffer->setGenerationNumber(generation);

    LOG(VERBOSE) << "attachToBufferQueue -- attaching buffer:"
            << " block dimension " << block.width() << "x"
                                   << block.height()
            << ", graphicBuffer dimension " << graphicBuffer->getWidth() << "x"
                                           << graphicBuffer->getHeight()
            << std::hex << std::setfill('0')
            << ", format 0x" << std::setw(8) << graphicBuffer->getPixelFormat()
            << ", usage 0x" << std::setw(16) << graphicBuffer->getUsage()
            << std::dec << std::setfill(' ')
            << ", stride " << graphicBuffer->getStride()
            << ", generation " << graphicBuffer->getGenerationNumber();

    C2SyncVariables *syncVar = syncMem ? syncMem->mem() : nullptr;
    status_t result = OK;
    if (syncVar) {
        syncVar->lock();
        if (!syncVar->isDequeueableLocked() ||
            syncVar->getSyncStatusLocked() == C2SyncVariables::STATUS_SWITCHING) {
            syncVar->unlock();
            LOG(WARNING) << "attachToBufferQueue -- attachBuffer failed: "
                            "status = " << INVALID_OPERATION << ".";
            return INVALID_OPERATION;
        }
        syncVar->notifyDequeuedLocked();
        syncVar->unlock();
        result = igbp->attachBuffer(bqSlot, graphicBuffer);
        if (result != OK) {
            syncVar->lock();
            syncVar->notifyQueuedLocked();
            syncVar->unlock();
        }
    } else {
        result = igbp->attachBuffer(bqSlot, graphicBuffer);
    }
    if (result != OK) {
        LOG(WARNING) << "attachToBufferQueue -- attachBuffer failed: "
                        "status = " << result << ".";
        return result;
    }
    LOG(VERBOSE) << "attachToBufferQueue -- attachBuffer returned slot #"
                 << *bqSlot << ".";
    return OK;
}

bool getBufferQueueAssignment(const C2ConstGraphicBlock& block,
                              uint32_t* generation,
                              uint64_t* bqId,
                              int32_t* bqSlot) {
    return _C2BlockFactory::GetBufferQueueData(
            _C2BlockFactory::GetGraphicBlockPoolData(block),
            generation, bqId, bqSlot);
}

} // unnamed namespace

OutputBufferQueue::OutputBufferQueue()
      : mGeneration{0}, mBqId{0}, mStopped{false} {
}

OutputBufferQueue::~OutputBufferQueue() {
}

bool OutputBufferQueue::configure(const sp<IGraphicBufferProducer>& igbp,
                                  uint32_t generation,
                                  uint64_t bqId,
                                  int maxDequeueBufferCount,
                                  std::shared_ptr<V1_2::SurfaceSyncObj> *syncObj) {
    uint64_t consumerUsage = 0;
    if (igbp && igbp->getConsumerUsage(&consumerUsage) != OK) {
        ALOGW("failed to get consumer usage");
    }

    // TODO : Abstract creation process into C2SurfaceSyncMemory class.
    // use C2LinearBlock instead ashmem.
    std::shared_ptr<C2SurfaceSyncMemory> syncMem;
    if (syncObj && igbp) {
        bool mapped = false;
        int memFd = ashmem_create_region("C2SurfaceMem", sizeof(C2SyncVariables));
        size_t memSize = memFd < 0 ? 0 : ashmem_get_size_region(memFd);
        if (memSize > 0) {
            syncMem = C2SurfaceSyncMemory::Create(memFd, memSize);
            if (syncMem) {
                mapped = true;
                *syncObj = std::make_shared<V1_2::SurfaceSyncObj>();
                (*syncObj)->syncMemory = syncMem->handle();
                (*syncObj)->bqId = bqId;
                (*syncObj)->generationId = generation;
                (*syncObj)->consumerUsage = consumerUsage;
                ALOGD("C2SurfaceSyncMemory created %zu(%zu)", sizeof(C2SyncVariables), memSize);
            }
        }
        if (!mapped) {
            if (memFd >= 0) {
                ::close(memFd);
            }
            ALOGW("SurfaceSyncObj creation failure");
        }
    }

    size_t tryNum = 0;
    size_t success = 0;
    sp<GraphicBuffer> buffers[BufferQueueDefs::NUM_BUFFER_SLOTS];
    std::weak_ptr<_C2BlockPoolData>
            poolDatas[BufferQueueDefs::NUM_BUFFER_SLOTS];
    std::shared_ptr<C2SurfaceSyncMemory> oldMem;
    {
        std::scoped_lock<std::mutex> l(mMutex);
        bool stopped = mStopped;
        mStopped = false;
        if (generation == mGeneration) {
            // case of old BlockPool destruction
            C2SyncVariables *var = mSyncMem ? mSyncMem->mem() : nullptr;
            if (syncObj && var) {
                *syncObj = std::make_shared<V1_2::SurfaceSyncObj>();
                (*syncObj)->bqId = bqId;
                (*syncObj)->syncMemory = mSyncMem->handle();
                (*syncObj)->generationId = generation;
                (*syncObj)->consumerUsage = consumerUsage;
                mMaxDequeueBufferCount = maxDequeueBufferCount;
                var->lock();
                var->setSyncStatusLocked(C2SyncVariables::STATUS_INIT);
                var->setInitialDequeueCountLocked(mMaxDequeueBufferCount, 0);
                var->unlock();
            }
            return false;
        }
        oldMem = mSyncMem;
        C2SyncVariables *oldSync = mSyncMem ? mSyncMem->mem() : nullptr;
        if (oldSync) {
            oldSync->lock();
            oldSync->setSyncStatusLocked(C2SyncVariables::STATUS_SWITCHING);
            oldSync->unlock();
        }
        mSyncMem.reset();
        if (syncMem) {
            mSyncMem = syncMem;
        }
        C2SyncVariables *newSync = mSyncMem ? mSyncMem->mem() : nullptr;

        mIgbp = igbp;
        mGeneration = generation;
        mBqId = bqId;
        mOwner = std::make_shared<int>(0);
        mMaxDequeueBufferCount = maxDequeueBufferCount;
        if (igbp == nullptr) {
            return false;
        }
        for (int i = 0; i < BufferQueueDefs::NUM_BUFFER_SLOTS; ++i) {
            if (mBqId == 0 || !mBuffers[i] || stopped) {
                continue;
            }
            std::shared_ptr<_C2BlockPoolData> data = mPoolDatas[i].lock();
            if (!data ||
                !_C2BlockFactory::BeginAttachBlockToBufferQueue(data)) {
                continue;
            }
            ++tryNum;
            int bqSlot;

            // Update buffer's generation and usage.
            if ((mBuffers[i]->getUsage() & consumerUsage) != consumerUsage) {
                mBuffers[i] = new GraphicBuffer(
                    mBuffers[i]->handle, GraphicBuffer::CLONE_HANDLE,
                    mBuffers[i]->width, mBuffers[i]->height,
                    mBuffers[i]->format, mBuffers[i]->layerCount,
                    mBuffers[i]->getUsage() | consumerUsage,
                    mBuffers[i]->stride);
                if (mBuffers[i]->initCheck() != OK) {
                    ALOGW("%s() failed to update usage, original usage=%" PRIx64
                          ", consumer usage=%" PRIx64,
                          __func__, mBuffers[i]->getUsage(), consumerUsage);
                    continue;
                }
            }
            mBuffers[i]->setGenerationNumber(generation);

            status_t result = igbp->attachBuffer(&bqSlot, mBuffers[i]);
            if (result != OK) {
                continue;
            }
            bool attach =
                    _C2BlockFactory::EndAttachBlockToBufferQueue(
                            data, mOwner, getHgbp(mIgbp), mSyncMem,
                            generation, bqId, bqSlot);
            if (!attach) {
                igbp->cancelBuffer(bqSlot, Fence::NO_FENCE);
                continue;
            }
            buffers[bqSlot] = mBuffers[i];
            poolDatas[bqSlot] = data;
            ++success;
        }
        for (int i = 0; i < BufferQueueDefs::NUM_BUFFER_SLOTS; ++i) {
            mBuffers[i] = buffers[i];
            mPoolDatas[i] = poolDatas[i];
        }
        if (newSync) {
            newSync->lock();
            newSync->setInitialDequeueCountLocked(mMaxDequeueBufferCount, success);
            newSync->unlock();
        }
    }
    {
        std::scoped_lock<std::mutex> l(mOldMutex);
        mOldMem = oldMem;
    }
    ALOGD("remote graphic buffer migration %zu/%zu",
          success, tryNum);
    return true;
}

void OutputBufferQueue::expireOldWaiters() {
    std::scoped_lock<std::mutex> l(mOldMutex);
    if (mOldMem) {
        C2SyncVariables *oldSync = mOldMem->mem();
        if (oldSync) {
            oldSync->notifyAll();
        }
        mOldMem.reset();
    }
}

void OutputBufferQueue::stop() {
    std::shared_ptr<C2SurfaceSyncMemory> oldMem;
    {
        std::scoped_lock<std::mutex> l(mMutex);
        if (mStopped) {
            return;
        }
        mStopped = true;
        mOwner.reset(); // destructor of the block will not trigger IGBP::cancel()
        // basically configuring null surface
        oldMem = mSyncMem;
        mSyncMem.reset();
        mIgbp.clear();
        mGeneration = 0;
        mBqId = 0;
    }
    {
        std::scoped_lock<std::mutex> l(mOldMutex);
        mOldMem = oldMem;
    }
}

bool OutputBufferQueue::registerBuffer(const C2ConstGraphicBlock& block) {
    std::shared_ptr<_C2BlockPoolData> data =
            _C2BlockFactory::GetGraphicBlockPoolData(block);
    if (!data) {
        return false;
    }
    std::scoped_lock<std::mutex> l(mMutex);

    if (!mIgbp || mStopped) {
        return false;
    }

    uint32_t oldGeneration;
    uint64_t oldId;
    int32_t oldSlot;
    // If the block is not bufferqueue-based, do nothing.
    if (!_C2BlockFactory::GetBufferQueueData(
            data, &oldGeneration, &oldId, &oldSlot) || (oldId == 0)) {
        return false;
    }
    // If the block's bqId is the same as the desired bqId, just hold.
    if ((oldId == mBqId) && (oldGeneration == mGeneration)) {
        LOG(VERBOSE) << "holdBufferQueueBlock -- import without attaching:"
                     << " bqId " << oldId
                     << ", bqSlot " << oldSlot
                     << ", generation " << mGeneration
                     << ".";
        _C2BlockFactory::HoldBlockFromBufferQueue(data, mOwner, getHgbp(mIgbp), mSyncMem);
        mPoolDatas[oldSlot] = data;
        mBuffers[oldSlot] = createGraphicBuffer(block);
        mBuffers[oldSlot]->setGenerationNumber(mGeneration);
        return true;
    }
    int32_t d = (int32_t) mGeneration - (int32_t) oldGeneration;
    LOG(WARNING) << "receiving stale buffer: generation "
                 << mGeneration << " , diff " << d  << " : slot "
                 << oldSlot;
    return false;
}

status_t OutputBufferQueue::outputBuffer(
        const C2ConstGraphicBlock& block,
        const BnGraphicBufferProducer::QueueBufferInput& input,
        BnGraphicBufferProducer::QueueBufferOutput* output) {
    uint32_t generation;
    uint64_t bqId;
    int32_t bqSlot;
    ScopedTrace trace(ATRACE_TAG,"Codec2-OutputBufferQueue::outputBuffer");
    bool display = V1_0::utils::displayBufferQueueBlock(block);
    if (!getBufferQueueAssignment(block, &generation, &bqId, &bqSlot) ||
        bqId == 0) {
        // Block not from bufferqueue -- it must be attached before queuing.

        std::shared_ptr<C2SurfaceSyncMemory> syncMem;
        mMutex.lock();
        bool stopped = mStopped;
        sp<IGraphicBufferProducer> outputIgbp = mIgbp;
        uint32_t outputGeneration = mGeneration;
        syncMem = mSyncMem;
        mMutex.unlock();

        if (stopped) {
            LOG(INFO) << "outputBuffer -- already stopped.";
            return DEAD_OBJECT;
        }

        status_t status = attachToBufferQueue(
                block, outputIgbp, outputGeneration, &bqSlot, syncMem);

        if (status != OK) {
            LOG(WARNING) << "outputBuffer -- attaching failed.";
            return INVALID_OPERATION;
        }

        auto syncVar = syncMem ? syncMem->mem() : nullptr;
        if(syncVar) {
            status = outputIgbp->queueBuffer(static_cast<int>(bqSlot),
                                         input, output);
            if (status == OK) {
                if (output->bufferReplaced) {
                    syncVar->lock();
                    syncVar->notifyQueuedLocked();
                    syncVar->unlock();
                }
            }
        } else {
            status = outputIgbp->queueBuffer(static_cast<int>(bqSlot),
                                         input, output);
        }
        if (status != OK) {
            LOG(ERROR) << "outputBuffer -- queueBuffer() failed "
                       "on non-bufferqueue-based block. "
                       "Error = " << status << ".";
            return status;
        }
        return OK;
    }

    std::shared_ptr<C2SurfaceSyncMemory> syncMem;
    mMutex.lock();
    bool stopped = mStopped;
    sp<IGraphicBufferProducer> outputIgbp = mIgbp;
    uint32_t outputGeneration = mGeneration;
    uint64_t outputBqId = mBqId;
    syncMem = mSyncMem;
    mMutex.unlock();

    if (stopped) {
        LOG(INFO) << "outputBuffer -- already stopped.";
        return DEAD_OBJECT;
    }

    if (!outputIgbp) {
        LOG(VERBOSE) << "outputBuffer -- output surface is null.";
        return NO_INIT;
    }

    if (!display) {
        LOG(WARNING) << "outputBuffer -- cannot display "
                     "bufferqueue-based block to the bufferqueue.";
        return UNKNOWN_ERROR;
    }
    if (bqId != outputBqId || generation != outputGeneration) {
        int32_t diff = (int32_t) outputGeneration - (int32_t) generation;
        LOG(WARNING) << "outputBuffer -- buffers from old generation to "
                     << outputGeneration << " , diff: " << diff
                     << " , slot: " << bqSlot;
        return DEAD_OBJECT;
    }

    auto syncVar = syncMem ? syncMem->mem() : nullptr;
    status_t status = OK;
    if (syncVar) {
        status = outputIgbp->queueBuffer(static_cast<int>(bqSlot),
                                                  input, output);
        if (status == OK) {
            if (output->bufferReplaced) {
                syncVar->lock();
                syncVar->notifyQueuedLocked();
                syncVar->unlock();
            }
        }
    } else {
        status = outputIgbp->queueBuffer(static_cast<int>(bqSlot),
                                                  input, output);
    }

    if (status != OK) {
        LOG(ERROR) << "outputBuffer -- queueBuffer() failed "
                   "on bufferqueue-based block. "
                   "Error = " << status << ".";
        return status;
    }
    return OK;
}

void OutputBufferQueue::onBufferReleased(uint32_t generation) {
    std::shared_ptr<C2SurfaceSyncMemory> syncMem;
    sp<IGraphicBufferProducer> outputIgbp;
    uint32_t outputGeneration = 0;
    {
        std::unique_lock<std::mutex> l(mMutex);
        if (mStopped) {
            return;
        }
        outputIgbp = mIgbp;
        outputGeneration = mGeneration;
        syncMem = mSyncMem;
    }

    if (outputIgbp && generation == outputGeneration) {
        auto syncVar = syncMem ? syncMem->mem() : nullptr;
        if (syncVar) {
            syncVar->lock();
            syncVar->notifyQueuedLocked();
            syncVar->unlock();
        }
    }
}

void OutputBufferQueue::pollForRenderedFrames(FrameEventHistoryDelta* delta) {
    if (mIgbp) {
        mIgbp->getFrameTimestamps(delta);
    }
}

void OutputBufferQueue::holdBufferQueueBlocks(
        const std::list<std::unique_ptr<C2Work>>& workList) {
    forEachBlock(workList,
                 std::bind(&OutputBufferQueue::registerBuffer,
                           this, std::placeholders::_1));
}

void OutputBufferQueue::updateMaxDequeueBufferCount(int maxDequeueBufferCount) {
    mMutex.lock();
    mMaxDequeueBufferCount = maxDequeueBufferCount;
    auto syncVar = mSyncMem ? mSyncMem->mem() : nullptr;
    if (syncVar && !mStopped) {
        syncVar->lock();
        syncVar->updateMaxDequeueCountLocked(maxDequeueBufferCount);
        syncVar->unlock();
    }
    mMutex.unlock();
    ALOGD("set max dequeue count %d from update", maxDequeueBufferCount);
}

}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
