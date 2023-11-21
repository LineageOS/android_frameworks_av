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

#ifndef CODEC2_HIDL_V1_0_UTILS_OUTPUT_BUFFER_QUEUE
#define CODEC2_HIDL_V1_0_UTILS_OUTPUT_BUFFER_QUEUE

#include <gui/FrameTimestamps.h>
#include <gui/IGraphicBufferProducer.h>
#include <codec2/hidl/1.0/types.h>
#include <codec2/hidl/1.2/types.h>
#include <C2Work.h>

struct C2_HIDE _C2BlockPoolData;
class C2SurfaceSyncMemory;

namespace android {
namespace hardware {
namespace media {
namespace c2 {


// BufferQueue-Based Block Operations
// ==================================

// Manage BufferQueue and graphic blocks for both component and codec.
// Manage graphic blocks ownership consistently during surface change.
struct OutputBufferQueue {

    OutputBufferQueue();

    ~OutputBufferQueue();

    // Configure a new surface to render graphic blocks.
    // Graphic blocks from older surface will be migrated to new surface.
    bool configure(const sp<IGraphicBufferProducer>& igbp,
                   uint32_t generation,
                   uint64_t bqId,
                   int maxDequeueBufferCount,
                   std::shared_ptr<V1_2::SurfaceSyncObj> *syncObj);

    // If there are waiters to allocate from the old surface, wake up and expire
    // them.
    void expireOldWaiters();

    // Stop using the current output surface. Pending buffer opeations will not
    // perform anymore.
    void stop();

    // Render a graphic block to current surface.
    status_t outputBuffer(
            const C2ConstGraphicBlock& block,
            const BnGraphicBufferProducer::QueueBufferInput& input,
            BnGraphicBufferProducer::QueueBufferOutput* output);

    // Nofify a buffer is released from the output surface. If HAL ver is 1.2
    // update the number of dequeueable/allocatable buffers.
    void onBufferReleased(uint32_t generation);

    // Retrieve frame event history from the output surface.
    void pollForRenderedFrames(FrameEventHistoryDelta* delta);

    // Call holdBufferQueueBlock() on output blocks in the given workList.
    // The OutputBufferQueue will take the ownership of output blocks.
    //
    // Note: This function should be called after WorkBundle has been received
    // from another process.
    void holdBufferQueueBlocks(
            const std::list<std::unique_ptr<C2Work>>& workList);

    // Update # of max dequeue buffer from BQ. If # of max dequeued buffer is shared
    // via shared memory between HAL and framework, Update # of max dequeued buffer
    // and synchronize.
    void updateMaxDequeueBufferCount(int maxDequeueBufferCount);

private:

    std::mutex mMutex;
    sp<IGraphicBufferProducer> mIgbp;
    uint32_t mGeneration;
    uint64_t mBqId;
    int32_t mMaxDequeueBufferCount;
    std::shared_ptr<int> mOwner;
    // To migrate existing buffers
    sp<GraphicBuffer> mBuffers[BufferQueueDefs::NUM_BUFFER_SLOTS]; // find a better way
    std::weak_ptr<_C2BlockPoolData> mPoolDatas[BufferQueueDefs::NUM_BUFFER_SLOTS];
    std::shared_ptr<C2SurfaceSyncMemory> mSyncMem;
    bool mStopped;
    std::mutex mOldMutex;
    std::shared_ptr<C2SurfaceSyncMemory> mOldMem;

    bool registerBuffer(const C2ConstGraphicBlock& block);
};

}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // CODEC2_HIDL_V1_0_UTILS_OUTPUT_BUFFER_QUEUE
