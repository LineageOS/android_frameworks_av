/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef STAGEFRIGHT_CODEC2_BQ_BUFFER_PRIV_H_
#define STAGEFRIGHT_CODEC2_BQ_BUFFER_PRIV_H_

#include <android/hardware/graphics/bufferqueue/2.0/IGraphicBufferProducer.h>

#include <C2Buffer.h>
#include <C2BlockInternal.h>

#include <functional>

namespace android {
class GraphicBuffer;
}  // namespace android

class C2BufferQueueBlockPool : public C2BlockPool {
public:
    C2BufferQueueBlockPool(const std::shared_ptr<C2Allocator> &allocator, const local_id_t localId);

    virtual ~C2BufferQueueBlockPool() override;

    virtual C2Allocator::id_t getAllocatorId() const override {
        return mAllocator->getId();
    };

    virtual local_id_t getLocalId() const override {
        return mLocalId;
    };

    virtual c2_status_t fetchGraphicBlock(
            uint32_t width,
            uint32_t height,
            uint32_t format,
            C2MemoryUsage usage,
            std::shared_ptr<C2GraphicBlock> *block /* nonnull */) override;

    virtual c2_status_t fetchGraphicBlock(
            uint32_t width,
            uint32_t height,
            uint32_t format,
            C2MemoryUsage usage,
            std::shared_ptr<C2GraphicBlock> *block /* nonnull */,
            C2Fence *fence /* nonnull */) override;

    typedef std::function<void(uint64_t producer, int32_t slot, int64_t nsecs)> OnRenderCallback;

    /**
     * Sets render callback.
     *
     * \param renderCallbak callback to call for all dequeue buffer.
     */
    virtual void setRenderCallback(const OnRenderCallback &renderCallback = OnRenderCallback());

    typedef ::android::hardware::graphics::bufferqueue::V2_0::
            IGraphicBufferProducer HGraphicBufferProducer;
    /**
     * Configures an IGBP in order to create blocks. A newly created block is
     * dequeued from the configured IGBP. Unique Id of IGBP and the slot number of
     * blocks are passed via native_handle. Managing IGBP is responsibility of caller.
     * When IGBP is not configured, block will be created via allocator.
     * Since zero is not used for Unique Id of IGBP, if IGBP is not configured or producer
     * is configured as nullptr, unique id which is bundled in native_handle is zero.
     *
     * \param producer      the IGBP, which will be used to fetch blocks
     */
    virtual void configureProducer(const android::sp<HGraphicBufferProducer> &producer);

    /**
     * Configures an IGBP in order to create blocks. A newly created block is
     * dequeued from the configured IGBP. Unique Id of IGBP and the slot number of
     * blocks are passed via native_handle. Managing IGBP is responsibility of caller.
     * When IGBP is not configured, block will be created via allocator.
     * Since zero is not used for Unique Id of IGBP, if IGBP is not configured or producer
     * is configured as nullptr, unique id which is bundled in native_handle is zero.
     *
     * \param producer      the IGBP, which will be used to fetch blocks
     * \param syncMemory    Shared memory for synchronization of allocation & deallocation.
     * \param bqId          Id of IGBP
     * \param generationId  Generation Id for rendering output
     * \param consumerUsage consumerUsage flagof the IGBP
     */
    virtual void configureProducer(
            const android::sp<HGraphicBufferProducer> &producer,
            native_handle_t *syncMemory,
            uint64_t bqId,
            uint32_t generationId,
            uint64_t consumerUsage);

    virtual void getConsumerUsage(uint64_t *consumerUsage);

private:
    const std::shared_ptr<C2Allocator> mAllocator;
    const local_id_t mLocalId;

    class Impl;
    std::shared_ptr<Impl> mImpl;

    friend struct C2BufferQueueBlockPoolData;
};

class C2SurfaceSyncMemory;

struct C2BufferQueueBlockPoolData : public _C2BlockPoolData {
public:
    typedef ::android::hardware::graphics::bufferqueue::V2_0::
            IGraphicBufferProducer HGraphicBufferProducer;

    // Create a remote BlockPoolData.
    C2BufferQueueBlockPoolData(
            uint32_t generation, uint64_t bqId, int32_t bqSlot,
            const std::shared_ptr<int> &owner,
            const android::sp<HGraphicBufferProducer>& producer);

    // Create a local BlockPoolData.
    C2BufferQueueBlockPoolData(
            uint32_t generation, uint64_t bqId, int32_t bqSlot,
            const android::sp<HGraphicBufferProducer>& producer,
            std::shared_ptr<C2SurfaceSyncMemory>, int noUse);

    virtual ~C2BufferQueueBlockPoolData() override;

    virtual type_t getType() const override;

    int migrate(const android::sp<HGraphicBufferProducer>& producer,
                uint32_t toGeneration, uint64_t toUsage, uint64_t toBqId,
                android::sp<android::GraphicBuffer>& graphicBuffer, uint32_t oldGeneration,
                std::shared_ptr<C2SurfaceSyncMemory> syncMem);
private:
    friend struct _C2BlockFactory;

    // Methods delegated from _C2BlockFactory.
    void getBufferQueueData(uint32_t* generation, uint64_t* bqId, int32_t* bqSlot) const;
    bool holdBlockFromBufferQueue(const std::shared_ptr<int>& owner,
                                  const android::sp<HGraphicBufferProducer>& igbp,
                                  std::shared_ptr<C2SurfaceSyncMemory> syncMem);
    bool beginTransferBlockToClient();
    bool endTransferBlockToClient(bool transfer);
    bool beginAttachBlockToBufferQueue();
    bool endAttachBlockToBufferQueue(const std::shared_ptr<int>& owner,
                                     const android::sp<HGraphicBufferProducer>& igbp,
                                     std::shared_ptr<C2SurfaceSyncMemory> syncMem,
                                     uint32_t generation, uint64_t bqId, int32_t bqSlot);
    bool displayBlockToBufferQueue();

    const bool mLocal;
    bool mHeld;

    // Data of the corresponding buffer.
    uint32_t mGeneration;
    uint64_t mBqId;
    int32_t mBqSlot;

    // Data of the current IGBP, updated at migrate(). If the values are
    // mismatched, then the corresponding buffer will not be cancelled back to
    // IGBP at the destructor.
    uint32_t mCurrentGeneration;
    uint64_t mCurrentBqId;

    bool mTransfer; // local transfer to remote
    bool mAttach; // attach on remote
    bool mDisplay; // display on remote;
    std::weak_ptr<int> mOwner;
    android::sp<HGraphicBufferProducer> mIgbp;
    std::shared_ptr<C2SurfaceSyncMemory> mSyncMem;
    mutable std::mutex mLock;
};

#endif // STAGEFRIGHT_CODEC2_BUFFER_PRIV_H_
