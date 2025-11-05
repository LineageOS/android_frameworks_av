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

#include <C2Buffer.h>

#include <android-base/unique_fd.h>

#include <memory>

class C2IgbaInterface;

/**
 * Codec2-AIDL IGraphicBufferAllocator backed C2BlockPool
 *
 * Graphic Blocks are created using IGraphicBufferAllocator C2AIDL interface.
 * IGraphicBufferAllocator is wrapped as C2IgbaInterface in order not to
 * introduce unwanted dependency to HAL interface.
 */
class C2IgbaBlockPool : public C2BlockPool {
public:
    explicit C2IgbaBlockPool(
            const std::shared_ptr<C2Allocator> &allocator,
            const std::shared_ptr<C2IgbaInterface> &igba,
            ::android::base::unique_fd &&ufd,
            const bool blockFence,
            const local_id_t localId);

    virtual ~C2IgbaBlockPool() = default;

    virtual C2Allocator::id_t getAllocatorId() const override {
        return mAllocator->getId();
    }

    virtual local_id_t getLocalId() const override {
        return mLocalId;
    }

    /* Note: this is blocking due to H/W fence waiting */
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

    // Do we need this?
    void invalidate();

private:
    c2_status_t _fetchGraphicBlock(
        uint32_t width,
        uint32_t height,
        uint32_t format,
        C2MemoryUsage usage,
        c2_nsecs_t timeoutNs,
        bool blockFence,
        uint64_t *origId /* nonnull */,
        std::shared_ptr<C2GraphicBlock> *block /* nonnull */,
        C2Fence *fence /* nonnull */);

    const std::shared_ptr<C2Allocator> mAllocator;
    const std::shared_ptr<C2IgbaInterface> mIgba;
    const bool mBlockFence;
    const local_id_t mLocalId;
    std::atomic<bool> mValid;
    C2Fence mWaitFence;
};

typedef struct AHardwareBuffer AHardwareBuffer;

struct C2IgbaBlockPoolData : public _C2BlockPoolData {

    C2IgbaBlockPoolData(
            const AHardwareBuffer *buffer,
            std::shared_ptr<C2IgbaInterface> &igba);

    virtual ~C2IgbaBlockPoolData() override;

    virtual type_t getType() const override;

private:
    friend struct _C2BlockFactory;

    void getAHardwareBuffer(AHardwareBuffer **pBuf) const;

    void disown();

    void registerIgba(std::shared_ptr<C2IgbaInterface> &igba);

    bool mOwned;
    const AHardwareBuffer *mBuffer;
    std::weak_ptr<C2IgbaInterface> mIgba;
};
