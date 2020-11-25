/*
 * Copyright (C) 2019 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "C2AllocatorBlob"

#include <set>

#include <C2AllocatorBlob.h>
#include <C2PlatformSupport.h>

#include <android/hardware/graphics/common/1.2/types.h>
#include <utils/Log.h>

namespace android {

using ::android::hardware::graphics::common::V1_2::PixelFormat;

constexpr uint32_t kLinearBufferHeight = 1u;
constexpr uint32_t kLinearBufferFormat = static_cast<uint32_t>(PixelFormat::BLOB);

namespace {

c2_status_t GetCapacityFromHandle(const C2Handle* const grallocHandle, size_t* capacity) {
    uint32_t width, height, format, stride, generation, igbp_slot;
    uint64_t usage, igbp_id;
    _UnwrapNativeCodec2GrallocMetadata(grallocHandle, &width, &height, &format, &usage, &stride,
                                       &generation, &igbp_id, &igbp_slot);

    if (height != kLinearBufferHeight || format != kLinearBufferFormat) {
        return C2_BAD_VALUE;
    }
    *capacity = width;
    return C2_OK;
}

}  // namespace

// C2AllocationBlob is a wrapper for C2AllocationGralloc allocated by C2AllocatorGralloc.
// C2AllocationBlob::handle() delegates to the backed C2AllocationGralloc::handle().
class C2AllocationBlob : public C2LinearAllocation {
public:
    C2AllocationBlob(std::shared_ptr<C2GraphicAllocation> graphicAllocation, size_t capacity,
                     C2Allocator::id_t allocatorId);
    ~C2AllocationBlob() override;
    c2_status_t map(size_t offset, size_t size, C2MemoryUsage usage, C2Fence* fence,
                    void** addr /* nonnull */) override;
    c2_status_t unmap(void* addr, size_t size, C2Fence* fenceFd) override;

    id_t getAllocatorId() const override { return mAllocatorId; }
    const C2Handle* handle() const override { return mGraphicAllocation->handle(); }
    bool equals(const std::shared_ptr<C2LinearAllocation>& other) const override {
        return other && other->handle() == handle();
    }

private:
    const std::shared_ptr<C2GraphicAllocation> mGraphicAllocation;
    const C2Allocator::id_t mAllocatorId;

    std::mutex mMapLock;
    std::multiset<std::pair<size_t, size_t>> mMappedOffsetSize;
    uint8_t *mMappedAddr;
};

C2AllocationBlob::C2AllocationBlob(
        std::shared_ptr<C2GraphicAllocation> graphicAllocation, size_t capacity,
        C2Allocator::id_t allocatorId)
      : C2LinearAllocation(capacity),
        mGraphicAllocation(std::move(graphicAllocation)),
        mAllocatorId(allocatorId),
        mMappedAddr(nullptr) {}

C2AllocationBlob::~C2AllocationBlob() {
    if (mMappedAddr) {
        C2Rect rect(capacity(), kLinearBufferHeight);
        mGraphicAllocation->unmap(&mMappedAddr, rect, nullptr);
    }
}

c2_status_t C2AllocationBlob::map(size_t offset, size_t size, C2MemoryUsage usage,
                                  C2Fence* fence, void** addr /* nonnull */) {
    *addr = nullptr;
    if (size > capacity() || offset > capacity() || offset > capacity() - size) {
        ALOGV("C2AllocationBlob: map: bad offset / size: offset=%zu size=%zu capacity=%u",
                offset, size, capacity());
        return C2_BAD_VALUE;
    }
    std::unique_lock<std::mutex> lock(mMapLock);
    if (mMappedAddr) {
        *addr = mMappedAddr + offset;
        mMappedOffsetSize.insert({offset, size});
        ALOGV("C2AllocationBlob: mapped from existing mapping: offset=%zu size=%zu capacity=%u",
                offset, size, capacity());
        return C2_OK;
    }
    C2PlanarLayout layout;
    C2Rect rect = C2Rect(capacity(), kLinearBufferHeight);
    c2_status_t err = mGraphicAllocation->map(rect, usage, fence, &layout, &mMappedAddr);
    if (err != C2_OK) {
        ALOGV("C2AllocationBlob: map failed: offset=%zu size=%zu capacity=%u err=%d",
                offset, size, capacity(), err);
        mMappedAddr = nullptr;
        return err;
    }
    *addr = mMappedAddr + offset;
    mMappedOffsetSize.insert({offset, size});
    ALOGV("C2AllocationBlob: new map succeeded: offset=%zu size=%zu capacity=%u",
            offset, size, capacity());
    return C2_OK;
}

c2_status_t C2AllocationBlob::unmap(void* addr, size_t size, C2Fence* fenceFd) {
    std::unique_lock<std::mutex> lock(mMapLock);
    uint8_t *u8Addr = static_cast<uint8_t *>(addr);
    if (u8Addr < mMappedAddr || mMappedAddr + capacity() < u8Addr + size) {
        ALOGV("C2AllocationBlob: unmap: Bad addr / size: addr=%p size=%zu capacity=%u",
                addr, size, capacity());
        return C2_BAD_VALUE;
    }
    auto it = mMappedOffsetSize.find(std::make_pair(u8Addr - mMappedAddr, size));
    if (it == mMappedOffsetSize.end()) {
        ALOGV("C2AllocationBlob: unrecognized map: addr=%p size=%zu capacity=%u",
                addr, size, capacity());
        return C2_BAD_VALUE;
    }
    mMappedOffsetSize.erase(it);
    if (!mMappedOffsetSize.empty()) {
        ALOGV("C2AllocationBlob: still maintain mapping: addr=%p size=%zu capacity=%u",
                addr, size, capacity());
        return C2_OK;
    }
    C2Rect rect(capacity(), kLinearBufferHeight);
    c2_status_t err = mGraphicAllocation->unmap(&mMappedAddr, rect, fenceFd);
    ALOGV("C2AllocationBlob: last unmap: addr=%p size=%zu capacity=%u err=%d",
            addr, size, capacity(), err);
    mMappedAddr = nullptr;
    return err;
}

/* ====================================== BLOB ALLOCATOR ====================================== */
C2AllocatorBlob::C2AllocatorBlob(id_t id) {
    C2MemoryUsage minUsage = {0, 0};
    C2MemoryUsage maxUsage = {C2MemoryUsage::CPU_READ | C2MemoryUsage::READ_PROTECTED,
                              C2MemoryUsage::CPU_WRITE};
    Traits traits = {"android.allocator.blob", id, LINEAR, minUsage, maxUsage};
    mTraits = std::make_shared<C2Allocator::Traits>(traits);
    auto allocatorStore = GetCodec2PlatformAllocatorStore();
    allocatorStore->fetchAllocator(C2PlatformAllocatorStore::GRALLOC, &mC2AllocatorGralloc);
    if (!mC2AllocatorGralloc) {
        ALOGE("Failed to obtain C2AllocatorGralloc as backed allocator");
    }
}

C2AllocatorBlob::~C2AllocatorBlob() {}

c2_status_t C2AllocatorBlob::newLinearAllocation(
        uint32_t capacity, C2MemoryUsage usage, std::shared_ptr<C2LinearAllocation>* allocation) {
    if (allocation == nullptr) {
        return C2_BAD_VALUE;
    }

    allocation->reset();

    if (!mC2AllocatorGralloc) {
        return C2_CORRUPTED;
    }

    std::shared_ptr<C2GraphicAllocation> graphicAllocation;
    c2_status_t status = mC2AllocatorGralloc->newGraphicAllocation(
            capacity, kLinearBufferHeight, kLinearBufferFormat, usage, &graphicAllocation);
    if (status != C2_OK) {
        ALOGE("Failed newGraphicAllocation");
        return status;
    }

    allocation->reset(new C2AllocationBlob(std::move(graphicAllocation),
                                           static_cast<size_t>(capacity), mTraits->id));
    return C2_OK;
}

c2_status_t C2AllocatorBlob::priorLinearAllocation(
        const C2Handle* handle, std::shared_ptr<C2LinearAllocation>* allocation) {
    if (allocation == nullptr) {
        return C2_BAD_VALUE;
    }

    allocation->reset();

    if (!mC2AllocatorGralloc) {
        return C2_CORRUPTED;
    }

    std::shared_ptr<C2GraphicAllocation> graphicAllocation;
    c2_status_t status = mC2AllocatorGralloc->priorGraphicAllocation(handle, &graphicAllocation);
    if (status != C2_OK) {
        ALOGE("Failed priorGraphicAllocation");
        return status;
    }

    const C2Handle* const grallocHandle = graphicAllocation->handle();
    size_t capacity = 0;
    status = GetCapacityFromHandle(grallocHandle, &capacity);
    if (status != C2_OK) {
        ALOGE("Failed to extract capacity from Handle");
        return status;
    }

    allocation->reset(new C2AllocationBlob(std::move(graphicAllocation), capacity, mTraits->id));
    return C2_OK;
}

id_t C2AllocatorBlob::getId() const {
    return mTraits->id;
}

C2String C2AllocatorBlob::getName() const {
    return mTraits->name;
}

std::shared_ptr<const C2Allocator::Traits> C2AllocatorBlob::getTraits() const {
    return mTraits;
}

// static
bool C2AllocatorBlob::isValid(const C2Handle* const o) {
    size_t capacity;
    // Distinguish C2Handle purely allocated by C2AllocatorGralloc, or one allocated through
    // C2AllocatorBlob, by checking the handle's height is 1, and its format is
    // PixelFormat::BLOB by GetCapacityFromHandle().
    return C2AllocatorGralloc::isValid(o) && GetCapacityFromHandle(o, &capacity) == C2_OK;
}

}  // namespace android
