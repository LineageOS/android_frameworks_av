/*
 * Copyright (C) 2016 The Android Open Source Project
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
#define LOG_TAG "C2AllocatorGralloc"
#include <utils/Log.h>

#include <android/hardware/graphics/allocator/2.0/IAllocator.h>
#include <android/hardware/graphics/mapper/2.0/IMapper.h>
#include <hardware/gralloc.h>

#include <C2AllocatorGralloc.h>
#include <C2Buffer.h>

namespace android {

using ::android::hardware::graphics::allocator::V2_0::IAllocator;
using ::android::hardware::graphics::common::V1_0::BufferUsage;
using ::android::hardware::graphics::common::V1_0::PixelFormat;
using ::android::hardware::graphics::mapper::V2_0::BufferDescriptor;
using ::android::hardware::graphics::mapper::V2_0::Error;
using ::android::hardware::graphics::mapper::V2_0::IMapper;
using ::android::hardware::graphics::mapper::V2_0::YCbCrLayout;
using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_vec;

/* ===================================== GRALLOC ALLOCATION ==================================== */
static c2_status_t maperr2error(Error maperr) {
    switch (maperr) {
        case Error::NONE:           return C2_OK;
        case Error::BAD_DESCRIPTOR: return C2_BAD_VALUE;
        case Error::BAD_BUFFER:     return C2_BAD_VALUE;
        case Error::BAD_VALUE:      return C2_BAD_VALUE;
        case Error::NO_RESOURCES:   return C2_NO_MEMORY;
        case Error::UNSUPPORTED:    return C2_CANNOT_DO;
    }
    return C2_CORRUPTED;
}

class C2AllocationGralloc : public C2GraphicAllocation {
public:
    virtual ~C2AllocationGralloc() override;

    virtual c2_status_t map(
            C2Rect rect, C2MemoryUsage usage, int *fenceFd,
            C2PlanarLayout *layout /* nonnull */, uint8_t **addr /* nonnull */) override;
    virtual c2_status_t unmap(C2Fence *fenceFd /* nullable */) override;
    virtual bool isValid() const override { return true; }
    virtual const C2Handle *handle() const override { return mHandle; }
    virtual bool equals(const std::shared_ptr<const C2GraphicAllocation> &other) const override;

    // internal methods
    // |handle| will be moved.
    C2AllocationGralloc(
              const IMapper::BufferDescriptorInfo &info,
              const sp<IMapper> &mapper,
              hidl_handle &handle);
    int dup() const;
    c2_status_t status() const;

private:
    const IMapper::BufferDescriptorInfo mInfo;
    const sp<IMapper> mMapper;
    const hidl_handle mHandle;
    buffer_handle_t mBuffer;
    bool mLocked;
};

C2AllocationGralloc::C2AllocationGralloc(
          const IMapper::BufferDescriptorInfo &info,
          const sp<IMapper> &mapper,
          hidl_handle &handle)
    : C2GraphicAllocation(info.width, info.height),
      mInfo(info),
      mMapper(mapper),
      mHandle(std::move(handle)),
      mBuffer(nullptr),
      mLocked(false) {}

C2AllocationGralloc::~C2AllocationGralloc() {
    if (!mBuffer) {
        return;
    }
    if (mLocked) {
        unmap(nullptr);
    }
    mMapper->freeBuffer(const_cast<native_handle_t *>(mBuffer));
}

c2_status_t C2AllocationGralloc::map(
        C2Rect rect, C2MemoryUsage usage, int *fenceFd,
        C2PlanarLayout *layout /* nonnull */, uint8_t **addr /* nonnull */) {
    // TODO
    (void) fenceFd;
    (void) usage;

    if (mBuffer && mLocked) {
        return C2_DUPLICATE;
    }
    if (!layout || !addr) {
        return C2_BAD_VALUE;
    }

    c2_status_t err = C2_OK;
    if (!mBuffer) {
        mMapper->importBuffer(
                mHandle, [&err, this](const auto &maperr, const auto &buffer) {
                    err = maperr2error(maperr);
                    if (err == C2_OK) {
                        mBuffer = static_cast<buffer_handle_t>(buffer);
                    }
                });
        if (err != C2_OK) {
            return err;
        }
    }

    if (mInfo.format == PixelFormat::YCBCR_420_888 || mInfo.format == PixelFormat::YV12) {
        YCbCrLayout ycbcrLayout;
        mMapper->lockYCbCr(
                const_cast<native_handle_t *>(mBuffer),
                BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN,
                { (int32_t)rect.left, (int32_t)rect.top, (int32_t)rect.width, (int32_t)rect.height },
                // TODO: fence
                hidl_handle(),
                [&err, &ycbcrLayout](const auto &maperr, const auto &mapLayout) {
                    err = maperr2error(maperr);
                    if (err == C2_OK) {
                        ycbcrLayout = mapLayout;
                    }
                });
        if (err != C2_OK) {
            return err;
        }
        addr[C2PlanarLayout::PLANE_Y] = (uint8_t *)ycbcrLayout.y;
        addr[C2PlanarLayout::PLANE_U] = (uint8_t *)ycbcrLayout.cb;
        addr[C2PlanarLayout::PLANE_V] = (uint8_t *)ycbcrLayout.cr;
        layout->type = C2PlanarLayout::TYPE_YUV;
        layout->numPlanes = 3;
        layout->planes[C2PlanarLayout::PLANE_Y] = {
            C2PlaneInfo::CHANNEL_Y,         // channel
            1,                              // colInc
            (int32_t)ycbcrLayout.yStride,   // rowInc
            1,                              // mColSampling
            1,                              // mRowSampling
            8,                              // allocatedDepth
            8,                              // bitDepth
            0,                              // rightShift
            C2PlaneInfo::NATIVE,            // endianness
        };
        layout->planes[C2PlanarLayout::PLANE_U] = {
            C2PlaneInfo::CHANNEL_CB,          // channel
            (int32_t)ycbcrLayout.chromaStep,  // colInc
            (int32_t)ycbcrLayout.cStride,     // rowInc
            2,                                // mColSampling
            2,                                // mRowSampling
            8,                                // allocatedDepth
            8,                                // bitDepth
            0,                                // rightShift
            C2PlaneInfo::NATIVE,              // endianness
        };
        layout->planes[C2PlanarLayout::PLANE_V] = {
            C2PlaneInfo::CHANNEL_CR,          // channel
            (int32_t)ycbcrLayout.chromaStep,  // colInc
            (int32_t)ycbcrLayout.cStride,     // rowInc
            2,                                // mColSampling
            2,                                // mRowSampling
            8,                                // allocatedDepth
            8,                                // bitDepth
            0,                                // rightShift
            C2PlaneInfo::NATIVE,              // endianness
        };
    } else {
        void *pointer = nullptr;
        mMapper->lock(
                const_cast<native_handle_t *>(mBuffer),
                BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN,
                { (int32_t)rect.left, (int32_t)rect.top, (int32_t)rect.width, (int32_t)rect.height },
                // TODO: fence
                hidl_handle(),
                [&err, &pointer](const auto &maperr, const auto &mapPointer) {
                    err = maperr2error(maperr);
                    if (err == C2_OK) {
                        pointer = mapPointer;
                    }
                });
        if (err != C2_OK) {
            return err;
        }
        // TODO
        return C2_OMITTED;
    }
    mLocked = true;

    return C2_OK;
}

c2_status_t C2AllocationGralloc::unmap(C2Fence *fenceFd /* nullable */) {
    // TODO: fence
    c2_status_t err = C2_OK;
    mMapper->unlock(
            const_cast<native_handle_t *>(mBuffer),
            [&err, &fenceFd](const auto &maperr, const auto &releaseFence) {
                // TODO
                (void) fenceFd;
                (void) releaseFence;
                err = maperr2error(maperr);
                if (err == C2_OK) {
                    // TODO: fence
                }
            });
    if (err == C2_OK) {
        mLocked = false;
    }
    return err;
}

bool C2AllocationGralloc::equals(const std::shared_ptr<const C2GraphicAllocation> &other) const {
    return other && other->handle() == handle();
}

/* ===================================== GRALLOC ALLOCATOR ==================================== */
class C2AllocatorGralloc::Impl {
public:
    Impl();

    id_t getId() const;

    C2String getName() const;

    c2_status_t newGraphicAllocation(
            uint32_t width, uint32_t height, uint32_t format, const C2MemoryUsage &usage,
            std::shared_ptr<C2GraphicAllocation> *allocation);

    c2_status_t priorGraphicAllocation(
            const C2Handle *handle,
            std::shared_ptr<C2GraphicAllocation> *allocation);

    c2_status_t status() const { return mInit; }

private:
    c2_status_t mInit;
    sp<IAllocator> mAllocator;
    sp<IMapper> mMapper;
};

C2AllocatorGralloc::Impl::Impl() : mInit(C2_OK) {
    // TODO: share a global service
    mAllocator = IAllocator::getService();
    mMapper = IMapper::getService();
    if (mAllocator == nullptr || mMapper == nullptr) {
        mInit = C2_CORRUPTED;
    }
}

C2Allocator::id_t C2AllocatorGralloc::Impl::getId() const {
    return 1; /// \todo implement ID
}

C2String C2AllocatorGralloc::Impl::getName() const {
    return "android.allocator.gralloc";
}

c2_status_t C2AllocatorGralloc::Impl::newGraphicAllocation(
        uint32_t width, uint32_t height, uint32_t format, const C2MemoryUsage &usage,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    // TODO: buffer usage should be determined according to |usage|
    (void) usage;

    IMapper::BufferDescriptorInfo info = {
        width,
        height,
        1u,  // layerCount
        (PixelFormat)format,
        BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN,
    };
    c2_status_t err = C2_OK;
    BufferDescriptor desc;
    mMapper->createDescriptor(
            info, [&err, &desc](const auto &maperr, const auto &descriptor) {
                err = maperr2error(maperr);
                if (err == C2_OK) {
                    desc = descriptor;
                }
            });
    if (err != C2_OK) {
        return err;
    }

    // IAllocator shares IMapper error codes.
    hidl_handle buffer;
    mAllocator->allocate(
            desc,
            1u,
            [&err, &buffer](const auto &maperr, const auto &stride, auto &buffers) {
                (void) stride;
                err = maperr2error(maperr);
                if (err != C2_OK) {
                    return;
                }
                if (buffers.size() != 1u) {
                    err = C2_CORRUPTED;
                    return;
                }
                buffer = std::move(buffers[0]);
            });
    if (err != C2_OK) {
        return err;
    }

    allocation->reset(new C2AllocationGralloc(info, mMapper, buffer));
    return C2_OK;
}

c2_status_t C2AllocatorGralloc::Impl::priorGraphicAllocation(
        const C2Handle *handle,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    (void) handle;

    // TODO: need to figure out BufferDescriptorInfo from the handle.
    allocation->reset();
    return C2_OMITTED;
}

C2AllocatorGralloc::C2AllocatorGralloc() : mImpl(new Impl) {}

C2AllocatorGralloc::~C2AllocatorGralloc() { delete mImpl; }

C2Allocator::id_t C2AllocatorGralloc::getId() const {
    return mImpl->getId();
}

C2String C2AllocatorGralloc::getName() const {
    return mImpl->getName();
}

c2_status_t C2AllocatorGralloc::newGraphicAllocation(
        uint32_t width, uint32_t height, uint32_t format, C2MemoryUsage usage,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    return mImpl->newGraphicAllocation(width, height, format, usage, allocation);
}

c2_status_t C2AllocatorGralloc::priorGraphicAllocation(
        const C2Handle *handle,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    return mImpl->priorGraphicAllocation(handle, allocation);
}

c2_status_t C2AllocatorGralloc::status() const {
    return mImpl->status();
}

} // namespace android
