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

#include <mutex>

#include <android/hardware/graphics/common/1.2/types.h>
#include <cutils/native_handle.h>
#include <hardware/gralloc.h>
#include <ui/GraphicBufferAllocator.h>
#include <ui/GraphicBufferMapper.h>

#include <C2AllocatorGralloc.h>
#include <C2Buffer.h>
#include <C2PlatformSupport.h>

using ::android::hardware::hidl_handle;
using PixelFormat4 = ::android::hardware::graphics::common::V1_2::PixelFormat;

namespace android {

namespace /* unnamed */ {
    enum : uint64_t {
        /**
         * Usage mask that is passed through from gralloc to Codec 2.0 usage.
         */
        PASSTHROUGH_USAGE_MASK =
            ~(GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK | GRALLOC_USAGE_PROTECTED)
    };

    // verify that passthrough mask is within the platform mask
    static_assert((~C2MemoryUsage::PLATFORM_MASK & PASSTHROUGH_USAGE_MASK) == 0, "");
} // unnamed

C2MemoryUsage C2AndroidMemoryUsage::FromGrallocUsage(uint64_t usage) {
    // gralloc does not support WRITE_PROTECTED
    return C2MemoryUsage(
            ((usage & GRALLOC_USAGE_SW_READ_MASK) ? C2MemoryUsage::CPU_READ : 0) |
            ((usage & GRALLOC_USAGE_SW_WRITE_MASK) ? C2MemoryUsage::CPU_WRITE : 0) |
            ((usage & GRALLOC_USAGE_PROTECTED) ? C2MemoryUsage::READ_PROTECTED : 0) |
            (usage & PASSTHROUGH_USAGE_MASK));
}

uint64_t C2AndroidMemoryUsage::asGrallocUsage() const {
    // gralloc does not support WRITE_PROTECTED
    return (((expected & C2MemoryUsage::CPU_READ) ? GRALLOC_USAGE_SW_READ_OFTEN : 0) |
            ((expected & C2MemoryUsage::CPU_WRITE) ? GRALLOC_USAGE_SW_WRITE_OFTEN : 0) |
            ((expected & C2MemoryUsage::READ_PROTECTED) ? GRALLOC_USAGE_PROTECTED : 0) |
            (expected & PASSTHROUGH_USAGE_MASK));
}

namespace /* unnamed */ {

/* ===================================== GRALLOC ALLOCATION ==================================== */
bool native_handle_is_invalid(const native_handle_t *const handle) {
    // perform basic validation of a native handle
    if (handle == nullptr) {
        // null handle is considered valid
        return false;
    }
    return ((size_t)handle->version != sizeof(native_handle_t) ||
            handle->numFds < 0 ||
            handle->numInts < 0 ||
            // for sanity assume handles must occupy less memory than INT_MAX bytes
            handle->numFds > int((INT_MAX - handle->version) / sizeof(int)) - handle->numInts);
}

class C2HandleGralloc : public C2Handle {
private:
    struct ExtraData {
        uint32_t width;
        uint32_t height;
        uint32_t format;
        uint32_t usage_lo;
        uint32_t usage_hi;
        uint32_t stride;
        uint32_t generation;
        uint32_t igbp_id_lo;
        uint32_t igbp_id_hi;
        uint32_t igbp_slot;
        uint32_t magic;
    };

    enum {
        NUM_INTS = sizeof(ExtraData) / sizeof(int),
    };
    const static uint32_t MAGIC = '\xc2gr\x00';

    static
    const ExtraData* getExtraData(const C2Handle *const handle) {
        if (handle == nullptr
                || native_handle_is_invalid(handle)
                || handle->numInts < NUM_INTS) {
            return nullptr;
        }
        return reinterpret_cast<const ExtraData*>(
                &handle->data[handle->numFds + handle->numInts - NUM_INTS]);
    }

    static
    ExtraData *getExtraData(C2Handle *const handle) {
        return const_cast<ExtraData *>(getExtraData(const_cast<const C2Handle *const>(handle)));
    }

public:
    void getIgbpData(uint32_t *generation, uint64_t *igbp_id, uint32_t *igbp_slot) const {
        const ExtraData *ed = getExtraData(this);
        *generation = ed->generation;
        *igbp_id = unsigned(ed->igbp_id_lo) | uint64_t(unsigned(ed->igbp_id_hi)) << 32;
        *igbp_slot = ed->igbp_slot;
    }

    static bool isValid(const C2Handle *const o) {
        if (o == nullptr) { // null handle is always valid
            return true;
        }
        const ExtraData *xd = getExtraData(o);
        // we cannot validate width/height/format/usage without accessing gralloc driver
        return xd != nullptr && xd->magic == MAGIC;
    }

    static C2HandleGralloc* WrapAndMoveNativeHandle(
            const native_handle_t *const handle,
            uint32_t width, uint32_t height, uint32_t format, uint64_t usage,
            uint32_t stride, uint32_t generation, uint64_t igbp_id = 0, uint32_t igbp_slot = 0) {
        //CHECK(handle != nullptr);
        if (native_handle_is_invalid(handle) ||
            handle->numInts > int((INT_MAX - handle->version) / sizeof(int)) - NUM_INTS - handle->numFds) {
            return nullptr;
        }
        ExtraData xd = {
            width, height, format, uint32_t(usage & 0xFFFFFFFF), uint32_t(usage >> 32),
            stride, generation, uint32_t(igbp_id & 0xFFFFFFFF), uint32_t(igbp_id >> 32),
            igbp_slot, MAGIC
        };
        native_handle_t *res = native_handle_create(handle->numFds, handle->numInts + NUM_INTS);
        if (res != nullptr) {
            memcpy(&res->data, &handle->data, sizeof(int) * (handle->numFds + handle->numInts));
            *getExtraData(res) = xd;
        }
        return reinterpret_cast<C2HandleGralloc *>(res);
    }

    static C2HandleGralloc* WrapNativeHandle(
            const native_handle_t *const handle,
            uint32_t width, uint32_t height, uint32_t format, uint64_t usage,
            uint32_t stride, uint32_t generation, uint64_t igbp_id = 0, uint32_t igbp_slot = 0) {
        if (handle == nullptr) {
            return nullptr;
        }
        native_handle_t *clone = native_handle_clone(handle);
        if (clone == nullptr) {
            return nullptr;
        }
        C2HandleGralloc *res = WrapAndMoveNativeHandle(
                clone, width, height, format, usage, stride, generation, igbp_id, igbp_slot);
        if (res == nullptr) {
            native_handle_close(clone);
        }
        native_handle_delete(clone);
        return res;
    }

    static bool MigrateNativeHandle(
            native_handle_t *handle,
            uint32_t generation, uint64_t igbp_id, uint32_t igbp_slot) {
        if (handle == nullptr || !isValid(handle)) {
            return false;
        }
        ExtraData *ed = getExtraData(handle);
        if (!ed) return false;
        ed->generation = generation;
        ed->igbp_id_lo = uint32_t(igbp_id & 0xFFFFFFFF);
        ed->igbp_id_hi = uint32_t(igbp_id >> 32);
        ed->igbp_slot = igbp_slot;
        return true;
    }


    static native_handle_t* UnwrapNativeHandle(
            const C2Handle *const handle) {
        const ExtraData *xd = getExtraData(handle);
        if (xd == nullptr || xd->magic != MAGIC) {
            return nullptr;
        }
        native_handle_t *res = native_handle_create(handle->numFds, handle->numInts - NUM_INTS);
        if (res != nullptr) {
            memcpy(&res->data, &handle->data, sizeof(int) * (res->numFds + res->numInts));
        }
        return res;
    }

    static const C2HandleGralloc* Import(
            const C2Handle *const handle,
            uint32_t *width, uint32_t *height, uint32_t *format,
            uint64_t *usage, uint32_t *stride,
            uint32_t *generation, uint64_t *igbp_id, uint32_t *igbp_slot) {
        const ExtraData *xd = getExtraData(handle);
        if (xd == nullptr) {
            return nullptr;
        }
        *width = xd->width;
        *height = xd->height;
        *format = xd->format;
        *usage = xd->usage_lo | (uint64_t(xd->usage_hi) << 32);
        *stride = xd->stride;
        *generation = xd->generation;
        *igbp_id = xd->igbp_id_lo | (uint64_t(xd->igbp_id_hi) << 32);
        *igbp_slot = xd->igbp_slot;
        return reinterpret_cast<const C2HandleGralloc *>(handle);
    }
};

} // unnamed namespace

native_handle_t *UnwrapNativeCodec2GrallocHandle(const C2Handle *const handle) {
    return C2HandleGralloc::UnwrapNativeHandle(handle);
}

C2Handle *WrapNativeCodec2GrallocHandle(
        const native_handle_t *const handle,
        uint32_t width, uint32_t height, uint32_t format, uint64_t usage, uint32_t stride,
        uint32_t generation, uint64_t igbp_id, uint32_t igbp_slot) {
    return C2HandleGralloc::WrapNativeHandle(handle, width, height, format, usage, stride,
                                             generation, igbp_id, igbp_slot);
}

bool MigrateNativeCodec2GrallocHandle(
        native_handle_t *handle,
        uint32_t generation, uint64_t igbp_id, uint32_t igbp_slot) {
    return C2HandleGralloc::MigrateNativeHandle(handle, generation, igbp_id, igbp_slot);
}


class C2AllocationGralloc : public C2GraphicAllocation {
public:
    virtual ~C2AllocationGralloc() override;

    virtual c2_status_t map(
            C2Rect rect, C2MemoryUsage usage, C2Fence *fence,
            C2PlanarLayout *layout /* nonnull */, uint8_t **addr /* nonnull */) override;
    virtual c2_status_t unmap(
            uint8_t **addr /* nonnull */, C2Rect rect, C2Fence *fence /* nullable */) override;
    virtual C2Allocator::id_t getAllocatorId() const override { return mAllocatorId; }
    virtual const C2Handle *handle() const override { return mLockedHandle ? : mHandle; }
    virtual bool equals(const std::shared_ptr<const C2GraphicAllocation> &other) const override;

    // internal methods
    // |handle| will be moved.

    C2AllocationGralloc(
              uint32_t width, uint32_t height,
              uint32_t format, uint32_t layerCount,
              uint64_t grallocUsage, uint32_t stride,
              hidl_handle &hidlHandle,
              const C2HandleGralloc *const handle,
              C2Allocator::id_t allocatorId);
    int dup() const;
    c2_status_t status() const;

private:
    const uint32_t mWidth;
    const uint32_t mHeight;
    const uint32_t mFormat;
    const uint32_t mLayerCount;
    const uint64_t mGrallocUsage;
    const uint32_t mStride;
    const hidl_handle mHidlHandle;
    const C2HandleGralloc *mHandle;
    buffer_handle_t mBuffer;
    const C2HandleGralloc *mLockedHandle;
    bool mLocked;
    C2Allocator::id_t mAllocatorId;
    std::mutex mMappedLock;
};

C2AllocationGralloc::C2AllocationGralloc(
          uint32_t width, uint32_t height,
          uint32_t format, uint32_t layerCount,
          uint64_t grallocUsage, uint32_t stride,
          hidl_handle &hidlHandle,
          const C2HandleGralloc *const handle,
          C2Allocator::id_t allocatorId)
    : C2GraphicAllocation(width, height),
      mWidth(width),
      mHeight(height),
      mFormat(format),
      mLayerCount(layerCount),
      mGrallocUsage(grallocUsage),
      mStride(stride),
      mHidlHandle(std::move(hidlHandle)),
      mHandle(handle),
      mBuffer(nullptr),
      mLockedHandle(nullptr),
      mLocked(false),
      mAllocatorId(allocatorId) {
}

C2AllocationGralloc::~C2AllocationGralloc() {
    if (mBuffer && mLocked) {
        // implementation ignores addresss and rect
        uint8_t* addr[C2PlanarLayout::MAX_NUM_PLANES] = {};
        unmap(addr, C2Rect(), nullptr);
    }
    if (mBuffer) {
        status_t err = GraphicBufferMapper::get().freeBuffer(mBuffer);
        if (err) {
            ALOGE("failed transaction: freeBuffer");
        }
    }
    if (mHandle) {
        native_handle_delete(
                const_cast<native_handle_t *>(reinterpret_cast<const native_handle_t *>(mHandle)));
    }
    if (mLockedHandle) {
        native_handle_delete(
                const_cast<native_handle_t *>(
                        reinterpret_cast<const native_handle_t *>(mLockedHandle)));
    }
}

c2_status_t C2AllocationGralloc::map(
        C2Rect rect, C2MemoryUsage usage, C2Fence *fence,
        C2PlanarLayout *layout /* nonnull */, uint8_t **addr /* nonnull */) {
    uint64_t grallocUsage = static_cast<C2AndroidMemoryUsage>(usage).asGrallocUsage();
    ALOGV("mapping buffer with usage %#llx => %#llx",
          (long long)usage.expected, (long long)grallocUsage);

    // TODO
    (void)fence;

    std::lock_guard<std::mutex> lock(mMappedLock);
    if (mBuffer && mLocked) {
        ALOGD("already mapped");
        return C2_DUPLICATE;
    }
    if (!layout || !addr) {
        ALOGD("wrong param");
        return C2_BAD_VALUE;
    }

    if (!mBuffer) {
        status_t err = GraphicBufferMapper::get().importBuffer(
                            mHidlHandle.getNativeHandle(), mWidth, mHeight, mLayerCount,
                            mFormat, mGrallocUsage, mStride, &mBuffer);
        if (err) {
            ALOGE("failed transaction: importBuffer");
            return C2_CORRUPTED;
        }
        if (mBuffer == nullptr) {
            ALOGD("importBuffer returned null buffer");
            return C2_CORRUPTED;
        }
        uint32_t generation = 0;
        uint64_t igbp_id = 0;
        uint32_t igbp_slot = 0;
        if (mHandle) {
            mHandle->getIgbpData(&generation, &igbp_id, &igbp_slot);
        }

        mLockedHandle = C2HandleGralloc::WrapAndMoveNativeHandle(
                mBuffer, mWidth, mHeight, mFormat, mGrallocUsage,
                mStride, generation, igbp_id, igbp_slot);
    }
    switch (mFormat) {
        case static_cast<uint32_t>(PixelFormat4::RGBA_1010102): {
            // TRICKY: this is used for media as YUV444 in the case when it is queued directly to a
            // Surface. In all other cases it is RGBA. We don't know which case it is here, so
            // default to YUV for now.
            void *pointer = nullptr;
            // TODO: fence
            status_t err = GraphicBufferMapper::get().lock(
                                const_cast<native_handle_t *>(mBuffer), grallocUsage,
                                { (int32_t)rect.left, (int32_t)rect.top,
                                  (int32_t)rect.width, (int32_t)rect.height },
                                &pointer);
            if (err) {
                ALOGE("failed transaction: lock(RGBA_1010102)");
                return C2_CORRUPTED;
            }
            // treat as 32-bit values
            addr[C2PlanarLayout::PLANE_Y] = (uint8_t *)pointer;
            addr[C2PlanarLayout::PLANE_U] = (uint8_t *)pointer;
            addr[C2PlanarLayout::PLANE_V] = (uint8_t *)pointer;
            addr[C2PlanarLayout::PLANE_A] = (uint8_t *)pointer;
            layout->type = C2PlanarLayout::TYPE_YUVA;
            layout->numPlanes = 4;
            layout->rootPlanes = 1;
            layout->planes[C2PlanarLayout::PLANE_Y] = {
                C2PlaneInfo::CHANNEL_Y,         // channel
                4,                              // colInc
                static_cast<int32_t>(4 * mStride), // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                32,                             // allocatedDepth
                10,                             // bitDepth
                10,                             // rightShift
                C2PlaneInfo::LITTLE_END,        // endianness
                C2PlanarLayout::PLANE_Y,        // rootIx
                0,                              // offset
            };
            layout->planes[C2PlanarLayout::PLANE_U] = {
                C2PlaneInfo::CHANNEL_CB,         // channel
                4,                              // colInc
                static_cast<int32_t>(4 * mStride), // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                32,                             // allocatedDepth
                10,                             // bitDepth
                0,                              // rightShift
                C2PlaneInfo::LITTLE_END,        // endianness
                C2PlanarLayout::PLANE_Y,        // rootIx
                0,                              // offset
            };
            layout->planes[C2PlanarLayout::PLANE_V] = {
                C2PlaneInfo::CHANNEL_CR,         // channel
                4,                              // colInc
                static_cast<int32_t>(4 * mStride), // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                32,                             // allocatedDepth
                10,                             // bitDepth
                20,                             // rightShift
                C2PlaneInfo::LITTLE_END,        // endianness
                C2PlanarLayout::PLANE_Y,        // rootIx
                0,                              // offset
            };
            layout->planes[C2PlanarLayout::PLANE_A] = {
                C2PlaneInfo::CHANNEL_A,         // channel
                4,                              // colInc
                static_cast<int32_t>(4 * mStride), // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                32,                             // allocatedDepth
                2,                              // bitDepth
                30,                             // rightShift
                C2PlaneInfo::LITTLE_END,        // endianness
                C2PlanarLayout::PLANE_Y,        // rootIx
                0,                              // offset
            };
            break;
        }

        case static_cast<uint32_t>(PixelFormat4::RGBA_8888):
            // TODO: alpha channel
            // fall-through
        case static_cast<uint32_t>(PixelFormat4::RGBX_8888): {
            void *pointer = nullptr;
            // TODO: fence
            status_t err = GraphicBufferMapper::get().lock(
                                const_cast<native_handle_t*>(mBuffer), grallocUsage,
                                { (int32_t)rect.left, (int32_t)rect.top,
                                  (int32_t)rect.width, (int32_t)rect.height },
                                &pointer);
            if (err) {
                ALOGE("failed transaction: lock(RGBA_8888)");
                return C2_CORRUPTED;
            }
            addr[C2PlanarLayout::PLANE_R] = (uint8_t *)pointer;
            addr[C2PlanarLayout::PLANE_G] = (uint8_t *)pointer + 1;
            addr[C2PlanarLayout::PLANE_B] = (uint8_t *)pointer + 2;
            layout->type = C2PlanarLayout::TYPE_RGB;
            layout->numPlanes = 3;
            layout->rootPlanes = 1;
            layout->planes[C2PlanarLayout::PLANE_R] = {
                C2PlaneInfo::CHANNEL_R,         // channel
                4,                              // colInc
                static_cast<int32_t>(4 * mStride), // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                8,                              // allocatedDepth
                8,                              // bitDepth
                0,                              // rightShift
                C2PlaneInfo::NATIVE,            // endianness
                C2PlanarLayout::PLANE_R,        // rootIx
                0,                              // offset
            };
            layout->planes[C2PlanarLayout::PLANE_G] = {
                C2PlaneInfo::CHANNEL_G,         // channel
                4,                              // colInc
                static_cast<int32_t>(4 * mStride), // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                8,                              // allocatedDepth
                8,                              // bitDepth
                0,                              // rightShift
                C2PlaneInfo::NATIVE,            // endianness
                C2PlanarLayout::PLANE_R,        // rootIx
                1,                              // offset
            };
            layout->planes[C2PlanarLayout::PLANE_B] = {
                C2PlaneInfo::CHANNEL_B,         // channel
                4,                              // colInc
                static_cast<int32_t>(4 * mStride), // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                8,                              // allocatedDepth
                8,                              // bitDepth
                0,                              // rightShift
                C2PlaneInfo::NATIVE,            // endianness
                C2PlanarLayout::PLANE_R,        // rootIx
                2,                              // offset
            };
            break;
        }

        case static_cast<uint32_t>(PixelFormat4::BLOB): {
            void *pointer = nullptr;
            // TODO: fence
            status_t err = GraphicBufferMapper::get().lock(
                                const_cast<native_handle_t*>(mBuffer), grallocUsage,
                                { (int32_t)rect.left, (int32_t)rect.top,
                                  (int32_t)rect.width, (int32_t)rect.height },
                                &pointer);
            if (err) {
                ALOGE("failed transaction: lock(BLOB)");
                return C2_CORRUPTED;
            }
            *addr = (uint8_t *)pointer;
            break;
        }

        case static_cast<uint32_t>(PixelFormat4::YCBCR_420_888):
            // fall-through
        case static_cast<uint32_t>(PixelFormat4::YV12):
            // fall-through
        default: {
            android_ycbcr ycbcrLayout;

            status_t err = GraphicBufferMapper::get().lockYCbCr(
                        const_cast<native_handle_t*>(mBuffer), grallocUsage,
                        { (int32_t)rect.left, (int32_t)rect.top,
                          (int32_t)rect.width, (int32_t)rect.height },
                        &ycbcrLayout);
            if (err) {
                ALOGE("failed transaction: lockYCbCr");
                return C2_CORRUPTED;
            }

            addr[C2PlanarLayout::PLANE_Y] = (uint8_t *)ycbcrLayout.y;
            addr[C2PlanarLayout::PLANE_U] = (uint8_t *)ycbcrLayout.cb;
            addr[C2PlanarLayout::PLANE_V] = (uint8_t *)ycbcrLayout.cr;
            layout->type = C2PlanarLayout::TYPE_YUV;
            layout->numPlanes = 3;
            layout->rootPlanes = 3;
            layout->planes[C2PlanarLayout::PLANE_Y] = {
                C2PlaneInfo::CHANNEL_Y,         // channel
                1,                              // colInc
                (int32_t)ycbcrLayout.ystride,   // rowInc
                1,                              // mColSampling
                1,                              // mRowSampling
                8,                              // allocatedDepth
                8,                              // bitDepth
                0,                              // rightShift
                C2PlaneInfo::NATIVE,            // endianness
                C2PlanarLayout::PLANE_Y,        // rootIx
                0,                              // offset
            };
            layout->planes[C2PlanarLayout::PLANE_U] = {
                C2PlaneInfo::CHANNEL_CB,          // channel
                (int32_t)ycbcrLayout.chroma_step, // colInc
                (int32_t)ycbcrLayout.cstride,     // rowInc
                2,                                // mColSampling
                2,                                // mRowSampling
                8,                                // allocatedDepth
                8,                                // bitDepth
                0,                                // rightShift
                C2PlaneInfo::NATIVE,              // endianness
                C2PlanarLayout::PLANE_U,          // rootIx
                0,                                // offset
            };
            layout->planes[C2PlanarLayout::PLANE_V] = {
                C2PlaneInfo::CHANNEL_CR,          // channel
                (int32_t)ycbcrLayout.chroma_step, // colInc
                (int32_t)ycbcrLayout.cstride,     // rowInc
                2,                                // mColSampling
                2,                                // mRowSampling
                8,                                // allocatedDepth
                8,                                // bitDepth
                0,                                // rightShift
                C2PlaneInfo::NATIVE,              // endianness
                C2PlanarLayout::PLANE_V,          // rootIx
                0,                                // offset
            };
            // handle interleaved formats
            intptr_t uvOffset = addr[C2PlanarLayout::PLANE_V] - addr[C2PlanarLayout::PLANE_U];
            if (uvOffset > 0 && uvOffset < (intptr_t)ycbcrLayout.chroma_step) {
                layout->rootPlanes = 2;
                layout->planes[C2PlanarLayout::PLANE_V].rootIx = C2PlanarLayout::PLANE_U;
                layout->planes[C2PlanarLayout::PLANE_V].offset = uvOffset;
            } else if (uvOffset < 0 && uvOffset > -(intptr_t)ycbcrLayout.chroma_step) {
                layout->rootPlanes = 2;
                layout->planes[C2PlanarLayout::PLANE_U].rootIx = C2PlanarLayout::PLANE_V;
                layout->planes[C2PlanarLayout::PLANE_U].offset = -uvOffset;
            }
            break;
        }
    }
    mLocked = true;

    return C2_OK;
}

c2_status_t C2AllocationGralloc::unmap(
        uint8_t **addr, C2Rect rect, C2Fence *fence /* nullable */) {
    // TODO: check addr and size, use fence
    (void)addr;
    (void)rect;
    (void)fence;

    std::lock_guard<std::mutex> lock(mMappedLock);
    // TODO: fence
    status_t err = GraphicBufferMapper::get().unlock(mBuffer);
    if (err) {
        ALOGE("failed transaction: unlock");
        return C2_CORRUPTED;
    }

    mLocked = false;
    return C2_OK;
}

bool C2AllocationGralloc::equals(const std::shared_ptr<const C2GraphicAllocation> &other) const {
    return other && other->handle() == handle();
}

/* ===================================== GRALLOC ALLOCATOR ==================================== */
class C2AllocatorGralloc::Impl {
public:
    Impl(id_t id, bool bufferQueue);

    id_t getId() const {
        return mTraits->id;
    }

    C2String getName() const {
        return mTraits->name;
    }

    std::shared_ptr<const C2Allocator::Traits> getTraits() const {
        return mTraits;
    }

    c2_status_t newGraphicAllocation(
            uint32_t width, uint32_t height, uint32_t format, const C2MemoryUsage &usage,
            std::shared_ptr<C2GraphicAllocation> *allocation);

    c2_status_t priorGraphicAllocation(
            const C2Handle *handle,
            std::shared_ptr<C2GraphicAllocation> *allocation);

    c2_status_t status() const { return mInit; }

private:
    std::shared_ptr<C2Allocator::Traits> mTraits;
    c2_status_t mInit;
    const bool mBufferQueue;
};

void _UnwrapNativeCodec2GrallocMetadata(
        const C2Handle *const handle,
        uint32_t *width, uint32_t *height, uint32_t *format,uint64_t *usage, uint32_t *stride,
        uint32_t *generation, uint64_t *igbp_id, uint32_t *igbp_slot) {
    (void)C2HandleGralloc::Import(handle, width, height, format, usage, stride,
                                  generation, igbp_id, igbp_slot);
}

C2AllocatorGralloc::Impl::Impl(id_t id, bool bufferQueue)
    : mInit(C2_OK), mBufferQueue(bufferQueue) {
    // TODO: get this from allocator
    C2MemoryUsage minUsage = { 0, 0 }, maxUsage = { ~(uint64_t)0, ~(uint64_t)0 };
    Traits traits = { "android.allocator.gralloc", id, C2Allocator::GRAPHIC, minUsage, maxUsage };
    mTraits = std::make_shared<C2Allocator::Traits>(traits);
}

c2_status_t C2AllocatorGralloc::Impl::newGraphicAllocation(
        uint32_t width, uint32_t height, uint32_t format, const C2MemoryUsage &usage,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    uint64_t grallocUsage = static_cast<C2AndroidMemoryUsage>(usage).asGrallocUsage();
    ALOGV("allocating buffer with usage %#llx => %#llx",
          (long long)usage.expected, (long long)grallocUsage);

    buffer_handle_t buffer;

    uint32_t stride = 0;

    status_t err = GraphicBufferAllocator::get().allocateRawHandle(width, height, format,
            1u /* layer count */, grallocUsage, &buffer, &stride, "C2GrallocAllocation");
    if (err) {
        ALOGE("failed transaction: allocate");
        return C2_CORRUPTED;
    }

    hidl_handle hidlHandle;
    hidlHandle.setTo(const_cast<native_handle_t*>(buffer), true);

    allocation->reset(new C2AllocationGralloc(
            width, height, format, 1u /* layer count */, grallocUsage, stride, hidlHandle,
            C2HandleGralloc::WrapAndMoveNativeHandle(
                    hidlHandle, width, height,
                    format, grallocUsage, stride,
                    0, 0, mBufferQueue ? ~0 : 0),
            mTraits->id));
    return C2_OK;
}

c2_status_t C2AllocatorGralloc::Impl::priorGraphicAllocation(
        const C2Handle *handle,
        std::shared_ptr<C2GraphicAllocation> *allocation) {

    uint32_t generation;
    uint64_t igbp_id;
    uint32_t igbp_slot;

    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t layerCount = 1;
    uint64_t grallocUsage;
    uint32_t stride;

    const C2HandleGralloc *grallocHandle = C2HandleGralloc::Import(
            handle, &width, &height, &format, &grallocUsage, &stride,
            &generation, &igbp_id, &igbp_slot);
    if (grallocHandle == nullptr) {
        return C2_BAD_VALUE;
    }

    hidl_handle hidlHandle;
    hidlHandle.setTo(C2HandleGralloc::UnwrapNativeHandle(grallocHandle), true);

    allocation->reset(new C2AllocationGralloc(
            width, height, format, layerCount,
            grallocUsage, stride, hidlHandle, grallocHandle, mTraits->id));
    return C2_OK;
}

C2AllocatorGralloc::C2AllocatorGralloc(id_t id, bool bufferQueue)
        : mImpl(new Impl(id, bufferQueue)) {}

C2AllocatorGralloc::~C2AllocatorGralloc() { delete mImpl; }

C2Allocator::id_t C2AllocatorGralloc::getId() const {
    return mImpl->getId();
}

C2String C2AllocatorGralloc::getName() const {
    return mImpl->getName();
}

std::shared_ptr<const C2Allocator::Traits> C2AllocatorGralloc::getTraits() const {
    return mImpl->getTraits();
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

bool C2AllocatorGralloc::isValid(const C2Handle* const o) {
    return C2HandleGralloc::isValid(o);
}

} // namespace android
