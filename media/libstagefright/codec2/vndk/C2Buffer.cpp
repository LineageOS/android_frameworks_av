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
#define LOG_TAG "C2Buffer"
#include <utils/Log.h>

#include <C2BufferPriv.h>

#include <android/hardware/graphics/allocator/2.0/IAllocator.h>
#include <android/hardware/graphics/mapper/2.0/IMapper.h>

#include <ion/ion.h>
#include <hardware/gralloc.h>
#include <sys/mman.h>

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

// standard ERRNO mappings
template<int N> constexpr C2Error _c2_errno2error_impl();
template<> constexpr C2Error _c2_errno2error_impl<0>()       { return C2_OK; }
template<> constexpr C2Error _c2_errno2error_impl<EINVAL>()  { return C2_BAD_VALUE; }
template<> constexpr C2Error _c2_errno2error_impl<EACCES>()  { return C2_NO_PERMISSION; }
template<> constexpr C2Error _c2_errno2error_impl<EPERM>()   { return C2_NO_PERMISSION; }
template<> constexpr C2Error _c2_errno2error_impl<ENOMEM>()  { return C2_NO_MEMORY; }

// map standard errno-s to the equivalent C2Error
template<int... N> struct _c2_map_errno_impl;
template<int E, int ... N> struct _c2_map_errno_impl<E, N...> {
    static C2Error map(int result) {
        if (result == E) {
            return _c2_errno2error_impl<E>();
        } else {
            return _c2_map_errno_impl<N...>::map(result);
        }
    }
};
template<> struct _c2_map_errno_impl<> {
    static C2Error map(int result) {
        return result == 0 ? C2_OK : C2_CORRUPTED;
    }
};

template<int... N>
C2Error c2_map_errno(int result) {
    return _c2_map_errno_impl<N...>::map(result);
}

namespace {

// Inherit from the parent, share with the friend.

class DummyCapacityAspect : public _C2LinearCapacityAspect {
    using _C2LinearCapacityAspect::_C2LinearCapacityAspect;
    friend class ::android::C2ReadView;
    friend class ::android::C2ConstLinearBlock;
};

class C2DefaultReadView : public C2ReadView {
    using C2ReadView::C2ReadView;
    friend class ::android::C2ConstLinearBlock;
};

class C2DefaultWriteView : public C2WriteView {
    using C2WriteView::C2WriteView;
    friend class ::android::C2LinearBlock;
};

class C2AcquirableReadView : public C2Acquirable<C2ReadView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2ConstLinearBlock;
};

class C2AcquirableWriteView : public C2Acquirable<C2WriteView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2LinearBlock;
};

class C2DefaultConstLinearBlock : public C2ConstLinearBlock {
    using C2ConstLinearBlock::C2ConstLinearBlock;
    friend class ::android::C2LinearBlock;
};

class C2DefaultLinearBlock : public C2LinearBlock {
    using C2LinearBlock::C2LinearBlock;
    friend class ::android::C2DefaultBlockAllocator;
};

class C2DefaultGraphicView : public C2GraphicView {
    using C2GraphicView::C2GraphicView;
    friend class ::android::C2ConstGraphicBlock;
    friend class ::android::C2GraphicBlock;
};

class C2AcquirableConstGraphicView : public C2Acquirable<const C2GraphicView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2ConstGraphicBlock;
};

class C2AcquirableGraphicView : public C2Acquirable<C2GraphicView> {
    using C2Acquirable::C2Acquirable;
    friend class ::android::C2GraphicBlock;
};

class C2DefaultConstGraphicBlock : public C2ConstGraphicBlock {
    using C2ConstGraphicBlock::C2ConstGraphicBlock;
    friend class ::android::C2GraphicBlock;
};

class C2DefaultGraphicBlock : public C2GraphicBlock {
    using C2GraphicBlock::C2GraphicBlock;
    friend class ::android::C2DefaultGraphicBlockAllocator;
};

class C2DefaultBufferData : public C2BufferData {
    using C2BufferData::C2BufferData;
    friend class ::android::C2Buffer;
};

}  // namespace

/* ======================================= ION ALLOCATION ====================================== */

/**
 * ION handle
 */
struct C2HandleIon : public C2Handle {
    C2HandleIon(int ionFd, ion_user_handle_t buffer) : C2Handle(cHeader),
          mFds{ ionFd, buffer },
          mInts{ kMagic } { }

    static bool isValid(const C2Handle * const o);

    int ionFd() const { return mFds.mIon; }
    ion_user_handle_t buffer() const { return mFds.mBuffer; }

    void setBuffer(ion_user_handle_t bufferFd) { mFds.mBuffer = bufferFd; }

protected:
    struct {
        int mIon;
        int mBuffer; // ion_user_handle_t
    } mFds;
    struct {
        int mMagic;
    } mInts;

private:
    typedef C2HandleIon _type;
    enum {
        kMagic = 'ion1',
        numFds = sizeof(mFds) / sizeof(int),
        numInts = sizeof(mInts) / sizeof(int),
        version = sizeof(C2Handle) + sizeof(mFds) + sizeof(mInts)
    };
    //constexpr static C2Handle cHeader = { version, numFds, numInts, {} };
    const static C2Handle cHeader;
};

const C2Handle C2HandleIon::cHeader = {
    C2HandleIon::version,
    C2HandleIon::numFds,
    C2HandleIon::numInts,
    {}
};

// static
bool C2HandleIon::isValid(const C2Handle * const o) {
    if (!o || memcmp(o, &cHeader, sizeof(cHeader))) {
        return false;
    }
    const C2HandleIon *other = static_cast<const C2HandleIon*>(o);
    return other->mInts.mMagic == kMagic;
}

// TODO: is the dup of an ion fd identical to ion_share?

class C2AllocationIon : public C2LinearAllocation {
public:
    virtual C2Error map(
        size_t offset, size_t size, C2MemoryUsage usage, int *fence,
        void **addr /* nonnull */);
    virtual C2Error unmap(void *addr, size_t size, int *fenceFd);
    virtual bool isValid() const;
    virtual ~C2AllocationIon();
    virtual const C2Handle *handle() const;
    virtual bool equals(const std::shared_ptr<C2LinearAllocation> &other) const;

    // internal methods
    C2AllocationIon(int ionFd, size_t size, size_t align, unsigned heapMask, unsigned flags);
    C2AllocationIon(int ionFd, size_t size, int shareFd);
    int dup() const;
    C2Error status() const;

protected:
    class Impl;
    Impl *mImpl;
};

class C2AllocationIon::Impl {
public:
    // NOTE: using constructor here instead of a factory method as we will need the
    // error value and this simplifies the error handling by the wrapper.
    Impl(int ionFd, size_t capacity, size_t align, unsigned heapMask, unsigned flags)
        : mInit(C2_OK),
          mHandle(ionFd, -1),
          mMapFd(-1),
          mCapacity(capacity) {
        ion_user_handle_t buffer = -1;
        int ret = ion_alloc(mHandle.ionFd(), mCapacity, align, heapMask, flags, &buffer);
        if (ret == 0) {
            mHandle.setBuffer(buffer);
        } else {
            mInit = c2_map_errno<ENOMEM, EACCES, EINVAL>(-ret);
        }
    }

    Impl(int ionFd, size_t capacity, int shareFd)
        : mHandle(ionFd, -1),
          mMapFd(-1),
          mCapacity(capacity) {
        ion_user_handle_t buffer;
        mInit = ion_import(mHandle.ionFd(), shareFd, &buffer);
        if (mInit == 0) {
            mHandle.setBuffer(buffer);
        }
        (void)mCapacity; // TODO
    }

    C2Error map(size_t offset, size_t size, C2MemoryUsage usage, int *fenceFd, void **addr) {
        (void)fenceFd; // TODO: wait for fence
        *addr = nullptr;
        int prot = PROT_NONE;
        int flags = MAP_PRIVATE;
        if (usage.mConsumer & GRALLOC_USAGE_SW_READ_MASK) {
            prot |= PROT_READ;
        }
        if (usage.mProducer & GRALLOC_USAGE_SW_WRITE_MASK) {
            prot |= PROT_WRITE;
            flags = MAP_SHARED;
        }

        size_t alignmentBytes = offset % PAGE_SIZE;
        size_t mapOffset = offset - alignmentBytes;
        size_t mapSize = size + alignmentBytes;

        C2Error err = C2_OK;
        if (mMapFd == -1) {
            int ret = ion_map(mHandle.ionFd(), mHandle.buffer(), mapSize, prot,
                              flags, mapOffset, (unsigned char**)&mMapAddr, &mMapFd);
            if (ret) {
                mMapFd = -1;
                *addr = nullptr;
                err = c2_map_errno<EINVAL>(-ret);
            } else {
                *addr = (uint8_t *)mMapAddr + alignmentBytes;
                mMapAlignmentBytes = alignmentBytes;
                mMapSize = mapSize;
            }
        } else {
            mMapAddr = mmap(nullptr, mapSize, prot, flags, mMapFd, mapOffset);
            if (mMapAddr == MAP_FAILED) {
                mMapAddr = *addr = nullptr;
                err = c2_map_errno<EINVAL>(errno);
            } else {
                *addr = (uint8_t *)mMapAddr + alignmentBytes;
                mMapAlignmentBytes = alignmentBytes;
                mMapSize = mapSize;
            }
        }
        return err;
    }

    C2Error unmap(void *addr, size_t size, int *fenceFd) {
        if (addr != (uint8_t *)mMapAddr + mMapAlignmentBytes ||
                size + mMapAlignmentBytes != mMapSize) {
            return C2_BAD_VALUE;
        }
        int err = munmap(mMapAddr, mMapSize);
        if (err != 0) {
            return c2_map_errno<EINVAL>(errno);
        }
        if (fenceFd) {
            *fenceFd = -1;
        }
        return C2_OK;
    }

    ~Impl() {
        if (mMapFd != -1) {
            close(mMapFd);
            mMapFd = -1;
        }

        (void)ion_free(mHandle.ionFd(), mHandle.buffer());
    }

    C2Error status() const {
        return mInit;
    }

    const C2Handle * handle() const {
        return &mHandle;
    }

    int dup() const {
        int fd = -1;
        if (mInit != 0 || ion_share(mHandle.ionFd(), mHandle.buffer(), &fd) != 0) {
            fd = -1;
        }
        return fd;
    }

private:
    C2Error mInit;
    C2HandleIon mHandle;
    int mMapFd; // only one for now
    void *mMapAddr;
    size_t mMapAlignmentBytes;
    size_t mMapSize;
    size_t mCapacity;
};

C2Error C2AllocationIon::map(
    size_t offset, size_t size, C2MemoryUsage usage, int *fenceFd, void **addr) {
    return mImpl->map(offset, size, usage, fenceFd, addr);
}

C2Error C2AllocationIon::unmap(void *addr, size_t size, int *fenceFd) {
    return mImpl->unmap(addr, size, fenceFd);
}

bool C2AllocationIon::isValid() const {
    return mImpl->status() == C2_OK;
}

C2Error C2AllocationIon::status() const {
    return mImpl->status();
}

bool C2AllocationIon::equals(const std::shared_ptr<C2LinearAllocation> &other) const {
    return other != nullptr &&
        other->handle(); // TODO
}

const C2Handle *C2AllocationIon::handle() const {
    return mImpl->handle();
}

C2AllocationIon::~C2AllocationIon() {
    delete mImpl;
}

C2AllocationIon::C2AllocationIon(int ionFd, size_t size, size_t align, unsigned heapMask, unsigned flags)
    : C2LinearAllocation(size),
      mImpl(new Impl(ionFd, size, align, heapMask, flags)) { }

C2AllocationIon::C2AllocationIon(int ionFd, size_t size, int shareFd)
    : C2LinearAllocation(size),
      mImpl(new Impl(ionFd, size, shareFd)) { }

int C2AllocationIon::dup() const {
    return mImpl->dup();
}

/* ======================================= ION ALLOCATOR ====================================== */

C2AllocatorIon::C2AllocatorIon() : mInit(C2_OK), mIonFd(ion_open()) {
    if (mIonFd < 0) {
        switch (errno) {
        case ENOENT:    mInit = C2_UNSUPPORTED; break;
        default:        mInit = c2_map_errno<EACCES>(errno); break;
        }
    }
}

C2AllocatorIon::~C2AllocatorIon() {
    if (mInit == C2_OK) {
        ion_close(mIonFd);
    }
}

/**
 * Allocates a 1D allocation of given |capacity| and |usage|. If successful, the allocation is
 * stored in |allocation|. Otherwise, |allocation| is set to 'nullptr'.
 *
 * \param capacity        the size of requested allocation (the allocation could be slightly
 *                      larger, e.g. to account for any system-required alignment)
 * \param usage           the memory usage info for the requested allocation. \note that the
 *                      returned allocation may be later used/mapped with different usage.
 *                      The allocator should layout the buffer to be optimized for this usage,
 *                      but must support any usage. One exception: protected buffers can
 *                      only be used in a protected scenario.
 * \param allocation      pointer to where the allocation shall be stored on success. nullptr
 *                      will be stored here on failure
 *
 * \retval C2_OK        the allocation was successful
 * \retval C2_NO_MEMORY not enough memory to complete the allocation
 * \retval C2_TIMED_OUT the allocation timed out
 * \retval C2_NO_PERMISSION     no permission to complete the allocation
 * \retval C2_BAD_VALUE capacity or usage are not supported (invalid) (caller error)
 * \retval C2_UNSUPPORTED       this allocator does not support 1D allocations
 * \retval C2_CORRUPTED some unknown, unrecoverable error occured during allocation (unexpected)
 */
C2Error C2AllocatorIon::allocateLinearBuffer(
        uint32_t capacity, C2MemoryUsage usage, std::shared_ptr<C2LinearAllocation> *allocation) {
    *allocation = nullptr;
    if (mInit != C2_OK) {
        return C2_UNSUPPORTED;
    }

    // get align, heapMask and flags
    //size_t align = 1;
    size_t align = 0;
    unsigned heapMask = ~0;
    unsigned flags = 0;
    //TODO
    (void) usage;
#if 0
    int err = mUsageMapper(usage, capacity, &align, &heapMask, &flags);
    if (err < 0) {
        return c2_map_errno<EINVAL, ENOMEM, EACCES>(-err);
    }
#endif

    std::shared_ptr<C2AllocationIon> alloc
        = std::make_shared<C2AllocationIon>(mIonFd, capacity, align, heapMask, flags);
    C2Error ret = alloc->status();
    if (ret == C2_OK) {
        *allocation = alloc;
    }
    return ret;
}

/**
 * (Re)creates a 1D allocation from a native |handle|. If successful, the allocation is stored
 * in |allocation|. Otherwise, |allocation| is set to 'nullptr'.
 *
 * \param handle      the handle for the existing allocation
 * \param allocation  pointer to where the allocation shall be stored on success. nullptr
 *                  will be stored here on failure
 *
 * \retval C2_OK        the allocation was recreated successfully
 * \retval C2_NO_MEMORY not enough memory to recreate the allocation
 * \retval C2_TIMED_OUT the recreation timed out (unexpected)
 * \retval C2_NO_PERMISSION     no permission to recreate the allocation
 * \retval C2_BAD_VALUE invalid handle (caller error)
 * \retval C2_UNSUPPORTED       this allocator does not support 1D allocations
 * \retval C2_CORRUPTED some unknown, unrecoverable error occured during allocation (unexpected)
 */
C2Error C2AllocatorIon::recreateLinearBuffer(
        const C2Handle *handle, std::shared_ptr<C2LinearAllocation> *allocation) {
    *allocation = nullptr;
    if (mInit != C2_OK) {
        return C2_UNSUPPORTED;
    }

    if (!C2HandleIon::isValid(handle)) {
        return C2_BAD_VALUE;
    }

    // TODO: get capacity and validate it
    const C2HandleIon *h = static_cast<const C2HandleIon*>(handle);
    std::shared_ptr<C2AllocationIon> alloc
        = std::make_shared<C2AllocationIon>(mIonFd, 0 /* capacity */, h->buffer());
    C2Error ret = alloc->status();
    if (ret == C2_OK) {
        *allocation = alloc;
    }
    return ret;
}

/* ========================================== 1D BLOCK ========================================= */

class C2Block1D::Impl {
public:
    const C2Handle *handle() const {
        return mAllocation->handle();
    }

    Impl(std::shared_ptr<C2LinearAllocation> alloc)
        : mAllocation(alloc) {}

private:
    std::shared_ptr<C2LinearAllocation> mAllocation;
};

const C2Handle *C2Block1D::handle() const {
    return mImpl->handle();
};

C2Block1D::C2Block1D(std::shared_ptr<C2LinearAllocation> alloc)
    : _C2LinearRangeAspect(alloc.get()), mImpl(new Impl(alloc)) {
}

C2Block1D::C2Block1D(std::shared_ptr<C2LinearAllocation> alloc, size_t offset, size_t size)
    : _C2LinearRangeAspect(alloc.get(), offset, size), mImpl(new Impl(alloc)) {
}

class C2ReadView::Impl {
public:
    explicit Impl(const uint8_t *data)
        : mData(data), mError(C2_OK) {}

    explicit Impl(C2Error error)
        : mData(nullptr), mError(error) {}

    const uint8_t *data() const {
        return mData;
    }

    C2Error error() const {
        return mError;
    }

private:
    const uint8_t *mData;
    C2Error mError;
};

C2ReadView::C2ReadView(const _C2LinearCapacityAspect *parent, const uint8_t *data)
    : _C2LinearCapacityAspect(parent), mImpl(std::make_shared<Impl>(data)) {}

C2ReadView::C2ReadView(C2Error error)
    : _C2LinearCapacityAspect(0u), mImpl(std::make_shared<Impl>(error)) {}

const uint8_t *C2ReadView::data() const {
    return mImpl->data();
}

C2ReadView C2ReadView::subView(size_t offset, size_t size) const {
    if (offset > capacity()) {
        offset = capacity();
    }
    if (size > capacity() - offset) {
        size = capacity() - offset;
    }
    // TRICKY: newCapacity will just be used to grab the size.
    DummyCapacityAspect newCapacity((uint32_t)size);
    return C2ReadView(&newCapacity, data() + offset);
}

C2Error C2ReadView::error() {
    return mImpl->error();
}

class C2WriteView::Impl {
public:
    explicit Impl(uint8_t *base)
        : mBase(base), mError(C2_OK) {}

    explicit Impl(C2Error error)
        : mBase(nullptr), mError(error) {}

    uint8_t *base() const {
        return mBase;
    }

    C2Error error() const {
        return mError;
    }

private:
    uint8_t *mBase;
    C2Error mError;
};

C2WriteView::C2WriteView(const _C2LinearRangeAspect *parent, uint8_t *base)
    : _C2EditableLinearRange(parent), mImpl(std::make_shared<Impl>(base)) {}

C2WriteView::C2WriteView(C2Error error)
    : _C2EditableLinearRange(nullptr), mImpl(std::make_shared<Impl>(error)) {}

uint8_t *C2WriteView::base() { return mImpl->base(); }

uint8_t *C2WriteView::data() { return mImpl->base() + offset(); }

C2Error C2WriteView::error() { return mImpl->error(); }

class C2ConstLinearBlock::Impl {
public:
    explicit Impl(std::shared_ptr<C2LinearAllocation> alloc)
        : mAllocation(alloc), mBase(nullptr), mSize(0u), mError(C2_CORRUPTED) {}

    ~Impl() {
        if (mBase != nullptr) {
            // TODO: fence
            C2Error err = mAllocation->unmap(mBase, mSize, nullptr);
            if (err != C2_OK) {
                // TODO: Log?
            }
        }
    }

    C2ConstLinearBlock subBlock(size_t offset, size_t size) const {
        return C2ConstLinearBlock(mAllocation, offset, size);
    }

    void map(size_t offset, size_t size) {
        if (mBase == nullptr) {
            void *base = nullptr;
            mError = mAllocation->map(
                    offset, size, { C2MemoryUsage::kSoftwareRead, 0 }, nullptr, &base);
            // TODO: fence
            if (mError == C2_OK) {
                mBase = (uint8_t *)base;
                mSize = size;
            }
        }
    }

    const uint8_t *base() const { return mBase; }

    C2Error error() const { return mError; }

private:
    std::shared_ptr<C2LinearAllocation> mAllocation;
    uint8_t *mBase;
    size_t mSize;
    C2Error mError;
};

C2ConstLinearBlock::C2ConstLinearBlock(std::shared_ptr<C2LinearAllocation> alloc)
    : C2Block1D(alloc), mImpl(std::make_shared<Impl>(alloc)) {}

C2ConstLinearBlock::C2ConstLinearBlock(
        std::shared_ptr<C2LinearAllocation> alloc, size_t offset, size_t size)
    : C2Block1D(alloc, offset, size), mImpl(std::make_shared<Impl>(alloc)) {}

C2Acquirable<C2ReadView> C2ConstLinearBlock::map() const {
    mImpl->map(offset(), size());
    if (mImpl->base() == nullptr) {
        C2DefaultReadView view(mImpl->error());
        return C2AcquirableReadView(mImpl->error(), mFence, view);
    }
    DummyCapacityAspect newCapacity(size());
    C2DefaultReadView view(&newCapacity, mImpl->base());
    return C2AcquirableReadView(mImpl->error(), mFence, view);
}

C2ConstLinearBlock C2ConstLinearBlock::subBlock(size_t offset, size_t size) const {
    return mImpl->subBlock(offset, size);
}

class C2LinearBlock::Impl {
public:
    Impl(std::shared_ptr<C2LinearAllocation> alloc)
        : mAllocation(alloc), mBase(nullptr), mSize(0u), mError(C2_CORRUPTED) {}

    ~Impl() {
        if (mBase != nullptr) {
            // TODO: fence
            C2Error err = mAllocation->unmap(mBase, mSize, nullptr);
            if (err != C2_OK) {
                // TODO: Log?
            }
        }
    }

    void map(size_t capacity) {
        if (mBase == nullptr) {
            void *base = nullptr;
            // TODO: fence
            mError = mAllocation->map(
                    0u,
                    capacity,
                    { C2MemoryUsage::kSoftwareRead, C2MemoryUsage::kSoftwareWrite },
                    nullptr,
                    &base);
            if (mError == C2_OK) {
                mBase = (uint8_t *)base;
                mSize = capacity;
            }
        }
    }

    C2ConstLinearBlock share(size_t offset, size_t size, C2Fence &fence) {
        // TODO
        (void) fence;
        return C2DefaultConstLinearBlock(mAllocation, offset, size);
    }

    uint8_t *base() const { return mBase; }

    C2Error error() const { return mError; }

    C2Fence fence() const { return mFence; }

private:
    std::shared_ptr<C2LinearAllocation> mAllocation;
    uint8_t *mBase;
    size_t mSize;
    C2Error mError;
    C2Fence mFence;
};

C2LinearBlock::C2LinearBlock(std::shared_ptr<C2LinearAllocation> alloc)
    : C2Block1D(alloc),
      mImpl(new Impl(alloc)) {}

C2LinearBlock::C2LinearBlock(std::shared_ptr<C2LinearAllocation> alloc, size_t offset, size_t size)
    : C2Block1D(alloc, offset, size),
      mImpl(new Impl(alloc)) {}

C2Acquirable<C2WriteView> C2LinearBlock::map() {
    mImpl->map(capacity());
    if (mImpl->base() == nullptr) {
        C2DefaultWriteView view(mImpl->error());
        return C2AcquirableWriteView(mImpl->error(), mImpl->fence(), view);
    }
    C2DefaultWriteView view(this, mImpl->base());
    view.setOffset_be(offset());
    view.setSize_be(size());
    return C2AcquirableWriteView(mImpl->error(), mImpl->fence(), view);
}

C2ConstLinearBlock C2LinearBlock::share(size_t offset, size_t size, C2Fence fence) {
    return mImpl->share(offset, size, fence);
}

C2DefaultBlockAllocator::C2DefaultBlockAllocator(
        const std::shared_ptr<C2Allocator> &allocator)
  : mAllocator(allocator) {}

C2Error C2DefaultBlockAllocator::allocateLinearBlock(
        uint32_t capacity,
        C2MemoryUsage usage,
        std::shared_ptr<C2LinearBlock> *block /* nonnull */) {
    block->reset();

    std::shared_ptr<C2LinearAllocation> alloc;
    C2Error err = mAllocator->allocateLinearBuffer(capacity, usage, &alloc);
    if (err != C2_OK) {
        return err;
    }

    block->reset(new C2DefaultLinearBlock(alloc));

    return C2_OK;
}

/* ===================================== GRALLOC ALLOCATION ==================================== */

static C2Error maperr2error(Error maperr) {
    switch (maperr) {
        case Error::NONE:           return C2_OK;
        case Error::BAD_DESCRIPTOR: return C2_BAD_VALUE;
        case Error::BAD_BUFFER:     return C2_BAD_VALUE;
        case Error::BAD_VALUE:      return C2_BAD_VALUE;
        case Error::NO_RESOURCES:   return C2_NO_MEMORY;
        case Error::UNSUPPORTED:    return C2_UNSUPPORTED;
    }
    return C2_CORRUPTED;
}

class C2AllocationGralloc : public C2GraphicAllocation {
public:
    virtual ~C2AllocationGralloc();

    virtual C2Error map(
            C2Rect rect, C2MemoryUsage usage, int *fenceFd,
            C2PlaneLayout *layout /* nonnull */, uint8_t **addr /* nonnull */) override;
    virtual C2Error unmap(C2Fence *fenceFd /* nullable */) override;
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
    C2Error status() const;

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

C2Error C2AllocationGralloc::map(
        C2Rect rect, C2MemoryUsage usage, int *fenceFd,
        C2PlaneLayout *layout /* nonnull */, uint8_t **addr /* nonnull */) {
    // TODO
    (void) fenceFd;
    (void) usage;

    if (mBuffer && mLocked) {
        return C2_DUPLICATE;
    }
    if (!layout || !addr) {
        return C2_BAD_VALUE;
    }

    C2Error err = C2_OK;
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
                { (int32_t)rect.mLeft, (int32_t)rect.mTop, (int32_t)rect.mWidth, (int32_t)rect.mHeight },
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
        addr[C2PlaneLayout::Y] = (uint8_t *)ycbcrLayout.y;
        addr[C2PlaneLayout::U] = (uint8_t *)ycbcrLayout.cb;
        addr[C2PlaneLayout::V] = (uint8_t *)ycbcrLayout.cr;
        layout->mType = C2PlaneLayout::MEDIA_IMAGE_TYPE_YUV;
        layout->mNumPlanes = 3;
        layout->mPlanes[C2PlaneLayout::Y] = {
            C2PlaneInfo::Y,                 // mChannel
            1,                              // mColInc
            (int32_t)ycbcrLayout.yStride,   // mRowInc
            1,                              // mHorizSubsampling
            1,                              // mVertSubsampling
            8,                              // mBitDepth
            8,                              // mAllocatedDepth
        };
        layout->mPlanes[C2PlaneLayout::U] = {
            C2PlaneInfo::Cb,                  // mChannel
            (int32_t)ycbcrLayout.chromaStep,  // mColInc
            (int32_t)ycbcrLayout.cStride,     // mRowInc
            2,                                // mHorizSubsampling
            2,                                // mVertSubsampling
            8,                                // mBitDepth
            8,                                // mAllocatedDepth
        };
        layout->mPlanes[C2PlaneLayout::V] = {
            C2PlaneInfo::Cr,                  // mChannel
            (int32_t)ycbcrLayout.chromaStep,  // mColInc
            (int32_t)ycbcrLayout.cStride,     // mRowInc
            2,                                // mHorizSubsampling
            2,                                // mVertSubsampling
            8,                                // mBitDepth
            8,                                // mAllocatedDepth
        };
    } else {
        void *pointer = nullptr;
        mMapper->lock(
                const_cast<native_handle_t *>(mBuffer),
                BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN,
                { (int32_t)rect.mLeft, (int32_t)rect.mTop, (int32_t)rect.mWidth, (int32_t)rect.mHeight },
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
        return C2_UNSUPPORTED;
    }
    mLocked = true;

    return C2_OK;
}

C2Error C2AllocationGralloc::unmap(C2Fence *fenceFd /* nullable */) {
    // TODO: fence
    C2Error err = C2_OK;
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

    C2Error allocateGraphicBuffer(
            uint32_t width, uint32_t height, uint32_t format, const C2MemoryUsage &usage,
            std::shared_ptr<C2GraphicAllocation> *allocation);

    C2Error recreateGraphicBuffer(
            const C2Handle *handle,
            std::shared_ptr<C2GraphicAllocation> *allocation);

    C2Error status() const { return mInit; }

private:
    C2Error mInit;
    sp<IAllocator> mAllocator;
    sp<IMapper> mMapper;
};

C2AllocatorGralloc::Impl::Impl() : mInit(C2_OK) {
    mAllocator = IAllocator::getService();
    mMapper = IMapper::getService();
    if (mAllocator == nullptr || mMapper == nullptr) {
        mInit = C2_CORRUPTED;
    }
}

C2Error C2AllocatorGralloc::Impl::allocateGraphicBuffer(
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
    C2Error err = C2_OK;
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

C2Error C2AllocatorGralloc::Impl::recreateGraphicBuffer(
        const C2Handle *handle,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    (void) handle;

    // TODO: need to figure out BufferDescriptorInfo from the handle.
    allocation->reset();
    return C2_UNSUPPORTED;
}

C2AllocatorGralloc::C2AllocatorGralloc() : mImpl(new Impl) {}
C2AllocatorGralloc::~C2AllocatorGralloc() { delete mImpl; }

C2Error C2AllocatorGralloc::allocateGraphicBuffer(
        uint32_t width, uint32_t height, uint32_t format, C2MemoryUsage usage,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    return mImpl->allocateGraphicBuffer(width, height, format, usage, allocation);
}

C2Error C2AllocatorGralloc::recreateGraphicBuffer(
        const C2Handle *handle,
        std::shared_ptr<C2GraphicAllocation> *allocation) {
    return mImpl->recreateGraphicBuffer(handle, allocation);
}

C2Error C2AllocatorGralloc::status() const { return mImpl->status(); }

/* ========================================== 2D BLOCK ========================================= */

class C2Block2D::Impl {
public:
    const C2Handle *handle() const {
        return mAllocation->handle();
    }

    Impl(const std::shared_ptr<C2GraphicAllocation> &alloc)
        : mAllocation(alloc) {}

private:
    std::shared_ptr<C2GraphicAllocation> mAllocation;
};

C2Block2D::C2Block2D(const std::shared_ptr<C2GraphicAllocation> &alloc)
    : _C2PlanarSection(alloc.get()), mImpl(new Impl(alloc)) {}

const C2Handle *C2Block2D::handle() const {
    return mImpl->handle();
}

class C2GraphicView::Impl {
public:
    Impl(uint8_t *const *data, const C2PlaneLayout &layout)
        : mData(data), mLayout(layout), mError(C2_OK) {}
    explicit Impl(C2Error error) : mData(nullptr), mError(error) {}

    uint8_t *const *data() const { return mData; }
    const C2PlaneLayout &layout() const { return mLayout; }
    C2Error error() const { return mError; }

private:
    uint8_t *const *mData;
    C2PlaneLayout mLayout;
    C2Error mError;
};

C2GraphicView::C2GraphicView(
        const _C2PlanarCapacityAspect *parent,
        uint8_t *const *data,
        const C2PlaneLayout& layout)
    : _C2PlanarSection(parent), mImpl(new Impl(data, layout)) {}

C2GraphicView::C2GraphicView(C2Error error)
    : _C2PlanarSection(nullptr), mImpl(new Impl(error)) {}

const uint8_t *const *C2GraphicView::data() const {
    return mImpl->data();
}

uint8_t *const *C2GraphicView::data() {
    return mImpl->data();
}

const C2PlaneLayout C2GraphicView::layout() const {
    return mImpl->layout();
}

const C2GraphicView C2GraphicView::subView(const C2Rect &rect) const {
    C2GraphicView view(this, mImpl->data(), mImpl->layout());
    view.setCrop_be(rect);
    return view;
}

C2GraphicView C2GraphicView::subView(const C2Rect &rect) {
    C2GraphicView view(this, mImpl->data(), mImpl->layout());
    view.setCrop_be(rect);
    return view;
}

C2Error C2GraphicView::error() const {
    return mImpl->error();
}

class C2ConstGraphicBlock::Impl {
public:
    explicit Impl(const std::shared_ptr<C2GraphicAllocation> &alloc)
        : mAllocation(alloc), mData{ nullptr } {}

    ~Impl() {
        if (mData[0] != nullptr) {
            // TODO: fence
            mAllocation->unmap(nullptr);
        }
    }

    C2Error map(C2Rect rect) {
        if (mData[0] != nullptr) {
            // Already mapped.
            return C2_OK;
        }
        C2Error err = mAllocation->map(
                rect,
                { C2MemoryUsage::kSoftwareRead, 0 },
                nullptr,
                &mLayout,
                mData);
        if (err != C2_OK) {
            memset(mData, 0, sizeof(mData));
        }
        return err;
    }

    C2ConstGraphicBlock subBlock(const C2Rect &rect, C2Fence fence) const {
        C2ConstGraphicBlock block(mAllocation, fence);
        block.setCrop_be(rect);
        return block;
    }

    uint8_t *const *data() const {
        return mData[0] == nullptr ? nullptr : &mData[0];
    }

    const C2PlaneLayout &layout() const { return mLayout; }

private:
    std::shared_ptr<C2GraphicAllocation> mAllocation;
    C2PlaneLayout mLayout;
    uint8_t *mData[C2PlaneLayout::MAX_NUM_PLANES];
};

C2ConstGraphicBlock::C2ConstGraphicBlock(
        const std::shared_ptr<C2GraphicAllocation> &alloc, C2Fence fence)
    : C2Block2D(alloc), mImpl(new Impl(alloc)), mFence(fence) {}

C2Acquirable<const C2GraphicView> C2ConstGraphicBlock::map() const {
    C2Error err = mImpl->map(crop());
    if (err != C2_OK) {
        C2DefaultGraphicView view(err);
        return C2AcquirableConstGraphicView(err, mFence, view);
    }
    C2DefaultGraphicView view(this, mImpl->data(), mImpl->layout());
    return C2AcquirableConstGraphicView(err, mFence, view);
}

C2ConstGraphicBlock C2ConstGraphicBlock::subBlock(const C2Rect &rect) const {
    return mImpl->subBlock(rect, mFence);
}

class C2GraphicBlock::Impl {
public:
    explicit Impl(const std::shared_ptr<C2GraphicAllocation> &alloc)
        : mAllocation(alloc), mData{ nullptr } {}

    ~Impl() {
        if (mData[0] != nullptr) {
            // TODO: fence
            mAllocation->unmap(nullptr);
        }
    }

    C2Error map(C2Rect rect) {
        if (mData[0] != nullptr) {
            // Already mapped.
            return C2_OK;
        }
        uint8_t *data[C2PlaneLayout::MAX_NUM_PLANES];
        C2Error err = mAllocation->map(
                rect,
                { C2MemoryUsage::kSoftwareRead, C2MemoryUsage::kSoftwareWrite },
                nullptr,
                &mLayout,
                data);
        if (err == C2_OK) {
            memcpy(mData, data, sizeof(mData));
        } else {
            memset(mData, 0, sizeof(mData));
        }
        return err;
    }

    C2ConstGraphicBlock share(const C2Rect &crop, C2Fence fence) const {
        C2DefaultConstGraphicBlock block(mAllocation, fence);
        block.setCrop_be(crop);
        return block;
    }

    uint8_t *const *data() const {
        return mData[0] == nullptr ? nullptr : mData;
    }

    const C2PlaneLayout &layout() const { return mLayout; }

private:
    std::shared_ptr<C2GraphicAllocation> mAllocation;
    C2PlaneLayout mLayout;
    uint8_t *mData[C2PlaneLayout::MAX_NUM_PLANES];
};

C2GraphicBlock::C2GraphicBlock(const std::shared_ptr<C2GraphicAllocation> &alloc)
    : C2Block2D(alloc), mImpl(new Impl(alloc)) {}

C2Acquirable<C2GraphicView> C2GraphicBlock::map() {
    C2Error err = mImpl->map(crop());
    if (err != C2_OK) {
        C2DefaultGraphicView view(err);
        // TODO: fence
        return C2AcquirableGraphicView(err, C2Fence(), view);
    }
    C2DefaultGraphicView view(this, mImpl->data(), mImpl->layout());
    // TODO: fence
    return C2AcquirableGraphicView(err, C2Fence(), view);
}

C2ConstGraphicBlock C2GraphicBlock::share(const C2Rect &crop, C2Fence fence) {
    return mImpl->share(crop, fence);
}

C2DefaultGraphicBlockAllocator::C2DefaultGraphicBlockAllocator(
        const std::shared_ptr<C2Allocator> &allocator)
  : mAllocator(allocator) {}

C2Error C2DefaultGraphicBlockAllocator::allocateGraphicBlock(
        uint32_t width,
        uint32_t height,
        uint32_t format,
        C2MemoryUsage usage,
        std::shared_ptr<C2GraphicBlock> *block /* nonnull */) {
    block->reset();

    std::shared_ptr<C2GraphicAllocation> alloc;
    C2Error err = mAllocator->allocateGraphicBuffer(width, height, format, usage, &alloc);
    if (err != C2_OK) {
        return err;
    }

    block->reset(new C2DefaultGraphicBlock(alloc));

    return C2_OK;
}

/* ========================================== BUFFER ========================================= */

class C2BufferData::Impl {
public:
    explicit Impl(const std::list<C2ConstLinearBlock> &blocks)
        : mType(blocks.size() == 1 ? LINEAR : LINEAR_CHUNKS),
          mLinearBlocks(blocks) {
    }

    explicit Impl(const std::list<C2ConstGraphicBlock> &blocks)
        : mType(blocks.size() == 1 ? GRAPHIC : GRAPHIC_CHUNKS),
          mGraphicBlocks(blocks) {
    }

    Type type() const { return mType; }
    const std::list<C2ConstLinearBlock> &linearBlocks() const { return mLinearBlocks; }
    const std::list<C2ConstGraphicBlock> &graphicBlocks() const { return mGraphicBlocks; }

private:
    Type mType;
    std::list<C2ConstLinearBlock> mLinearBlocks;
    std::list<C2ConstGraphicBlock> mGraphicBlocks;
};

C2BufferData::C2BufferData(const std::list<C2ConstLinearBlock> &blocks) : mImpl(new Impl(blocks)) {}
C2BufferData::C2BufferData(const std::list<C2ConstGraphicBlock> &blocks) : mImpl(new Impl(blocks)) {}

C2BufferData::Type C2BufferData::type() const { return mImpl->type(); }

const std::list<C2ConstLinearBlock> C2BufferData::linearBlocks() const {
    return mImpl->linearBlocks();
}

const std::list<C2ConstGraphicBlock> C2BufferData::graphicBlocks() const {
    return mImpl->graphicBlocks();
}

class C2Buffer::Impl {
public:
    Impl(C2Buffer *thiz, const std::list<C2ConstLinearBlock> &blocks)
        : mThis(thiz), mData(blocks) {}
    Impl(C2Buffer *thiz, const std::list<C2ConstGraphicBlock> &blocks)
        : mThis(thiz), mData(blocks) {}

    ~Impl() {
        for (const auto &pair : mNotify) {
            pair.first(mThis, pair.second);
        }
    }

    const C2BufferData &data() const { return mData; }

    C2Error registerOnDestroyNotify(OnDestroyNotify onDestroyNotify, void *arg = nullptr) {
        auto it = std::find_if(
                mNotify.begin(), mNotify.end(),
                [onDestroyNotify, arg] (const auto &pair) {
                    return pair.first == onDestroyNotify && pair.second == arg;
                });
        if (it != mNotify.end()) {
            return C2_DUPLICATE;
        }
        mNotify.emplace_back(onDestroyNotify, arg);
        return C2_OK;
    }

    C2Error unregisterOnDestroyNotify(OnDestroyNotify onDestroyNotify) {
        auto it = std::find_if(
                mNotify.begin(), mNotify.end(),
                [onDestroyNotify] (const auto &pair) {
                    return pair.first == onDestroyNotify;
                });
        if (it == mNotify.end()) {
            return C2_NOT_FOUND;
        }
        mNotify.erase(it);
        return C2_OK;
    }

    std::list<std::shared_ptr<const C2Info>> infos() const {
        std::list<std::shared_ptr<const C2Info>> result(mInfos.size());
        std::transform(
                mInfos.begin(), mInfos.end(), result.begin(),
                [] (const auto &elem) { return elem.second; });
        return result;
    }

    C2Error setInfo(const std::shared_ptr<C2Info> &info) {
        // To "update" you need to erase the existing one if any, and then insert.
        (void) mInfos.erase(info->type());
        (void) mInfos.insert({ info->type(), info });
        return C2_OK;
    }

    bool hasInfo(C2Param::Type index) const {
        return mInfos.count(index.type()) > 0;
    }

    std::shared_ptr<C2Info> removeInfo(C2Param::Type index) {
        auto it = mInfos.find(index.type());
        if (it == mInfos.end()) {
            return nullptr;
        }
        std::shared_ptr<C2Info> ret = it->second;
        (void) mInfos.erase(it);
        return ret;
    }

private:
    C2Buffer * const mThis;
    C2DefaultBufferData mData;
    std::map<uint32_t, std::shared_ptr<C2Info>> mInfos;
    std::list<std::pair<OnDestroyNotify, void *>> mNotify;
};

C2Buffer::C2Buffer(const std::list<C2ConstLinearBlock> &blocks)
    : mImpl(new Impl(this, blocks)) {}

C2Buffer::C2Buffer(const std::list<C2ConstGraphicBlock> &blocks)
    : mImpl(new Impl(this, blocks)) {}

const C2BufferData C2Buffer::data() const { return mImpl->data(); }

C2Error C2Buffer::registerOnDestroyNotify(OnDestroyNotify onDestroyNotify, void *arg) {
    return mImpl->registerOnDestroyNotify(onDestroyNotify, arg);
}

C2Error C2Buffer::unregisterOnDestroyNotify(OnDestroyNotify onDestroyNotify) {
    return mImpl->unregisterOnDestroyNotify(onDestroyNotify);
}

const std::list<std::shared_ptr<const C2Info>> C2Buffer::infos() const {
    return mImpl->infos();
}

C2Error C2Buffer::setInfo(const std::shared_ptr<C2Info> &info) {
    return mImpl->setInfo(info);
}

bool C2Buffer::hasInfo(C2Param::Type index) const {
    return mImpl->hasInfo(index);
}

std::shared_ptr<C2Info> C2Buffer::removeInfo(C2Param::Type index) {
    return mImpl->removeInfo(index);
}

} // namespace android
