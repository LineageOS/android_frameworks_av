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
#define LOG_TAG "C2AllocatorIon"
#include <utils/Log.h>

#include <ion/ion.h>
#include <sys/mman.h>

#include <C2AllocatorIon.h>
#include <C2Buffer.h>
#include <C2ErrnoUtils.h>

namespace android {

/* size_t <=> int(lo), int(hi) conversions */
constexpr inline int size2intLo(size_t s) {
    return int(s & 0xFFFFFFFF);
}

constexpr inline int size2intHi(size_t s) {
    // cast to uint64_t as size_t may be 32 bits wide
    return int((uint64_t(s) >> 32) & 0xFFFFFFFF);
}

constexpr inline size_t ints2size(int intLo, int intHi) {
    // convert in 2 stages to 64 bits as intHi may be negative
    return size_t(unsigned(intLo)) | size_t(uint64_t(unsigned(intHi)) << 32);
}

/* ========================================= ION HANDLE ======================================== */
/**
 * ION handle
 *
 * There can be only a sole ion client per process, this is captured in the ion fd that is passed
 * to the constructor, but this should be managed by the ion buffer allocator/mapper.
 *
 * ion uses ion_user_handle_t for buffers. We don't store this in the native handle as
 * it requires an ion_free to decref. Instead, we share the buffer to get an fd that also holds
 * a refcount.
 *
 * This handle will not capture mapped fd-s as updating that would require a global mutex.
 */

struct C2HandleIon : public C2Handle {
    // ion handle owns ionFd(!) and bufferFd
    C2HandleIon(int bufferFd, size_t size)
        : C2Handle(cHeader),
          mFds{ bufferFd },
          mInts{ int(size & 0xFFFFFFFF), int((uint64_t(size) >> 32) & 0xFFFFFFFF), kMagic } { }

    static bool isValid(const C2Handle * const o);

    int bufferFd() const { return mFds.mBuffer; }
    size_t size() const {
        return size_t(unsigned(mInts.mSizeLo))
                | size_t(uint64_t(unsigned(mInts.mSizeHi)) << 32);
    }

protected:
    struct {
        int mBuffer; // shared ion buffer
    } mFds;
    struct {
        int mSizeLo; // low 32-bits of size
        int mSizeHi; // high 32-bits of size
        int mMagic;
    } mInts;

private:
    typedef C2HandleIon _type;
    enum {
        kMagic = '\xc2io\x00',
        numFds = sizeof(mFds) / sizeof(int),
        numInts = sizeof(mInts) / sizeof(int),
        version = sizeof(C2Handle)
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

/* ======================================= ION ALLOCATION ====================================== */
class C2AllocationIon : public C2LinearAllocation {
public:
    /* Interface methods */
    virtual c2_status_t map(
        size_t offset, size_t size, C2MemoryUsage usage, int *fence,
        void **addr /* nonnull */) override;
    virtual c2_status_t unmap(void *addr, size_t size, int *fenceFd) override;
    virtual bool isValid() const override;
    virtual ~C2AllocationIon() override;
    virtual const C2Handle *handle() const override;
    virtual bool equals(const std::shared_ptr<C2LinearAllocation> &other) const override;

    // internal methods
    C2AllocationIon(int ionFd, size_t size, size_t align, unsigned heapMask, unsigned flags);
    C2AllocationIon(int ionFd, size_t size, int shareFd);

    c2_status_t status() const;

protected:
    class Impl;
    Impl *mImpl;

    // TODO: we could make this encapsulate shared_ptr and copiable
    C2_DO_NOT_COPY(C2AllocationIon);
};

class C2AllocationIon::Impl {
private:
    /**
     * Constructs an ion allocation.
     *
     * \note We always create an ion allocation, even if the allocation or import fails
     * so that we can capture the error.
     *
     * \param ionFd     ion client (ownership transferred to created object)
     * \param capacity  size of allocation
     * \param bufferFd  buffer handle (ownership transferred to created object). Must be
     *                  invalid if err is not 0.
     * \param buffer    ion buffer user handle (ownership transferred to created object). Must be
     *                  invalid if err is not 0.
     * \param err       errno during buffer allocation or import
     */
    Impl(int ionFd, size_t capacity, int bufferFd, ion_user_handle_t buffer, int err)
        : mIonFd(ionFd),
          mHandle(bufferFd, capacity),
          mBuffer(buffer),
          mInit(c2_map_errno<ENOMEM, EACCES, EINVAL>(err)),
          mMapFd(-1),
          mMapSize(0) {
        if (mInit != C2_OK) {
            // close ionFd now on error
            if (mIonFd >= 0) {
                close(mIonFd);
                mIonFd = -1;
            }
            // C2_CHECK(bufferFd < 0);
            // C2_CHECK(buffer < 0);
        }
    }

public:
    /**
     * Constructs an ion allocation by importing a shared buffer fd.
     *
     * \param ionFd     ion client (ownership transferred to created object)
     * \param capacity  size of allocation
     * \param bufferFd  buffer handle (ownership transferred to created object)
     *
     * \return created ion allocation (implementation) which may be invalid if the
     * import failed.
     */
    static Impl *Import(int ionFd, size_t capacity, int bufferFd) {
        ion_user_handle_t buffer = -1;
        int ret = ion_import(ionFd, bufferFd, &buffer);
        return new Impl(ionFd, capacity, bufferFd, buffer, ret);
    }

    /**
     * Constructs an ion allocation by allocating an ion buffer.
     *
     * \param ionFd     ion client (ownership transferred to created object)
     * \param size      size of allocation
     * \param align     desired alignment of allocation
     * \param heapMask  mask of heaps considered
     * \param flags     ion allocation flags
     *
     * \return created ion allocation (implementation) which may be invalid if the
     * allocation failed.
     */
    static Impl *Alloc(int ionFd, size_t size, size_t align, unsigned heapMask, unsigned flags) {
        int bufferFd = -1;
        ion_user_handle_t buffer = -1;
        int ret = ion_alloc(ionFd, size, align, heapMask, flags, &buffer);
        if (ret == 0) {
            // get buffer fd for native handle constructor
            ret = ion_share(ionFd, buffer, &bufferFd);
            if (ret != 0) {
                ion_free(ionFd, buffer);
                buffer = -1;
            }
        }
        return new Impl(ionFd, size, bufferFd, buffer, ret);
    }

    c2_status_t map(size_t offset, size_t size, C2MemoryUsage usage, int *fenceFd, void **addr) {
        (void)fenceFd; // TODO: wait for fence
        *addr = nullptr;
        if (mMapSize > 0) {
            // TODO: technically we should return DUPLICATE here, but our block views don't
            // actually unmap, so we end up remapping an ion buffer multiple times.
            //
            // return C2_DUPLICATE;
        }
        if (size == 0) {
            return C2_BAD_VALUE;
        }

        int prot = PROT_NONE;
        int flags = MAP_PRIVATE;
        if (usage.consumer & C2MemoryUsage::CPU_READ) {
            prot |= PROT_READ;
        }
        if (usage.producer & C2MemoryUsage::CPU_WRITE) {
            prot |= PROT_WRITE;
            flags = MAP_SHARED;
        }

        size_t alignmentBytes = offset % PAGE_SIZE;
        size_t mapOffset = offset - alignmentBytes;
        size_t mapSize = size + alignmentBytes;

        c2_status_t err = C2_OK;
        if (mMapFd == -1) {
            int ret = ion_map(mIonFd, mBuffer, mapSize, prot,
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

    c2_status_t unmap(void *addr, size_t size, int *fenceFd) {
        if (mMapFd < 0 || mMapSize == 0) {
            return C2_NOT_FOUND;
        }
        if (addr != (uint8_t *)mMapAddr + mMapAlignmentBytes ||
                size + mMapAlignmentBytes != mMapSize) {
            return C2_BAD_VALUE;
        }
        int err = munmap(mMapAddr, mMapSize);
        if (err != 0) {
            return c2_map_errno<EINVAL>(errno);
        }
        if (fenceFd) {
            *fenceFd = -1; // not using fences
        }
        mMapSize = 0;
        return C2_OK;
    }

    ~Impl() {
        if (mMapFd >= 0) {
            close(mMapFd);
            mMapFd = -1;
        }
        if (mInit == C2_OK) {
            (void)ion_free(mIonFd, mBuffer);
        }
        if (mIonFd >= 0) {
            close(mIonFd);
        }
        native_handle_close(&mHandle);
    }

    c2_status_t status() const {
        return mInit;
    }

    const C2Handle *handle() const {
        return &mHandle;
    }

private:
    int mIonFd;
    C2HandleIon mHandle;
    ion_user_handle_t mBuffer;
    c2_status_t mInit;
    int mMapFd; // only one for now
    void *mMapAddr;
    size_t mMapAlignmentBytes;
    size_t mMapSize;
};

c2_status_t C2AllocationIon::map(
    size_t offset, size_t size, C2MemoryUsage usage, int *fenceFd, void **addr) {
    return mImpl->map(offset, size, usage, fenceFd, addr);
}

c2_status_t C2AllocationIon::unmap(void *addr, size_t size, int *fenceFd) {
    return mImpl->unmap(addr, size, fenceFd);
}

bool C2AllocationIon::isValid() const {
    return mImpl->status() == C2_OK;
}

c2_status_t C2AllocationIon::status() const {
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
      mImpl(Impl::Alloc(ionFd, size, align, heapMask, flags)) { }

C2AllocationIon::C2AllocationIon(int ionFd, size_t size, int shareFd)
    : C2LinearAllocation(size),
      mImpl(Impl::Import(ionFd, size, shareFd)) { }

/* ======================================= ION ALLOCATOR ====================================== */
C2AllocatorIon::C2AllocatorIon() : mInit(C2_OK), mIonFd(ion_open()) {
    if (mIonFd < 0) {
        switch (errno) {
        case ENOENT:    mInit = C2_OMITTED; break;
        default:        mInit = c2_map_errno<EACCES>(errno); break;
        }
    }
}

C2AllocatorIon::~C2AllocatorIon() {
    if (mInit == C2_OK) {
        ion_close(mIonFd);
    }
}

C2Allocator::id_t C2AllocatorIon::getId() const {
    return 0; /// \todo implement ID
}

C2String C2AllocatorIon::getName() const {
    return "android.allocator.ion";
}

c2_status_t C2AllocatorIon::newLinearAllocation(
        uint32_t capacity, C2MemoryUsage usage, std::shared_ptr<C2LinearAllocation> *allocation) {
    if (allocation == nullptr) {
        return C2_BAD_VALUE;
    }

    allocation->reset();
    if (mInit != C2_OK) {
        return mInit;
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
        = std::make_shared<C2AllocationIon>(dup(mIonFd), capacity, align, heapMask, flags);
    c2_status_t ret = alloc->status();
    if (ret == C2_OK) {
        *allocation = alloc;
    }
    return ret;
}

c2_status_t C2AllocatorIon::priorLinearAllocation(
        const C2Handle *handle, std::shared_ptr<C2LinearAllocation> *allocation) {
    *allocation = nullptr;
    if (mInit != C2_OK) {
        return mInit;
    }

    if (!C2HandleIon::isValid(handle)) {
        return C2_BAD_VALUE;
    }

    // TODO: get capacity and validate it
    const C2HandleIon *h = static_cast<const C2HandleIon*>(handle);
    std::shared_ptr<C2AllocationIon> alloc
        = std::make_shared<C2AllocationIon>(dup(mIonFd), h->size(), h->bufferFd());
    c2_status_t ret = alloc->status();
    if (ret == C2_OK) {
        *allocation = alloc;
    }
    return ret;
}

} // namespace android

