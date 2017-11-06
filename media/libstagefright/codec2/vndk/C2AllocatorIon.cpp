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

/* ========================================= ION HANDLE ======================================== */
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

/* ======================================= ION ALLOCATION ====================================== */
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

C2Error C2AllocatorIon::allocateLinearBuffer(
        uint32_t capacity, C2MemoryUsage usage, std::shared_ptr<C2LinearAllocation> *allocation) {
    if (allocation == nullptr) {
        return C2_BAD_VALUE;
    }

    allocation->reset();
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

} // namespace android

