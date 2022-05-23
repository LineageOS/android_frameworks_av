/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "C2FenceFactory"
#include <cutils/native_handle.h>
#include <utils/Log.h>
#include <ui/Fence.h>

#include <C2FenceFactory.h>
#include <C2SurfaceSyncObj.h>

#define MAX_FENCE_FDS 1

class C2Fence::Impl {
public:
    enum type_t : uint32_t {
        INVALID_FENCE,
        NULL_FENCE,
        SURFACE_FENCE,
        SYNC_FENCE,
    };

    virtual c2_status_t wait(c2_nsecs_t timeoutNs) = 0;

    virtual bool valid() const = 0;

    virtual bool ready() const = 0;

    virtual int fd() const = 0;

    virtual bool isHW() const = 0;

    virtual type_t type() const = 0;

    /**
     * Create a native handle for the fence so it can be marshalled.
     * The native handle must store fence type in the first integer.
     *
     * \return a valid native handle if the fence can be marshalled, otherwise return null.
     */
    virtual native_handle_t *createNativeHandle() const = 0;

    virtual ~Impl() = default;

    Impl() = default;

    static type_t GetTypeFromNativeHandle(const native_handle_t* nh) {
        if (nh && nh->numFds >= 0 && nh->numFds <= MAX_FENCE_FDS && nh->numInts > 0) {
            return static_cast<type_t>(nh->data[nh->numFds]);
        }
        return INVALID_FENCE;
    }
};

c2_status_t C2Fence::wait(c2_nsecs_t timeoutNs) {
    if (mImpl) {
        return mImpl->wait(timeoutNs);
    }
    // null fence is always signalled.
    return C2_OK;
}

bool C2Fence::valid() const {
    if (mImpl) {
        return mImpl->valid();
    }
    // null fence is always valid.
    return true;
}

bool C2Fence::ready() const {
    if (mImpl) {
        return mImpl->ready();
    }
    // null fence is always signalled.
    return true;
}

int C2Fence::fd() const {
    if (mImpl) {
        return mImpl->fd();
    }
    // null fence does not have fd.
    return -1;
}

bool C2Fence::isHW() const {
    if (mImpl) {
        return mImpl->isHW();
    }
    return false;
}

/**
 * Fence implementation for C2BufferQueueBlockPool based block allocation.
 * The implementation supports all C2Fence interface except fd().
 */
class _C2FenceFactory::SurfaceFenceImpl: public C2Fence::Impl {
public:
    virtual c2_status_t wait(c2_nsecs_t timeoutNs) {
        if (mPtr) {
            return mPtr->waitForChange(mWaitId, timeoutNs);
        }
        return C2_OK;
    }

    virtual bool valid() const {
        return mPtr;
    }

    virtual bool ready() const {
        uint32_t status;
        if (mPtr) {
            mPtr->lock();
            status = mPtr->getWaitIdLocked();
            mPtr->unlock();

            return status != mWaitId;
        }
        return true;
    }

    virtual int fd() const {
        // does not support fd, since this is shared mem and futex based
        return -1;
    }

    virtual bool isHW() const {
        return false;
    }

    virtual type_t type() const {
        return SURFACE_FENCE;
    }

    virtual native_handle_t *createNativeHandle() const {
        ALOG_ASSERT(false, "Cannot create native handle from surface fence");
        return nullptr;
    }

    virtual ~SurfaceFenceImpl() {};

    SurfaceFenceImpl(std::shared_ptr<C2SurfaceSyncMemory> syncMem, uint32_t waitId) :
            mSyncMem(syncMem),
            mPtr(syncMem ? syncMem->mem() : nullptr),
            mWaitId(syncMem ? waitId : 0) {}
private:
    const std::shared_ptr<const C2SurfaceSyncMemory> mSyncMem; // This is for life-cycle guarantee
    C2SyncVariables *const mPtr;
    const uint32_t mWaitId;
};

C2Fence::C2Fence(std::shared_ptr<Impl> impl) : mImpl(impl) {}

C2Fence _C2FenceFactory::CreateSurfaceFence(
        std::shared_ptr<C2SurfaceSyncMemory> syncMem,
        uint32_t waitId) {
    if (syncMem) {
        C2Fence::Impl *p
                = new _C2FenceFactory::SurfaceFenceImpl(syncMem, waitId);
        if (p->valid()) {
            return C2Fence(std::shared_ptr<C2Fence::Impl>(p));
        } else {
            delete p;
        }
    }
    return C2Fence();
}

using namespace android;

class _C2FenceFactory::SyncFenceImpl : public C2Fence::Impl {
public:
    virtual c2_status_t wait(c2_nsecs_t timeoutNs) {
        c2_nsecs_t timeoutMs = timeoutNs / 1000;
        if (timeoutMs > INT_MAX) {
            timeoutMs = INT_MAX;
        }

        switch (mFence->wait((int)timeoutMs)) {
            case NO_ERROR:
                return C2_OK;
            case -ETIME:
                return C2_TIMED_OUT;
            default:
                return C2_CORRUPTED;
        }
    }

    virtual bool valid() const {
        return mFence->getStatus() != Fence::Status::Invalid;
    }

    virtual bool ready() const {
        return mFence->getStatus() == Fence::Status::Signaled;
    }

    virtual int fd() const {
        return mFence->dup();
    }

    virtual bool isHW() const {
        return true;
    }

    virtual type_t type() const {
        return SYNC_FENCE;
    }

    virtual native_handle_t *createNativeHandle() const {
        native_handle_t* nh = native_handle_create(1, 1);
        if (!nh) {
            ALOGE("Failed to allocate native handle for sync fence");
            return nullptr;
        }
        nh->data[0] = fd();
        nh->data[1] = type();
        return nh;
    }

    virtual ~SyncFenceImpl() {};

    SyncFenceImpl(int fenceFd) :
            mFence(sp<Fence>::make(fenceFd)) {}

    static std::shared_ptr<SyncFenceImpl> CreateFromNativeHandle(const native_handle_t* nh) {
        if (!nh || nh->numFds != 1 || nh->numInts != 1) {
            ALOGE("Invalid handle for sync fence");
            return nullptr;
        }
        int fd = dup(nh->data[0]);
        std::shared_ptr<SyncFenceImpl> p = std::make_shared<SyncFenceImpl>(fd);
        if (!p) {
            ALOGE("Failed to allocate sync fence impl");
            close(fd);
        }
        return p;
    }

private:
    const sp<Fence> mFence;
};

C2Fence _C2FenceFactory::CreateSyncFence(int fenceFd) {
    std::shared_ptr<C2Fence::Impl> p;
    if (fenceFd >= 0) {
        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(fenceFd);
        if (!p) {
            ALOGE("Failed to allocate sync fence impl");
            close(fenceFd);
        }
        if (!p->valid()) {
            p.reset();
        }
    } else {
        ALOGE("Create sync fence from invalid fd");
    }
    return C2Fence(p);
}

native_handle_t* _C2FenceFactory::CreateNativeHandle(const C2Fence& fence) {
    return fence.mImpl? fence.mImpl->createNativeHandle() : nullptr;
}

C2Fence _C2FenceFactory::CreateFromNativeHandle(const native_handle_t* handle) {
    if (!handle) {
        return C2Fence();
    }
    C2Fence::Impl::type_t type = C2Fence::Impl::GetTypeFromNativeHandle(handle);
    std::shared_ptr<C2Fence::Impl> p;
    switch (type) {
        case C2Fence::Impl::SYNC_FENCE:
            p = SyncFenceImpl::CreateFromNativeHandle(handle);
            break;
        default:
            ALOG_ASSERT(false, "Unsupported fence type %d", type);
            break;
    }
    if (p && !p->valid()) {
        p.reset();
    }
    return C2Fence(p);
}

