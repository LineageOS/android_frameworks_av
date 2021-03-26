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
#include <utils/Log.h>

#include <C2FenceFactory.h>
#include <C2SurfaceSyncObj.h>

class C2Fence::Impl {
public:
    virtual c2_status_t wait(c2_nsecs_t timeoutNs) = 0;

    virtual bool valid() const = 0;

    virtual bool ready() const = 0;

    virtual int fd() const = 0;

    virtual bool isHW() const = 0;

    virtual ~Impl() = default;

    Impl() = default;
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
