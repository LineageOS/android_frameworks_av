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
#include <poll.h>

#include <android-base/unique_fd.h>
#include <cutils/native_handle.h>
#include <utils/Log.h>
#include <ui/Fence.h>

#include <C2FenceFactory.h>
#include <C2SurfaceSyncObj.h>

#include <utility>

#define MAX_FENCE_FDS 1

class C2Fence::Impl {
public:
    enum type_t : uint32_t {
        INVALID_FENCE,
        NULL_FENCE,
        SURFACE_FENCE,
        SYNC_FENCE,
        PIPE_FENCE,
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
        ALOGD("Cannot create native handle from surface fence");
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
        int64_t timeoutMs = timeoutNs / 1000000;
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
        return (mFence && (mFence->getStatus() != Fence::Status::Invalid));
    }

    virtual bool ready() const {
        return mFence->getStatus() == Fence::Status::Signaled;
    }

    virtual int fd() const {
        return mFence->dup();
    }

    std::vector<int> fds() const {
        std::vector<int> retFds;
        for (int index = 0; index < mListFences.size(); index++) {
            retFds.push_back(mListFences[index]->dup());
        }
        return retFds;
    }

    virtual bool isHW() const {
        return true;
    }

    virtual type_t type() const {
        return SYNC_FENCE;
    }

    virtual native_handle_t *createNativeHandle() const {
        std::vector<int> nativeFds = fds();
        nativeFds.push_back(fd());
        native_handle_t* nh = native_handle_create(nativeFds.size(), 1);
        if (!nh) {
            ALOGE("Failed to allocate native handle for sync fence");
            for (int fd : nativeFds) {
                close(fd);
            }
            return nullptr;
        }

        for (int i = 0; i < nativeFds.size(); i++) {
            nh->data[i] = nativeFds[i];
        }
        nh->data[nativeFds.size()] = type();
        return nh;
    }

    virtual ~SyncFenceImpl() {};

    SyncFenceImpl(int fenceFd) :
        mFence(sp<Fence>::make(fenceFd)) {
        mListFences.clear();
        if (mFence) {
            mListFences.push_back(mFence);
        }
    }

    SyncFenceImpl(const std::vector<int>& fenceFds, int mergedFd) {
        mListFences.clear();

        for (int fenceFd : fenceFds) {
            if (fenceFd < 0) {
                continue;
            } else {
                mListFences.push_back(sp<Fence>::make(fenceFd));
                if (!mListFences.back()) {
                    mFence.clear();
                    break;
                }
                if (mergedFd == -1) {
                    mFence = (mFence == nullptr) ? (mListFences.back()) :
                        (Fence::merge("syncFence", mFence, mListFences.back()));
                }
            }
        }
        if (mergedFd != -1)
        {
            mFence = sp<Fence>::make(mergedFd);
        }
        if (!mFence) {
            mListFences.clear();
        }
    }

    static std::shared_ptr<SyncFenceImpl> CreateFromNativeHandle(const native_handle_t* nh) {
        if (!nh || nh->numFds < 1 || nh->numInts < 1) {
            ALOGE("Invalid handle for sync fence");
            return nullptr;
        }
        std::vector<int> fds;
        for (int i = 0; i < nh->numFds-1; i++) {
            fds.push_back(dup(nh->data[i]));
        }
        std::shared_ptr<SyncFenceImpl> p = (nh->numFds == 1)?
                (std::make_shared<SyncFenceImpl>(fds.back())):
                (std::make_shared<SyncFenceImpl>(fds, (dup(nh->data[nh->numFds-1]))));
        if (!p) {
            ALOGE("Failed to allocate sync fence impl");
            for (int fd : fds) {
                close(fd);
            }
        }
        return p;
    }

private:
    std::vector<sp<Fence>> mListFences;
    sp<Fence> mFence;  //merged fence in case mListFences size > 0
};

std::vector<int> ExtractFdsFromCodec2SyncFence(const C2Fence& fence) {
    std::vector<int> retFds;
    if ((fence.mImpl) && (fence.mImpl->type() == C2Fence::Impl::SYNC_FENCE)) {
        retFds = static_cast<_C2FenceFactory::SyncFenceImpl *>(fence.mImpl.get())->fds();
    }
    return retFds;
}

C2Fence _C2FenceFactory::CreateSyncFence(int fenceFd) {
    std::shared_ptr<C2Fence::Impl> p;
    if (fenceFd >= 0) {
        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(fenceFd);
        if (!p) {
            ALOGE("Failed to allocate sync fence impl");
            close(fenceFd);
        } else if (!p->valid()) {
            p.reset();
        }
    } else {
        ALOGV("Create sync fence from invalid fd");
        return C2Fence();
    }
    return C2Fence(p);
}

C2Fence _C2FenceFactory::CreateMultipleFdSyncFence(const std::vector<int>& fenceFds) {
    std::shared_ptr<C2Fence::Impl> p;
    if (fenceFds.size() > 0) {
        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(fenceFds, -1);
        if (!p) {
            ALOGE("Failed to allocate sync fence impl closing FDs");
            for (int fenceFd : fenceFds) {
                close(fenceFd);
            }
        } else if (!p->valid()) {
            ALOGE("Invalid sync fence created");
            p.reset();
        }
    } else {
        ALOGE("Create sync fence from invalid fd list of size 0");
    }
    return C2Fence(p);
}

/**
 * Fence implementation for notifying # of events available based on
 * file descriptors created by pipe()/pipe2(). The writing end of the
 * file descriptors is used to create the implementation.
 * The implementation supports all C2Fence interface.
 */
class _C2FenceFactory::PipeFenceImpl: public C2Fence::Impl {
private:
    bool waitEvent(c2_nsecs_t timeoutNs, bool *hangUp, bool *event) const {
        if (!mValid) {
            *hangUp = true;
            return true;
        }

        struct pollfd pfd;
        pfd.fd = mPipeFd.get();
        pfd.events = POLLIN;
        pfd.revents = 0;
        struct timespec ts;
        if (timeoutNs >= 0) {
            ts.tv_sec = int(timeoutNs / 1000000000);
            ts.tv_nsec = timeoutNs % 1000000000;
        } else {
            ALOGD("polling for indefinite duration requested, but changed to wait for %d sec",
                  kPipeFenceWaitLimitSecs);
            ts.tv_sec = kPipeFenceWaitLimitSecs;
            ts.tv_nsec = 0;
        }
        int ret = ::ppoll(&pfd, 1, &ts, nullptr);
        if (ret >= 0) {
            if (pfd.revents) {
                if (pfd.revents & ~POLLIN) {
                    // Mostly this means the writing end fd was closed.
                    *hangUp = true;
                    mValid = false;
                    ALOGD("PipeFenceImpl: pipe fd hangup or err event returned");
                }
                *event = true;
                return true;
            }
            // event not ready yet.
            return true;
        }
        if (errno == EINTR) {
            // poll() was cancelled by signal or inner kernel status.
            return false;
        }
        // Since poll error happened here, treat the error is irrecoverable.
        ALOGE("PipeFenceImpl: poll() error %d", errno);
        *hangUp = true;
        mValid = false;
        return true;
    }

public:
    virtual c2_status_t wait(c2_nsecs_t timeoutNs) {
        if (!mValid) {
            return C2_BAD_STATE;
        }
        bool hangUp = false;
        bool event = false;
        if (waitEvent(timeoutNs, &hangUp, &event)) {
            if (hangUp) {
                return C2_BAD_STATE;
            }
            if (event) {
                return C2_OK;
            }
            return C2_TIMED_OUT;
        } else {
            return C2_CANCELED;
        }
    }

    virtual bool valid() const {
        if (!mValid) {
            return false;
        }
        bool hangUp = false;
        bool event = false;
        if (waitEvent(0, &hangUp, &event)) {
            if (hangUp) {
                return false;
            }
        }
        return true;
    }

    virtual bool ready() const {
        if (!mValid) {
            return false;
        }
        bool hangUp = false;
        bool event = false;
        if (waitEvent(0, &hangUp, &event)) {
            if (event) {
                return true;
            }
        }
        return false;
    }

    virtual int fd() const {
        if (!mValid) {
            return -1;
        }
        return ::dup(mPipeFd.get());
    }

    virtual bool isHW() const {
        return false;
    }

    virtual type_t type() const {
        return PIPE_FENCE;
    }

    virtual native_handle_t *createNativeHandle() const {
        // This is not supported.
        return nullptr;
    }

    virtual ~PipeFenceImpl() = default;

    PipeFenceImpl(int fd) : mPipeFd(fd) {
        mValid = (mPipeFd.get() >= 0);
    }

    PipeFenceImpl(::android::base::unique_fd &&ufd) : mPipeFd{std::move(ufd)} {
        mValid = (mPipeFd.get() >= 0);
    }

private:
    friend struct _C2FenceFactory;
    static constexpr int kPipeFenceWaitLimitSecs = 5;

    mutable std::atomic<bool> mValid;
    const ::android::base::unique_fd mPipeFd;
};

C2Fence _C2FenceFactory::CreatePipeFence(int fd) {
    ::android::base::unique_fd ufd{fd};
    return CreatePipeFence(std::move(ufd));
}

C2Fence _C2FenceFactory::CreatePipeFence(::android::base::unique_fd &&ufd) {
    std::shared_ptr<_C2FenceFactory::PipeFenceImpl> impl =
        std::make_shared<_C2FenceFactory::PipeFenceImpl>(std::move(ufd));
    std::shared_ptr<C2Fence::Impl> p = std::static_pointer_cast<C2Fence::Impl>(impl);
    if (!p) {
        ALOGE("PipeFence creation failure");
    } else if (!impl->mValid) {
        p.reset();
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
            ALOGV("Unsupported fence type %d", type);
            // If this is malformed-handle close the handle here.
            (void) native_handle_close(handle);
            // return a null-fence in this case
            break;
    }
    if (p && !p->valid()) {
        p.reset();
    }
    return C2Fence(p);
}

