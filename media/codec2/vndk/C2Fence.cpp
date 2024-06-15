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

// support up to 32 sync fds (and an optional merged fd), and 1 int
#define MAX_FENCE_FDS  33
#define MAX_FENCE_INTS 1

class C2Fence::Impl {
public:
    // These enums are not part of the ABI, so can be changed.
    enum type_t : int32_t {
        INVALID_FENCE     = -1,
        NULL_FENCE        = 0,
        SURFACE_FENCE     = 2,

        SYNC_FENCE        = 3,
        PIPE_FENCE        = 4,
    };

    // magic numbers for native handles
    enum : int32_t {
        SYNC_FENCE_DEPRECATED_MAGIC     = 3,
        SYNC_FENCE_UNORDERED_MAGIC      = '\302fsu',
        SYNC_FENCE_MAGIC                = '\302fso',
    };

    virtual c2_status_t wait(c2_nsecs_t timeoutNs) = 0;

    virtual bool valid() const = 0;

    virtual bool ready() const = 0;

    virtual int fd() const = 0;

    virtual bool isHW() const = 0;

    virtual type_t type() const = 0;

    /**
     * Create a native handle for the fence so it can be marshalled.
     * All native handles must store fence type in the last integer.
     * The created native handle (if not null) must be closed by the caller.
     *
     * \return a valid native handle if the fence can be marshalled, otherwise return null.
     */
    virtual native_handle_t *createNativeHandle() const = 0;

    virtual ~Impl() = default;

    Impl() = default;

    /**
     * Get the type of the fence from the native handle.
     *
     * \param nh the native handle to get the type from.
     * \return the type of the fence, or INVALID_FENCE if the native handle is
     * invalid or malformed.
     */
    static type_t GetTypeFromNativeHandle(const native_handle_t* nh) {
        if (!nh || nh->numFds < 0 || nh->numFds > MAX_FENCE_FDS
                || nh->numInts < 1 || nh->numInts > MAX_FENCE_INTS) {
            return INVALID_FENCE;
        }

        // the magic number for Codec 2.0 native handles is the last integer
        switch (nh->data[nh->numFds + nh->numInts - 1]) {
            case SYNC_FENCE_MAGIC:
            case SYNC_FENCE_UNORDERED_MAGIC:
            case SYNC_FENCE_DEPRECATED_MAGIC:
                return SYNC_FENCE;

            default:
                return INVALID_FENCE;
        }
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

/**
 * Implementation for a sync fence.
 *
 * A sync fence is fundamentally a fence that is created from an android sync
 * fd (which represents a HW fence).
 *
 * The native handle layout for a single sync fence is:
 *   fd[0]  - sync fd
 *   int[0] - magic (SYNC_FENCE_MAGIC (=`\302fso'))
 *
 * Note: Between Android T and 24Q3, the magic number was erroneously
 * SYNC_FENCE (=3).
 *
 * Multi(ple) Sync Fences
 *
 * Since Android 24Q3, this implementation also supports a sequence of
 * sync fences. When this is the case, there is an expectation that the last
 * sync fence being ready will guarantee that all other sync fences are
 * also ready. (This guarantees backward compatibility to a single fd sync fence,
 * and mFence will be that final fence.)
 *
 * It is furthermore recommended that the fences be in order - either by
 * expected signaling time, or by the order in which they need to be ready. The
 * specific ordering is not specified or enforced, but it could be an
 * implementation requirement of the specific use case in the future.
 *
 * This implementation also supports an unordered set of sync fences. In this
 * case, it will merge all the fences into a single merged fence, which will
 * be the backward compatible singular fence (stored in mFence).
 *
 * The native handle layout for an unordered multi-fence sync fence (from Android
 * 24Q3) is:
 *
 *   fd[0]   - sync fd 1
 *   ...
 *   fd[n-1] - sync fd N
 *   fd[n]   - merged fence fd
 *   int[0]  - magic (SYNC_FENCE_UNORDERED_MAGIC (='\302fsu'))
 *
 * The native handle layout for an ordered multi-fence sync fence (from Android
 * 24Q3) is:
 *
 *   fd[0]   - sync fd 1
 *   ...
 *   fd[n-1] - sync fd N
 *   int[0]  - magic (SYNC_FENCE_MAGIC (='\302fso'))
 */
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

    /**
     * Returns a duped list of fds used when creating this fence. It will
     * not return the internally created merged fence fd.
     */
    std::vector<int> fds() const {
        std::vector<int> retFds;
        for (int index = 0; index < mListFences.size(); index++) {
            retFds.push_back(mListFences[index]->dup());
        }
        // ensure that at least one fd is returned
        if (mListFences.empty()) {
            retFds.push_back(mFence->dup());
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
        int32_t magic = SYNC_FENCE_MAGIC;

        // Also parcel the singular fence if it is not already part of the list.
        // If this was a single-fd fence, mListFences will be empty, but fds()
        // already returned that a list with that single fd.
        if (!mListFences.empty() && mListFences.back() != mFence) {
            nativeFds.push_back(fd());
            if (!mListFences.empty()) {
                magic = SYNC_FENCE_UNORDERED_MAGIC;
            }
        }

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
        nh->data[nativeFds.size()] = magic;
        return nh;
    }

    virtual ~SyncFenceImpl() {};

    /**
     * Constructs a SyncFenceImpl from a single sync fd. No error checking is
     * performed on the fd here as we cannot make this a null fence.
     *
     * \param fenceFd the fence fd to create the SyncFenceImpl from.
     */
    SyncFenceImpl(int fenceFd) :
        mFence(sp<Fence>::make(fenceFd)) {
    }

    SyncFenceImpl(const sp<Fence> &fence) :
        mFence(fence) {
    }

    /**
     * Constructs a SyncFenceImpl from a list of sync fds.
     *
     * \param fenceFds the list of fence fds to create the SyncFenceImpl from.
     * \param finalFence the singular fence for this multi-fd fence. This can
     * be either the last fence in fences or a sepearate (merged) fence.
     */
    SyncFenceImpl(const std::vector<sp<Fence>>& fences, const sp<Fence> &finalFence) :
        mListFences(fences),
        mFence(finalFence) {
    }

    /**
     * Creates a SyncFenceImpl from a native handle.
     *
     * \param nh the native handle to create the SyncFenceImpl from.
     * \param takeOwnership if true, the SyncFenceImpl will take ownership of the
     *                      file descriptors in the native handle. Otherwise,
     *                      the SyncFenceImpl will dup the file descriptors.
     *
     * \return a shared_ptr to the SyncFenceImpl, or nullptr if the native
     * handle is invalid or malformed.
    */
    static std::shared_ptr<SyncFenceImpl> CreateFromNativeHandle(
            const native_handle_t* nh, bool takeOwnership) {
        // we should only call this method if _C2FenceFactory::GetTypeFromNativeHandle
        // returned SYNC_FENCE, but do these checks anyways to avoid overflows
        // in case that does not happen.
        if (!nh) {
            ALOGE("Invalid handle for a sync fence (nullptr)");
            return nullptr;
        } else if (nh->numFds < 1 || nh->numInts < 1
                || nh->numFds > MAX_FENCE_FDS || nh->numInts > MAX_FENCE_INTS) {
            ALOGE("Invalid handle for a sync fence (%d fds, %d ints)", nh->numFds, nh->numInts);
            return nullptr;
        }
        std::vector<sp<Fence>> fences;
        for (int i = 0; i < nh->numFds; i++) {
            int fd = nh->data[i];
            if (!takeOwnership && fd >= 0) {
                fd = dup(fd);
            }
            if (fd >= 0) {
                sp<Fence> fence = sp<Fence>::make(fd);
                if (fence) {
                    fences.push_back(fence);
                } else {
                    ALOGW("Failed to create fence from fd %d", fd);
                }
            }
        }

        std::shared_ptr<SyncFenceImpl> p;
        if (fences.size() == 0) {
            ALOGE("No valid fences found in handle for a sync fence");
            return nullptr;
        } else if (fences.size() == 1) {
            p = std::make_shared<SyncFenceImpl>(fences[0]);
        } else {
            int32_t magic = nh->data[nh->numFds + nh->numInts - 1];
            if (magic != SYNC_FENCE_MAGIC) {
                // The last fence is the merged fence. Separate it.
                sp<Fence> finalFence = fences.back();
                fences.pop_back();

                // Special case: if we end up with only a single element list
                // with another merged fence, that merged fence must be the
                // same fence. This happened in an early version of multi fd
                // support for single-fd sync fences.
                if (fences.size() == 1) {
                    // For single-fd fence the sp-s must be equal
                    finalFence = fences.back();
                }
                p = std::make_shared<SyncFenceImpl>(fences, finalFence);
            } else {
                // Use the last fence as the standalone fence.
                p = std::make_shared<SyncFenceImpl>(fences, fences.back());
            }
        }

        ALOGE_IF(!p, "Failed to allocate sync fence impl");
        return p;
    }

private:
    /**
     * The list of fences in case of a multi-fence sync fence. Otherwise, this
     * list is empty.
     */
    std::vector<sp<Fence>> mListFences;

    /**
     * The singular fence for this sync fence. For multi-fence sync fences,
     * this could be a merged fence, or simply the final fence.
     */
    sp<Fence> mFence;
};

std::vector<int> ExtractFdsFromCodec2SyncFence(const C2Fence& fence) {
    std::vector<int> retFds;
    if ((fence.mImpl) && (fence.mImpl->type() == C2Fence::Impl::SYNC_FENCE)) {
        retFds = static_cast<_C2FenceFactory::SyncFenceImpl *>(fence.mImpl.get())->fds();
    }
    return retFds;
}

C2Fence _C2FenceFactory::CreateSyncFence(int fenceFd, bool validate) {
    std::shared_ptr<C2Fence::Impl> p;
    if (fenceFd >= 0) {
        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(fenceFd);
        if (!p) {
            ALOGE("Failed to allocate sync fence impl");
            close(fenceFd);
        } else if (validate && (!p->valid() || p->ready())) {
            // don't create a fence object if the sync fd already signaled or is invalid
            p.reset();
        }
    } else {
        ALOGV("Won't create sync fence from invalid fd");
    }
    return C2Fence(p);
}

C2Fence _C2FenceFactory::CreateUnorderedMultiSyncFence(
        const std::vector<int>& fenceFds, c2_status_t *status) {
    if (status) {
        *status = C2_OK;
    }

    sp<Fence> finalFence;
    std::vector<sp<Fence>> fences;

    bool mergeFailed = false;
    for (int fenceFd : fenceFds) {
        if (fenceFd < 0) {
            // ignore invalid fences
            continue;
        }
        sp<Fence> fence = sp<Fence>::make(fenceFd);

        // If we could not create an sp, further sp-s will also fail.
        if (fence == nullptr) {
            if (status) {
                *status = C2_NO_MEMORY;
            }
            break;
        }
        fences.push_back(fence);

        if (finalFence == nullptr) {
            finalFence = fence;
        } else {
            sp<Fence> mergedFence = Fence::merge("syncFence", finalFence, fence);
            if (mergedFence == nullptr || mergedFence == Fence::NO_FENCE) {
                ALOGE_IF(!mergeFailed, "Could not merge fences for sync fence.");
                mergeFailed = true;
                if (status) {
                    *status = (mergedFence == nullptr) ? C2_NO_MEMORY : C2_CORRUPTED;
                }

                if (mergedFence == nullptr) {
                    break;
                }
                // If we cannot merge one of the fences, the best course of action
                // is to keep going, as the alternative would be to clear all fences
                // (making this a null fence) but that will always be ready.
            } else {
                finalFence = mergedFence;
            }
        }
    }

    // we may have ended up with a single or no fence due to merging failures or
    // invalid fds.
    if (fences.size() == 0) {
        // we have no fds, we have a null fence.
        return C2Fence();
    }

    std::shared_ptr<C2Fence::Impl> p;

    if (fences.size() == 1) {
        // We have a single sync fd. We don't need the merged fence, which is
        // already simply that sole fence.
        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(finalFence);
    } else {
        // if we couldn't merge any fences just use the last one
        if (finalFence == fences[0]) {
            finalFence = fences.back();
        }

        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(fences, finalFence);
    }

    if (!p) {
        ALOGE("Failed to allocate sync fence impl closing FDs");
        // all fds were moved into Fence objects which will close them.
        if (status) {
            *status = C2_NO_MEMORY;
        }
        return C2Fence();
    }

    return C2Fence(p);
}

C2Fence _C2FenceFactory::CreateMultiSyncFence(
        const std::vector<int>& fenceFds, c2_status_t *status) {
    if (status) {
        *status = C2_OK;
    }

    std::vector<sp<Fence>> fences;

    for (int fenceFd : fenceFds) {
        if (fenceFd < 0) {
            // ignore invalid fences
            continue;
        }
        sp<Fence> fence = sp<Fence>::make(fenceFd);

        // If we could not create an sp, keep going with the existing fences.
        if (fence == nullptr) {
            if (status) {
                *status = C2_NO_MEMORY;
            }
            break;
        }
        fences.push_back(fence);
    }

    // we may have ended up with a single or no fence due to invalid fds.
    if (fences.size() == 0) {
        // we have no fds, we have a null fence.
        return C2Fence();
    }

    std::shared_ptr<C2Fence::Impl> p;

    if (fences.size() == 1) {
        // We have a single sync fd, this is a simple sync fence.
        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(fences[0]);
    } else {
        p = std::make_shared<_C2FenceFactory::SyncFenceImpl>(fences, fences.back());
    }

    if (!p) {
        ALOGE("Failed to allocate sync fence impl closing FDs");
        // all fds were moved into Fence objects which will close them.
        if (status) {
            *status = C2_NO_MEMORY;
        }
        return C2Fence();
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

C2Fence _C2FenceFactory::CreateFromNativeHandle(
        const native_handle_t* handle, bool takeOwnership) {
    if (!handle) {
        return C2Fence();
    }
    C2Fence::Impl::type_t type = C2Fence::Impl::GetTypeFromNativeHandle(handle);
    std::shared_ptr<C2Fence::Impl> p;
    switch (type) {
        case C2Fence::Impl::SYNC_FENCE:
            p = SyncFenceImpl::CreateFromNativeHandle(handle, takeOwnership);
            break;
        default:
            ALOGV("Unsupported fence type %d", type);
            // Still close the handle here if taking ownership.
            if (takeOwnership) {
                (void) native_handle_close(handle);
            }
            // return a null-fence in this case
            break;
    }
    if (p && !p->valid()) {
        p.reset();
    }
    return C2Fence(p);
}

