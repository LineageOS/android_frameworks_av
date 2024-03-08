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

#ifndef STAGEFRIGHT_CODEC2_SURFACE_SYNC_OBJ_H_
#define STAGEFRIGHT_CODEC2_SURFACE_SYNC_OBJ_H_

#include <cutils/native_handle.h>
#include <memory>
#include <atomic>

#include <C2Buffer.h>

/**
 * Futex based lock / wait implementation for sharing output buffer allocation
 * information between Framework and HAL.
 */
struct C2SyncVariables {
    enum SyncStatus : uint32_t {
           STATUS_INIT = 0,         // When surface configuration starts.
           STATUS_ACTIVE = 1,       // When surface configuration finishs.
                                    // STATUS_INIT -> STATUS_ACTIVE
           STATUS_SWITCHING = 2,    // When the surface is replaced by a new surface
                                    // during surface configuration.
                                    // STATUS_ACTIVE -> STATUS_SWITCHING
    };

    /**
     * Lock the memory region
     */
    int lock();

    /**
     * Unlock the memory region
     */
    int unlock();

    /**
     * Set initial dequeued buffer count.
     *
     * \param maxDequeueCount           Initial value of # of max dequeued buffer count
     * \param curDequeueCount           Initial value of # of current dequeued buffer count
     */
    void setInitialDequeueCountLocked(int32_t maxDequeueCount, int32_t curDequeueCount);

    /**
     * Get a waitId which will be used to implement fence.
     */
    uint32_t getWaitIdLocked();

    /**
     * Return whether the upcoming dequeue operation is not blocked.
     * if it's blocked and waitId is non-null, waitId is returned to be used for waiting.
     *
     * \retval false    dequeue operation is blocked now.
     * \retval true     dequeue operation is possible.
     */
    bool isDequeueableLocked(uint32_t *waitId = nullptr);

    /**
     * Notify a buffer is queued. Return whether the upcoming dequeue operation
     * is not blocked. if it's blocked and waitId is non-null, waitId is returned
     * to be used for waiting. Notify(wake-up) waitors only when 'notify' is
     * true.
     *
     * \retval false    dequeue operation is blocked now.
     * \retval true     dequeue operation is possible.
     */
    bool notifyQueuedLocked(uint32_t *waitId = nullptr, bool notify = true);

    /**
     * Notify a buffer is dequeued.
     */
    void notifyDequeuedLocked();

    /**
     * Set sync status.
     */
    void setSyncStatusLocked(SyncStatus status);

    /**
     * Get sync status.
     */
    C2SyncVariables::SyncStatus getSyncStatusLocked();

    /**
     * Update current max dequeue count.
     */
    void updateMaxDequeueCountLocked(int32_t maxDequeueCount);

    /**
     * Wait until status is no longer equal to waitId, or until timeout.
     *
     * \param waitId            internal status for waiting until it is changed.
     * \param timeousNs         nano seconds to timeout.
     *
     * \retval C2_TIMEDOUT      change does not happen during waiting.
     * \retval C2_BAD_VALUE     invalid event waiting.
     * \retval C2_OK            change was signalled.
     */
    c2_status_t waitForChange(uint32_t waitId, c2_nsecs_t timeoutNs);

    /**
     * Wake up and expire all waitors.
     */
    void notifyAll();

    /**
     * Invalide current sync variables on the death of the other process.
     */
    void invalidate();

    /**
     * If a dead process holds the lock, clear the lock.
     */
    void clearLockIfNecessary();

    C2SyncVariables() {}

private:
    /**
     * signal one waiter to wake up.
     */
    int signal();

    /**
     * signal all waiter to wake up.
     */
    int broadcast();

    /**
     * wait for signal or broadcast.
     */
    int wait();

    /**
     * try lock for the specified duration.
     */
    bool tryLockFor(size_t ms);

    std::atomic<uint32_t> mLock;
    std::atomic<uint32_t> mCond;
    int32_t mMaxDequeueCount;
    int32_t mCurDequeueCount;
    SyncStatus mStatus;
};

/**
 * Shared memory in order to synchronize information for Surface(IGBP)
 * based output buffer allocation.
 */
class C2SurfaceSyncMemory {
public:
    /**
     * Shared memory handle in order to synchronize information for
     * Surface based output buffer allocation.
     */
    struct HandleSyncMem : public native_handle_t {
        HandleSyncMem(int fd, size_t size) :
            native_handle_t(cHeader),
            mFds{fd},
            mInts{int(size & 0xFFFFFFFF),
                int((uint64_t(size) >> 32) & 0xFFFFFFFF), kMagic} {}

        /** Returns a file descriptor of the shared memory
         * \return a file descriptor representing the shared memory
         */
        int memFd() const {return mFds.mMem;}

        /** Returns the size of the shared memory */
        size_t size() const {
            return size_t(unsigned(mInts.mSizeLo))
                    | size_t(uint64_t(unsigned(mInts.mSizeHi)) << 32);
        }

        /** Check whether the native handle is in the form of HandleSyncMem
         *
         * \return whether the native handle is compatible
         */
        static bool isValid(const native_handle_t * const o);

    protected:
        struct {
            int mMem;
        } mFds;
        struct {
            int mSizeLo;
            int mSizeHi;
            int mMagic;
        } mInts;
    private:
        enum {
            kMagic = 'ssm\x00',
            numFds = sizeof(mFds) / sizeof(int),
            numInts = sizeof(mInts) / sizeof(int),
            version = sizeof(native_handle_t)
        };
        const static native_handle_t cHeader;
    };

    /**
     * Imports a shared memory object from a native handle(The shared memory is already existing).
     * This is usually used after native_handle_t is passed via RPC.
     *
     * \param handle        handle representing shared memory for output buffer allocation.
     */
    static std::shared_ptr<C2SurfaceSyncMemory> Import(native_handle_t *handle);

    /**
     * Creats a shared memory object for synchronization of output buffer allocation.
     * Shared memory creation should be done explicitly.
     *
     * \param fd            file descriptor to shared memory
     * \param size          size of the shared memory
     */
    static std::shared_ptr<C2SurfaceSyncMemory> Create(int fd, size_t size);

    /**
     * Returns a handle representing the shread memory for synchronization of
     * output buffer allocation.
     */
    native_handle_t *handle();

    /**
     * Returns synchronization object which will provide synchronization primitives.
     *
     * \return a ptr to synchronization primitive class
     */
    C2SyncVariables *mem();

    ~C2SurfaceSyncMemory();

private:
    bool mInit;
    HandleSyncMem *mHandle;
    C2SyncVariables *mMem;

    C2SurfaceSyncMemory();
};

#endif // STAGEFRIGHT_CODEC2_SURFACE_SYNC_OBJ_H_
