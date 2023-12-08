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
#define LOG_TAG "C2SurfaceSyncObj"
#include <limits.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <utils/Log.h>

#include <chrono>
#include <C2SurfaceSyncObj.h>

namespace {
static inline void timespec_add_ms(timespec& ts, size_t ms) {
    constexpr int kNanoSecondsPerSec = 1000000000;
    ts.tv_sec  += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000;
    if (ts.tv_nsec >= kNanoSecondsPerSec) {
        ts.tv_sec++;
        ts.tv_nsec -= kNanoSecondsPerSec;
    }
}

/*
 * lhs < rhs:  return <0
 * lhs == rhs: return 0
 * lhs > rhs:  return >0
 */
static inline int timespec_compare(const timespec& lhs, const timespec& rhs) {
    if (lhs.tv_sec < rhs.tv_sec) {
        return -1;
    }
    if (lhs.tv_sec > rhs.tv_sec) {
        return 1;
    }
    return lhs.tv_nsec - rhs.tv_nsec;
}
}

const native_handle_t C2SurfaceSyncMemory::HandleSyncMem::cHeader = {
    C2SurfaceSyncMemory::HandleSyncMem::version,
    C2SurfaceSyncMemory::HandleSyncMem::numFds,
    C2SurfaceSyncMemory::HandleSyncMem::numInts,
    {}
};

bool C2SurfaceSyncMemory::HandleSyncMem::isValid(const native_handle_t * const o) {
    if (!o || memcmp(o, &cHeader, sizeof(cHeader))) {
        return false;
    }

    const HandleSyncMem *other = static_cast<const HandleSyncMem*>(o);
    return other->mInts.mMagic == kMagic;
}

C2SurfaceSyncMemory::C2SurfaceSyncMemory()
    : mInit(false), mHandle(nullptr), mMem(nullptr) {}

C2SurfaceSyncMemory::~C2SurfaceSyncMemory() {
    if (mInit) {
        if (mMem) {
            munmap(static_cast<void *>(mMem), mHandle->size());
        }
        if (mHandle) {
            native_handle_close(mHandle);
            native_handle_delete(mHandle);
        }
    }
}

std::shared_ptr<C2SurfaceSyncMemory> C2SurfaceSyncMemory::Import(
        native_handle_t *handle) {
    if (!HandleSyncMem::isValid(handle)) {
        return nullptr;
    }

    HandleSyncMem *o = static_cast<HandleSyncMem*>(handle);
    if (o->size() < sizeof(C2SyncVariables)) {
        android_errorWriteLog(0x534e4554, "240140929");
        return nullptr;
    }

    void *ptr = mmap(NULL, o->size(), PROT_READ | PROT_WRITE, MAP_SHARED, o->memFd(), 0);

    if (ptr == MAP_FAILED) {
        native_handle_close(handle);
        native_handle_delete(handle);
        return nullptr;
    }

    std::shared_ptr<C2SurfaceSyncMemory> syncMem(new C2SurfaceSyncMemory);
    syncMem->mInit = true;
    syncMem->mHandle = o;
    syncMem->mMem = static_cast<C2SyncVariables*>(ptr);
    return syncMem;
}

std::shared_ptr<C2SurfaceSyncMemory> C2SurfaceSyncMemory::Create(int fd, size_t size) {
    if (fd < 0 || size == 0) {
        return nullptr;
    }
    HandleSyncMem *handle = new HandleSyncMem(fd, size);

    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        native_handle_close(handle);
        native_handle_delete(handle);
        return nullptr;
    }
    memset(ptr, 0, size);

    std::shared_ptr<C2SurfaceSyncMemory> syncMem(new C2SurfaceSyncMemory);
    syncMem->mInit = true;
    syncMem->mHandle = handle;
    syncMem->mMem = static_cast<C2SyncVariables*>(ptr);
    return syncMem;
}

native_handle_t *C2SurfaceSyncMemory::handle() {
    return !mInit ? nullptr : mHandle;
}

C2SyncVariables *C2SurfaceSyncMemory::mem() {
    return !mInit ? nullptr : mMem;
}

namespace {
    constexpr int kSpinNumForLock = 0;
    constexpr int kSpinNumForUnlock = 0;

    enum : uint32_t {
        FUTEX_UNLOCKED = 0,
        FUTEX_LOCKED_UNCONTENDED = 1,  // user-space locking
        FUTEX_LOCKED_CONTENDED = 2,    // futex locking
    };
}

int C2SyncVariables::lock() {
    uint32_t old = FUTEX_UNLOCKED;

    // see if we can lock uncontended immediately (if previously unlocked)
    if (mLock.compare_exchange_strong(old, FUTEX_LOCKED_UNCONTENDED)) {
        return 0;
    }

    // spin to see if we can get it with a short wait without involving kernel
    for (int i = 0; i < kSpinNumForLock; i++) {
        sched_yield();

        old = FUTEX_UNLOCKED;
        if (mLock.compare_exchange_strong(old, FUTEX_LOCKED_UNCONTENDED)) {
            return 0;
        }
    }

    // still locked, if other side thinks it was uncontended, now it is contended, so let them
    // know that they need to wake us up.
    if (old == FUTEX_LOCKED_UNCONTENDED) {
        old = mLock.exchange(FUTEX_LOCKED_CONTENDED);
        // It is possible that the other holder released the lock at this very moment (and old
        // becomes UNLOCKED), If so, we will not involve the kernel to wait for the lock to be
        // released, but are still marking our lock contended (even though we are the only
        // holders.)
    }

    // while the futex is still locked by someone else
    while (old != FUTEX_UNLOCKED) {
        // wait until other side releases the lock (and still contented)
        (void)syscall(__NR_futex, &mLock, FUTEX_WAIT, FUTEX_LOCKED_CONTENDED, NULL, NULL, 0);
        // try to relock
        old = mLock.exchange(FUTEX_LOCKED_CONTENDED);
    }
    return 0;
}

int C2SyncVariables::unlock() {
    // TRICKY: here we assume that we are holding this lock

    // unlock the lock immediately (since we were holding it)
    // If it is (still) locked uncontested, we are done (no need to involve the kernel)
    if (mLock.exchange(FUTEX_UNLOCKED) == FUTEX_LOCKED_UNCONTENDED) {
        return 0;
    }

    // We don't need to spin for unlock as here we know already we have a waiter who we need to
    // wake up. This code was here in case someone just happened to lock this lock (uncontested)
    // before we would wake up other waiters to avoid a syscall. It is unsure if this ever gets
    // exercised or if this is the behavior we want. (Note that if this code is removed, the same
    // situation is still handled in lock() by the woken up waiter that realizes that the lock is
    // now taken.)
    for (int i = 0; i < kSpinNumForUnlock; i++) {
        // here we seem to check if someone relocked this lock, and if they relocked uncontested,
        // we up it to contested (since there are other waiters.)
        if (mLock.load() != FUTEX_UNLOCKED) {
            uint32_t old = FUTEX_LOCKED_UNCONTENDED;
            mLock.compare_exchange_strong(old, FUTEX_LOCKED_CONTENDED);
            // this is always true here so we return immediately
            if (old) {
                return 0;
            }
        }
        sched_yield();
    }

    // wake up one waiter
    (void)syscall(__NR_futex, &mLock, FUTEX_WAKE, 1, NULL, NULL, 0);
    return 0;
}

void C2SyncVariables::setInitialDequeueCountLocked(
        int32_t maxDequeueCount, int32_t curDequeueCount) {
    mMaxDequeueCount = maxDequeueCount;
    mCurDequeueCount = curDequeueCount;
}

uint32_t C2SyncVariables::getWaitIdLocked() {
    return mCond.load();
}

bool C2SyncVariables::isDequeueableLocked(uint32_t *waitId) {
    if (mMaxDequeueCount <= mCurDequeueCount) {
        if (waitId) {
            *waitId = getWaitIdLocked();
        }
        return false;
    }
    return true;
}

bool C2SyncVariables::notifyQueuedLocked(uint32_t *waitId, bool notify) {
    // Note. thundering herds may occur. Edge trigged signalling.
    // But one waiter will guarantee to dequeue. others may wait again.
    // Minimize futex syscall(trap) for the main use case(one waiter case).
    if (mMaxDequeueCount == mCurDequeueCount--) {
        if (notify) {
            broadcast();
        }
        return true;
    }

    if (mCurDequeueCount >= mMaxDequeueCount) {
        if (waitId) {
            *waitId = getWaitIdLocked();
        }
        ALOGV("dequeue blocked %d/%d", mCurDequeueCount, mMaxDequeueCount);
        return false;
    }
    return true;
}

void C2SyncVariables::notifyDequeuedLocked() {
    mCurDequeueCount++;
    ALOGV("dequeue successful %d/%d", mCurDequeueCount, mMaxDequeueCount);
}

void C2SyncVariables::setSyncStatusLocked(SyncStatus status) {
    mStatus = status;
    if (mStatus == STATUS_ACTIVE) {
        broadcast();
    }
}

C2SyncVariables::SyncStatus C2SyncVariables::getSyncStatusLocked() {
    return mStatus;
}

void C2SyncVariables::updateMaxDequeueCountLocked(int32_t maxDequeueCount) {
    mMaxDequeueCount = maxDequeueCount;
    if (mStatus == STATUS_ACTIVE) {
        broadcast();
    }
}

c2_status_t C2SyncVariables::waitForChange(uint32_t waitId, c2_nsecs_t timeoutNs) {
    if (timeoutNs < 0) {
        timeoutNs = 0;
    }
    struct timespec tv;
    tv.tv_sec = timeoutNs / 1000000000;
    tv.tv_nsec = timeoutNs % 1000000000;

    int ret =  syscall(__NR_futex, &mCond, FUTEX_WAIT, waitId, &tv, NULL, 0);
    if (ret == 0 || errno == EAGAIN) {
        return C2_OK;
    }
    if (errno == EINTR || errno == ETIMEDOUT) {
        return C2_TIMED_OUT;
    }
    return C2_BAD_VALUE;
}

void C2SyncVariables::notifyAll() {
    this->lock();
    this->broadcast();
    this->unlock();
}

void C2SyncVariables::invalidate() {
    mCond++;
    (void) syscall(__NR_futex, &mCond, FUTEX_REQUEUE, INT_MAX, (void *)INT_MAX, &mLock, 0);
}

void C2SyncVariables::clearLockIfNecessary() {
    // Note: After waiting for 30ms without acquiring the lock,
    // we will consider the lock is dangling.
    // Since the lock duration is very brief to manage the counter,
    // waiting for 30ms should be more than enough.
    constexpr size_t kTestLockDurationMs = 30;

    bool locked = tryLockFor(kTestLockDurationMs);
    unlock();

    if (!locked) {
        ALOGW("A dead process might be holding the lock");
    }
}

int C2SyncVariables::signal() {
    mCond++;

    (void) syscall(__NR_futex, &mCond, FUTEX_WAKE, 1, NULL, NULL, 0);
    return 0;
}

int C2SyncVariables::broadcast() {
    mCond++;

    (void) syscall(__NR_futex, &mCond, FUTEX_REQUEUE, 1, (void *)INT_MAX, &mLock, 0);
    return 0;
}

int C2SyncVariables::wait() {
    uint32_t old = mCond.load();
    unlock();

    (void) syscall(__NR_futex, &mCond, FUTEX_WAIT, old, NULL, NULL, 0);
    while (mLock.exchange(FUTEX_LOCKED_CONTENDED)) {
        (void) syscall(__NR_futex, &mLock, FUTEX_WAIT, FUTEX_LOCKED_CONTENDED, NULL, NULL, 0);
    }
    return 0;
}

bool C2SyncVariables::tryLockFor(size_t ms) {
    uint32_t old = FUTEX_UNLOCKED;

    if (mLock.compare_exchange_strong(old, FUTEX_LOCKED_UNCONTENDED)) {
        return true;
    }

    if (old == FUTEX_LOCKED_UNCONTENDED) {
        old = mLock.exchange(FUTEX_LOCKED_CONTENDED);
    }

    struct timespec wait{
            static_cast<time_t>(ms / 1000),
            static_cast<long>((ms % 1000) * 1000000)};
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);
    timespec_add_ms(end, ms);

    while (old != FUTEX_UNLOCKED) { // case of EINTR being returned;
        (void)syscall(__NR_futex, &mLock, FUTEX_WAIT, FUTEX_LOCKED_CONTENDED, &wait, NULL, 0);
        old = mLock.exchange(FUTEX_LOCKED_CONTENDED);

        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        if (timespec_compare(now, end) >= 0) {
            break;
        }
    }

    return old == FUTEX_UNLOCKED;
}
