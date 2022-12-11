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
    constexpr int kSpinNumForLock = 100;
    constexpr int kSpinNumForUnlock = 200;

    enum : uint32_t {
        FUTEX_UNLOCKED = 0,
        FUTEX_LOCKED_UNCONTENDED = 1,  // user-space locking
        FUTEX_LOCKED_CONTENDED = 2,    // futex locking
    };
}

int C2SyncVariables::lock() {
    uint32_t old;
    for (int i = 0; i < kSpinNumForLock; i++) {
        old = 0;
        if (mLock.compare_exchange_strong(old, FUTEX_LOCKED_UNCONTENDED)) {
            return 0;
        }
        sched_yield();
    }

    if (old == FUTEX_LOCKED_UNCONTENDED)
        old = mLock.exchange(FUTEX_LOCKED_CONTENDED);

    while (old) {
        (void) syscall(__NR_futex, &mLock, FUTEX_WAIT, FUTEX_LOCKED_CONTENDED, NULL, NULL, 0);
        old = mLock.exchange(FUTEX_LOCKED_CONTENDED);
    }
    return 0;
}

int C2SyncVariables::unlock() {
    if (mLock.exchange(FUTEX_UNLOCKED) == FUTEX_LOCKED_UNCONTENDED) return 0;

    for (int i = 0; i < kSpinNumForUnlock; i++) {
        if (mLock.load()) {
            uint32_t old = FUTEX_LOCKED_UNCONTENDED;
            mLock.compare_exchange_strong(old, FUTEX_LOCKED_CONTENDED);
            if (old) {
                return 0;
            }
        }
        sched_yield();
    }

    (void) syscall(__NR_futex, &mLock, FUTEX_WAKE, 1, NULL, NULL, 0);
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

bool C2SyncVariables::notifyQueuedLocked(uint32_t *waitId) {
    // Note. thundering herds may occur. Edge trigged signalling.
    // But one waiter will guarantee to dequeue. others may wait again.
    // Minimize futex syscall(trap) for the main use case(one waiter case).
    if (mMaxDequeueCount == mCurDequeueCount--) {
        broadcast();
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
    if (ret == 0 || ret == EAGAIN) {
        return C2_OK;
    }
    if (ret == EINTR || ret == ETIMEDOUT) {
        return C2_TIMED_OUT;
    }
    return C2_BAD_VALUE;
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
