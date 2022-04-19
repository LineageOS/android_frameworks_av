/*
 * Copyright (C) 2020 The Android Open Source Project
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
#define LOG_TAG "C2DmaBufAllocator"

#include <BufferAllocator/BufferAllocator.h>
#include <C2Buffer.h>
#include <C2Debug.h>
#include <C2DmaBufAllocator.h>
#include <C2ErrnoUtils.h>

#include <linux/ion.h>
#include <sys/mman.h>
#include <unistd.h>  // getpagesize, size_t, close, dup
#include <utils/Log.h>

#include <list>

#include <android-base/properties.h>
#include <media/stagefright/foundation/Mutexed.h>

namespace android {

namespace {
    constexpr size_t USAGE_LRU_CACHE_SIZE = 1024;

    // max padding after ion/dmabuf allocations in bytes
    constexpr uint32_t MAX_PADDING = 0x8000; // 32KB
}

/* =========================== BUFFER HANDLE =========================== */
/**
 * Buffer handle
 *
 * Stores dmabuf fd & metadata
 *
 * This handle will not capture mapped fd-s as updating that would require a
 * global mutex.
 */

struct C2HandleBuf : public C2Handle {
    C2HandleBuf(int bufferFd, size_t size)
        : C2Handle(cHeader),
          mFds{bufferFd},
          mInts{int(size & 0xFFFFFFFF), int((uint64_t(size) >> 32) & 0xFFFFFFFF), kMagic} {}

    static bool IsValid(const C2Handle* const o);

    int bufferFd() const { return mFds.mBuffer; }
    size_t size() const {
        return size_t(unsigned(mInts.mSizeLo)) | size_t(uint64_t(unsigned(mInts.mSizeHi)) << 32);
    }

   protected:
    struct {
        int mBuffer;  // dmabuf fd
    } mFds;
    struct {
        int mSizeLo;  // low 32-bits of size
        int mSizeHi;  // high 32-bits of size
        int mMagic;
    } mInts;

   private:
    typedef C2HandleBuf _type;
    enum {
        kMagic = '\xc2io\x00',
        numFds = sizeof(mFds) / sizeof(int),
        numInts = sizeof(mInts) / sizeof(int),
        version = sizeof(C2Handle)
    };
    // constexpr static C2Handle cHeader = { version, numFds, numInts, {} };
    const static C2Handle cHeader;
};

const C2Handle C2HandleBuf::cHeader = {
        C2HandleBuf::version, C2HandleBuf::numFds, C2HandleBuf::numInts, {}};

// static
bool C2HandleBuf::IsValid(const C2Handle* const o) {
    if (!o || memcmp(o, &cHeader, sizeof(cHeader))) {
        return false;
    }
    const C2HandleBuf* other = static_cast<const C2HandleBuf*>(o);
    return other->mInts.mMagic == kMagic;
}

/* =========================== DMABUF ALLOCATION =========================== */
class C2DmaBufAllocation : public C2LinearAllocation {
   public:
    /* Interface methods */
    virtual c2_status_t map(size_t offset, size_t size, C2MemoryUsage usage, C2Fence* fence,
                            void** addr /* nonnull */) override;
    virtual c2_status_t unmap(void* addr, size_t size, C2Fence* fenceFd) override;
    virtual ~C2DmaBufAllocation() override;
    virtual const C2Handle* handle() const override;
    virtual id_t getAllocatorId() const override;
    virtual bool equals(const std::shared_ptr<C2LinearAllocation>& other) const override;

    // internal methods

    /**
      * Constructs an allocation via a new allocation.
      *
      * @param alloc     allocator
      * @param allocSize size used for the allocator
      * @param capacity  capacity advertised to the client
      * @param heap_name name of the dmabuf heap (device)
      * @param flags     flags
      * @param id        allocator id
      */
    C2DmaBufAllocation(BufferAllocator& alloc, size_t allocSize, size_t capacity,
                       C2String heap_name, unsigned flags, C2Allocator::id_t id);

    /**
      * Constructs an allocation by wrapping an existing allocation.
      *
      * @param size    capacity advertised to the client
      * @param shareFd dmabuf fd of the wrapped allocation
      * @param id      allocator id
      */
    C2DmaBufAllocation(size_t size, int shareFd, C2Allocator::id_t id);

    c2_status_t status() const;

   protected:
    virtual c2_status_t mapInternal(size_t mapSize, size_t mapOffset, size_t alignmentBytes,
                                    int prot, int flags, void** base, void** addr) {
        c2_status_t err = C2_OK;
        *base = mmap(nullptr, mapSize, prot, flags, mHandle.bufferFd(), mapOffset);
        ALOGV("mmap(size = %zu, prot = %d, flags = %d, mapFd = %d, offset = %zu) "
              "returned (%d)",
              mapSize, prot, flags, mHandle.bufferFd(), mapOffset, errno);
        if (*base == MAP_FAILED) {
            *base = *addr = nullptr;
            err = c2_map_errno<EINVAL>(errno);
        } else {
            *addr = (uint8_t*)*base + alignmentBytes;
        }
        return err;
    }

    C2Allocator::id_t mId;
    C2HandleBuf mHandle;
    c2_status_t mInit;
    struct Mapping {
        void* addr;
        size_t alignmentBytes;
        size_t size;
    };
    Mutexed<std::list<Mapping>> mMappings;

    // TODO: we could make this encapsulate shared_ptr and copiable
    C2_DO_NOT_COPY(C2DmaBufAllocation);
};

c2_status_t C2DmaBufAllocation::map(size_t offset, size_t size, C2MemoryUsage usage, C2Fence* fence,
                                    void** addr) {
    (void)fence;  // TODO: wait for fence
    *addr = nullptr;
    if (!mMappings.lock()->empty()) {
        ALOGV("multiple map");
        // TODO: technically we should return DUPLICATE here, but our block views
        // don't actually unmap, so we end up remapping the buffer multiple times.
        //
        // return C2_DUPLICATE;
    }
    if (size == 0) {
        return C2_BAD_VALUE;
    }

    int prot = PROT_NONE;
    int flags = MAP_SHARED;
    if (usage.expected & C2MemoryUsage::CPU_READ) {
        prot |= PROT_READ;
    }
    if (usage.expected & C2MemoryUsage::CPU_WRITE) {
        prot |= PROT_WRITE;
    }

    size_t alignmentBytes = offset % PAGE_SIZE;
    size_t mapOffset = offset - alignmentBytes;
    size_t mapSize = size + alignmentBytes;
    Mapping map = {nullptr, alignmentBytes, mapSize};

    c2_status_t err =
            mapInternal(mapSize, mapOffset, alignmentBytes, prot, flags, &(map.addr), addr);
    if (map.addr) {
        mMappings.lock()->push_back(map);
    }
    return err;
}

c2_status_t C2DmaBufAllocation::unmap(void* addr, size_t size, C2Fence* fence) {
    Mutexed<std::list<Mapping>>::Locked mappings(mMappings);
    if (mappings->empty()) {
        ALOGD("tried to unmap unmapped buffer");
        return C2_NOT_FOUND;
    }
    for (auto it = mappings->begin(); it != mappings->end(); ++it) {
        if (addr != (uint8_t*)it->addr + it->alignmentBytes ||
            size + it->alignmentBytes != it->size) {
            continue;
        }
        int err = munmap(it->addr, it->size);
        if (err != 0) {
            ALOGD("munmap failed");
            return c2_map_errno<EINVAL>(errno);
        }
        if (fence) {
            *fence = C2Fence();  // not using fences
        }
        (void)mappings->erase(it);
        ALOGV("successfully unmapped: %d", mHandle.bufferFd());
        return C2_OK;
    }
    ALOGD("unmap failed to find specified map");
    return C2_BAD_VALUE;
}

c2_status_t C2DmaBufAllocation::status() const {
    return mInit;
}

C2Allocator::id_t C2DmaBufAllocation::getAllocatorId() const {
    return mId;
}

bool C2DmaBufAllocation::equals(const std::shared_ptr<C2LinearAllocation>& other) const {
    if (!other || other->getAllocatorId() != getAllocatorId()) {
        return false;
    }
    // get user handle to compare objects
    std::shared_ptr<C2DmaBufAllocation> otherAsBuf =
            std::static_pointer_cast<C2DmaBufAllocation>(other);
    return mHandle.bufferFd() == otherAsBuf->mHandle.bufferFd();
}

const C2Handle* C2DmaBufAllocation::handle() const {
    return &mHandle;
}

C2DmaBufAllocation::~C2DmaBufAllocation() {
    Mutexed<std::list<Mapping>>::Locked mappings(mMappings);
    if (!mappings->empty()) {
        ALOGD("Dangling mappings!");
        for (const Mapping& map : *mappings) {
            int err = munmap(map.addr, map.size);
            if (err) ALOGD("munmap failed");
        }
    }
    if (mInit == C2_OK) {
        native_handle_close(&mHandle);
    }
}

C2DmaBufAllocation::C2DmaBufAllocation(BufferAllocator& alloc, size_t allocSize, size_t capacity,
                                       C2String heap_name, unsigned flags, C2Allocator::id_t id)
    : C2LinearAllocation(capacity), mHandle(-1, 0) {
    int bufferFd = -1;
    int ret = 0;

    bufferFd = alloc.Alloc(heap_name, allocSize, flags);
    if (bufferFd < 0) {
        ret = bufferFd;
    }

    // this may be a non-working handle if bufferFd is negative
    mHandle = C2HandleBuf(bufferFd, capacity);
    mId = id;
    mInit = c2_status_t(c2_map_errno<ENOMEM, EACCES, EINVAL>(ret));
}

C2DmaBufAllocation::C2DmaBufAllocation(size_t size, int shareFd, C2Allocator::id_t id)
    : C2LinearAllocation(size), mHandle(-1, 0) {
    mHandle = C2HandleBuf(shareFd, size);
    mId = id;
    mInit = c2_status_t(c2_map_errno<ENOMEM, EACCES, EINVAL>(0));
}

/* =========================== DMABUF ALLOCATOR =========================== */
C2DmaBufAllocator::C2DmaBufAllocator(id_t id) : mInit(C2_OK) {
    C2MemoryUsage minUsage = {0, 0};
    C2MemoryUsage maxUsage = {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};
    Traits traits = {"android.allocator.dmabuf", id, LINEAR, minUsage, maxUsage};
    mTraits = std::make_shared<Traits>(traits);
}

C2Allocator::id_t C2DmaBufAllocator::getId() const {
    std::lock_guard<std::mutex> lock(mUsageMapperLock);
    return mTraits->id;
}

C2String C2DmaBufAllocator::getName() const {
    std::lock_guard<std::mutex> lock(mUsageMapperLock);
    return mTraits->name;
}

std::shared_ptr<const C2Allocator::Traits> C2DmaBufAllocator::getTraits() const {
    std::lock_guard<std::mutex> lock(mUsageMapperLock);
    return mTraits;
}

void C2DmaBufAllocator::setUsageMapper(const UsageMapperFn& mapper __unused, uint64_t minUsage,
                                       uint64_t maxUsage, uint64_t blockSize) {
    std::lock_guard<std::mutex> lock(mUsageMapperLock);
    mUsageMapperCache.clear();
    mUsageMapperLru.clear();
    mUsageMapper = mapper;
    Traits traits = {mTraits->name, mTraits->id, LINEAR, C2MemoryUsage(minUsage),
                     C2MemoryUsage(maxUsage)};
    mTraits = std::make_shared<Traits>(traits);
    mBlockSize = blockSize;
}

std::size_t C2DmaBufAllocator::MapperKeyHash::operator()(const MapperKey& k) const {
    return std::hash<uint64_t>{}(k.first) ^ std::hash<size_t>{}(k.second);
}

c2_status_t C2DmaBufAllocator::mapUsage(C2MemoryUsage usage, size_t capacity, C2String* heap_name,
                                        unsigned* flags) {
    std::lock_guard<std::mutex> lock(mUsageMapperLock);
    c2_status_t res = C2_OK;
    // align capacity
    capacity = (capacity + mBlockSize - 1) & ~(mBlockSize - 1);
    MapperKey key = std::make_pair(usage.expected, capacity);
    auto entry = mUsageMapperCache.find(key);
    if (entry == mUsageMapperCache.end()) {
        if (mUsageMapper) {
            res = mUsageMapper(usage, capacity, heap_name, flags);
        } else {
            if (C2DmaBufAllocator::system_uncached_supported() &&
                !(usage.expected & (C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE)))
                *heap_name = "system-uncached";
            else
                *heap_name = "system";
            *flags = 0;
            res = C2_NO_INIT;
        }
        // add usage to cache
        MapperValue value = std::make_tuple(*heap_name, *flags, res);
        mUsageMapperLru.emplace_front(key, value);
        mUsageMapperCache.emplace(std::make_pair(key, mUsageMapperLru.begin()));
        if (mUsageMapperCache.size() > USAGE_LRU_CACHE_SIZE) {
            // remove LRU entry
            MapperKey lruKey = mUsageMapperLru.front().first;
            mUsageMapperCache.erase(lruKey);
            mUsageMapperLru.pop_back();
        }
    } else {
        // move entry to MRU
        mUsageMapperLru.splice(mUsageMapperLru.begin(), mUsageMapperLru, entry->second);
        const MapperValue& value = entry->second->second;
        std::tie(*heap_name, *flags, res) = value;
    }
    return res;
}

c2_status_t C2DmaBufAllocator::newLinearAllocation(
        uint32_t capacity, C2MemoryUsage usage, std::shared_ptr<C2LinearAllocation>* allocation) {
    if (allocation == nullptr) {
        return C2_BAD_VALUE;
    }

    allocation->reset();
    if (mInit != C2_OK) {
        return mInit;
    }

    C2String heap_name;
    unsigned flags = 0;
    c2_status_t ret = mapUsage(usage, capacity, &heap_name, &flags);
    if (ret && ret != C2_NO_INIT) {
        return ret;
    }

    // TODO: should we pad before mapping usage?

    // NOTE: read this property directly from the property as this code has to run on
    // Android Q, but the sysprop was only introduced in Android S.
    static size_t sPadding =
        base::GetUintProperty("media.c2.dmabuf.padding", (uint32_t)0, MAX_PADDING);
    if (sPadding > SIZE_MAX - capacity) {
        // size would overflow
        ALOGD("dmabuf_alloc: size #%x cannot accommodate padding #%zx", capacity, sPadding);
        return C2_NO_MEMORY;
    }

    size_t allocSize = (size_t)capacity + sPadding;
    // TODO: should we align allocation size to mBlockSize to reflect the true allocation size?
    std::shared_ptr<C2DmaBufAllocation> alloc = std::make_shared<C2DmaBufAllocation>(
            mBufferAllocator, allocSize, allocSize - sPadding, heap_name, flags, getId());
    ret = alloc->status();
    if (ret == C2_OK) {
        *allocation = alloc;
    }
    return ret;
}

c2_status_t C2DmaBufAllocator::priorLinearAllocation(
        const C2Handle* handle, std::shared_ptr<C2LinearAllocation>* allocation) {
    *allocation = nullptr;
    if (mInit != C2_OK) {
        return mInit;
    }

    if (!C2HandleBuf::IsValid(handle)) {
        return C2_BAD_VALUE;
    }

    // TODO: get capacity and validate it
    const C2HandleBuf* h = static_cast<const C2HandleBuf*>(handle);
    std::shared_ptr<C2DmaBufAllocation> alloc =
            std::make_shared<C2DmaBufAllocation>(h->size(), h->bufferFd(), getId());
    c2_status_t ret = alloc->status();
    if (ret == C2_OK) {
        *allocation = alloc;
        native_handle_delete(
                const_cast<native_handle_t*>(reinterpret_cast<const native_handle_t*>(handle)));
    }
    return ret;
}

// static
bool C2DmaBufAllocator::CheckHandle(const C2Handle* const o) {
    return C2HandleBuf::IsValid(o);
}

}  // namespace android
