/*
** Copyright 2022, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#pragma once

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>

#include <binder/MemoryBase.h>
#include <binder/MemoryHeapBase.h>
#include <log/log_main.h>
#include <utils/StrongPointer.h>

namespace std {
template <typename T>
struct hash<::android::wp<T>> {
    size_t operator()(const ::android::wp<T>& x) const {
        return std::hash<const T*>()(x.unsafe_get());
    }
};
}  // namespace std

namespace android::mediautils {

// Allocations represent owning handles to a region of shared memory (and thus
// should not be copied in order to fulfill RAII).
// To share ownership between multiple objects, a
// ref-counting solution such as sp or shared ptr is appropriate, so the dtor
// is called once for a particular block of memory.

using AllocationType = ::android::sp<IMemory>;
using WeakAllocationType = ::android::wp<IMemory>;

namespace shared_allocator_impl {
constexpr inline size_t roundup(size_t size, size_t pageSize) {
    LOG_ALWAYS_FATAL_IF(pageSize == 0 || (pageSize & (pageSize - 1)) != 0,
                        "Page size not multiple of 2");
    return ((size + pageSize - 1) & ~(pageSize - 1));
}

constexpr inline bool isHeapValid(const sp<IMemoryHeap>& heap) {
    return (heap && heap->getBase() &&
            heap->getBase() != MAP_FAILED);  // TODO if not mapped locally
}

template <typename, typename = void>
static constexpr bool has_deallocate_all = false;

template <typename T>
static constexpr bool has_deallocate_all<
        T, std::enable_if_t<std::is_same_v<decltype(std::declval<T>().deallocate_all()), void>,
                            void>> = true;

template <typename, typename = void>
static constexpr bool has_owns = false;

template <typename T>
static constexpr bool
        has_owns<T, std::enable_if_t<std::is_same_v<decltype(std::declval<T>().owns(
                                                            std::declval<const AllocationType>())),
                                                    bool>,
                                     void>> = true;

template <typename, typename = void>
static constexpr bool has_dump = false;

template <typename T>
static constexpr bool has_dump<
        T,
        std::enable_if_t<std::is_same_v<decltype(std::declval<T>().dump()), std::string>, void>> =
        true;

}  // namespace shared_allocator_impl

struct BasicAllocRequest {
    size_t size;
};
struct NamedAllocRequest : public BasicAllocRequest {
    std::string_view name;
};

// We are required to add a layer of indirection to hold a handle to the actual
// block due to sp<> being unable to be created from an object once its
// ref-count has dropped to zero. So, we have to hold onto an extra reference
// here. We effectively want to know when the refCount of the object drops to
// one, since we need to hold on to a reference to pass the object to interfaces
// requiring an sp<>.
// TODO is there some way to avoid paying this cost?
template <typename Allocator>
class ScopedAllocator;

class ScopedAllocation : public BnMemory {
  public:
    template <typename T>
    friend class ScopedAllocator;
    template <typename Deallocator>
    ScopedAllocation(const AllocationType& allocation, Deallocator&& deallocator)
        : mAllocation(allocation), mDeallocator(std::forward<Deallocator>(deallocator)) {}

    // Defer the implementation to the underlying mAllocation

    virtual sp<IMemoryHeap> getMemory(ssize_t* offset = nullptr,
                                      size_t* size = nullptr) const override {
        return mAllocation->getMemory(offset, size);
    }

  private:
    ~ScopedAllocation() override { mDeallocator(mAllocation); }

    const AllocationType mAllocation;
    const std::function<void(const AllocationType&)> mDeallocator;
};

// Allocations are only deallocated when going out of scope.
// This should almost always be the outermost allocator.
template <typename Allocator>
class ScopedAllocator {
  public:
    static constexpr size_t alignment() { return Allocator::alignment(); }

    explicit ScopedAllocator(const std::shared_ptr<Allocator>& allocator) : mAllocator(allocator) {}

    ScopedAllocator() : mAllocator(std::make_shared<Allocator>()) {}

    template <typename T>
    auto allocate(T&& request) {
        std::lock_guard l{*mLock};
        const auto allocation = mAllocator->allocate(std::forward<T>(request));
        if (!allocation) {
            return sp<ScopedAllocation>{};
        }
        return sp<ScopedAllocation>::make(allocation,
                [allocator = mAllocator, lock = mLock] (const AllocationType& allocation) {
                    std::lock_guard l{*lock};
                    allocator->deallocate(allocation);
                });
    }

    // Deallocate and deallocate_all are implicitly unsafe due to double
    // deallocates upon ScopedAllocation destruction. We can protect against this
    // efficiently with a gencount (for deallocate_all) or inefficiently (for
    // deallocate) but we choose not to
    //
    // Owns is only safe to pseudo-impl due to static cast reqs
    template <typename Enable = bool>
    auto owns(const sp<ScopedAllocation>& allocation) const
            -> std::enable_if_t<shared_allocator_impl::has_owns<Allocator>, Enable> {
        std::lock_guard l{*mLock};
        return mAllocator->owns(allocation->mAllocation);
    }

    template <typename Enable = std::string>
    auto dump() const -> std::enable_if_t<shared_allocator_impl::has_dump<Allocator>, Enable> {
        std::lock_guard l{*mLock};
        return mAllocator->dump();
    }

  private:
    // We store a shared pointer in order to ensure that the allocator outlives
    // allocations (which call back to become dereferenced).
    const std::shared_ptr<Allocator> mAllocator;
    const std::shared_ptr<std::mutex> mLock = std::make_shared<std::mutex>();
};

// A simple policy for PolicyAllocator which enforces a pool size and an allocation
// size range.
template <size_t PoolSize, size_t MinAllocSize = 0,
          size_t MaxAllocSize = std::numeric_limits<size_t>::max()>
class SizePolicy {
    static_assert(PoolSize > 0);

  public:
    template <typename T>
    bool isValid(T&& request) const {
        static_assert(std::is_base_of_v<BasicAllocRequest, std::decay_t<T>>);
        return !(request.size > kMaxAllocSize || request.size < kMinAllocSize ||
                 mPoolSize + request.size > kPoolSize);
    }

    void allocated(const AllocationType& alloc) { mPoolSize += alloc->size(); }

    void deallocated(const AllocationType& alloc) { mPoolSize -= alloc->size(); }

    void deallocated_all() { mPoolSize = 0; }

    static constexpr size_t kPoolSize = PoolSize;
    static constexpr size_t kMinAllocSize = MinAllocSize;
    static constexpr size_t kMaxAllocSize = MaxAllocSize;

  private:
    size_t mPoolSize = 0;
};

// An allocator which accepts or rejects allocation requests by a parametrized
// policy (which can carry state).
template <typename Allocator, typename Policy>
class PolicyAllocator {
  public:
    static constexpr size_t alignment() { return Allocator::alignment(); }

    PolicyAllocator(Allocator allocator, Policy policy)
        : mAllocator(allocator), mPolicy(std::move(policy)) {}

    // Default initialize the allocator and policy
    PolicyAllocator() = default;

    template <typename T>
    AllocationType allocate(T&& request) {
        static_assert(std::is_base_of_v<android::mediautils::BasicAllocRequest, std::decay_t<T>>);
        request.size = shared_allocator_impl::roundup(request.size, alignment());
        if (!mPolicy.isValid(request)) {
            return {};
        }
        AllocationType val = mAllocator.allocate(std::forward<T>(request));
        if (val == nullptr) return val;
        mPolicy.allocated(val);
        return val;
    }

    void deallocate(const AllocationType& allocation) {
        if (!allocation) return;
        mPolicy.deallocated(allocation);
        mAllocator.deallocate(allocation);
    }

    template <typename Enable = void>
    auto deallocate_all()
            -> std::enable_if_t<shared_allocator_impl::has_deallocate_all<Allocator>, Enable> {
        mAllocator.deallocate_all();
        mPolicy.deallocated_all();
    }

    template <typename Enable = bool>
    auto owns(const AllocationType& allocation) const
            -> std::enable_if_t<shared_allocator_impl::has_owns<Allocator>, Enable> {
        return mAllocator.owns(allocation);
    }

    template <typename Enable = std::string>
    auto dump() const -> std::enable_if_t<shared_allocator_impl::has_dump<Allocator>, Enable> {
        return mAllocator.dump();
    }

  private:
    [[no_unique_address]] Allocator mAllocator;
    [[no_unique_address]] Policy mPolicy;
};

// An allocator which keeps track of outstanding allocations for logging and
// querying ownership.
template <class Allocator>
class SnoopingAllocator {
  public:
    struct AllocationData {
        std::string name;
        size_t allocation_number;
    };
    static constexpr size_t alignment() { return Allocator::alignment(); }

    SnoopingAllocator(Allocator allocator, std::string_view name)
        : mName(name), mAllocator(std::move(allocator)) {}

    explicit SnoopingAllocator(std::string_view name) : mName(name), mAllocator(Allocator{}) {}

    explicit SnoopingAllocator(Allocator allocator) : mAllocator(std::move(allocator)) {}

    // Default construct allocator and name
    SnoopingAllocator() = default;

    template <typename T>
    AllocationType allocate(T&& request) {
        static_assert(std::is_base_of_v<NamedAllocRequest, std::decay_t<T>>);
        AllocationType allocation = mAllocator.allocate(request);
        if (allocation)
            mAllocations.insert({WeakAllocationType{allocation},
                                 {std::string{request.name}, mAllocationNumber++}});
        return allocation;
    }

    void deallocate(const AllocationType& allocation) {
        if (!allocation) return;
        mAllocations.erase(WeakAllocationType{allocation});
        mAllocator.deallocate(allocation);
    }

    void deallocate_all() {
        if constexpr (shared_allocator_impl::has_deallocate_all<Allocator>) {
            mAllocator.deallocate_all();
        } else {
            for (auto& [mem, value] : mAllocations) {
                mAllocator.deallocate(mem);
            }
        }
        mAllocations.clear();
    }

    bool owns(const AllocationType& allocation) const {
        return (mAllocations.count(WeakAllocationType{allocation}) > 0);
    }

    std::string dump() const {
        std::ostringstream dump;
        dump << mName << " Allocator Dump:\n";
        dump << std::setw(8) << "HeapID" << std::setw(8) << "Size" << std::setw(8) << "Offset"
             << std::setw(8) << "Order"
             << "   Name\n";
        for (auto& [mem, value] : mAllocations) {
            // TODO Imem size and offset
            const AllocationType handle = mem.promote();
            if (!handle) {
                dump << "Invalid memory lifetime!";
                continue;
            }
            const auto heap = handle->getMemory();
            dump << std::setw(8) << heap->getHeapID() << std::setw(8) << heap->getSize()
                 << std::setw(8) << heap->getOffset() << std::setw(8) << value.allocation_number
                 << "   " << value.name << "\n";
        }
        return dump.str();
    }

    const std::unordered_map<WeakAllocationType, AllocationData>& getAllocations() {
        return mAllocations;
    }

  private:
    const std::string mName;
    [[no_unique_address]] Allocator mAllocator;
    // We don't take copies of the underlying information in an allocation,
    // rather, the allocation information is put on the heap and referenced via
    // a ref-counted solution. So, the address of the allocation information is
    // appropriate to hash. In order for this block to be freed, the underlying
    // allocation must be referenced by no one (thus deallocated).
    std::unordered_map<WeakAllocationType, AllocationData> mAllocations;
    // For debugging purposes, monotonic
    size_t mAllocationNumber = 0;
};

// An allocator which passes a failed allocation request to a backup allocator.
template <class PrimaryAllocator, class SecondaryAllocator>
class FallbackAllocator {
  public:
    static_assert(PrimaryAllocator::alignment() == SecondaryAllocator::alignment());
    static_assert(shared_allocator_impl::has_owns<PrimaryAllocator>);

    static constexpr size_t alignment() { return PrimaryAllocator::alignment(); }

    FallbackAllocator(const PrimaryAllocator& primary, const SecondaryAllocator& secondary)
        : mPrimary(primary), mSecondary(secondary) {}

    // Default construct primary and secondary allocator
    FallbackAllocator() = default;

    template <typename T>
    AllocationType allocate(T&& request) {
        AllocationType allocation = mPrimary.allocate(std::forward<T>(request));
        if (!allocation) allocation = mSecondary.allocate(std::forward<T>(request));
        return allocation;
    }

    void deallocate(const AllocationType& allocation) {
        if (!allocation) return;
        if (mPrimary.owns(allocation)) {
            mPrimary.deallocate(allocation);
        } else {
            mSecondary.deallocate(allocation);
        }
    }

    template <typename Enable = void>
    auto deallocate_all() -> std::enable_if_t<
            shared_allocator_impl::has_deallocate_all<PrimaryAllocator> &&
                    shared_allocator_impl::has_deallocate_all<SecondaryAllocator>,
            Enable> {
        mPrimary.deallocate_all();
        mSecondary.deallocate_all();
    }

    template <typename Enable = bool>
    auto owns(const AllocationType& allocation) const
            -> std::enable_if_t<shared_allocator_impl::has_owns<SecondaryAllocator>, Enable> {
        return mPrimary.owns(allocation) || mSecondary.owns(allocation);
    }

    template <typename Enable = std::string>
    auto dump() const
            -> std::enable_if_t<shared_allocator_impl::has_dump<PrimaryAllocator> &&
                                        shared_allocator_impl::has_dump<SecondaryAllocator>,
                                Enable> {
        return std::string("Primary: \n") + mPrimary.dump() + std::string("Secondary: \n") +
               mSecondary.dump();
    }

  private:
    [[no_unique_address]] PrimaryAllocator mPrimary;
    [[no_unique_address]] SecondaryAllocator mSecondary;
};

// An allocator which is backed by a shared_ptr to an allocator, so multiple
// allocators can share the same backing allocator (and thus the same state).
template <typename Allocator>
class IndirectAllocator {
  public:
    static constexpr size_t alignment() { return Allocator::alignment(); }

    explicit IndirectAllocator(const std::shared_ptr<Allocator>& allocator)
        : mAllocator(allocator) {}

    template <typename T>
    AllocationType allocate(T&& request) {
        return mAllocator->allocate(std::forward<T>(request));
    }

    void deallocate(const AllocationType& allocation) {
        if (!allocation) return;
        mAllocator->deallocate(allocation);
    }

    // We can't implement deallocate_all/dump/owns, since we may not be the only allocator with
    // access to the underlying allocator (making it not well-defined). If these
    // methods are necesesary, we need to wrap with a snooping allocator.
  private:
    const std::shared_ptr<Allocator> mAllocator;
};

// Stateless. This allocator allocates full page-aligned MemoryHeapBases (backed by
// a shared memory mapped anonymous file) as allocations.
class MemoryHeapBaseAllocator {
  public:
    static constexpr size_t alignment() { return 4096; /* PAGE_SIZE */ }
    static constexpr unsigned FLAGS = 0;  // default flags

    template <typename T>
    AllocationType allocate(T&& request) {
        static_assert(std::is_base_of_v<BasicAllocRequest, std::decay_t<T>>);
        auto heap =
                sp<MemoryHeapBase>::make(shared_allocator_impl::roundup(request.size, alignment()));
        if (!shared_allocator_impl::isHeapValid(heap)) {
            return {};
        }
        return sp<MemoryBase>::make(heap, 0, heap->getSize());
    }

    // Passing a block not allocated by a HeapAllocator is undefined.
    void deallocate(const AllocationType& allocation) {
        if (!allocation) return;
        const auto heap = allocation->getMemory();
        if (!heap) return;
        // This causes future mapped accesses (even across process boundaries)
        // to receive SIGBUS.
        ftruncate(heap->getHeapID(), 0);
        // This static cast is safe, since as long as the block was originally
        // allocated by us, the underlying IMemoryHeap was a MemoryHeapBase
        static_cast<MemoryHeapBase&>(*heap).dispose();
    }
};
}  // namespace android::mediautils
