/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "shared_memory_allocator_tests"

#include <gtest/gtest.h>
#include <mediautils/SharedMemoryAllocator.h>
#include <sys/stat.h>
#include <utils/Log.h>

using namespace android;
using namespace android::mediautils;

namespace {
void validate_block(const AllocationType& block) {
    ASSERT_TRUE(block != nullptr);
    memset(block->unsecurePointer(), 10, 4096);
    EXPECT_EQ(*(static_cast<char*>(block->unsecurePointer()) + 100), static_cast<char>(10));
}

template <size_t N = 0, bool FatalOwn = true>
struct ValidateForwarding {
    static constexpr size_t alignment() { return 1337; }

    bool owns(const AllocationType& allocation) const {
        if (allocation == owned) return true;
        if constexpr (FatalOwn) {
            LOG_ALWAYS_FATAL_IF(allocation != not_owned, "Invalid allocation passed to allocator");
        }
        return false;
    }

    void deallocate_all() { deallocate_all_count++; }
    std::string dump() const { return dump_string; }

    static inline size_t deallocate_all_count = 0;
    static inline const AllocationType owned =
            MemoryHeapBaseAllocator().allocate(BasicAllocRequest{4096});
    static inline const AllocationType not_owned =
            MemoryHeapBaseAllocator().allocate(BasicAllocRequest{4096});
    static inline const std::string dump_string = std::to_string(N) + "Test Dump Forwarding";
};

};  // namespace
static_assert(shared_allocator_impl::has_owns<MemoryHeapBaseAllocator> == false);
static_assert(shared_allocator_impl::has_dump<MemoryHeapBaseAllocator> == false);
static_assert(shared_allocator_impl::has_deallocate_all<MemoryHeapBaseAllocator> == false);
static_assert(shared_allocator_impl::has_owns<SnoopingAllocator<MemoryHeapBaseAllocator>> == true);
static_assert(shared_allocator_impl::has_dump<SnoopingAllocator<MemoryHeapBaseAllocator>> == true);
static_assert(
        shared_allocator_impl::has_deallocate_all<SnoopingAllocator<MemoryHeapBaseAllocator>> ==
        true);
static_assert(
        shared_allocator_impl::has_owns<
                PolicyAllocator<SnoopingAllocator<MemoryHeapBaseAllocator>, SizePolicy<4096>>> ==
        true);
static_assert(
        shared_allocator_impl::has_dump<
                PolicyAllocator<SnoopingAllocator<MemoryHeapBaseAllocator>, SizePolicy<4096>>> ==
        true);
static_assert(
        shared_allocator_impl::has_deallocate_all<
                PolicyAllocator<SnoopingAllocator<MemoryHeapBaseAllocator>, SizePolicy<4096>>> ==
        true);
static_assert(shared_allocator_impl::has_owns<
                      FallbackAllocator<SnoopingAllocator<MemoryHeapBaseAllocator>,
                                        SnoopingAllocator<MemoryHeapBaseAllocator>>> == true);

TEST(shared_memory_allocator_tests, roundup) {
    using namespace shared_allocator_impl;
    EXPECT_EQ(roundup(1023, 1024), 1024ul);
    EXPECT_EQ(roundup(1024, 1024), 1024ul);
    EXPECT_EQ(roundup(1025, 1024), 2048ul);
    EXPECT_DEATH(roundup(1023, 1023), "");
    EXPECT_DEATH(roundup(1023, 0), "");
}

TEST(shared_memory_allocator_tests, mheapbase_allocator) {
    MemoryHeapBaseAllocator allocator;
    const auto memory = allocator.allocate(BasicAllocRequest{500});
    ASSERT_TRUE(memory != nullptr);
    const auto fd = dup(memory->getMemory()->getHeapID());
    EXPECT_EQ(memory->size(), static_cast<unsigned>(4096));
    EXPECT_EQ(memory->size(), memory->getMemory()->getSize());
    validate_block(memory);
    allocator.deallocate(memory);
    // Ensures we have closed the fd
    EXPECT_EQ(memory->unsecurePointer(), nullptr);
    EXPECT_EQ(memory->getMemory()->getBase(), nullptr);
    struct stat st;
    const auto err = fstat(fd, &st);
    EXPECT_EQ(err, 0);
    // Ensure we reclaim pages (overly-zealous)
    EXPECT_EQ(st.st_size, 0);
}

TEST(shared_memory_allocator_tests, mheapbase_allocator_independence) {
    static_assert(MemoryHeapBaseAllocator::alignment() == 4096);
    MemoryHeapBaseAllocator allocator;
    const auto first_memory = allocator.allocate(BasicAllocRequest{500});
    const auto second_memory = allocator.allocate(BasicAllocRequest{500});
    ASSERT_TRUE(first_memory != nullptr && second_memory != nullptr);
    EXPECT_NE(first_memory->getMemory()->getHeapID(), second_memory->getMemory()->getHeapID());
    allocator.deallocate(first_memory);
    validate_block(second_memory);
    allocator.deallocate(second_memory);
}

TEST(shared_memory_allocator_tests, snooping_allocator) {
    static_assert(SnoopingAllocator<ValidateForwarding<0>>::alignment() ==
                  ValidateForwarding<0>::alignment());

    SnoopingAllocator<MemoryHeapBaseAllocator> allocator{"allocator"};
    const auto first_memory = allocator.allocate(NamedAllocRequest{{500}, "allocate_1"});
    auto second_memory = first_memory;
    {
        const auto tmp = allocator.allocate(NamedAllocRequest{{5000}, "allocate_2"});
        // Test copying handle around
        second_memory = tmp;
    }
    ASSERT_TRUE(first_memory && second_memory);
    EXPECT_TRUE(allocator.owns(first_memory) && allocator.owns(second_memory));
    const auto first_allocations = allocator.getAllocations();
    EXPECT_EQ(first_allocations.size(), 2ull);
    for (const auto& [key, val] : allocator.getAllocations()) {
        if (val.allocation_number == 0) {
            EXPECT_EQ(val.name, "allocate_1");
            EXPECT_TRUE(first_memory == key);
        }
        if (val.allocation_number == 1) {
            EXPECT_EQ(val.name, "allocate_2");
            EXPECT_TRUE(second_memory == key);
        }
    }
    // TODO test dump and deallocate forwarding
    // EXPECT_EQ(allocator.dump(), std::string{});
    validate_block(second_memory);
    allocator.deallocate(second_memory);
    EXPECT_EQ(second_memory->unsecurePointer(), nullptr);
    EXPECT_FALSE(allocator.owns(second_memory));
    EXPECT_TRUE(allocator.owns(first_memory));
    const auto second_allocations = allocator.getAllocations();
    EXPECT_EQ(second_allocations.size(), 1ul);
    for (const auto& [key, val] : second_allocations) {
        EXPECT_EQ(val.name, "allocate_1");
        EXPECT_TRUE(first_memory == key);
    }
    // EXPECT_EQ(allocator.dump(), std::string{});
    // TODO test deallocate_all O(1)
}

// TODO generic policy test
TEST(shared_memory_allocator_tests, size_policy_allocator_enforcement) {
    PolicyAllocator allocator{MemoryHeapBaseAllocator{},
                              SizePolicy<4096 * 7, 4096 * 2, 4096 * 4>{}};
    // Violate max size
    EXPECT_TRUE(allocator.allocate(BasicAllocRequest{4096 * 5}) == nullptr);
    // Violate min alloc size
    EXPECT_TRUE(allocator.allocate(BasicAllocRequest{4096}) == nullptr);
    const auto first_memory = allocator.allocate(BasicAllocRequest{4096 * 4});
    validate_block(first_memory);
    // Violate pool size
    EXPECT_TRUE(allocator.allocate(BasicAllocRequest{4096 * 4}) == nullptr);
    const auto second_memory = allocator.allocate(BasicAllocRequest{4096 * 3});
    validate_block(second_memory);
    allocator.deallocate(second_memory);
    // Check pool size update after deallocation
    const auto new_second_memory = allocator.allocate(BasicAllocRequest{4096 * 2});
    validate_block(new_second_memory);
}

TEST(shared_memory_allocator_tests, indirect_allocator) {
    static_assert(IndirectAllocator<ValidateForwarding<0>>::alignment() ==
                  ValidateForwarding<0>::alignment());
    const auto allocator_handle = std::make_shared<SnoopingAllocator<MemoryHeapBaseAllocator>>();
    IndirectAllocator allocator{allocator_handle};
    const auto memory = allocator.allocate(NamedAllocRequest{{4096}, "allocation"});
    EXPECT_TRUE(allocator_handle->owns(memory));
    EXPECT_TRUE(allocator_handle->getAllocations().size() == 1);
    allocator.deallocate(memory);
    EXPECT_FALSE(allocator_handle->owns(memory));
    EXPECT_TRUE(allocator_handle->getAllocations().size() == 0);
}

TEST(shared_memory_allocator_tests, policy_allocator_forwarding) {
    // Test appropriate forwarding of allocator, deallocate
    const auto primary_allocator =
            std::make_shared<SnoopingAllocator<MemoryHeapBaseAllocator>>("allocator");
    PolicyAllocator allocator{IndirectAllocator(primary_allocator), SizePolicy<4096>{}};
    const auto memory = allocator.allocate(NamedAllocRequest{{4096}, "allocation"});
    EXPECT_TRUE(primary_allocator->owns(memory));
    const auto& allocations = primary_allocator->getAllocations();
    EXPECT_TRUE(allocations.size() == 1);
    allocator.deallocate(memory);
    EXPECT_TRUE(allocations.size() == 0);
    const auto memory2 = allocator.allocate(NamedAllocRequest{{4096}, "allocation_2"});
    EXPECT_TRUE(allocations.size() == 1);
    EXPECT_TRUE(primary_allocator->owns(memory2));
    allocator.deallocate(memory2);
    EXPECT_FALSE(primary_allocator->owns(memory2));
    EXPECT_TRUE(allocations.size() == 0);
    // Test appropriate forwarding of own, dump, alignment, deallocate_all
    PolicyAllocator allocator2{ValidateForwarding<0>{}, SizePolicy<4096>{}};
    EXPECT_TRUE(allocator2.owns(ValidateForwarding<0>::owned));
    EXPECT_FALSE(allocator2.owns(ValidateForwarding<0>::not_owned));
    EXPECT_TRUE(allocator2.dump().find(ValidateForwarding<0>::dump_string) != std::string::npos);
    static_assert(decltype(allocator2)::alignment() == ValidateForwarding<0>::alignment());
    size_t prev = ValidateForwarding<0>::deallocate_all_count;
    allocator2.deallocate_all();
    EXPECT_EQ(ValidateForwarding<0>::deallocate_all_count, prev + 1);
}

TEST(shared_memory_allocator_tests, snooping_allocator_nullptr) {
    SnoopingAllocator allocator{PolicyAllocator{MemoryHeapBaseAllocator{}, SizePolicy<4096 * 2>{}}};
    const auto memory = allocator.allocate(NamedAllocRequest{{3000}, "allocation_1"});
    validate_block(memory);
    ASSERT_TRUE(allocator.allocate(NamedAllocRequest{{5000}, "allocation_2"}) == nullptr);
    const auto& allocations = allocator.getAllocations();
    EXPECT_EQ(allocations.size(), 1ul);
    for (const auto& [key, val] : allocations) {
        EXPECT_EQ(val.name, "allocation_1");
        EXPECT_EQ(val.allocation_number, 0ul);
        EXPECT_TRUE(key == memory);
    }
}

TEST(shared_memory_allocator_tests, fallback_allocator) {
    // Construct Fallback Allocator
    const auto primary_allocator = std::make_shared<
            SnoopingAllocator<PolicyAllocator<MemoryHeapBaseAllocator, SizePolicy<4096>>>>(
            PolicyAllocator<MemoryHeapBaseAllocator, SizePolicy<4096>>{}, "primary_allocator");
    const auto secondary_allocator =
            std::make_shared<SnoopingAllocator<MemoryHeapBaseAllocator>>("secondary_allocator");

    FallbackAllocator fallback_allocator{SnoopingAllocator{IndirectAllocator{primary_allocator}},
                                         SnoopingAllocator{IndirectAllocator{secondary_allocator}}};
    static_assert(decltype(fallback_allocator)::alignment() == 4096);
    // Basic Allocation Test
    const auto memory = fallback_allocator.allocate(NamedAllocRequest{{3000}, "allocation_1"});
    validate_block(memory);
    // Correct allocator selected
    EXPECT_TRUE(fallback_allocator.owns(memory));
    EXPECT_TRUE(primary_allocator->owns(memory));
    EXPECT_FALSE(secondary_allocator->owns(memory));
    // Test fallback allocation
    const auto memory2 = fallback_allocator.allocate(NamedAllocRequest{{3000}, "allocation_2"});
    validate_block(memory2);
    // Correct allocator selected
    EXPECT_TRUE(fallback_allocator.owns(memory2));
    EXPECT_FALSE(primary_allocator->owns(memory2));
    EXPECT_TRUE(secondary_allocator->owns(memory2));
    // Allocations ended up in the correct allocators
    const auto& primary_allocations = primary_allocator->getAllocations();
    EXPECT_TRUE(primary_allocations.size() == 1ul);
    ASSERT_TRUE(primary_allocations.find(memory) != primary_allocations.end());
    EXPECT_EQ(primary_allocations.find(memory)->second.name, std::string{"allocation_1"});
    const auto& secondary_allocations = secondary_allocator->getAllocations();
    EXPECT_TRUE(secondary_allocations.size() == 1ul);
    ASSERT_TRUE(secondary_allocations.find(memory2) != secondary_allocations.end());
    EXPECT_EQ(secondary_allocations.find(memory2)->second.name, std::string{"allocation_2"});
    // Test deallocate appropriate forwarding
    fallback_allocator.deallocate(memory);
    EXPECT_TRUE(primary_allocator->getAllocations().size() == 0ul);
    EXPECT_TRUE(secondary_allocator->getAllocations().size() == 1ul);
    // Appropriate fallback after deallocation
    const auto memory3 = fallback_allocator.allocate(NamedAllocRequest{{3000}, "allocation_3"});
    EXPECT_TRUE(fallback_allocator.owns(memory3));
    EXPECT_TRUE(primary_allocator->owns(memory3));
    EXPECT_FALSE(secondary_allocator->owns(memory3));
    EXPECT_TRUE(primary_allocator->getAllocations().size() == 1ul);
    // Test deallocate appropriate forwarding
    EXPECT_TRUE(secondary_allocator->getAllocations().size() == 1ul);
    fallback_allocator.deallocate(memory2);
    EXPECT_TRUE(secondary_allocator->getAllocations().size() == 0ul);
    const auto memory4 = fallback_allocator.allocate(NamedAllocRequest{{3000}, "allocation_4"});
    EXPECT_TRUE(fallback_allocator.owns(memory4));
    EXPECT_FALSE(primary_allocator->owns(memory4));
    EXPECT_TRUE(secondary_allocator->owns(memory4));
    // Allocations ended up in the correct allocators
    EXPECT_TRUE(primary_allocator->getAllocations().size() == 1ul);
    EXPECT_TRUE(secondary_allocator->getAllocations().size() == 1ul);
    ASSERT_TRUE(primary_allocations.find(memory3) != primary_allocations.end());
    EXPECT_EQ(primary_allocations.find(memory3)->second.name, std::string{"allocation_3"});
    ASSERT_TRUE(secondary_allocations.find(memory4) != secondary_allocations.end());
    EXPECT_EQ(secondary_allocations.find(memory4)->second.name, std::string{"allocation_4"});
}

TEST(shared_memory_allocator_tests, fallback_allocator_forwarding) {
    // Test forwarding
    using Alloc1 = ValidateForwarding<0, false>;
    using Alloc2 = ValidateForwarding<1, false>;
    FallbackAllocator forward_test{Alloc1{}, Alloc2{}};
    EXPECT_TRUE(forward_test.dump().find(Alloc1::dump_string) != std::string::npos);
    EXPECT_TRUE(forward_test.dump().find(Alloc2::dump_string) != std::string::npos);
    // Test owned forwarding
    EXPECT_TRUE(forward_test.owns(Alloc1::owned));
    EXPECT_TRUE(forward_test.owns(Alloc2::owned));
    EXPECT_FALSE(forward_test.owns(Alloc1::not_owned));
    EXPECT_FALSE(forward_test.owns(Alloc2::not_owned));
    // Test alignment forwarding
    static_assert(FallbackAllocator<Alloc1, Alloc2>::alignment() == Alloc1::alignment());
    // Test deallocate_all forwarding
    size_t prev1 = Alloc1::deallocate_all_count;
    size_t prev2 = Alloc2::deallocate_all_count;
    forward_test.deallocate_all();
    EXPECT_EQ(prev1 + 1, Alloc1::deallocate_all_count);
    EXPECT_EQ(prev2 + 1, Alloc2::deallocate_all_count);
}

TEST(shared_memory_allocator_tests, scoped_allocator) {
    const auto underlying_allocator =
            std::make_shared<SnoopingAllocator<MemoryHeapBaseAllocator>>("Allocator");
    ScopedAllocator allocator{underlying_allocator};
    const auto& allocations = underlying_allocator->getAllocations();
    {
        decltype(allocator.allocate(NamedAllocRequest{})) copy;
        {
            EXPECT_EQ(allocations.size(), 0ul);
            const auto memory = allocator.allocate(NamedAllocRequest{{3000}, "allocation_1"});
            copy = memory;
            EXPECT_EQ(allocations.size(), 1ul);
            EXPECT_TRUE(allocator.owns(copy));
            EXPECT_TRUE(allocator.owns(memory));
        }
        EXPECT_TRUE(allocator.owns(copy));
        EXPECT_EQ(allocations.size(), 1ul);
        for (const auto& [key, value] : allocations) {
            EXPECT_EQ(value.name, std::string{"allocation_1"});
        }
    }
    EXPECT_EQ(allocations.size(), 0ul);
    // Test forwarding
    static_assert(ScopedAllocator<ValidateForwarding<0>>::alignment() ==
                  ValidateForwarding<0>::alignment());
    ScopedAllocator<ValidateForwarding<0>> forwarding{};
    EXPECT_EQ(forwarding.dump(), ValidateForwarding<0>::dump_string);
}
