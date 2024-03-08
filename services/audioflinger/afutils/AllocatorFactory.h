/*
**
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

#include <mediautils/SharedMemoryAllocator.h>

#pragma once

// TODO how do we appropriately restrict visibility of this header?
// It should only be included in AudioFlinger.h
// We will make everything internal linkage for now.
namespace android {
namespace AllocatorFactory {
namespace {
// TODO make sure these are appropriate
constexpr inline size_t MAX_MEMORY_SIZE = 1024 * 1024 * 100;                  // 100 MiB
constexpr inline size_t DED_SIZE = (MAX_MEMORY_SIZE * 4) / 10;                // 40 MiB
constexpr inline size_t SHARED_SIZE = MAX_MEMORY_SIZE - DED_SIZE;             // 60 MiB
constexpr inline size_t SHARED_SIZE_LARGE = (SHARED_SIZE * 4) / 6;            // 40 MiB
constexpr inline size_t SHARED_SIZE_SMALL = SHARED_SIZE - SHARED_SIZE_LARGE;  // 20 MiB
constexpr inline size_t SMALL_THRESHOLD = 1024 * 40;                          // 40 KiB

inline auto getDedicated() {
    using namespace mediautils;
    static const auto allocator =
            std::make_shared<PolicyAllocator<MemoryHeapBaseAllocator, SizePolicy<DED_SIZE>>>();
    return allocator;
}

inline auto getSharedLarge() {
    using namespace mediautils;
    static const auto allocator = std::make_shared<
            PolicyAllocator<MemoryHeapBaseAllocator, SizePolicy<SHARED_SIZE_LARGE>>>();
    return allocator;
}

inline auto getSharedSmall() {
    using namespace mediautils;
    static const auto allocator =
            std::make_shared<PolicyAllocator<MemoryHeapBaseAllocator,
                                             SizePolicy<SHARED_SIZE_SMALL, 0, SMALL_THRESHOLD>>>();
    return allocator;
}

template <typename Policy, typename Allocator>
inline auto wrapWithPolicySnooping(Allocator allocator, std::string_view name) {
    using namespace mediautils;
    return SnoopingAllocator{PolicyAllocator{IndirectAllocator{allocator}, Policy{}}, name};
}

// A reasonable upper bound on how many clients we expect, and how many pieces to slice
// the dedicate pool.
constexpr inline size_t CLIENT_BOUND = 32;
// Maximum amount of shared pools a single client can take (50%).
constexpr inline size_t ADV_THRESHOLD_INV = 2;

inline auto getClientAllocator() {
    using namespace mediautils;
    const auto makeDedPool = []() {
        return wrapWithPolicySnooping<SizePolicy<DED_SIZE / CLIENT_BOUND>>(getDedicated(),
                                                                           "Dedicated Pool");
    };
    const auto makeLargeShared = []() {
        return wrapWithPolicySnooping<SizePolicy<SHARED_SIZE_LARGE / ADV_THRESHOLD_INV>>(
                getSharedLarge(), "Large Shared");
    };
    const auto makeSmallShared = []() {
        return wrapWithPolicySnooping<
                SizePolicy<SHARED_SIZE_SMALL / ADV_THRESHOLD_INV>>(
                getSharedSmall(), "Small Shared");
    };

    return ScopedAllocator{std::make_shared<
            FallbackAllocator<decltype(makeDedPool()),
                              decltype(FallbackAllocator(makeLargeShared(), makeSmallShared()))>>(
            makeDedPool(), FallbackAllocator{makeLargeShared(), makeSmallShared()})};
}

using ClientAllocator = decltype(getClientAllocator());
}  // namespace
}  // namespace AllocatorFactory
}  // namespace android
