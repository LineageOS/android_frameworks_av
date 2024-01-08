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

#define LOG_TAG "extended_accumulator_tests"

#include <mediautils/ExtendedAccumulator.h>

#include <type_traits>
#include <cstdint>
#include <limits.h>

#include <gtest/gtest.h>
#include <log/log.h>

using namespace android;
using namespace android::mediautils;

// Conditionally choose a base accumulating counter value in order to prevent
// unsigned underflow on the accumulator from aborting the tests.
template <typename TType, typename CType>
static constexpr CType getBase() {
  static_assert(sizeof(TType) < sizeof(CType));
  if constexpr (std::is_unsigned_v<CType>) {
      return std::numeric_limits<TType>::max() + 1;
  } else {
      return 0;
  }
}

// Since the entire state of this utility is the previous value, and the
// behavior is isomorphic mod the underlying type on the previous value, we can
// test combinations of the previous value of the underlying type and a
// hypothetical signed update to that type and ensure the accumulator moves
// correctly and reports overflow correctly.
template <typename TestUInt, typename CType>
void testPair(TestUInt prevVal, std::make_signed_t<TestUInt> delta) {
    using TestDetect = ExtendedAccumulator<TestUInt, CType>;
    using TestInt = typename TestDetect::SignedInt;
    static_assert(std::is_same_v<typename TestDetect::UnsignedInt, TestUInt>);
    static_assert(std::is_same_v<TestInt, std::make_signed_t<TestUInt>>);
    static_assert(sizeof(TestUInt) < sizeof(CType));

    // To safely detect underflow/overflow for testing
    // Should be 0 mod TestUInt, max + 1 is convenient
    static constexpr CType base = getBase<TestUInt, CType>();
    const CType prev = base + prevVal;
    TestDetect test{prev};
    EXPECT_EQ(test.getValue(), prev);
    // Prevent unsigned wraparound abort
    CType next;
    const auto err =  __builtin_add_overflow(prev, delta, &next);
    LOG_ALWAYS_FATAL_IF(err, "Unexpected wrap in tests");
    const auto [result, status] = test.poll(static_cast<TestUInt>(next));
    EXPECT_EQ(test.getValue(), next);
    EXPECT_EQ(result, delta);

    // Test overflow/underflow event reporting.
    if (next < base) EXPECT_EQ(TestDetect::Wrap::Underflow, status);
    else if (next > base + std::numeric_limits<TestUInt>::max())
        EXPECT_EQ(TestDetect::Wrap::Overflow, status);
    else EXPECT_EQ(TestDetect::Wrap::Normal, status);
}

// Test this utility on every combination of prior and update value for the
// type uint8_t, with an unsigned containing type.
TEST(wraparound_tests, cover_u8_u64) {
    using TType = uint8_t;
    using CType = uint64_t;
    static constexpr CType max = std::numeric_limits<TType>::max();
    for (CType i = 0; i <= max; i++) {
        for (CType j = 0; j <= max; j++) {
            testPair<TType, CType>(i, static_cast<int64_t>(j));
        }
    }
}

// Test this utility on every combination of prior and update value for the
// type uint8_t, with a signed containing type.
TEST(wraparound_tests, cover_u8_s64) {
    using TType = uint8_t;
    using CType = int64_t;
    static constexpr CType max = std::numeric_limits<TType>::max();
    for (CType i = 0; i <= max; i++) {
        for (CType j = 0; j <= max; j++) {
            testPair<TType, CType>(i, static_cast<int64_t>(j));
        }
    }
}
