/*
 * Copyright 2022 The Android Open Source Project
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

/*
 * Test MonotonicCounter
 */

#include <iostream>

#include <gtest/gtest.h>

#include "utility/MonotonicCounter.h"

TEST(test_monotonic_counter, builtin_wrap) {
    int32_t x = 0x7FFFFFF0;
    int32_t y = 0x80000010;
    int32_t delta;
    // delta = y - x; // This would cause a numeric overflow!
    __builtin_sub_overflow(y, x, &delta);
    ASSERT_EQ(0x20, delta);
}

// test updating past some overflow points
TEST(test_monotonic_counter, mono_counter_update32_wrap) {
    MonotonicCounter counter;
    ASSERT_EQ(0, counter.get());

    static constexpr uint32_t x = (uint32_t) 0x7FFFFFF0;
    counter.update32(x);
    ASSERT_EQ((int64_t)0x7FFFFFF0, counter.get());

    static constexpr uint32_t y = (uint32_t) 0x80000010;
    counter.update32(y);
    ASSERT_EQ((int64_t)0x80000010, counter.get());

    counter.update32(0);
    ASSERT_EQ((int64_t)0x100000000, counter.get());
}

TEST(test_monotonic_counter, mono_counter_roundup) {
    MonotonicCounter counter;
    static constexpr uint32_t x = 2345;
    counter.update32(x);
    ASSERT_EQ((int64_t)x, counter.get());

    counter.roundUp64(100);
    ASSERT_EQ((int64_t)2400, counter.get());
}

TEST(test_monotonic_counter, mono_counter_catchup) {
    MonotonicCounter counter;
    counter.update32(7654);
    counter.catchUpTo(5000); // already past 5000 so no change
    ASSERT_EQ((int64_t)7654, counter.get());
    counter.catchUpTo(9876); // jumps
    ASSERT_EQ((int64_t)9876, counter.get());
}

TEST(test_monotonic_counter, mono_counter_increment) {
    MonotonicCounter counter;
    counter.update32(1000);
    counter.increment(-234); // will not go backwards
    ASSERT_EQ((int64_t)1000, counter.get());
    counter.increment(96); // advances
    ASSERT_EQ((int64_t)1096, counter.get());
}

TEST(test_monotonic_counter, mono_counter_reset) {
    MonotonicCounter counter;
    counter.update32(1000);
    // Counter is monotonic and should not go backwards.
    counter.update32(500); // No change because 32-bit counter is already past 1000.
    ASSERT_EQ((int64_t)1000, counter.get());

    counter.reset32();
    counter.update32(500);
    ASSERT_EQ((int64_t)1500, counter.get());
}
