/*
 * Copyright 2019 The Android Open Source Project
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
 * Test Histogram
 */

#include <iostream>

#include <gtest/gtest.h>

#include <audio_utils/Histogram.h>

using namespace android::audio_utils;

static constexpr int32_t kBinWidth = 10;
static constexpr int32_t kNumBins = 20;

TEST(test_histogram, module_sinki16) {
    Histogram histogram(kNumBins, kBinWidth);
    ASSERT_EQ(kNumBins, histogram.getNumBinsInRange());

    // Is it clear initially?
    for (int i = 0; i < kNumBins; i++) {
        ASSERT_EQ(0, histogram.getCount(i));
    }
    ASSERT_EQ(0, histogram.getCountBelowRange());
    ASSERT_EQ(0, histogram.getCountAboveRange());
    ASSERT_EQ(0, histogram.getCount());

    // Add some items.
    histogram.add(27);
    histogram.add(53);
    histogram.add(171);
    histogram.add(23);

    // Did they count correctly.
    ASSERT_EQ(2, histogram.getCount(2));          // For items 27 and 23
    ASSERT_EQ(3, histogram.getLastItemNumber(2)); // Item 23 was the 0,1,2,3th item added.
    ASSERT_EQ(1, histogram.getCount(5));          // For item 53
    ASSERT_EQ(1, histogram.getLastItemNumber(5)); // item 53 was the second item added.
    ASSERT_EQ(1, histogram.getCount(17));         // For item 171
    ASSERT_EQ(4, histogram.getCount());           // A total of four items were added.

    // Add values out of range.
    histogram.add(-5);
    ASSERT_EQ(1, histogram.getCountBelowRange()); // -5 is below zero.
    ASSERT_EQ(0, histogram.getCountAboveRange());
    ASSERT_EQ(5, histogram.getCount());

    histogram.add(200);
    ASSERT_EQ(1, histogram.getCountBelowRange());
    ASSERT_EQ(1, histogram.getCountAboveRange()); // 200 is above top bin
    ASSERT_EQ(6, histogram.getCount());

    // Try to read values out of range. Should not crash.
    // Legal index range is 0 to numBins-1
    histogram.add(-1);
    histogram.add(kNumBins);
    ASSERT_EQ(0, histogram.getCount(-1)); // edge
    ASSERT_EQ(0, histogram.getCount(kNumBins)); // edge
    ASSERT_EQ(0, histogram.getCount(-1234)); // extreme
    ASSERT_EQ(0, histogram.getCount(98765)); // extreme
    ASSERT_EQ(0, histogram.getLastItemNumber(-1));
    ASSERT_EQ(0, histogram.getLastItemNumber(kNumBins));

    // Clear all the counts.
    histogram.clear();
    // Is it clear?
    for (int i = 0; i < kNumBins; i++) {
        ASSERT_EQ(0, histogram.getCount(i));
    }
    ASSERT_EQ(0, histogram.getCountBelowRange());
    ASSERT_EQ(0, histogram.getCountAboveRange());
    ASSERT_EQ(0, histogram.getCount());
}
