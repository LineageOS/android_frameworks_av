/*
 * Copyright (C) 2014 The Android Open Source Project
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
#define LOG_TAG "SessionStatsBuilderTest"

#include <gtest/gtest.h>
#include <utils/Errors.h>

#include "../utils/SessionStatsBuilder.h"

using namespace std;
using namespace android;

TEST(SessionStatsBuilderTest, FpsHistogramTest) {
    SessionStatsBuilder b{};

    int64_t requestCount, resultErrorCount;
    bool deviceError;
    pair<int32_t, int32_t> mostRequestedFpsRange;
    map<int, StreamStats> streamStatsMap;

    // Verify we get the most common FPS
    int64_t fc = 0;
    for (size_t i = 0; i < 10; i++, fc++) b.incFpsRequestedCount(30, 30, fc);
    for (size_t i = 0; i < 15; i++, fc++) b.incFpsRequestedCount(15, 30, fc);
    for (size_t i = 0; i < 20; i++, fc++) b.incFpsRequestedCount(15, 15, fc);
    for (size_t i = 0; i < 10; i++, fc++) b.incFpsRequestedCount(60, 60, fc);

    b.buildAndReset(&requestCount, &resultErrorCount,
        &deviceError, &mostRequestedFpsRange, &streamStatsMap);
    ASSERT_EQ(mostRequestedFpsRange, make_pair(15, 15)) << "Incorrect most common FPS selected";

    // Verify empty stats behavior
    b.buildAndReset(&requestCount, &resultErrorCount,
        &deviceError, &mostRequestedFpsRange, &streamStatsMap);
    ASSERT_EQ(mostRequestedFpsRange, make_pair(0, 0)) << "Incorrect empty stats FPS reported";

    // Verify one frame behavior
    b.incFpsRequestedCount(30, 30, 1);
    b.buildAndReset(&requestCount, &resultErrorCount,
        &deviceError, &mostRequestedFpsRange, &streamStatsMap);
    ASSERT_EQ(mostRequestedFpsRange, make_pair(30, 30)) << "Incorrect single-frame FPS reported";

    // Verify overflow stats behavior
    fc = 0;
    for (size_t range = 1; range < SessionStatsBuilder::FPS_HISTOGRAM_MAX_SIZE + 2; range++) {
        int count = SessionStatsBuilder::FPS_HISTOGRAM_MAX_SIZE * 3;
        for (size_t i = 0; i < count - range; i++, fc++) b.incFpsRequestedCount(range, range, fc);
    }
    // Should have the oldest bucket dropped, so second oldest should be most common
    b.buildAndReset(&requestCount, &resultErrorCount,
        &deviceError, &mostRequestedFpsRange, &streamStatsMap);
    ASSERT_EQ(mostRequestedFpsRange, make_pair(2, 2)) << "Incorrect stats overflow behavior";

}
