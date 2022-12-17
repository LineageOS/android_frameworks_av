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

// #define LOG_NDEBUG 0
#define LOG_TAG "monotonicframecounter_tests"

#include "../MonotonicFrameCounter.h"

#include <gtest/gtest.h>

using namespace android::audioflinger;

namespace {

TEST(MonotonicFrameCounterTest, SimpleProgression) {
    MonotonicFrameCounter monotonicFrameCounter;

    const std::vector<std::pair<int64_t, int64_t>> frametimes{
        {0, 0}, {100, 100}, {200, 200},
    };

    int64_t maxReceivedFrameCount = 0;
    for (const auto& p : frametimes) {
        maxReceivedFrameCount = std::max(maxReceivedFrameCount, p.first);
        ASSERT_EQ(p.first,
                monotonicFrameCounter.updateAndGetMonotonicFrameCount(p.first, p.second));
    }
    ASSERT_EQ(maxReceivedFrameCount, monotonicFrameCounter.getLastReportedFrameCount());
}

TEST(MonotonicFrameCounterTest, InvalidData) {
    MonotonicFrameCounter monotonicFrameCounter;

    const std::vector<std::pair<int64_t, int64_t>> frametimes{
        {-1, -1}, {100, 100}, {-1, -1}, {90, 90}, {200, 200},
    };

    int64_t prevFrameCount = 0;
    int64_t maxReceivedFrameCount = 0;
    for (const auto& p : frametimes) {
        maxReceivedFrameCount = std::max(maxReceivedFrameCount, p.first);
        const int64_t frameCount =
                monotonicFrameCounter.updateAndGetMonotonicFrameCount(p.first, p.second);
        // we must be monotonic
        ASSERT_GE(frameCount, prevFrameCount);
        prevFrameCount = frameCount;
    }
    ASSERT_EQ(maxReceivedFrameCount, monotonicFrameCounter.getLastReportedFrameCount());
}

TEST(MonotonicFrameCounterTest, Flush) {
    MonotonicFrameCounter monotonicFrameCounter;

    // Different playback sequences are separated by a flush.
    const std::vector<std::vector<std::pair<int64_t, int64_t>>> frameset{
        {{-1, -1}, {100, 10}, {200, 20}, {300, 30},},
        {{-1, -1}, {100, 10}, {200, 20}, {300, 30},},
        {{-1, -1}, {100, 100}, {-1, -1}, {90, 90}, {200, 200},},
    };

    int64_t prevFrameCount = 0;
    int64_t maxReceivedFrameCount = 0;
    int64_t sumMaxReceivedFrameCount = 0;
    for (const auto& v : frameset) {
        for (const auto& p : v) {
            maxReceivedFrameCount = std::max(maxReceivedFrameCount, p.first);
            const int64_t frameCount =
                    monotonicFrameCounter.updateAndGetMonotonicFrameCount(p.first, p.second);
            // we must be monotonic
            ASSERT_GE(frameCount, prevFrameCount);
            prevFrameCount = frameCount;
        }
        monotonicFrameCounter.onFlush();
        sumMaxReceivedFrameCount += maxReceivedFrameCount;
        maxReceivedFrameCount = 0;
    }

    // On flush we keep a monotonic reported framecount
    // even though the received framecount resets to 0.
    // The requirement of equality here is implementation dependent.
    ASSERT_EQ(sumMaxReceivedFrameCount, monotonicFrameCounter.getLastReportedFrameCount());
}

}  // namespace
