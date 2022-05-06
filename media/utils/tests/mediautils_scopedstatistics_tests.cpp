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

#define LOG_TAG "mediautils_scopedstatistics_tests"

#include <mediautils/ScopedStatistics.h>

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <utils/Log.h>

using namespace android::mediautils;
using namespace std::chrono_literals;

TEST(mediautils_scopedstatistics_tests, basic) {
    auto methodStatistics = std::make_shared<MethodStatistics<std::string>>();
    std::string METHOD_NAME{"MyMethod"};

    // no stats before
    auto empty = methodStatistics->getStatistics(METHOD_NAME);
    ASSERT_EQ(0, empty.getN());

    // create a scoped statistics object.
    {
        ScopedStatistics scopedStatistics(METHOD_NAME, methodStatistics);

        std::this_thread::sleep_for(100ms);
    }

    // check that some stats were logged.
    auto stats = methodStatistics->getStatistics(METHOD_NAME);
    ASSERT_EQ(1, stats.getN());
    auto mean = stats.getMean();

    // mean should be about 100ms, but to avoid false failures,
    // we check 50ms < mean < 300ms.
    ASSERT_GT(mean, 50.);   // took more than 50ms.
    ASSERT_LT(mean, 300.);  // took less than 300ms.
}
