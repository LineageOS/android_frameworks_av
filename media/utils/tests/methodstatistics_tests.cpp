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

#define LOG_TAG "methodstatistics_tests"

#include <mediautils/MethodStatistics.h>

#include <atomic>
#include <gtest/gtest.h>
#include <utils/Log.h>

using namespace android::mediautils;
using CodeType = size_t;

constexpr CodeType HELLO_CODE = 10;
constexpr const char * HELLO_NAME = "hello";
constexpr float HELLO_EVENTS[] = { 1.f, 3.f }; // needs lossless average

constexpr CodeType WORLD_CODE = 21;
constexpr const char * WORLD_NAME = "world";

constexpr CodeType UNKNOWN_CODE = 12345;

TEST(methodstatistics_tests, method_names) {
    const MethodStatistics<CodeType> methodStatistics{
            {HELLO_CODE, HELLO_NAME},
            {WORLD_CODE, WORLD_NAME},
    };

    ASSERT_EQ(std::string(HELLO_NAME), methodStatistics.getMethodForCode(HELLO_CODE));
    ASSERT_EQ(std::string(WORLD_NAME), methodStatistics.getMethodForCode(WORLD_CODE));
    // an unknown code returns itself as a number.
    ASSERT_EQ(std::to_string(UNKNOWN_CODE), methodStatistics.getMethodForCode(UNKNOWN_CODE));
}

TEST(methodstatistics_tests, events) {
    MethodStatistics<CodeType> methodStatistics{
            {HELLO_CODE, HELLO_NAME},
            {WORLD_CODE, WORLD_NAME},
    };

    size_t n = 0;
    float sum = 0.f;
    for (const auto event : HELLO_EVENTS) {
        methodStatistics.event(HELLO_CODE, event);
        sum += event;
        ++n;
    }

    const auto helloStats = methodStatistics.getStatistics(HELLO_CODE);
    ASSERT_EQ((signed)n, helloStats.getN());
    ASSERT_EQ(sum / n, helloStats.getMean());
    ASSERT_EQ(n, methodStatistics.getMethodCount(HELLO_CODE));

    const auto unsetStats = methodStatistics.getStatistics(UNKNOWN_CODE);
    ASSERT_EQ(0, unsetStats.getN());
    ASSERT_EQ(0.f, unsetStats.getMean());
    ASSERT_EQ(0U, methodStatistics.getMethodCount(UNKNOWN_CODE));
}
