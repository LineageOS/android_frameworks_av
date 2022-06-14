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

#define LOG_TAG "timecheck_tests"

#include <mediautils/TimeCheck.h>

#include <atomic>
#include <gtest/gtest.h>
#include <utils/Log.h>

using namespace android::mediautils;
using namespace std::chrono_literals;

namespace {

TEST(timecheck_tests, success) {
    bool timeoutRegistered = false;
    float elapsedMsRegistered = 0.f;
    bool event = false;

    {
        TimeCheck timeCheck("success",
                [&event, &timeoutRegistered, &elapsedMsRegistered]
                        (bool timeout, float elapsedMs) {
            timeoutRegistered = timeout;
            elapsedMsRegistered = elapsedMs;
            event = true;
        }, 1000ms /* timeoutDuration */, {} /* secondChanceDuration */, false /* crash */);
    }
    ASSERT_TRUE(event);
    ASSERT_FALSE(timeoutRegistered);
    ASSERT_GT(elapsedMsRegistered, 0.f);
}

TEST(timecheck_tests, timeout) {
    bool timeoutRegistered = false;
    float elapsedMsRegistered = 0.f;
    std::atomic_bool event = false;  // seq-cst implies acquire-release

    {
        TimeCheck timeCheck("timeout",
                [&event, &timeoutRegistered, &elapsedMsRegistered]
                        (bool timeout, float elapsedMs) {
            timeoutRegistered = timeout;
            elapsedMsRegistered = elapsedMs;
            event = true; // store-release, must be last.
        }, 1ms /* timeoutDuration */, {} /* secondChanceDuration */, false /* crash */);
        std::this_thread::sleep_for(100ms);
    }
    ASSERT_TRUE(event); // load-acquire, must be first.
    ASSERT_TRUE(timeoutRegistered); // only called once on failure, not on dealloc.
    ASSERT_GT(elapsedMsRegistered, 0.f);
}

// Note: We do not test TimeCheck crash because TimeCheck is multithreaded and the
// EXPECT_EXIT() signal catching is imperfect due to the gtest fork.

} // namespace
