/*
 * Copyright (C) 2025 The Android Open Source Project
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

#define LOG_TAG "stop_token_tests"

#include <mediautils/stop_token.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <thread>
#include <vector>

using namespace android::mediautils;

namespace {

TEST(stop_token_tests, basic_stop_request) {
    stop_source source;
    stop_token token = source.get_token();
    EXPECT_FALSE(token.stop_requested());
    EXPECT_FALSE(source.stop_requested());

    EXPECT_TRUE(source.request_stop());
    EXPECT_TRUE(token.stop_requested());
    EXPECT_TRUE(source.stop_requested());

    // Subsequent requests should return false
    EXPECT_FALSE(source.request_stop());
}

TEST(stop_token_tests, callback_invoked_on_stop) {
    stop_source source;
    stop_token token = source.get_token();
    std::atomic_bool callback_invoked = false;

    {
        stop_callback cb(token, [&]() { callback_invoked = true; });

        EXPECT_FALSE(callback_invoked.load());
        EXPECT_TRUE(source.request_stop());
        EXPECT_TRUE(callback_invoked.load());
    }
}

TEST(stop_token_tests, callback_invoked_if_already_stopped) {
    stop_source source;
    stop_token token = source.get_token();
    std::atomic_bool callback_invoked = false;

    EXPECT_TRUE(source.request_stop());

    stop_callback cb(token, [&]() { callback_invoked = true; });

    EXPECT_TRUE(callback_invoked.load());
}

TEST(stop_token_tests, callback_unregistered_on_destruction) {
    stop_source source;
    stop_token token = source.get_token();
    std::atomic_bool callback_invoked = false;

    {
        stop_callback cb(token, [&]() { callback_invoked = true; });
    }  // cb is destroyed here

    EXPECT_TRUE(source.request_stop());
    EXPECT_FALSE(callback_invoked.load());
}

TEST(stop_token_tests, callback_reregistration) {
    stop_source source;
    stop_token token = source.get_token();
    std::atomic_bool callback1_invoked = false;
    std::atomic_bool callback2_invoked = false;

    {
        stop_callback cb1(token, [&]() { callback1_invoked = true; });
    }  // cb1 destroyed

    {
        stop_callback cb2(token, [&]() { callback2_invoked = true; });
        EXPECT_TRUE(source.request_stop());
        EXPECT_TRUE(callback2_invoked.load());
    }

    EXPECT_FALSE(callback1_invoked.load());
}

TEST(stop_token_tests, thread_safety_concurrent_stop_requests) {
    constexpr int kNumThreads = 4;
    stop_source source;
    std::vector<std::future<bool>> futures;
    std::atomic_int successful_stops = 0;

    for (int i = 0; i < kNumThreads; ++i) {
        futures.emplace_back(
                std::async(std::launch::async, [&]() { return source.request_stop(); }));
    }

    for (auto& f : futures) {
        if (f.get()) {
            successful_stops++;
        }
    }

    EXPECT_EQ(successful_stops.load(), 1);
    EXPECT_TRUE(source.stop_requested());
}

TEST(stop_token_tests, concurrent_callback_construction_and_stop) {
    stop_source source;
    stop_token token = source.get_token();
    auto f1 = std::async(std::launch::async,
                         [&]() {
        std::condition_variable cv;
        std::mutex m;
        std::unique_lock l{m};
        bool invoked = false;
        l.unlock();
        // this should be called even as we race against the stop request
        stop_callback cb(token, [&]() {
            std::unique_lock l2 {m};
            invoked = true;
            cv.notify_one();
        });
        l.lock();
        while (!invoked) {
            cv.wait(l);
        }
     });

    auto f2 = std::async(std::launch::async, [&]() { source.request_stop(); });

    f1.get();
    f2.get();
}

TEST(stop_token_tests, concurrent_callback_destruction_and_stop) {
    stop_source source;
    stop_token token = source.get_token();
    std::atomic_bool callback_invoked = false;

    auto cb = std::make_unique<stop_callback>(token, [&]() { callback_invoked = true; });

    auto f1 = std::async(std::launch::async, [&]() { cb.reset(); });

    auto f2 = std::async(std::launch::async, [&]() { source.request_stop(); });

    f1.get();
    f2.get();
    // cb may or not be called based on ordering, but should not race or crash
}
}  // namespace
