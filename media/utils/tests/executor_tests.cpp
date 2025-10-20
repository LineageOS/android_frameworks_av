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

#define LOG_TAG "executor_tests"

#include <mediautils/SingleThreadExecutor.h>
#include <mediautils/TidWrapper.h>

#include <future>

#include <gtest/gtest.h>

using namespace android::mediautils;

class ExecutorTests : public ::testing::Test {
  protected:
    void TearDown() override { executor_.shutdown(); }
    SingleThreadExecutor executor_;
};

TEST_F(ExecutorTests, TaskEnqueue) {
    std::atomic<int> counter = 0;
    std::packaged_task<int()> task1([&]() {
        counter++;
        return 7;
    });

    auto future1 = task1.get_future();
    executor_.enqueue(Runnable{std::move(task1)});
    EXPECT_EQ(future1.get(), 7);
    EXPECT_EQ(counter, 1);
}

TEST_F(ExecutorTests, TaskThread) {
    std::packaged_task<int()> task1([&]() { return getThreadIdWrapper(); });

    auto future1 = task1.get_future();
    executor_.enqueue(Runnable{std::move(task1)});
    EXPECT_NE(future1.get(), getThreadIdWrapper());
}

TEST_F(ExecutorTests, TaskOrder) {
    std::atomic<int> counter = 0;
    std::packaged_task<int()> task1([&]() { return counter++; });
    std::packaged_task<int()> task2([&]() { return counter++; });
    auto future1 = task1.get_future();
    auto future2 = task2.get_future();

    executor_.enqueue(Runnable{std::move(task1)});
    executor_.enqueue(Runnable{std::move(task2)});

    EXPECT_EQ(future1.get(), 0);
    EXPECT_EQ(future2.get(), 1);
    EXPECT_EQ(counter, 2);
}

TEST_F(ExecutorTests, EmptyTask) {
    // does not crash
    executor_.enqueue(Runnable{});
}

TEST_F(ExecutorTests, ShutdownTwice) {
    executor_.shutdown();
    executor_.shutdown();
}

TEST_F(ExecutorTests, Submit) {
    auto future = submit(executor_, [&]() { return 5; });
    EXPECT_EQ(future.get(), 5);
}
