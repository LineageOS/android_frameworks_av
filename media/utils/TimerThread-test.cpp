/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <chrono>
#include <thread>
#include <gtest/gtest.h>
#include <mediautils/TimerThread.h>

using namespace std::chrono_literals;

namespace android {
namespace {

constexpr auto kJitter = 10ms;

TEST(TimerThread, Basic) {
    std::atomic<bool> taskRan = false;
    TimerThread thread;
    thread.scheduleTask([&taskRan] { taskRan = true; }, 100ms);
    std::this_thread::sleep_for(100ms - kJitter);
    ASSERT_FALSE(taskRan);
    std::this_thread::sleep_for(2 * kJitter);
    ASSERT_TRUE(taskRan);
}

TEST(TimerThread, Cancel) {
    std::atomic<bool> taskRan = false;
    TimerThread thread;
    TimerThread::Handle handle = thread.scheduleTask([&taskRan] { taskRan = true; }, 100ms);
    std::this_thread::sleep_for(100ms - kJitter);
    ASSERT_FALSE(taskRan);
    thread.cancelTask(handle);
    std::this_thread::sleep_for(2 * kJitter);
    ASSERT_FALSE(taskRan);
}

TEST(TimerThread, CancelAfterRun) {
    std::atomic<bool> taskRan = false;
    TimerThread thread;
    TimerThread::Handle handle = thread.scheduleTask([&taskRan] { taskRan = true; }, 100ms);
    std::this_thread::sleep_for(100ms + kJitter);
    ASSERT_TRUE(taskRan);
    thread.cancelTask(handle);
}

TEST(TimerThread, MultipleTasks) {
    std::array<std::atomic<bool>, 6> taskRan;
    TimerThread thread;

    auto startTime = std::chrono::steady_clock::now();

    thread.scheduleTask([&taskRan] { taskRan[0] = true; }, 300ms);
    thread.scheduleTask([&taskRan] { taskRan[1] = true; }, 100ms);
    thread.scheduleTask([&taskRan] { taskRan[2] = true; }, 200ms);
    thread.scheduleTask([&taskRan] { taskRan[3] = true; }, 400ms);
    auto handle4 = thread.scheduleTask([&taskRan] { taskRan[4] = true; }, 200ms);
    thread.scheduleTask([&taskRan] { taskRan[5] = true; }, 200ms);

    // Task 1 should trigger around 100ms.
    std::this_thread::sleep_until(startTime + 100ms - kJitter);
    ASSERT_FALSE(taskRan[0]);
    ASSERT_FALSE(taskRan[1]);
    ASSERT_FALSE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_FALSE(taskRan[5]);

    std::this_thread::sleep_until(startTime + 100ms + kJitter);
    ASSERT_FALSE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_FALSE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_FALSE(taskRan[5]);

    // Cancel task 4 before it gets a chance to run.
    thread.cancelTask(handle4);

    // Tasks 2 and 5 should trigger around 200ms.
    std::this_thread::sleep_until(startTime + 200ms - kJitter);
    ASSERT_FALSE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_FALSE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_FALSE(taskRan[5]);

    std::this_thread::sleep_until(startTime + 200ms + kJitter);
    ASSERT_FALSE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_TRUE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_TRUE(taskRan[5]);

    // Task 0 should trigger around 300ms.
    std::this_thread::sleep_until(startTime + 300ms - kJitter);
    ASSERT_FALSE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_TRUE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_TRUE(taskRan[5]);

    std::this_thread::sleep_until(startTime + 300ms + kJitter);
    ASSERT_TRUE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_TRUE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_TRUE(taskRan[5]);

    // Task 3 should trigger around 400ms.
    std::this_thread::sleep_until(startTime + 400ms - kJitter);
    ASSERT_TRUE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_TRUE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_TRUE(taskRan[5]);

    std::this_thread::sleep_until(startTime + 400ms + kJitter);
    ASSERT_TRUE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_TRUE(taskRan[2]);
    ASSERT_TRUE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_TRUE(taskRan[5]);
}


}  // namespace
}  // namespace android
