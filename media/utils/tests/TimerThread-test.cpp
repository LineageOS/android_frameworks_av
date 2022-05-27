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
using namespace android::mediautils;

namespace {

constexpr auto kJitter = 10ms;

// Each task written by *ToString() will start with a left brace.
constexpr char REQUEST_START = '{';

inline size_t countChars(std::string_view s, char c) {
    return std::count(s.begin(), s.end(), c);
}

TEST(TimerThread, Basic) {
    std::atomic<bool> taskRan = false;
    TimerThread thread;
    thread.scheduleTask("Basic", [&taskRan] { taskRan = true; }, 100ms);
    std::this_thread::sleep_for(100ms - kJitter);
    ASSERT_FALSE(taskRan);
    std::this_thread::sleep_for(2 * kJitter);
    ASSERT_TRUE(taskRan); // timed-out called.
    ASSERT_EQ(1ul, countChars(thread.timeoutToString(), REQUEST_START));
    // nothing cancelled
    ASSERT_EQ(0ul, countChars(thread.retiredToString(), REQUEST_START));
}

TEST(TimerThread, Cancel) {
    std::atomic<bool> taskRan = false;
    TimerThread thread;
    TimerThread::Handle handle =
            thread.scheduleTask("Cancel", [&taskRan] { taskRan = true; }, 100ms);
    std::this_thread::sleep_for(100ms - kJitter);
    ASSERT_FALSE(taskRan);
    ASSERT_TRUE(thread.cancelTask(handle));
    std::this_thread::sleep_for(2 * kJitter);
    ASSERT_FALSE(taskRan); // timed-out did not call.
    ASSERT_EQ(0ul, countChars(thread.timeoutToString(), REQUEST_START));
    // task cancelled.
    ASSERT_EQ(1ul, countChars(thread.retiredToString(), REQUEST_START));
}

TEST(TimerThread, CancelAfterRun) {
    std::atomic<bool> taskRan = false;
    TimerThread thread;
    TimerThread::Handle handle =
            thread.scheduleTask("CancelAfterRun", [&taskRan] { taskRan = true; }, 100ms);
    std::this_thread::sleep_for(100ms + kJitter);
    ASSERT_TRUE(taskRan); //  timed-out called.
    ASSERT_FALSE(thread.cancelTask(handle));
    ASSERT_EQ(1ul, countChars(thread.timeoutToString(), REQUEST_START));
    // nothing actually cancelled
    ASSERT_EQ(0ul, countChars(thread.retiredToString(), REQUEST_START));
}

TEST(TimerThread, MultipleTasks) {
    std::array<std::atomic<bool>, 6> taskRan{};
    TimerThread thread;

    auto startTime = std::chrono::steady_clock::now();

    thread.scheduleTask("0", [&taskRan] { taskRan[0] = true; }, 300ms);
    thread.scheduleTask("1", [&taskRan] { taskRan[1] = true; }, 100ms);
    thread.scheduleTask("2", [&taskRan] { taskRan[2] = true; }, 200ms);
    thread.scheduleTask("3", [&taskRan] { taskRan[3] = true; }, 400ms);
    auto handle4 = thread.scheduleTask("4", [&taskRan] { taskRan[4] = true; }, 200ms);
    thread.scheduleTask("5", [&taskRan] { taskRan[5] = true; }, 200ms);

    // 6 tasks pending
    ASSERT_EQ(6ul, countChars(thread.pendingToString(), REQUEST_START));
    // 0 tasks completed
    ASSERT_EQ(0ul, countChars(thread.retiredToString(), REQUEST_START));

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

    // 1 task pending
    ASSERT_EQ(1ul, countChars(thread.pendingToString(), REQUEST_START));
    // 4 tasks called on timeout,  and 1 cancelled
    ASSERT_EQ(4ul, countChars(thread.timeoutToString(), REQUEST_START));
    ASSERT_EQ(1ul, countChars(thread.retiredToString(), REQUEST_START));

    // Task 3 should trigger around 400ms.
    std::this_thread::sleep_until(startTime + 400ms - kJitter);
    ASSERT_TRUE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_TRUE(taskRan[2]);
    ASSERT_FALSE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_TRUE(taskRan[5]);

    // 4 tasks called on timeout and 1 cancelled
    ASSERT_EQ(4ul, countChars(thread.timeoutToString(), REQUEST_START));
    ASSERT_EQ(1ul, countChars(thread.retiredToString(), REQUEST_START));

    std::this_thread::sleep_until(startTime + 400ms + kJitter);
    ASSERT_TRUE(taskRan[0]);
    ASSERT_TRUE(taskRan[1]);
    ASSERT_TRUE(taskRan[2]);
    ASSERT_TRUE(taskRan[3]);
    ASSERT_FALSE(taskRan[4]);
    ASSERT_TRUE(taskRan[5]);

    // 0 tasks pending
    ASSERT_EQ(0ul, countChars(thread.pendingToString(), REQUEST_START));
    // 5 tasks called on timeout and 1 cancelled
    ASSERT_EQ(5ul, countChars(thread.timeoutToString(), REQUEST_START));
    ASSERT_EQ(1ul, countChars(thread.retiredToString(), REQUEST_START));
}

TEST(TimerThread, TrackedTasks) {
    TimerThread thread;

    auto handle0 = thread.trackTask("0");
    auto handle1 = thread.trackTask("1");
    auto handle2 = thread.trackTask("2");

    // 3 tasks pending
    ASSERT_EQ(3ul, countChars(thread.pendingToString(), REQUEST_START));
    // 0 tasks retired
    ASSERT_EQ(0ul, countChars(thread.retiredToString(), REQUEST_START));

    ASSERT_TRUE(thread.cancelTask(handle0));
    ASSERT_TRUE(thread.cancelTask(handle1));

    // 1 task pending
    ASSERT_EQ(1ul, countChars(thread.pendingToString(), REQUEST_START));
    // 2 tasks retired
    ASSERT_EQ(2ul, countChars(thread.retiredToString(), REQUEST_START));

    // handle1 is stale, cancel returns false.
    ASSERT_FALSE(thread.cancelTask(handle1));

    // 1 task pending
    ASSERT_EQ(1ul, countChars(thread.pendingToString(), REQUEST_START));
    // 2 tasks retired
    ASSERT_EQ(2ul, countChars(thread.retiredToString(), REQUEST_START));

    // Add another tracked task.
    auto handle3 = thread.trackTask("3");

    // 2 tasks pending
    ASSERT_EQ(2ul, countChars(thread.pendingToString(), REQUEST_START));
    // 2 tasks retired
    ASSERT_EQ(2ul, countChars(thread.retiredToString(), REQUEST_START));

    ASSERT_TRUE(thread.cancelTask(handle2));

    // 1 tasks pending
    ASSERT_EQ(1ul, countChars(thread.pendingToString(), REQUEST_START));
    // 3 tasks retired
    ASSERT_EQ(3ul, countChars(thread.retiredToString(), REQUEST_START));

    ASSERT_TRUE(thread.cancelTask(handle3));

    // 0 tasks pending
    ASSERT_EQ(0ul, countChars(thread.pendingToString(), REQUEST_START));
    // 4 tasks retired
    ASSERT_EQ(4ul, countChars(thread.retiredToString(), REQUEST_START));
}

}  // namespace
