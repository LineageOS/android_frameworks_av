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


// Split msec time between timeout and second chance time
// This tests expiration times weighted between timeout and the second chance time.
#define DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(msec, frac) \
    std::chrono::milliseconds(int((msec) * (frac)) + 1), \
    std::chrono::milliseconds(int((msec) * (1.f - (frac))))

// The TimerThreadTest is parameterized on a fraction between 0.f and 1.f which
// is how the total timeout time is split between the first timeout and the second chance time.
//
class TimerThreadTest : public ::testing::TestWithParam<float> {
protected:

static void testBasic() {
    const auto frac = GetParam();

    std::atomic<bool> taskRan = false;
    TimerThread thread;
    TimerThread::Handle handle =
            thread.scheduleTask("Basic", [&taskRan](TimerThread::Handle handle __unused) {
                    taskRan = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(100, frac));
    ASSERT_TRUE(TimerThread::isTimeoutHandle(handle));
    std::this_thread::sleep_for(100ms - kJitter);
    ASSERT_FALSE(taskRan);
    std::this_thread::sleep_for(2 * kJitter);
    ASSERT_TRUE(taskRan);
    ASSERT_EQ(1, countChars(thread.retiredToString(), REQUEST_START));
}

static void testCancel() {
    const auto frac = GetParam();

    std::atomic<bool> taskRan = false;
    TimerThread thread;
    TimerThread::Handle handle =
            thread.scheduleTask("Cancel", [&taskRan](TimerThread::Handle handle __unused) {
                    taskRan = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(100, frac));
    ASSERT_TRUE(TimerThread::isTimeoutHandle(handle));
    std::this_thread::sleep_for(100ms - kJitter);
    ASSERT_FALSE(taskRan);
    ASSERT_TRUE(thread.cancelTask(handle));
    std::this_thread::sleep_for(2 * kJitter);
    ASSERT_FALSE(taskRan);
    ASSERT_EQ(1, countChars(thread.retiredToString(), REQUEST_START));
}

static void testCancelAfterRun() {
    const auto frac = GetParam();

    std::atomic<bool> taskRan = false;
    TimerThread thread;
    TimerThread::Handle handle =
            thread.scheduleTask("CancelAfterRun",
                    [&taskRan](TimerThread::Handle handle __unused) {
                            taskRan = true; },
                            DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(100, frac));
    ASSERT_TRUE(TimerThread::isTimeoutHandle(handle));
    std::this_thread::sleep_for(100ms + kJitter);
    ASSERT_TRUE(taskRan);
    ASSERT_FALSE(thread.cancelTask(handle));
    ASSERT_EQ(1, countChars(thread.retiredToString(), REQUEST_START));
}

static void testMultipleTasks() {
    const auto frac = GetParam();

    std::array<std::atomic<bool>, 6> taskRan{};
    TimerThread thread;

    auto startTime = std::chrono::steady_clock::now();

    thread.scheduleTask("0", [&taskRan](TimerThread::Handle handle __unused) {
            taskRan[0] = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(300, frac));
    thread.scheduleTask("1", [&taskRan](TimerThread::Handle handle __unused) {
            taskRan[1] = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(100, frac));
    thread.scheduleTask("2", [&taskRan](TimerThread::Handle handle __unused) {
            taskRan[2] = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(200, frac));
    thread.scheduleTask("3", [&taskRan](TimerThread::Handle handle __unused) {
            taskRan[3] = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(400, frac));
    auto handle4 = thread.scheduleTask("4", [&taskRan](TimerThread::Handle handle __unused) {
            taskRan[4] = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(200, frac));
    thread.scheduleTask("5", [&taskRan](TimerThread::Handle handle __unused) {
            taskRan[5] = true; }, DISTRIBUTE_TIMEOUT_SECONDCHANCE_MS_FRAC(200, frac));

    // 6 tasks pending
    ASSERT_EQ(6, countChars(thread.pendingToString(), REQUEST_START));
    // 0 tasks completed
    ASSERT_EQ(0, countChars(thread.retiredToString(), REQUEST_START));

    // None of the tasks are expected to have finished at the start.
    std::array<std::atomic<bool>, 6> expected{};

    // Task 1 should trigger around 100ms.
    std::this_thread::sleep_until(startTime + 100ms - kJitter);

    ASSERT_EQ(expected, taskRan);


    std::this_thread::sleep_until(startTime + 100ms + kJitter);

    expected[1] = true;
    ASSERT_EQ(expected, taskRan);

    // Cancel task 4 before it gets a chance to run.
    thread.cancelTask(handle4);

    // Tasks 2 and 5 should trigger around 200ms.
    std::this_thread::sleep_until(startTime + 200ms - kJitter);

    ASSERT_EQ(expected, taskRan);


    std::this_thread::sleep_until(startTime + 200ms + kJitter);

    expected[2] = true;
    expected[5] = true;
    ASSERT_EQ(expected, taskRan);

    // Task 0 should trigger around 300ms.
    std::this_thread::sleep_until(startTime + 300ms - kJitter);

    ASSERT_EQ(expected, taskRan);

    std::this_thread::sleep_until(startTime + 300ms + kJitter);

    expected[0] = true;
    ASSERT_EQ(expected, taskRan);

    // 1 task pending
    ASSERT_EQ(1, countChars(thread.pendingToString(), REQUEST_START));
    // 4 tasks ran and 1 cancelled
    ASSERT_EQ(4 + 1, countChars(thread.retiredToString(), REQUEST_START));

    // Task 3 should trigger around 400ms.
    std::this_thread::sleep_until(startTime + 400ms - kJitter);

    ASSERT_EQ(expected, taskRan);

    // 4 tasks ran and 1 cancelled
    ASSERT_EQ(4 + 1, countChars(thread.retiredToString(), REQUEST_START));

    std::this_thread::sleep_until(startTime + 400ms + kJitter);

    expected[3] = true;
    ASSERT_EQ(expected, taskRan);

    // 0 tasks pending
    ASSERT_EQ(0, countChars(thread.pendingToString(), REQUEST_START));
    // 5 tasks ran and 1 cancelled
    ASSERT_EQ(5 + 1, countChars(thread.retiredToString(), REQUEST_START));
}

}; // class TimerThreadTest

TEST_P(TimerThreadTest, Basic) {
    testBasic();
}

TEST_P(TimerThreadTest, Cancel) {
    testCancel();
}

TEST_P(TimerThreadTest, CancelAfterRun) {
    testCancelAfterRun();
}

TEST_P(TimerThreadTest, MultipleTasks) {
    testMultipleTasks();
}

INSTANTIATE_TEST_CASE_P(
        TimerThread,
        TimerThreadTest,
        ::testing::Values(0.f, 0.5f, 1.f)
        );

TEST(TimerThread, TrackedTasks) {
    TimerThread thread;

    auto handle0 = thread.trackTask("0");
    auto handle1 = thread.trackTask("1");
    auto handle2 = thread.trackTask("2");

    ASSERT_TRUE(TimerThread::isNoTimeoutHandle(handle0));
    ASSERT_TRUE(TimerThread::isNoTimeoutHandle(handle1));
    ASSERT_TRUE(TimerThread::isNoTimeoutHandle(handle2));

    // 3 tasks pending
    ASSERT_EQ(3, countChars(thread.pendingToString(), REQUEST_START));
    // 0 tasks retired
    ASSERT_EQ(0, countChars(thread.retiredToString(), REQUEST_START));

    ASSERT_TRUE(thread.cancelTask(handle0));
    ASSERT_TRUE(thread.cancelTask(handle1));

    // 1 task pending
    ASSERT_EQ(1, countChars(thread.pendingToString(), REQUEST_START));
    // 2 tasks retired
    ASSERT_EQ(2, countChars(thread.retiredToString(), REQUEST_START));

    // handle1 is stale, cancel returns false.
    ASSERT_FALSE(thread.cancelTask(handle1));

    // 1 task pending
    ASSERT_EQ(1, countChars(thread.pendingToString(), REQUEST_START));
    // 2 tasks retired
    ASSERT_EQ(2, countChars(thread.retiredToString(), REQUEST_START));

    // Add another tracked task.
    auto handle3 = thread.trackTask("3");
    ASSERT_TRUE(TimerThread::isNoTimeoutHandle(handle3));

    // 2 tasks pending
    ASSERT_EQ(2, countChars(thread.pendingToString(), REQUEST_START));
    // 2 tasks retired
    ASSERT_EQ(2, countChars(thread.retiredToString(), REQUEST_START));

    ASSERT_TRUE(thread.cancelTask(handle2));

    // 1 tasks pending
    ASSERT_EQ(1, countChars(thread.pendingToString(), REQUEST_START));
    // 3 tasks retired
    ASSERT_EQ(3, countChars(thread.retiredToString(), REQUEST_START));

    ASSERT_TRUE(thread.cancelTask(handle3));

    // 0 tasks pending
    ASSERT_EQ(0, countChars(thread.pendingToString(), REQUEST_START));
    // 4 tasks retired
    ASSERT_EQ(4, countChars(thread.retiredToString(), REQUEST_START));
}

}  // namespace
