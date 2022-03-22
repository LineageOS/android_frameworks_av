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

#pragma once

#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <thread>

#include <android-base/thread_annotations.h>

namespace android {

/**
 * A thread for deferred execution of tasks, with cancellation.
 */
class TimerThread {
  public:
    using Handle = std::chrono::steady_clock::time_point;

    TimerThread();
    ~TimerThread();

    /**
     * Schedule a task to be executed in the future (`timeout` duration from now).
     * Returns a handle that can be used for cancellation.
     */
    template <typename R, typename P>
    Handle scheduleTask(std::function<void()>&& func, std::chrono::duration<R, P> timeout) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
        return scheduleTaskAtDeadline(std::move(func), deadline);
    }

    /**
     * Cancel a task, previously scheduled with scheduleTask().
     * If the task has already executed, this is a no-op and returns false.
     */
    bool cancelTask(Handle handle);

  private:
    using TimePoint = std::chrono::steady_clock::time_point;

    std::condition_variable mCond;
    std::mutex mMutex;
    std::thread mThread;
    std::map<TimePoint, std::function<void()>> mMonitorRequests GUARDED_BY(mMutex);
    bool mShouldExit GUARDED_BY(mMutex) = false;

    void threadFunc();
    Handle scheduleTaskAtDeadline(std::function<void()>&& func, TimePoint deadline);
};

}  // namespace android
