/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/thread_annotations.h>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>

namespace android::mediametrics {

class TimedAction {
    // Use system_clock instead of steady_clock to include suspend time.
    using TimerClock = class std::chrono::system_clock;

    // Define granularity of wakeup to prevent delayed events if
    // device is suspended.
    static constexpr auto kWakeupInterval = std::chrono::minutes(3);
public:
    TimedAction() : mThread{[this](){threadLoop();}} {}

    ~TimedAction() {
        quit();
    }

    // TODO: return a handle for cancelling the action?
    template <typename T> // T is in units of std::chrono::duration.
    void postIn(const T& time, std::function<void()> f) {
        postAt(TimerClock::now() + time, f);
    }

    template <typename T> // T is in units of std::chrono::time_point
    void postAt(const T& targetTime, std::function<void()> f) {
        std::lock_guard l(mLock);
        if (mQuit) return;
        if (mMap.empty() || targetTime < mMap.begin()->first) {
            mMap.emplace_hint(mMap.begin(), targetTime, std::move(f));
            mCondition.notify_one();
        } else {
            mMap.emplace(targetTime, std::move(f));
        }
    }

    void clear() {
        std::lock_guard l(mLock);
        mMap.clear();
    }

    void quit() {
        {
            std::lock_guard l(mLock);
            if (mQuit) return;
            mQuit = true;
            mMap.clear();
            mCondition.notify_all();
        }
        mThread.join();
    }

    size_t size() const {
        std::lock_guard l(mLock);
        return mMap.size();
    }

private:
    void threadLoop() NO_THREAD_SAFETY_ANALYSIS { // thread safety doesn't cover unique_lock
        std::unique_lock l(mLock);
        while (!mQuit) {
            auto sleepUntilTime = std::chrono::time_point<TimerClock>::max();
            if (!mMap.empty()) {
                sleepUntilTime = mMap.begin()->first;
                const auto now = TimerClock::now();
                if (sleepUntilTime <= now) {
                    auto node = mMap.extract(mMap.begin()); // removes from mMap.
                    l.unlock();
                    node.mapped()();
                    l.lock();
                    continue;
                }
                // Bionic uses CLOCK_MONOTONIC for its pthread_mutex regardless
                // of REALTIME specification, use kWakeupInterval to ensure minimum
                // granularity if suspended.
                sleepUntilTime = std::min(sleepUntilTime, now + kWakeupInterval);
            }
            mCondition.wait_until(l, sleepUntilTime);
        }
    }

    mutable std::mutex mLock;
    std::condition_variable mCondition GUARDED_BY(mLock);
    bool mQuit GUARDED_BY(mLock) = false;
    std::multimap<std::chrono::time_point<TimerClock>, std::function<void()>>
            mMap GUARDED_BY(mLock); // multiple functions could execute at the same time.

    // needs to be initialized after the variables above, done in constructor initializer list.
    std::thread mThread;
};

} // namespace android::mediametrics
