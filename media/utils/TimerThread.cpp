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

#define LOG_TAG "TimerThread"

#include <optional>

#include <mediautils/TimerThread.h>
#include <utils/ThreadDefs.h>

namespace android {

TimerThread::TimerThread() : mThread([this] { threadFunc(); }) {
    pthread_setname_np(mThread.native_handle(), "TimeCheckThread");
    pthread_setschedprio(mThread.native_handle(), PRIORITY_URGENT_AUDIO);
}

TimerThread::~TimerThread() {
    {
        std::lock_guard _l(mMutex);
        mShouldExit = true;
        mCond.notify_all();
    }
    mThread.join();
}

TimerThread::Handle TimerThread::scheduleTaskAtDeadline(std::function<void()>&& func,
                                                        TimePoint deadline) {
    std::lock_guard _l(mMutex);

    // To avoid key collisions, advance by 1 tick until the key is unique.
    for (; mMonitorRequests.find(deadline) != mMonitorRequests.end();
         deadline += TimePoint::duration(1))
        ;
    mMonitorRequests.emplace(deadline, std::move(func));
    mCond.notify_all();
    return deadline;
}

// Returns true if cancelled, false if handle doesn't exist.
// Beware of lock inversion with cancelTask() as the callback
// is called while holding mMutex.
bool TimerThread::cancelTask(Handle handle) {
    std::lock_guard _l(mMutex);
    return mMonitorRequests.erase(handle) != 0;
}

void TimerThread::threadFunc() {
    std::unique_lock _l(mMutex);

    while (!mShouldExit) {
        if (!mMonitorRequests.empty()) {
            TimePoint nextDeadline = mMonitorRequests.begin()->first;
            if (nextDeadline < std::chrono::steady_clock::now()) {
                // Deadline expired.
                mMonitorRequests.begin()->second();
                mMonitorRequests.erase(mMonitorRequests.begin());
            }
            mCond.wait_until(_l, nextDeadline);
        } else {
            mCond.wait(_l);
        }
    }
}

}  // namespace android
