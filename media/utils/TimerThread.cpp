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
#include <sstream>
#include <unistd.h>
#include <vector>

#include <mediautils/TimerThread.h>
#include <utils/ThreadDefs.h>

namespace android::mediautils {

extern std::string formatTime(std::chrono::system_clock::time_point t);
extern std::string_view timeSuffix(std::string_view time1, std::string_view time2);

TimerThread::Handle TimerThread::scheduleTask(
        std::string tag, std::function<void()>&& func, std::chrono::milliseconds timeout) {
    const auto now = std::chrono::system_clock::now();
    std::shared_ptr<const Request> request{
            new Request{ now, now + timeout, gettid(), std::move(tag) }};
    return mMonitorThread.add(std::move(request), std::move(func), timeout);
}

TimerThread::Handle TimerThread::trackTask(std::string tag) {
    const auto now = std::chrono::system_clock::now();
    std::shared_ptr<const Request> request{
            new Request{ now, now, gettid(), std::move(tag) }};
    return mNoTimeoutMap.add(std::move(request));
}

bool TimerThread::cancelTask(Handle handle) {
    std::shared_ptr<const Request> request = mNoTimeoutMap.isValidHandle(handle) ?
             mNoTimeoutMap.remove(handle) : mMonitorThread.remove(handle);
    if (!request) return false;
    mRetiredQueue.add(std::move(request));
    return true;
}

std::string TimerThread::toString(size_t retiredCount) const {
    return std::string("now ")
            .append(formatTime(std::chrono::system_clock::now()))
            .append("\npending [ ")
            .append(pendingToString())
            .append(" ]\ntimeout [ ")
            .append(timeoutToString())
            .append(" ]\nretired [ ")
            .append(retiredToString(retiredCount))
            .append(" ]");
}

std::vector<std::shared_ptr<const TimerThread::Request>> TimerThread::getPendingRequests() const {
    constexpr size_t kEstimatedPendingRequests = 8;  // approx 128 byte alloc.
    std::vector<std::shared_ptr<const Request>> pendingRequests;
    pendingRequests.reserve(kEstimatedPendingRequests); // preallocate vector out of lock.

    // following are internally locked calls, which add to our local pendingRequests.
    mMonitorThread.copyRequests(pendingRequests);
    mNoTimeoutMap.copyRequests(pendingRequests);

    // Sort in order of scheduled time.
    std::sort(pendingRequests.begin(), pendingRequests.end(),
        [](const std::shared_ptr<const Request>& r1,
           const std::shared_ptr<const Request>& r2) {
               return r1->scheduled < r2->scheduled;
           });
    return pendingRequests;
}

std::string TimerThread::pendingToString() const {
    return requestsToString(getPendingRequests());
}

std::string TimerThread::retiredToString(size_t n) const {
    std::vector<std::shared_ptr<const Request>> retiredRequests;
    mRetiredQueue.copyRequests(retiredRequests, n);

    // Dump to string
    return requestsToString(retiredRequests);
}

std::string TimerThread::timeoutToString(size_t n) const {
    std::vector<std::shared_ptr<const Request>> timeoutRequests;
    mTimeoutQueue.copyRequests(timeoutRequests, n);

    // Dump to string
    return requestsToString(timeoutRequests);
}

std::string TimerThread::Request::toString() const {
    const auto scheduledString = formatTime(scheduled);
    const auto deadlineString = formatTime(deadline);
    return std::string(tag)
        .append(" scheduled ").append(scheduledString)
        .append(" deadline ").append(timeSuffix(scheduledString, deadlineString))
        .append(" tid ").append(std::to_string(tid));
}

void TimerThread::RequestQueue::add(std::shared_ptr<const Request> request) {
    std::lock_guard lg(mRQMutex);
    mRequestQueue.emplace_back(std::chrono::system_clock::now(), std::move(request));
    if (mRequestQueue.size() > mRequestQueueMax) {
        mRequestQueue.pop_front();
    }
}

void TimerThread::RequestQueue::copyRequests(
        std::vector<std::shared_ptr<const Request>>& requests, size_t n) const {
    std::lock_guard lg(mRQMutex);
    const size_t size = mRequestQueue.size();
    size_t i = n >=  size ? 0 : size - n;
    for (; i < size; ++i) {
        const auto &[time, request] = mRequestQueue[i];
        requests.emplace_back(request);
    }
}

bool TimerThread::NoTimeoutMap::isValidHandle(Handle handle) const {
    return handle > getIndexedHandle(mNoTimeoutRequests);
}

TimerThread::Handle TimerThread::NoTimeoutMap::add(std::shared_ptr<const Request> request) {
    std::lock_guard lg(mNTMutex);
    // A unique handle is obtained by mNoTimeoutRequests.fetch_add(1),
    // This need not be under a lock, but we do so anyhow.
    const Handle handle = getIndexedHandle(mNoTimeoutRequests++);
    mMap[handle] = request;
    return handle;
}

std::shared_ptr<const TimerThread::Request> TimerThread::NoTimeoutMap::remove(Handle handle) {
    std::lock_guard lg(mNTMutex);
    auto it = mMap.find(handle);
    if (it == mMap.end()) return {};
    auto request = it->second;
    mMap.erase(it);
    return request;
}

void TimerThread::NoTimeoutMap::copyRequests(
        std::vector<std::shared_ptr<const Request>>& requests) const {
    std::lock_guard lg(mNTMutex);
    for (const auto &[handle, request] : mMap) {
        requests.emplace_back(request);
    }
}

TimerThread::Handle TimerThread::MonitorThread::getUniqueHandle_l(
        std::chrono::milliseconds timeout) {
    // To avoid key collisions, advance by 1 tick until the key is unique.
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (; mMonitorRequests.find(deadline) != mMonitorRequests.end();
         deadline += std::chrono::steady_clock::duration(1))
        ;
    return deadline;
}

TimerThread::MonitorThread::MonitorThread(RequestQueue& timeoutQueue)
        : mTimeoutQueue(timeoutQueue)
        , mThread([this] { threadFunc(); }) {
     pthread_setname_np(mThread.native_handle(), "TimerThread");
     pthread_setschedprio(mThread.native_handle(), PRIORITY_URGENT_AUDIO);
}

TimerThread::MonitorThread::~MonitorThread() {
    {
        std::lock_guard _l(mMutex);
        mShouldExit = true;
        mCond.notify_all();
    }
    mThread.join();
}

void TimerThread::MonitorThread::threadFunc() {
    std::unique_lock _l(mMutex);
    while (!mShouldExit) {
        if (!mMonitorRequests.empty()) {
            Handle nextDeadline = mMonitorRequests.begin()->first;
            if (nextDeadline < std::chrono::steady_clock::now()) {
                // Deadline has expired, handle the request.
                {
                    auto node = mMonitorRequests.extract(mMonitorRequests.begin());
                    _l.unlock();
                    // We add Request to retired queue early so that it can be dumped out.
                    mTimeoutQueue.add(std::move(node.mapped().first));
                    node.mapped().second(); // Caution: we don't hold lock here - but do we care?
                                            // this is the timeout case!  We will crash soon,
                                            // maybe before returning.
                    // anything left over is released here outside lock.
                }
                // reacquire the lock - if something was added, we loop immediately to check.
                _l.lock();
                continue;
            }
            mCond.wait_until(_l, nextDeadline);
        } else {
            mCond.wait(_l);
        }
    }
}

TimerThread::Handle TimerThread::MonitorThread::add(
        std::shared_ptr<const Request> request, std::function<void()>&& func,
        std::chrono::milliseconds timeout) {
    std::lock_guard _l(mMutex);
    const Handle handle = getUniqueHandle_l(timeout);
    mMonitorRequests.emplace(handle, std::make_pair(std::move(request), std::move(func)));
    mCond.notify_all();
    return handle;
}

std::shared_ptr<const TimerThread::Request> TimerThread::MonitorThread::remove(Handle handle) {
    std::unique_lock ul(mMutex);
    const auto it = mMonitorRequests.find(handle);
    if (it == mMonitorRequests.end()) {
        return {};
    }
    std::shared_ptr<const TimerThread::Request> request = std::move(it->second.first);
    std::function<void()> func = std::move(it->second.second);
    mMonitorRequests.erase(it);
    ul.unlock();  // manually release lock here so func is released outside of lock.
    return request;
}

void TimerThread::MonitorThread::copyRequests(
        std::vector<std::shared_ptr<const Request>>& requests) const {
    std::lock_guard lg(mMutex);
    for (const auto &[deadline, monitorpair] : mMonitorRequests) {
        requests.emplace_back(monitorpair.first);
    }
}

}  // namespace android::mediautils
