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

#include <mediautils/MediaUtilsDelayed.h>
#include <mediautils/TimerThread.h>
#include <utils/Log.h>
#include <utils/ThreadDefs.h>

using namespace std::chrono_literals;

namespace android::mediautils {

extern std::string formatTime(std::chrono::system_clock::time_point t);
extern std::string_view timeSuffix(std::string_view time1, std::string_view time2);

TimerThread::Handle TimerThread::scheduleTask(
        std::string_view tag, TimerCallback&& func,
        Duration timeoutDuration, Duration secondChanceDuration) {
    const auto now = std::chrono::system_clock::now();
    auto request = std::make_shared<const Request>(now, now +
            std::chrono::duration_cast<std::chrono::system_clock::duration>(timeoutDuration),
            secondChanceDuration, gettid(), tag);
    return mMonitorThread.add(std::move(request), std::move(func), timeoutDuration);
}

TimerThread::Handle TimerThread::trackTask(std::string_view tag) {
    const auto now = std::chrono::system_clock::now();
    auto request = std::make_shared<const Request>(now, now,
            Duration{} /* secondChanceDuration */, gettid(), tag);
    return mNoTimeoutMap.add(std::move(request));
}

bool TimerThread::cancelTask(Handle handle) {
    std::shared_ptr<const Request> request = isNoTimeoutHandle(handle) ?
             mNoTimeoutMap.remove(handle) : mMonitorThread.remove(handle);
    if (!request) return false;
    mRetiredQueue.add(std::move(request));
    return true;
}

std::string TimerThread::toString(size_t retiredCount) const {
    // Note: These request queues are snapshot very close together but
    // not at "identical" times as we don't use a class-wide lock.

    std::vector<std::shared_ptr<const Request>> timeoutRequests;
    std::vector<std::shared_ptr<const Request>> retiredRequests;
    mTimeoutQueue.copyRequests(timeoutRequests);
    mRetiredQueue.copyRequests(retiredRequests, retiredCount);
    std::vector<std::shared_ptr<const Request>> pendingRequests =
        getPendingRequests();

    struct Analysis analysis = analyzeTimeout(timeoutRequests, pendingRequests);
    std::string analysisSummary;
    if (!analysis.summary.empty()) {
        analysisSummary = std::string("\nanalysis [ ").append(analysis.summary).append(" ]");
    }
    std::string timeoutStack;
    if (analysis.timeoutTid != -1) {
        timeoutStack = std::string("\ntimeout(")
                .append(std::to_string(analysis.timeoutTid)).append(") callstack [\n")
                .append(getCallStackStringForTid(analysis.timeoutTid)).append("]");
    }
    std::string blockedStack;
    if (analysis.HALBlockedTid != -1) {
        blockedStack = std::string("\nblocked(")
                .append(std::to_string(analysis.HALBlockedTid)).append(")  callstack [\n")
                .append(getCallStackStringForTid(analysis.HALBlockedTid)).append("]");
    }

    return std::string("now ")
            .append(formatTime(std::chrono::system_clock::now()))
            .append("\nsecondChanceCount ")
            .append(std::to_string(mMonitorThread.getSecondChanceCount()))
            .append(analysisSummary)
            .append("\ntimeout [ ")
            .append(requestsToString(timeoutRequests))
            .append(" ]\npending [ ")
            .append(requestsToString(pendingRequests))
            .append(" ]\nretired [ ")
            .append(requestsToString(retiredRequests))
            .append(" ]")
            .append(timeoutStack)
            .append(blockedStack);
}

// A HAL method is where the substring "Hidl" is in the class name.
// The tag should look like: ... Hidl ... :: ...
// When the audio HAL is updated to AIDL perhaps we will use instead
// a global directory of HAL classes.
//
// See MethodStatistics.cpp:
// mediautils::getStatisticsClassesForModule(METHOD_STATISTICS_MODULE_NAME_AUDIO_HIDL)
//
/* static */
bool TimerThread::isRequestFromHal(const std::shared_ptr<const Request>& request) {
    const size_t hidlPos = request->tag.asStringView().find("Hidl");
    if (hidlPos == std::string::npos) return false;
    // should be a separator afterwards Hidl which indicates the string was in the class.
    const size_t separatorPos = request->tag.asStringView().find("::", hidlPos);
    return separatorPos != std::string::npos;
}

/* static */
struct TimerThread::Analysis TimerThread::analyzeTimeout(
    const std::vector<std::shared_ptr<const Request>>& timeoutRequests,
    const std::vector<std::shared_ptr<const Request>>& pendingRequests) {

    if (timeoutRequests.empty() || pendingRequests.empty()) return {}; // nothing to say.

    // for now look at last timeout (in our case, the only timeout)
    const std::shared_ptr<const Request> timeout = timeoutRequests.back();

    // pending Requests that are problematic.
    std::vector<std::shared_ptr<const Request>> pendingExact;
    std::vector<std::shared_ptr<const Request>> pendingPossible;

    // We look at pending requests that were scheduled no later than kPendingDuration
    // after the timeout request. This prevents false matches with calls
    // that naturally block for a short period of time
    // such as HAL write() and read().
    //
    constexpr Duration kPendingDuration = 1000ms;
    for (const auto& pending : pendingRequests) {
        // If the pending tid is the same as timeout tid, problem identified.
        if (pending->tid == timeout->tid) {
            pendingExact.emplace_back(pending);
            continue;
        }

        // if the pending tid is scheduled within time limit
        if (pending->scheduled - timeout->scheduled < kPendingDuration) {
            pendingPossible.emplace_back(pending);
        }
    }

    struct Analysis analysis{};

    analysis.timeoutTid = timeout->tid;
    std::string& summary = analysis.summary;
    if (!pendingExact.empty()) {
        const auto& request = pendingExact.front();
        const bool hal = isRequestFromHal(request);

        if (hal) {
            summary = std::string("Blocked directly due to HAL call: ")
                .append(request->toString());
        }
    }
    if (summary.empty() && !pendingPossible.empty()) {
        for (const auto& request : pendingPossible) {
            const bool hal = isRequestFromHal(request);
            if (hal) {
                // The first blocked call is the most likely one.
                // Recent calls might be temporarily blocked
                // calls such as write() or read() depending on kDuration.
                summary = std::string("Blocked possibly due to HAL call: ")
                    .append(request->toString());
                analysis.HALBlockedTid = request->tid;
            }
       }
    }
    return analysis;
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

TimerThread::Handle TimerThread::NoTimeoutMap::add(std::shared_ptr<const Request> request) {
    std::lock_guard lg(mNTMutex);
    // A unique handle is obtained by mNoTimeoutRequests.fetch_add(1),
    // This need not be under a lock, but we do so anyhow.
    const Handle handle = getUniqueHandle_l();
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
        Handle nextDeadline = INVALID_HANDLE;
        Handle now = INVALID_HANDLE;
        if (!mMonitorRequests.empty()) {
            nextDeadline = mMonitorRequests.begin()->first;
            now = std::chrono::steady_clock::now();
            if (nextDeadline < now) {
                auto node = mMonitorRequests.extract(mMonitorRequests.begin());
                // Deadline has expired, handle the request.
                auto secondChanceDuration = node.mapped().first->secondChanceDuration;
                if (secondChanceDuration.count() != 0) {
                    // We now apply the second chance duration to find the clock
                    // monotonic second deadline.  The unique key is then the
                    // pair<second_deadline, first_deadline>.
                    //
                    // The second chance prevents a false timeout should there be
                    // any clock monotonic advancement during suspend.
                    auto newHandle = now + secondChanceDuration;
                    ALOGD("%s: TimeCheck second chance applied for %s",
                            __func__, node.mapped().first->tag.c_str()); // should be rare event.
                    mSecondChanceRequests.emplace_hint(mSecondChanceRequests.end(),
                            std::make_pair(newHandle, nextDeadline),
                            std::move(node.mapped()));
                    // increment second chance counter.
                    mSecondChanceCount.fetch_add(1 /* arg */, std::memory_order_relaxed);
                } else {
                    {
                        _l.unlock();
                        // We add Request to retired queue early so that it can be dumped out.
                        mTimeoutQueue.add(std::move(node.mapped().first));
                        node.mapped().second(nextDeadline);
                        // Caution: we don't hold lock when we call TimerCallback,
                        // but this is the timeout case!  We will crash soon,
                        // maybe before returning.
                        // anything left over is released here outside lock.
                    }
                    // reacquire the lock - if something was added, we loop immediately to check.
                    _l.lock();
                }
                // always process expiring monitor requests first.
                continue;
            }
        }
        // now process any second chance requests.
        if (!mSecondChanceRequests.empty()) {
            Handle secondDeadline = mSecondChanceRequests.begin()->first.first;
            if (now == INVALID_HANDLE) now = std::chrono::steady_clock::now();
            if (secondDeadline < now) {
                auto node = mSecondChanceRequests.extract(mSecondChanceRequests.begin());
                {
                    _l.unlock();
                    // We add Request to retired queue early so that it can be dumped out.
                    mTimeoutQueue.add(std::move(node.mapped().first));
                    const Handle originalHandle = node.key().second;
                    node.mapped().second(originalHandle);
                    // Caution: we don't hold lock when we call TimerCallback.
                    // This is benign issue - we permit concurrent operations
                    // while in the callback to the MonitorQueue.
                    //
                    // Anything left over is released here outside lock.
                }
                // reacquire the lock - if something was added, we loop immediately to check.
                _l.lock();
                continue;
            }
            // update the deadline.
            if (nextDeadline == INVALID_HANDLE) {
                nextDeadline = secondDeadline;
            } else {
                nextDeadline = std::min(nextDeadline, secondDeadline);
            }
        }
        if (nextDeadline != INVALID_HANDLE) {
            mCond.wait_until(_l, nextDeadline);
        } else {
            mCond.wait(_l);
        }
    }
}

TimerThread::Handle TimerThread::MonitorThread::add(
        std::shared_ptr<const Request> request, TimerCallback&& func, Duration timeout) {
    std::lock_guard _l(mMutex);
    const Handle handle = getUniqueHandle_l(timeout);
    mMonitorRequests.emplace_hint(mMonitorRequests.end(),
            handle, std::make_pair(std::move(request), std::move(func)));
    mCond.notify_all();
    return handle;
}

std::shared_ptr<const TimerThread::Request> TimerThread::MonitorThread::remove(Handle handle) {
    std::pair<std::shared_ptr<const Request>, TimerCallback> data;
    std::unique_lock ul(mMutex);
    if (const auto it = mMonitorRequests.find(handle);
        it != mMonitorRequests.end()) {
        data = std::move(it->second);
        mMonitorRequests.erase(it);
        ul.unlock();  // manually release lock here so func (data.second)
                      // is released outside of lock.
        return data.first;  // request
    }

    // this check is O(N), but since the second chance requests are ordered
    // in terms of earliest expiration time, we would expect better than average results.
    for (auto it = mSecondChanceRequests.begin(); it != mSecondChanceRequests.end(); ++it) {
        if (it->first.second == handle) {
            data = std::move(it->second);
            mSecondChanceRequests.erase(it);
            ul.unlock();  // manually release lock here so func (data.second)
                          // is released outside of lock.
            return data.first; // request
        }
    }
    return {};
}

void TimerThread::MonitorThread::copyRequests(
        std::vector<std::shared_ptr<const Request>>& requests) const {
    std::lock_guard lg(mMutex);
    for (const auto &[deadline, monitorpair] : mMonitorRequests) {
        requests.emplace_back(monitorpair.first);
    }
    // we combine the second map with the first map - this is
    // everything that is pending on the monitor thread.
    // The second map will be older than the first map so this
    // is in order.
    for (const auto &[deadline, monitorpair] : mSecondChanceRequests) {
        requests.emplace_back(monitorpair.first);
    }
}

}  // namespace android::mediautils
