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

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include <android-base/thread_annotations.h>

#include <mediautils/FixedString.h>

namespace android::mediautils {

/**
 * A thread for deferred execution of tasks, with cancellation.
 */
class TimerThread {
  public:
    // A Handle is a time_point that serves as a unique key.  It is ordered.
    using Handle = std::chrono::steady_clock::time_point;

    static inline constexpr Handle INVALID_HANDLE =
            std::chrono::steady_clock::time_point::min();

    /**
     * Schedules a task to be executed in the future (`timeout` duration from now).
     *
     * \param tag     string associated with the task.  This need not be unique,
     *                as the Handle returned is used for cancelling.
     * \param func    callback function that is invoked at the timeout.
     * \param timeout timeout duration which is converted to milliseconds with at
     *                least 45 integer bits.
     *                A timeout of 0 (or negative) means the timer never expires
     *                so func() is never called. These tasks are stored internally
     *                and reported in the toString() until manually cancelled.
     * \returns       a handle that can be used for cancellation.
     */
    Handle scheduleTask(
            std::string_view tag, std::function<void()>&& func, std::chrono::milliseconds timeout);

    /**
     * Tracks a task that shows up on toString() until cancelled.
     *
     * \param tag     string associated with the task.
     * \returns       a handle that can be used for cancellation.
     */
    Handle trackTask(std::string_view tag);

    /**
     * Cancels a task previously scheduled with scheduleTask()
     * or trackTask().
     *
     * \returns true if cancelled. If the task has already executed
     *          or if the handle doesn't exist, this is a no-op
     *          and returns false.
     */
    bool cancelTask(Handle handle);

    std::string toString(size_t retiredCount = SIZE_MAX) const;

    /**
     * Returns a string representation of the TimerThread queue.
     *
     * The queue is dumped in order of scheduling (not deadline).
     */
    std::string pendingToString() const;

    /**
     * Returns a string representation of the last retired tasks.
     *
     * These tasks from trackTask() or scheduleTask() are
     * cancelled.
     *
     * These are ordered when the task was retired.
     *
     * \param n is maximum number of tasks to dump.
     */
    std::string retiredToString(size_t n = SIZE_MAX) const;


    /**
     * Returns a string representation of the last timeout tasks.
     *
     * These tasks from scheduleTask() which have  timed-out.
     *
     * These are ordered when the task had timed-out.
     *
     * \param n is maximum number of tasks to dump.
     */
    std::string timeoutToString(size_t n = SIZE_MAX) const;

    /**
     * Dumps a container with SmartPointer<Request> to a string.
     *
     * "{ Request1 } { Request2} ...{ RequestN }"
     */
    template <typename T>
    static std::string requestsToString(const T& containerRequests) {
        std::string s;
        // append seems to be faster than stringstream.
        // https://stackoverflow.com/questions/18892281/most-optimized-way-of-concatenation-in-strings
        for (const auto& request : containerRequests) {
            s.append("{ ").append(request->toString()).append(" } ");
        }
        // If not empty, there's an extra space at the end, so we trim it off.
        if (!s.empty()) s.pop_back();
        return s;
    }

  private:
    // To minimize movement of data, we pass around shared_ptrs to Requests.
    // These are allocated and deallocated outside of the lock.
    struct Request {
        Request(const std::chrono::system_clock::time_point& _scheduled,
                const std::chrono::system_clock::time_point& _deadline,
                pid_t _tid,
                std::string_view _tag)
            : scheduled(_scheduled)
            , deadline(_deadline)
            , tid(_tid)
            , tag(_tag)
            {}

        const std::chrono::system_clock::time_point scheduled;
        const std::chrono::system_clock::time_point deadline; // deadline := scheduled + timeout
                                                              // if deadline == scheduled, no
                                                              // timeout, task not executed.
        const pid_t tid;
        const FixedString62 tag;

        std::string toString() const;
    };

    // Deque of requests, in order of add().
    // This class is thread-safe.
    class RequestQueue {
      public:
        explicit RequestQueue(size_t maxSize)
            : mRequestQueueMax(maxSize) {}

        void add(std::shared_ptr<const Request>);

        // return up to the last "n" requests retired.
        void copyRequests(std::vector<std::shared_ptr<const Request>>& requests,
            size_t n = SIZE_MAX) const;

      private:
        const size_t mRequestQueueMax;
        mutable std::mutex mRQMutex;
        std::deque<std::pair<std::chrono::system_clock::time_point,
                             std::shared_ptr<const Request>>>
                mRequestQueue GUARDED_BY(mRQMutex);
    };

    // A storage map of tasks without timeouts.  There is no std::function<void()>
    // required, it just tracks the tasks with the tag, scheduled time and the tid.
    // These tasks show up on a pendingToString() until manually cancelled.
    class NoTimeoutMap {
        // This a counter of the requests that have no timeout (timeout == 0).
        std::atomic<size_t> mNoTimeoutRequests{};

        mutable std::mutex mNTMutex;
        std::map<Handle, std::shared_ptr<const Request>> mMap GUARDED_BY(mNTMutex);

      public:
        bool isValidHandle(Handle handle) const; // lock free
        Handle add(std::shared_ptr<const Request> request);
        std::shared_ptr<const Request> remove(Handle handle);
        void copyRequests(std::vector<std::shared_ptr<const Request>>& requests) const;
    };

    // Monitor thread.
    // This thread manages shared pointers to Requests and a function to
    // call on timeout.
    // This class is thread-safe.
    class MonitorThread {
        mutable std::mutex mMutex;
        mutable std::condition_variable mCond;

        // Ordered map of requests based on time of deadline.
        //
        std::map<Handle, std::pair<std::shared_ptr<const Request>, std::function<void()>>>
                mMonitorRequests GUARDED_BY(mMutex);

        RequestQueue& mTimeoutQueue; // locked internally, added to when request times out.

        // Worker thread variables
        bool mShouldExit GUARDED_BY(mMutex) = false;

        // To avoid race with initialization,
        // mThread should be initialized last as the thread is launched immediately.
        std::thread mThread;

        void threadFunc();
        Handle getUniqueHandle_l(std::chrono::milliseconds timeout) REQUIRES(mMutex);

      public:
        MonitorThread(RequestQueue &timeoutQueue);
        ~MonitorThread();

        Handle add(std::shared_ptr<const Request> request, std::function<void()>&& func,
                std::chrono::milliseconds timeout);
        std::shared_ptr<const Request> remove(Handle handle);
        void copyRequests(std::vector<std::shared_ptr<const Request>>& requests) const;
    };

    // Analysis contains info deduced by analysisTimeout().
    //
    // Summary is the result string from checking timeoutRequests to see if
    // any might be caused by blocked calls in pendingRequests.
    //
    // Summary string is empty if there is no automatic actionable info.
    //
    // timeoutTid is the tid selected from timeoutRequests (if any).
    //
    // HALBlockedTid is the tid that is blocked from pendingRequests believed
    // to cause the timeout.
    // HALBlockedTid may be INVALID_PID if no suspected tid is found,
    // and if HALBlockedTid is valid, it will not be the same as timeoutTid.
    //
    static constexpr pid_t INVALID_PID = -1;
    struct Analysis {
        std::string summary;
        pid_t timeoutTid = INVALID_PID;
        pid_t HALBlockedTid = INVALID_PID;
    };

    // A HAL method is where the substring "Hidl" is in the class name.
    // The tag should look like: ... Hidl ... :: ...
    static bool isRequestFromHal(const std::shared_ptr<const Request>& request);

    // Returns analysis from the requests.
    static Analysis analyzeTimeout(
        const std::vector<std::shared_ptr<const Request>>& timeoutRequests,
        const std::vector<std::shared_ptr<const Request>>& pendingRequests);

    std::vector<std::shared_ptr<const Request>> getPendingRequests() const;

    // A no-timeout request is represented by a handles at the end of steady_clock time,
    // counting down by the number of no timeout requests previously requested.
    // We manage them on the NoTimeoutMap, but conceptually they could be scheduled
    // on the MonitorThread because those time handles won't expire in
    // the lifetime of the device.
    static inline Handle getIndexedHandle(size_t index) {
        return std::chrono::time_point<std::chrono::steady_clock>::max() -
                    std::chrono::time_point<std::chrono::steady_clock>::duration(index);
    }

    static constexpr size_t kRetiredQueueMax = 16;
    RequestQueue mRetiredQueue{kRetiredQueueMax};  // locked internally

    static constexpr size_t kTimeoutQueueMax = 16;
    RequestQueue mTimeoutQueue{kTimeoutQueueMax};  // locked internally

    NoTimeoutMap mNoTimeoutMap;  // locked internally

    MonitorThread mMonitorThread{mTimeoutQueue};  // This should be initialized last because
                                                  // the thread is launched immediately.
                                                  // Locked internally.
};

}  // namespace android::mediautils
