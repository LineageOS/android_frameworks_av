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
    // A Handle is a time_point that serves as a unique key to access a queued
    // request to the TimerThread.
    using Handle = std::chrono::steady_clock::time_point;

    // Duration is based on steady_clock (typically nanoseconds)
    // vs the system_clock duration (typically microseconds).
    using Duration = std::chrono::steady_clock::duration;

    static inline constexpr Handle INVALID_HANDLE =
            std::chrono::steady_clock::time_point::min();

    // Handle implementation details:
    // A Handle represents the timer expiration time based on std::chrono::steady_clock
    // (clock monotonic).  This Handle is computed as now() + timeout.
    //
    // The lsb of the Handle time_point is adjusted to indicate whether there is
    // a timeout action (1) or not (0).
    //

    template <size_t COUNT>
    static constexpr bool is_power_of_2_v = COUNT > 0 && (COUNT & (COUNT - 1)) == 0;

    template <size_t COUNT>
    static constexpr size_t mask_from_count_v = COUNT - 1;

    static constexpr size_t HANDLE_TYPES = 2;
    // HANDLE_TYPES must be a power of 2.
    static_assert(is_power_of_2_v<HANDLE_TYPES>);

    // The handle types
    enum class HANDLE_TYPE : size_t {
        NO_TIMEOUT = 0,
        TIMEOUT = 1,
    };

    static constexpr size_t HANDLE_TYPE_MASK = mask_from_count_v<HANDLE_TYPES>;

    template <typename T>
    static constexpr auto enum_as_value(T x) {
        return static_cast<std::underlying_type_t<T>>(x);
    }

    static inline bool isNoTimeoutHandle(Handle handle) {
        return (handle.time_since_epoch().count() & HANDLE_TYPE_MASK) ==
                enum_as_value(HANDLE_TYPE::NO_TIMEOUT);
    }

    static inline bool isTimeoutHandle(Handle handle) {
        return (handle.time_since_epoch().count() & HANDLE_TYPE_MASK) ==
                enum_as_value(HANDLE_TYPE::TIMEOUT);
    }

    // Returns a unique Handle that doesn't exist in the container.
    template <size_t MAX_TYPED_HANDLES, size_t HANDLE_TYPE_AS_VALUE, typename C, typename T>
    static Handle getUniqueHandleForHandleType_l(C container, T timeout) {
        static_assert(MAX_TYPED_HANDLES > 0 && HANDLE_TYPE_AS_VALUE < MAX_TYPED_HANDLES
                && is_power_of_2_v<MAX_TYPED_HANDLES>,
                " handles must be power of two");

        // Our initial handle is the deadline as computed from steady_clock.
        auto deadline = std::chrono::steady_clock::now() + timeout;

        // We adjust the lsbs by the minimum increment to have the correct
        // HANDLE_TYPE in the least significant bits.
        auto remainder = deadline.time_since_epoch().count() & HANDLE_TYPE_MASK;
        size_t offset = HANDLE_TYPE_AS_VALUE > remainder ? HANDLE_TYPE_AS_VALUE - remainder :
                     MAX_TYPED_HANDLES + HANDLE_TYPE_AS_VALUE - remainder;
        deadline += std::chrono::steady_clock::duration(offset);

        // To avoid key collisions, advance the handle by MAX_TYPED_HANDLES (the modulus factor)
        // until the key is unique.
        while (container.find(deadline) != container.end()) {
            deadline += std::chrono::steady_clock::duration(MAX_TYPED_HANDLES);
        }
        return deadline;
    }

    // TimerCallback invoked on timeout or cancel.
    using TimerCallback = std::function<void(Handle)>;

    /**
     * Schedules a task to be executed in the future (`timeout` duration from now).
     *
     * \param tag     string associated with the task.  This need not be unique,
     *                as the Handle returned is used for cancelling.
     * \param func    callback function that is invoked at the timeout.
     * \param timeoutDuration timeout duration which is converted to milliseconds with at
     *                least 45 integer bits.
     *                A timeout of 0 (or negative) means the timer never expires
     *                so func() is never called. These tasks are stored internally
     *                and reported in the toString() until manually cancelled.
     * \returns       a handle that can be used for cancellation.
     */
    Handle scheduleTask(
            std::string_view tag, TimerCallback&& func,
            Duration timeoutDuration, Duration secondChanceDuration);

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
    // TODO(b/243839867) consider options to merge Request with the
    // TimeCheck::TimeCheckHandler struct.
    struct Request {
        Request(std::chrono::system_clock::time_point _scheduled,
                std::chrono::system_clock::time_point _deadline,
                Duration _secondChanceDuration,
                pid_t _tid,
                std::string_view _tag)
            : scheduled(_scheduled)
            , deadline(_deadline)
            , secondChanceDuration(_secondChanceDuration)
            , tid(_tid)
            , tag(_tag)
            {}

        const std::chrono::system_clock::time_point scheduled;
        const std::chrono::system_clock::time_point deadline; // deadline := scheduled
                                                              // + timeoutDuration
                                                              // + secondChanceDuration
                                                              // if deadline == scheduled, no
                                                              // timeout, task not executed.
        Duration secondChanceDuration;
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

    // A storage map of tasks without timeouts.  There is no TimerCallback
    // required, it just tracks the tasks with the tag, scheduled time and the tid.
    // These tasks show up on a pendingToString() until manually cancelled.
    class NoTimeoutMap {
        mutable std::mutex mNTMutex;
        std::map<Handle, std::shared_ptr<const Request>> mMap GUARDED_BY(mNTMutex);
        Handle getUniqueHandle_l() REQUIRES(mNTMutex) {
            return getUniqueHandleForHandleType_l<
                    HANDLE_TYPES, enum_as_value(HANDLE_TYPE::NO_TIMEOUT)>(
                mMap, Duration{} /* timeout */);
        }

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
        std::atomic<size_t> mSecondChanceCount{};
        mutable std::mutex mMutex;
        mutable std::condition_variable mCond GUARDED_BY(mMutex);

        // Ordered map of requests based on time of deadline.
        //
        std::map<Handle, std::pair<std::shared_ptr<const Request>, TimerCallback>>
                mMonitorRequests GUARDED_BY(mMutex);

        // Due to monotonic/steady clock inaccuracies during suspend,
        // we allow an additional second chance waiting time to prevent
        // false removal.

        // This mSecondChanceRequests queue is almost always empty.
        // Using a pair with the original handle allows lookup and keeps
        // the Key unique.
        std::map<std::pair<Handle /* new */, Handle /* original */>,
                std::pair<std::shared_ptr<const Request>, TimerCallback>>
                        mSecondChanceRequests GUARDED_BY(mMutex);

        RequestQueue& mTimeoutQueue; // locked internally, added to when request times out.

        // Worker thread variables
        bool mShouldExit GUARDED_BY(mMutex) = false;

        // To avoid race with initialization,
        // mThread should be initialized last as the thread is launched immediately.
        std::thread mThread;

        void threadFunc();
        Handle getUniqueHandle_l(Duration timeout) REQUIRES(mMutex) {
            return getUniqueHandleForHandleType_l<
                    HANDLE_TYPES, enum_as_value(HANDLE_TYPE::TIMEOUT)>(
                mMonitorRequests, timeout);
        }

      public:
        MonitorThread(RequestQueue &timeoutQueue);
        ~MonitorThread();

        Handle add(std::shared_ptr<const Request> request, TimerCallback&& func,
                Duration timeout);
        std::shared_ptr<const Request> remove(Handle handle);
        void copyRequests(std::vector<std::shared_ptr<const Request>>& requests) const;
        size_t getSecondChanceCount() const {
            return mSecondChanceCount.load(std::memory_order_relaxed);
        }
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
