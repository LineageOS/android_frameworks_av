/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <deque>
#include <mutex>

#include <audio_utils/mutex.h>
#include <audio_utils/threads.h>
#include <utils/Log.h>

#include "Runnable.h"
#include "jthread.h"

#pragma push_macro("LOG_TAG")
#undef LOG_TAG
#define LOG_TAG "mediautils::SingleThreadExecutor"

namespace android::mediautils {

/**
 * A C++ implementation similar to a Java executor, which manages a thread which runs enqueued
 * runnable tasks in queue order. Spawns thread on construction and joins destruction
 */
class SingleThreadExecutor {
  public:
    /**
     * Default constructor for SingleThreadExecutor.
     * The worker thread is started immediately with default
     * inherited priority.
     *
     * @param name optional name for the worker thread.
     */
    explicit SingleThreadExecutor(std::string_view name = "")
        : SingleThreadExecutor(name, kPriorityUseDefault) {}

    /**
     * Constructor for SingleThreadExecutor with a specified priority.
     * The worker thread is started immediately with the given priority.
     *
     * @param priority the unified priority to set for the worker thread.
     */
    explicit SingleThreadExecutor(int priority)
        : SingleThreadExecutor("", priority) {}

    /**
     * Constructor for SingleThreadExecutor with a specified name and priority.
     * The worker thread is started immediately with the given priority.
     *
     * The linux kernel unified scheduler priority values are as follows:
     * 0 - 98    (A real time priority rtprio between 99 and 1)
     * 100 - 139 (A Completely Fair Scheduler niceness between -20 and 19)
     *
     * A priority value of 99 is changed to 98.
     *
     * See audio_utils/threads.h for a description of unified priority.
     *
     * @param name name for the worker thread.
     * @param priority the unified priority to set for the worker thread.
     */
    SingleThreadExecutor(std::string_view name, int priority)
        : thread_([this, nameStr = std::string(name), priority](stop_token stok) {
            if (!nameStr.empty()) {
                audio_utils::set_thread_name(nameStr);
            }
            if (priority != kPriorityUseDefault) {
                const status_t status = audio_utils::set_thread_priority(priority);
                ALOGW_IF(status != OK, "%s: set priority %d failed with status %d",
                        __func__, priority, status);
            }
            run(stok);
        }) {}

    void enqueue(Runnable r) {
        if (!r || thread_.stop_requested()) {
            return;
        } else {
            std::lock_guard l{mutex_};
            task_list_.push_back(std::move(r));
            if (task_list_.size() == 1) {
                // necessary under lock until our cv impl internally locks
                cv_.notify_one();
            }
        }
    }

    /**
     * Request thread termination, optionally dropping any enqueued tasks.
     * Note: does not join thread in this method and no task cancellation.
     */
    void shutdown(bool dropTasks = false) {
        if (dropTasks) {
            std::lock_guard l{mutex_};
            task_list_.clear();
        }
        thread_.request_stop();
    }


  private:
    static constexpr int kPriorityUseDefault = -1;

    void run(stop_token stok) {
        stop_callback cb {stok, [this]() {
            // This lock is necessary to prevent a missed notification on stop.
            // In particular, by grabbing the lock, the reader is either waiting already (so we
            // don't miss the notify), or running the task, in which case, when they re-lock, they
            // will re-check the stop_token before waiting again.
            std::unique_lock l{mutex_};
            cv_.notify_one();
        }};
        audio_utils::unique_lock l{mutex_};
        while (true) {
            if (!task_list_.empty()) {
                Runnable r {std::move(task_list_.front())};
                task_list_.pop_front();
                l.unlock();
                r();
                l.lock();
            } else if (stok.stop_requested()) {
                break;
            } else {
                cv_.wait(l);
            }
        }
    }

    std::condition_variable cv_;
    std::mutex mutex_;
    std::deque<Runnable> task_list_ GUARDED_BY(mutex_);
    // Must be the final declaration to ensure that it's destructor runs first.
    // Join on destruction means that this class *MUST NOT* have virtual dispatch
    jthread thread_;
};
}  // namespace android::mediautils

#pragma pop_macro("LOG_TAG")
