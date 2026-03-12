/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "AAudioThread"
//#define LOG_NDEBUG 0

#include <system_error>

#include <utils/Log.h>

#include <aaudio/AAudio.h>
#include <audio_utils/threads.h>
#include <system/thread_defs.h>
#include <utility/AAudioUtilities.h>

#include "AAudioThread.h"

using namespace aaudio;

std::atomic<uint32_t> AAudioThread::mNextThreadIndex{1};

AAudioThread::AAudioThread(const char *prefix) {
    setup(prefix);
}

AAudioThread::AAudioThread() {
    setup("AAudio");
}

AAudioThread::~AAudioThread() {
    ALOGE_IF(mThread.get_id() == std::this_thread::get_id(),
            "%s() destructor running in thread", __func__);
    ALOGE_IF(mHasThread, "%s() thread never joined", __func__);
}

void AAudioThread::setup(const char *prefix) {
    // Name the thread with an increasing index, "prefix_#", for debugging.
    uint32_t index = mNextThreadIndex++;
    // Wrap the index so that we do not hit the 16 char limit
    // and to avoid hard-to-read large numbers.
    index = index % 100000; // arbitrary
    snprintf(mName, sizeof(mName), "%s_%u", prefix, index);
}

void AAudioThread::dispatch() {
    if (mHasThread) {
        android::audio_utils::set_thread_name(mThread, mName);
        constexpr int kMinPriority =
                android::audio_utils::nice_to_unified_priority(ANDROID_PRIORITY_URGENT_AUDIO);
        const int priority = android::audio_utils::get_thread_priority();
        if (priority > kMinPriority) {  // lower priority is better.
            const android::status_t status =
                    android::audio_utils::set_thread_priority(kMinPriority);
            if (status == android::OK) {
                ALOGD("%s: elevating priority from %d to %d", __func__, priority, kMinPriority);
            } else {
                ALOGW("%s: could not set priority to %d, status %d",
                        __func__, kMinPriority, status);
            }
        }
    }

    if (mRunnable != nullptr) {
        mRunnable->run();
    } else {
        run();
    }
}

aaudio_result_t AAudioThread::start(Runnable *runnable) {
    if (mHasThread) {
        ALOGE("start() - mHasThread already true");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // mRunnable will be read by the new thread when it starts. A std::thread is created.
    mRunnable = runnable;
    mHasThread = true;
    mThread = std::thread(&AAudioThread::dispatch, this);
    return AAUDIO_OK;
}

aaudio_result_t AAudioThread::stop() {
    if (!mHasThread) {
        // There can be cases that the thread is just created but not started.
        // Logging as warning to attract attention but not too serious.
        ALOGW("stop() but no thread running");
        return AAUDIO_ERROR_INVALID_STATE;
    }

    if (mThread.get_id() == std::this_thread::get_id()) {
        // The thread must not be joined by itself.
        ALOGE("%s() attempt to join() from launched thread!", __func__);
        return AAUDIO_ERROR_INTERNAL;
    } else if (mThread.joinable()) {
        // Double check if the thread is joinable to avoid exception when calling join.
        mThread.join();
        mHasThread = false;
        return AAUDIO_OK;
    } else {
        ALOGE("%s() the thread is not joinable", __func__);
        return AAUDIO_ERROR_INTERNAL;
    }
}

android::audio_utils::CommandThread& AAudioThread::getAsyncCommandThread() {
    static android::audio_utils::CommandThread commandThread(
            "AAudioAsyncCommand",
            android::audio_utils::nice_to_unified_priority(ANDROID_PRIORITY_URGENT_AUDIO));
    return commandThread;
}
