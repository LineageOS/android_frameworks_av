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

// #define LOG_NDEBUG 0
#define LOG_TAG "MediaSampleQueue"

#include <android-base/logging.h>
#include <media/MediaSampleQueue.h>

namespace android {

bool MediaSampleQueue::enqueue(const std::shared_ptr<MediaSample>& sample) {
    std::scoped_lock<std::mutex> lock(mMutex);
    if (!mAborted) {
        mSampleQueue.push(sample);
        mCondition.notify_one();
    }
    return mAborted;
}

// Unfortunately std::unique_lock is incompatible with -Wthread-safety
bool MediaSampleQueue::dequeue(std::shared_ptr<MediaSample>* sample) NO_THREAD_SAFETY_ANALYSIS {
    std::unique_lock<std::mutex> lock(mMutex);
    while (mSampleQueue.empty() && !mAborted) {
        mCondition.wait(lock);
    }

    if (!mAborted) {
        if (sample != nullptr) {
            *sample = mSampleQueue.front();
        }
        mSampleQueue.pop();
    }
    return mAborted;
}

void MediaSampleQueue::abort() {
    std::scoped_lock<std::mutex> lock(mMutex);
    // Clear the queue and notify consumers.
    std::queue<std::shared_ptr<MediaSample>> empty = {};
    std::swap(mSampleQueue, empty);
    mAborted = true;
    mCondition.notify_all();
}
}  // namespace android