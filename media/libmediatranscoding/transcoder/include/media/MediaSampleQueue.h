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

#ifndef ANDROID_MEDIA_SAMPLE_QUEUE_H
#define ANDROID_MEDIA_SAMPLE_QUEUE_H

#include <media/MediaSample.h>
#include <utils/Mutex.h>

#include <memory>
#include <mutex>
#include <queue>

namespace android {

/**
 * MediaSampleQueue asynchronously connects a producer and a consumer of media samples.
 * Media samples flows through the queue in FIFO order. If the queue is empty the consumer will be
 * blocked until a new media sample is added or until the producer aborts the queue operation.
 */
class MediaSampleQueue {
public:
    /**
     * Enqueues a media sample at the end of the queue and notifies potentially waiting consumers.
     * If the queue has previously been aborted this method does nothing.
     * @param sample The media sample to enqueue.
     * @return True if the queue has been aborted.
     */
    bool enqueue(const std::shared_ptr<MediaSample>& sample);

    /**
     * Removes the next media sample from the queue and returns it. If the queue has previously been
     * aborted this method returns null. Note that this method will block while the queue is empty.
     * @param[out] sample The next media sample in the queue.
     * @return True if the queue has been aborted.
     */
    bool dequeue(std::shared_ptr<MediaSample>* sample /* nonnull */);

    /**
     * Aborts the queue operation. This clears the queue and notifies waiting consumers. After the
     * has been aborted it is not possible to enqueue more samples, and dequeue will return null.
     */
    void abort();

private:
    std::queue<std::shared_ptr<MediaSample>> mSampleQueue GUARDED_BY(mMutex);
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mAborted GUARDED_BY(mMutex) = false;
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_QUEUE_H
