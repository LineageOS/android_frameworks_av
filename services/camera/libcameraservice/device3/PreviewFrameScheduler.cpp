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

#define LOG_TAG "Camera3-PreviewFrameScheduler"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <utils/Log.h>
#include <utils/Trace.h>

#include <android/looper.h>
#include "PreviewFrameScheduler.h"
#include "Camera3OutputStream.h"

namespace android {

namespace camera3 {

/**
 * Internal Choreographer thread implementation for polling and handling callbacks
 */

// Callback function for Choreographer
static void frameCallback(const AChoreographerFrameCallbackData* callbackData, void* data) {
    PreviewFrameScheduler* parent = static_cast<PreviewFrameScheduler*>(data);
    if (parent == nullptr) {
        ALOGE("%s: Invalid data for Choreographer callback!", __FUNCTION__);
        return;
    }

    size_t length = AChoreographerFrameCallbackData_getFrameTimelinesLength(callbackData);
    std::vector<nsecs_t> timeline(length);
    for (size_t i = 0; i < length; i++) {
        nsecs_t timestamp = AChoreographerFrameCallbackData_getFrameTimelineExpectedPresentTimeNanos(
                callbackData, i);
        timeline[i] = timestamp;
    }

    parent->onNewPresentationTime(timeline);

    AChoreographer_postExtendedFrameCallback(AChoreographer_getInstance(), frameCallback, data);
}

struct ChoreographerThread : public Thread {
    ChoreographerThread();
    status_t start(PreviewFrameScheduler* parent);
    virtual status_t readyToRun() override;
    virtual bool threadLoop() override;

protected:
    virtual ~ChoreographerThread() {}

private:
    ChoreographerThread &operator=(const ChoreographerThread &);

    // This only impacts the shutdown time. It won't impact the choreographer
    // callback frequency.
    static constexpr nsecs_t kPollingTimeoutMs = 5;
    PreviewFrameScheduler* mParent = nullptr;
};

ChoreographerThread::ChoreographerThread() : Thread(false /*canCallJava*/) {
}

status_t ChoreographerThread::start(PreviewFrameScheduler* parent) {
    mParent = parent;
    return run("PreviewChoreographer");
}

status_t ChoreographerThread::readyToRun() {
    ALooper_prepare(ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
    if (AChoreographer_getInstance() == NULL) {
        return NO_INIT;
    }

    AChoreographer_postExtendedFrameCallback(
            AChoreographer_getInstance(), frameCallback, mParent);
    return OK;
}

bool ChoreographerThread::threadLoop() {
    if (exitPending()) {
        return false;
    }
    ALooper_pollOnce(kPollingTimeoutMs, nullptr, nullptr, nullptr);
    return true;
}

/**
 * PreviewFrameScheduler implementation
 */

PreviewFrameScheduler::PreviewFrameScheduler(Camera3OutputStream& parent, sp<Surface> consumer) :
        mParent(parent),
        mConsumer(consumer),
        mChoreographerThread(new ChoreographerThread()) {
}

PreviewFrameScheduler::~PreviewFrameScheduler() {
    {
        Mutex::Autolock l(mLock);
        mChoreographerThread->requestExit();
    }
    mChoreographerThread->join();
}

status_t PreviewFrameScheduler::queuePreviewBuffer(nsecs_t timestamp, int32_t transform,
        ANativeWindowBuffer* anwBuffer, int releaseFence) {
    // Start choreographer thread if it's not already running.
    if (!mChoreographerThread->isRunning()) {
        status_t res = mChoreographerThread->start(this);
        if (res != OK) {
            ALOGE("%s: Failed to init choreographer thread!", __FUNCTION__);
            return res;
        }
    }

    {
        Mutex::Autolock l(mLock);
        mPendingBuffers.emplace(timestamp, transform, anwBuffer, releaseFence);

        // Queue buffer to client right away if pending buffers are more than
        // the queue depth watermark.
        if (mPendingBuffers.size() > kQueueDepthWatermark) {
            auto oldBuffer = mPendingBuffers.front();
            mPendingBuffers.pop();

            status_t res = queueBufferToClientLocked(oldBuffer, oldBuffer.timestamp);
            if (res != OK) {
                return res;
            }

            // Reset the last capture and presentation time
            mLastCameraCaptureTime = 0;
            mLastCameraPresentTime = 0;
        } else {
            ATRACE_INT(kPendingBufferTraceName, mPendingBuffers.size());
        }
    }
    return OK;
}

void PreviewFrameScheduler::onNewPresentationTime(const std::vector<nsecs_t>& timeline) {
    ATRACE_CALL();
    Mutex::Autolock l(mLock);
    if (mPendingBuffers.size() > 0) {
        auto nextBuffer = mPendingBuffers.front();
        mPendingBuffers.pop();

        // Find the best presentation time by finding the element in the
        // choreographer timeline that's closest to the ideal presentation time.
        // The ideal presentation time is the last presentation time + frame
        // interval.
        nsecs_t cameraInterval = nextBuffer.timestamp - mLastCameraCaptureTime;
        nsecs_t idealPresentTime = (cameraInterval < kSpacingResetIntervalNs) ?
                (mLastCameraPresentTime + cameraInterval) : nextBuffer.timestamp;
        nsecs_t presentTime = *std::min_element(timeline.begin(), timeline.end(),
                [idealPresentTime](nsecs_t p1, nsecs_t p2) {
                        return std::abs(p1 - idealPresentTime) < std::abs(p2 - idealPresentTime);
                });

        status_t res = queueBufferToClientLocked(nextBuffer, presentTime);
        ATRACE_INT(kPendingBufferTraceName, mPendingBuffers.size());

        if (mParent.shouldLogError(res)) {
            ALOGE("%s: Preview Stream: Error queueing buffer to native window:"
                    " %s (%d)", __FUNCTION__, strerror(-res), res);
        }

        mLastCameraCaptureTime = nextBuffer.timestamp;
        mLastCameraPresentTime = presentTime;
    }
}

status_t PreviewFrameScheduler::queueBufferToClientLocked(
        const BufferHolder& bufferHolder, nsecs_t timestamp) {
    mParent.setTransform(bufferHolder.transform, true/*mayChangeMirror*/);

    status_t res = native_window_set_buffers_timestamp(mConsumer.get(), timestamp);
    if (res != OK) {
        ALOGE("%s: Preview Stream: Error setting timestamp: %s (%d)",
                __FUNCTION__, strerror(-res), res);
        return res;
    }

    Camera3Stream::queueHDRMetadata(bufferHolder.anwBuffer.get()->handle, mConsumer,
            mParent.getDynamicRangeProfile());

    res = mConsumer->queueBuffer(mConsumer.get(), bufferHolder.anwBuffer.get(),
            bufferHolder.releaseFence);
    if (res != OK) {
        close(bufferHolder.releaseFence);
    }

    return res;
}

}; // namespace camera3

}; // namespace android
