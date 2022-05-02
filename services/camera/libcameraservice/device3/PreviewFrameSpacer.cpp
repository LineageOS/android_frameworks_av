/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "Camera3-PreviewFrameSpacer"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <utils/Log.h>

#include "PreviewFrameSpacer.h"
#include "Camera3OutputStream.h"

namespace android {

namespace camera3 {

PreviewFrameSpacer::PreviewFrameSpacer(Camera3OutputStream& parent, sp<Surface> consumer) :
        mParent(parent),
        mConsumer(consumer) {
}

PreviewFrameSpacer::~PreviewFrameSpacer() {
    Thread::requestExitAndWait();
}

status_t PreviewFrameSpacer::queuePreviewBuffer(nsecs_t timestamp, int32_t transform,
        ANativeWindowBuffer* anwBuffer, int releaseFence) {
    Mutex::Autolock l(mLock);
    mPendingBuffers.emplace(timestamp, transform, anwBuffer, releaseFence);
    ALOGV("%s: mPendingBuffers size %zu, timestamp %" PRId64, __FUNCTION__,
            mPendingBuffers.size(), timestamp);

    mBufferCond.signal();
    return OK;
}

bool PreviewFrameSpacer::threadLoop() {
    Mutex::Autolock l(mLock);
    if (mPendingBuffers.size() == 0) {
        mBufferCond.waitRelative(mLock, kWaitDuration);
        return true;
    }

    nsecs_t currentTime = systemTime();
    auto buffer = mPendingBuffers.front();
    nsecs_t captureInterval = buffer.timestamp - mLastCameraCaptureTime;
    // If the capture interval exceeds threshold, directly queue
    // cached buffer.
    if (captureInterval >= kFrameIntervalThreshold) {
        mPendingBuffers.pop();
        queueBufferToClientLocked(buffer, currentTime);
        return true;
    }

    // Cache the frame to match capture time interval, for up to 33ms
    nsecs_t expectedQueueTime = mLastCameraPresentTime + captureInterval;
    nsecs_t frameWaitTime = std::min(kMaxFrameWaitTime, expectedQueueTime - currentTime);
    if (frameWaitTime > 0 && mPendingBuffers.size() < 2) {
        mBufferCond.waitRelative(mLock, frameWaitTime);
        if (exitPending()) {
            return true;
        }
        currentTime = systemTime();
    }
    ALOGV("%s: captureInterval %" PRId64 ", queueInterval %" PRId64 ", waited for %" PRId64
            ", timestamp %" PRId64, __FUNCTION__, captureInterval,
            currentTime - mLastCameraPresentTime, frameWaitTime, buffer.timestamp);
    mPendingBuffers.pop();
    queueBufferToClientLocked(buffer, currentTime);
    return true;
}

void PreviewFrameSpacer::requestExit() {
    // Call parent to set up shutdown
    Thread::requestExit();
    // Exit from other possible wait
    mBufferCond.signal();
}

void PreviewFrameSpacer::queueBufferToClientLocked(
        const BufferHolder& bufferHolder, nsecs_t currentTime) {
    mParent.setTransform(bufferHolder.transform, true/*mayChangeMirror*/);

    status_t res = native_window_set_buffers_timestamp(mConsumer.get(), bufferHolder.timestamp);
    if (res != OK) {
        ALOGE("%s: Preview Stream: Error setting timestamp: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }

    Camera3Stream::queueHDRMetadata(bufferHolder.anwBuffer.get()->handle, mConsumer,
            mParent.getDynamicRangeProfile());

    res = mConsumer->queueBuffer(mConsumer.get(), bufferHolder.anwBuffer.get(),
            bufferHolder.releaseFence);
    if (res != OK) {
        close(bufferHolder.releaseFence);
        if (mParent.shouldLogError(res)) {
            ALOGE("%s: Failed to queue buffer to client: %s(%d)", __FUNCTION__,
                    strerror(-res), res);
        }
    }

    mLastCameraPresentTime = currentTime;
    mLastCameraCaptureTime = bufferHolder.timestamp;
}

}; // namespace camera3

}; // namespace android
