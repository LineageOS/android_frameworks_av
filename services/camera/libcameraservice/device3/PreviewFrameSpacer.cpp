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

#include <com_android_internal_camera_flags.h>

#include <utils/Log.h>

#include "PreviewFrameSpacer.h"
#include "Camera3OutputStream.h"
#include "utils/SchedulingPolicyUtils.h"
#include "utils/Utils.h"

namespace flags = com::android::internal::camera::flags;

namespace android {

namespace camera3 {

PreviewFrameSpacer::PreviewFrameSpacer(wp<Camera3OutputStream> parent, sp<Surface> consumer,
        ssize_t surfaceId) :
        mParent(parent),
        mConsumer(consumer),
        mSurfaceId(surfaceId) {
}

PreviewFrameSpacer::~PreviewFrameSpacer() {
}

status_t PreviewFrameSpacer::queuePreviewBuffer(nsecs_t timestamp, nsecs_t readoutTimestamp,
        int32_t transform, ANativeWindowBuffer* anwBuffer, int releaseFence) {
    Mutex::Autolock l(mLock);
    mPendingBuffers.emplace(timestamp, readoutTimestamp, transform, anwBuffer, releaseFence);
    ALOGV("%s: mPendingBuffers size %zu, timestamp %" PRId64 ", readoutTime %" PRId64,
            __FUNCTION__, mPendingBuffers.size(), timestamp, readoutTimestamp);

    mBufferCond.signal();
    return OK;
}

bool PreviewFrameSpacer::threadLoop() {
    Mutex::Autolock l(mLock);
    if (mPendingBuffers.size() == 0) {
        mBufferCond.waitRelative(mLock, kWaitDuration);
        if (exitPending()) {
            return false;
        } else {
            return true;
        }
    }

    nsecs_t currentTime = systemTime();
    auto buffer = mPendingBuffers.front();
    nsecs_t readoutInterval = buffer.readoutTimestamp - mLastCameraReadoutTime;
    // If the readout interval exceeds threshold, directly queue
    // cached buffer.
    if (readoutInterval >= kFrameIntervalThreshold) {
        mPendingBuffers.pop();
        queueBufferToClientLocked(buffer, currentTime);
        return true;
    }

    // Cache the frame to match readout time interval, for up to kMaxFrameWaitTime
    // Because the code between here and queueBuffer() takes time to execute, make sure the
    // presentationInterval is slightly shorter than readoutInterval.
    nsecs_t expectedQueueTime = mLastCameraPresentTime + readoutInterval - kFrameAdjustThreshold;
    nsecs_t frameWaitTime = std::min(kMaxFrameWaitTime, expectedQueueTime - currentTime);
    if (frameWaitTime > 0 && mPendingBuffers.size() < 2) {
        mBufferCond.waitRelative(mLock, frameWaitTime);
        if (exitPending()) {
            return false;
        }
        currentTime = systemTime();
    }
    ALOGV("%s: readoutInterval %" PRId64 ", waited for %" PRId64
            ", timestamp %" PRId64, __FUNCTION__, readoutInterval,
            mPendingBuffers.size() < 2 ? frameWaitTime : 0, buffer.timestamp);
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
    sp<Camera3OutputStream> parent = mParent.promote();
    if (parent == nullptr) {
        ALOGV("%s: Parent camera3 output stream was destroyed", __FUNCTION__);
        return;
    }

    if (flags::seamless_transitions()) {
        parent->setTransform(bufferHolder.transform, mSurfaceId);
    } else {
        parent->setTransform(bufferHolder.transform);
    }

    status_t res = native_window_set_buffers_timestamp(mConsumer.get(), bufferHolder.timestamp);
    if (res != OK) {
        ALOGE("%s: Preview Stream: Error setting timestamp: %s (%d)",
                __FUNCTION__, strerror(-res), res);
    }

    Camera3Stream::queueHDRMetadata(bufferHolder.anwBuffer.get()->handle, mConsumer,
            parent->getDynamicRangeProfile());

    res = mConsumer->queueBuffer(mConsumer.get(), bufferHolder.anwBuffer.get(),
            bufferHolder.releaseFence);
    if (res != OK) {
        close(bufferHolder.releaseFence);
        if (parent->shouldLogError(res)) {
            ALOGE("%s: Failed to queue buffer to client: %s(%d)", __FUNCTION__,
                    strerror(-res), res);
        }
    }

    parent->onCachedBufferQueued();
    mLastCameraPresentTime = currentTime;
    mLastCameraReadoutTime = bufferHolder.readoutTimestamp;
}

status_t PreviewFrameSpacer::run(const char* name, int32_t priority, size_t stack) {
    auto ret = Thread::run(name, priority, stack);
    // Boost priority of the preview frame spacer thread to SCHED_FIFO.
    pid_t previewFrameSpacerTid = getTid();
    auto res = SchedulingPolicyUtils::requestPriorityDirect(getpid(), previewFrameSpacerTid,
            RunThreadWithRealtimePriority::kRequestThreadPriority);
    if (res != OK) {
        ALOGW("Can't set realtime priority for preview frame spacer thread: %s (%d)",
                strerror(-res), res);
    } else {
        ALOGV("Set real time priority for preview frame spacer thread (tid %d)",
                previewFrameSpacerTid);
    }
    return ret;
}

}; // namespace camera3

}; // namespace android
