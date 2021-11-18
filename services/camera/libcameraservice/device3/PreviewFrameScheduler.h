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

#ifndef ANDROID_SERVERS_CAMERA_CAMERA3_PREVIEWFRAMESCHEDULER_H
#define ANDROID_SERVERS_CAMERA_CAMERA3_PREVIEWFRAMESCHEDULER_H

#include <queue>

#include <android/choreographer.h>
#include <gui/Surface.h>
#include <gui/ISurfaceComposer.h>
#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/Looper.h>
#include <utils/Thread.h>
#include <utils/Timers.h>

namespace android {

namespace camera3 {

class Camera3OutputStream;
struct ChoreographerThread;

/***
 * Preview stream scheduler for better preview display synchronization
 *
 * The ideal viewfinder user experience is that frames are presented to the
 * user in the same cadence as outputed by the camera sensor. However, the
 * processing latency between frames could vary, due to factors such
 * as CPU load, differences in request settings, etc. This frame processing
 * latency results in variation in presentation of frames to the user.
 *
 * The PreviewFrameScheduler improves the viewfinder user experience by:
 * 1. Cache preview buffers in the scheduler
 * 2. For each choreographer callback, queue the oldest cached buffer with
 *    the best matching presentation timestamp. Frame N's presentation timestamp
 *    is the choreographer timeline timestamp closest to (Frame N-1's
 *    presentation time + camera capture interval between frame N-1 and frame N).
 * 3. Maintain at most 2 queue-able buffers. If the 3rd preview buffer becomes
 *    available, queue the oldest cached buffer to the buffer queue.
 */
class PreviewFrameScheduler {
  public:
    explicit PreviewFrameScheduler(Camera3OutputStream& parent, sp<Surface> consumer);
    virtual ~PreviewFrameScheduler();

    // Queue preview buffer locally
    status_t queuePreviewBuffer(nsecs_t timestamp, int32_t transform,
            ANativeWindowBuffer* anwBuffer, int releaseFence);

    // Callback function with a new presentation timeline from choreographer. This
    // will trigger a locally queued buffer be sent to the buffer queue.
    void onNewPresentationTime(const std::vector<nsecs_t>& presentationTimeline);

    // Maintain at most 2 queue-able buffers
    static constexpr int32_t kQueueDepthWatermark = 2;

  private:
    // structure holding cached preview buffer info
    struct BufferHolder {
        nsecs_t timestamp;
        int32_t transform;
        sp<ANativeWindowBuffer> anwBuffer;
        int releaseFence;

        BufferHolder(nsecs_t t, int32_t tr, ANativeWindowBuffer* anwb, int rf) :
                timestamp(t), transform(tr), anwBuffer(anwb), releaseFence(rf) {}
    };

    status_t queueBufferToClientLocked(const BufferHolder& bufferHolder,
            nsecs_t presentTime);

    static constexpr char kPendingBufferTraceName[] = "pending_preview_buffers";

    // Camera capture interval for resetting frame spacing between preview sessions
    static constexpr nsecs_t kSpacingResetIntervalNs = 1000000000L; // 1 second

    Camera3OutputStream& mParent;
    sp<ANativeWindow> mConsumer;
    mutable Mutex mLock;

    std::queue<BufferHolder> mPendingBuffers;
    nsecs_t mLastCameraCaptureTime = 0;
    nsecs_t mLastCameraPresentTime = 0;

    // Choreographer related
    sp<Looper> mLooper;
    sp<ChoreographerThread> mChoreographerThread;
};

}; //namespace camera3
}; //namespace android

#endif
