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

#ifndef ANDROID_SERVERS_CAMERA_CAMERA3_PREVIEWFRAMESPACER_H
#define ANDROID_SERVERS_CAMERA_CAMERA3_PREVIEWFRAMESPACER_H

#include <queue>

#include <gui/Surface.h>
#include <utils/Condition.h>
#include <utils/Mutex.h>
#include <utils/Thread.h>
#include <utils/Timers.h>

namespace android {

namespace camera3 {

class Camera3OutputStream;

/***
 * Preview stream spacer for better frame spacing
 *
 * The ideal viewfinder user experience is that frames are presented to the
 * user in the same cadence as outputed by the camera sensor. However, the
 * processing latency between frames could vary, due to factors such
 * as CPU load, differences in request settings, etc. This frame processing
 * latency results in variation in presentation of frames to the user.
 *
 * The PreviewFrameSpacer improves the viewfinder user experience by:
 * - Cache the frame buffers if the intervals between queueBuffer is shorter
 *   than the camera capture intervals.
 * - Queue frame buffers in the same cadence as the camera capture time.
 * - Maintain at most 1 queue-able buffer. If the 2nd preview buffer becomes
 *   available, queue the oldest cached buffer to the buffer queue.
 */
class PreviewFrameSpacer : public Thread {
  public:
    explicit PreviewFrameSpacer(Camera3OutputStream& parent, sp<Surface> consumer);
    virtual ~PreviewFrameSpacer();

    // Queue preview buffer locally
    status_t queuePreviewBuffer(nsecs_t timestamp, int32_t transform,
            ANativeWindowBuffer* anwBuffer, int releaseFence);

    bool threadLoop() override;
    void requestExit() override;

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

    void queueBufferToClientLocked(const BufferHolder& bufferHolder, nsecs_t currentTime);


    Camera3OutputStream& mParent;
    sp<ANativeWindow> mConsumer;
    mutable Mutex mLock;
    Condition mBufferCond;

    std::queue<BufferHolder> mPendingBuffers;
    nsecs_t mLastCameraCaptureTime = 0;
    nsecs_t mLastCameraPresentTime = 0;
    static constexpr nsecs_t kWaitDuration = 5000000LL; // 50ms
    static constexpr nsecs_t kFrameIntervalThreshold = 80000000LL; // 80ms
    static constexpr nsecs_t kMaxFrameWaitTime = 33333333LL; // 33ms
};

}; //namespace camera3
}; //namespace android

#endif
