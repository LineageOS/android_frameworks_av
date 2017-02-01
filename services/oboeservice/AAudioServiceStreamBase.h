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

#ifndef AAUDIO_AAUDIO_SERVICE_STREAM_BASE_H
#define AAUDIO_AAUDIO_SERVICE_STREAM_BASE_H

#include <utils/Mutex.h>

#include "IAAudioService.h"
#include "AAudioServiceDefinitions.h"
#include "fifo/FifoBuffer.h"
#include "SharedRingBuffer.h"
#include "AudioEndpointParcelable.h"
#include "AAudioThread.h"

namespace aaudio {

// We expect the queue to only have a few commands.
// This should be way more than we need.
#define QUEUE_UP_CAPACITY_COMMANDS (128)

class AAudioServiceStreamBase {

public:
    AAudioServiceStreamBase();
    virtual ~AAudioServiceStreamBase();

    enum {
        ILLEGAL_THREAD_ID = 0
    };

    /**
     * Fill in a parcelable description of stream.
     */
    virtual aaudio_result_t getDescription(aaudio::AudioEndpointParcelable &parcelable) = 0;

    /**
     * Open the device.
     */
    virtual aaudio_result_t open(aaudio::AAudioStreamRequest &request,
                               aaudio::AAudioStreamConfiguration &configuration) = 0;

    /**
     * Start the flow of data.
     */
    virtual aaudio_result_t start() = 0;

    /**
     * Stop the flow of data such that start() can resume with loss of data.
     */
    virtual aaudio_result_t pause() = 0;

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual aaudio_result_t flush() = 0;

    virtual aaudio_result_t close() = 0;

    virtual void sendCurrentTimestamp() = 0;

    aaudio_size_frames_t getFramesPerBurst() {
        return mFramesPerBurst;
    }

    virtual void sendServiceEvent(aaudio_service_event_t event,
                                  int32_t data1 = 0,
                                  int64_t data2 = 0);

    virtual void setRegisteredThread(pid_t pid) {
        mRegisteredClientThread = pid;
    }

    virtual pid_t getRegisteredThread() {
        return mRegisteredClientThread;
    }

protected:

    pid_t                    mRegisteredClientThread = ILLEGAL_THREAD_ID;

    SharedRingBuffer *       mUpMessageQueue;

    aaudio_sample_rate_t       mSampleRate = 0;
    aaudio_size_bytes_t        mBytesPerFrame = 0;
    aaudio_size_frames_t       mFramesPerBurst = 0;
    aaudio_size_frames_t       mCapacityInFrames = 0;
    aaudio_size_bytes_t        mCapacityInBytes = 0;

    android::Mutex           mLockUpMessageQueue;
};

} /* namespace aaudio */

#endif //AAUDIO_AAUDIO_SERVICE_STREAM_BASE_H
