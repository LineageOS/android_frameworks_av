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

#ifndef OBOE_OBOE_SERVICE_STREAM_BASE_H
#define OBOE_OBOE_SERVICE_STREAM_BASE_H

#include "IOboeAudioService.h"
#include "OboeService.h"
#include "AudioStream.h"
#include "fifo/FifoBuffer.h"
#include "SharedRingBuffer.h"
#include "AudioEndpointParcelable.h"

namespace oboe {

// We expect the queue to only have a few commands.
// This should be way more than we need.
#define QUEUE_UP_CAPACITY_COMMANDS (128)

class OboeServiceStreamBase  {

public:
    OboeServiceStreamBase();
    virtual ~OboeServiceStreamBase();

    enum {
        ILLEGAL_THREAD_ID = 0
    };

    /**
     * Fill in a parcelable description of stream.
     */
    virtual oboe_result_t getDescription(oboe::AudioEndpointParcelable &parcelable) = 0;

    /**
     * Open the device.
     */
    virtual oboe_result_t open(oboe::OboeStreamRequest &request,
                               oboe::OboeStreamConfiguration &configuration) = 0;

    /**
     * Start the flow of data.
     */
    virtual oboe_result_t start() = 0;

    /**
     * Stop the flow of data such that start() can resume with loss of data.
     */
    virtual oboe_result_t pause() = 0;

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual oboe_result_t flush() = 0;

    virtual oboe_result_t close() = 0;

    virtual void tickle() = 0;

    virtual void sendServiceEvent(oboe_service_event_t event,
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

    oboe_sample_rate_t       mSampleRate = 0;
    oboe_size_bytes_t        mBytesPerFrame = 0;
    oboe_size_frames_t       mFramesPerBurst = 0;
    oboe_size_frames_t       mCapacityInFrames = 0;
    oboe_size_bytes_t        mCapacityInBytes = 0;
};

} /* namespace oboe */

#endif //OBOE_OBOE_SERVICE_STREAM_BASE_H
