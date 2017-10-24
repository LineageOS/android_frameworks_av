/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef AAUDIO_AAUDIO_SERVICE_STREAM_SHARED_H
#define AAUDIO_AAUDIO_SERVICE_STREAM_SHARED_H

#include "fifo/FifoBuffer.h"
#include "binding/AAudioServiceMessage.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioStreamConfiguration.h"

#include "AAudioService.h"
#include "AAudioServiceStreamBase.h"

namespace aaudio {

// We expect the queue to only have a few commands.
// This should be way more than we need.
#define QUEUE_UP_CAPACITY_COMMANDS (128)

class AAudioEndpointManager;
class AAudioServiceEndpoint;
class SharedRingBuffer;

/**
 * One of these is created for every MODE_SHARED stream in the AAudioService.
 *
 * Each Shared stream will register itself with an AAudioServiceEndpoint when it is opened.
 */
class AAudioServiceStreamShared : public AAudioServiceStreamBase {

public:
    AAudioServiceStreamShared(android::AAudioService &aAudioService);
    virtual ~AAudioServiceStreamShared() = default;

    aaudio_result_t open(const aaudio::AAudioStreamRequest &request,
                         aaudio::AAudioStreamConfiguration &configurationOutput) override;

    /**
     * Start the flow of audio data.
     *
     * This is not guaranteed to be synchronous but it currently is.
     * An AAUDIO_SERVICE_EVENT_STARTED will be sent to the client when complete.
     */
    aaudio_result_t start() override;

    /**
     * Stop the flow of data so that start() can resume without loss of data.
     *
     * This is not guaranteed to be synchronous but it currently is.
     * An AAUDIO_SERVICE_EVENT_PAUSED will be sent to the client when complete.
    */
    aaudio_result_t pause() override;

    /**
     * Stop the flow of data after data in buffer has played.
     */
    aaudio_result_t stop() override;

    /**
     *  Discard any data held by the underlying HAL or Service.
     *
     * This is not guaranteed to be synchronous but it currently is.
     * An AAUDIO_SERVICE_EVENT_FLUSHED will be sent to the client when complete.
     */
    aaudio_result_t flush() override;

    aaudio_result_t close() override;

    android::FifoBuffer *getDataFifoBuffer() { return mAudioDataQueue->getFifoBuffer(); }

    /* Keep a record of when a buffer transfer completed.
     * This allows for a more accurate timing model.
     */
    void markTransferTime(int64_t nanoseconds);

protected:

    aaudio_result_t getDownDataDescription(AudioEndpointParcelable &parcelable) override;

    aaudio_result_t getFreeRunningPosition(int64_t *positionFrames, int64_t *timeNanos) override;

    /**
     * @param requestedCapacityFrames
     * @param framesPerBurst
     * @return capacity or negative error
     */
    static int32_t calculateBufferCapacity(int32_t requestedCapacityFrames,
                                            int32_t framesPerBurst);

private:
    android::AAudioService  &mAudioService;
    AAudioServiceEndpoint   *mServiceEndpoint = nullptr;
    SharedRingBuffer        *mAudioDataQueue = nullptr;

    int64_t                  mMarkedPosition = 0;
    int64_t                  mMarkedTime = 0;
};

} /* namespace aaudio */

#endif //AAUDIO_AAUDIO_SERVICE_STREAM_SHARED_H
