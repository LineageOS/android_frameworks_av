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

#ifndef AAUDIO_AUDIO_ENDPOINT_H
#define AAUDIO_AUDIO_ENDPOINT_H

#include <aaudio/AAudio.h>

#include "AAudioServiceMessage.h"
#include "AudioEndpointParcelable.h"
#include "fifo/FifoBuffer.h"

namespace aaudio {

#define ENDPOINT_DATA_QUEUE_SIZE_MIN   64

/**
 * A sink for audio.
 * Used by the client code.
 */
class AudioEndpoint {

public:
    AudioEndpoint();
    virtual ~AudioEndpoint();

    /**
     * Configure based on the EndPointDescriptor_t.
     */
    aaudio_result_t configure(const EndpointDescriptor *pEndpointDescriptor);

    /**
     * Read from a command passed up from the Server.
     * @return 1 if command received, 0 for no command, or negative error.
     */
    aaudio_result_t readUpCommand(AAudioServiceMessage *commandPtr);

    /**
     * Non-blocking write.
     * @return framesWritten or a negative error code.
     */
    aaudio_result_t writeDataNow(const void *buffer, int32_t numFrames);

    /**
     * Set the read index in the downData queue.
     * This is needed if the reader is not updating the index itself.
     */
    void setDownDataReadCounter(fifo_counter_t framesRead);
    fifo_counter_t getDownDataReadCounter();

    void setDownDataWriteCounter(fifo_counter_t framesWritten);
    fifo_counter_t getDownDataWriteCounter();

    /**
     * The result is not valid until after configure() is called.
     *
     * @return true if the output buffer read position is not updated, eg. DMA
     */
    bool isOutputFreeRunning() const { return mOutputFreeRunning; }

    int32_t setBufferSizeInFrames(aaudio_size_frames_t requestedFrames,
                                  aaudio_size_frames_t *actualFrames);
    aaudio_size_frames_t getBufferSizeInFrames() const;

    aaudio_size_frames_t getBufferCapacityInFrames() const;

    aaudio_size_frames_t getFullFramesAvailable();

private:
    FifoBuffer   * mUpCommandQueue;
    FifoBuffer   * mDownDataQueue;
    bool           mOutputFreeRunning;
    fifo_counter_t mDataReadCounter; // only used if free-running
    fifo_counter_t mDataWriteCounter; // only used if free-running
};

} // namespace aaudio

#endif //AAUDIO_AUDIO_ENDPOINT_H
