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

#ifndef OBOE_AUDIOSTREAMINTERNAL_H
#define OBOE_AUDIOSTREAMINTERNAL_H

#include <stdint.h>
#include <oboe/OboeAudio.h>

#include "binding/IOboeAudioService.h"
#include "binding/AudioEndpointParcelable.h"
#include "client/IsochronousClockModel.h"
#include "client/AudioEndpoint.h"
#include "core/AudioStream.h"

using android::sp;
using android::IOboeAudioService;

namespace oboe {

// A stream that talks to the OboeService or directly to a HAL.
class AudioStreamInternal : public AudioStream {

public:
    AudioStreamInternal();
    virtual ~AudioStreamInternal();

    // =========== Begin ABSTRACT methods ===========================
    virtual oboe_result_t requestStart() override;

    virtual oboe_result_t requestPause() override;

    virtual oboe_result_t requestFlush() override;

    virtual oboe_result_t requestStop() override;

    // TODO use oboe_clockid_t all the way down to AudioClock
    virtual oboe_result_t getTimestamp(clockid_t clockId,
                                       oboe_position_frames_t *framePosition,
                                       oboe_nanoseconds_t *timeNanoseconds) override;


    virtual oboe_result_t updateState() override;
    // =========== End ABSTRACT methods ===========================

    virtual oboe_result_t open(const AudioStreamBuilder &builder) override;

    virtual oboe_result_t close() override;

    virtual oboe_result_t write(const void *buffer,
                             int32_t numFrames,
                             oboe_nanoseconds_t timeoutNanoseconds) override;

    virtual oboe_result_t waitForStateChange(oboe_stream_state_t currentState,
                                          oboe_stream_state_t *nextState,
                                          oboe_nanoseconds_t timeoutNanoseconds) override;

    virtual oboe_result_t setBufferSize(oboe_size_frames_t requestedFrames,
                                        oboe_size_frames_t *actualFrames) override;

    virtual oboe_size_frames_t getBufferSize() const override;

    virtual oboe_size_frames_t getBufferCapacity() const override;

    virtual oboe_size_frames_t getFramesPerBurst() const override;

    virtual oboe_position_frames_t getFramesRead() override;

    virtual int32_t getXRunCount() const override {
        return mXRunCount;
    }

    virtual oboe_result_t registerThread() override;

    virtual oboe_result_t unregisterThread() override;

protected:

    oboe_result_t processCommands();

/**
 * Low level write that will not block. It will just write as much as it can.
 *
 * It passed back a recommended time to wake up if wakeTimePtr is not NULL.
 *
 * @return the number of frames written or a negative error code.
 */
    virtual oboe_result_t writeNow(const void *buffer,
                                int32_t numFrames,
                                oboe_nanoseconds_t currentTimeNanos,
                                oboe_nanoseconds_t *wakeTimePtr);

    void onFlushFromServer();

    oboe_result_t onEventFromServer(OboeServiceMessage *message);

    oboe_result_t onTimestampFromServer(OboeServiceMessage *message);

private:
    IsochronousClockModel    mClockModel;
    AudioEndpoint            mAudioEndpoint;
    oboe_handle_t            mServiceStreamHandle;
    EndpointDescriptor       mEndpointDescriptor;
    // Offset from underlying frame position.
    oboe_position_frames_t   mFramesOffsetFromService = 0;
    oboe_position_frames_t   mLastFramesRead = 0;
    oboe_size_frames_t       mFramesPerBurst;
    int32_t                  mXRunCount = 0;

    void processTimestamp(uint64_t position, oboe_nanoseconds_t time);
};

} /* namespace oboe */

#endif //OBOE_AUDIOSTREAMINTERNAL_H
