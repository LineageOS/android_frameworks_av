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

#ifndef AAUDIO_AUDIOSTREAMINTERNAL_H
#define AAUDIO_AUDIOSTREAMINTERNAL_H

#include <stdint.h>
#include <aaudio/AAudio.h>

#include "binding/IAAudioService.h"
#include "binding/AudioEndpointParcelable.h"
#include "client/IsochronousClockModel.h"
#include "client/AudioEndpoint.h"
#include "core/AudioStream.h"

using android::sp;
using android::IAAudioService;

namespace aaudio {

// A stream that talks to the AAudioService or directly to a HAL.
class AudioStreamInternal : public AudioStream {

public:
    AudioStreamInternal();
    virtual ~AudioStreamInternal();

    // =========== Begin ABSTRACT methods ===========================
    virtual aaudio_result_t requestStart() override;

    virtual aaudio_result_t requestPause() override;

    virtual aaudio_result_t requestFlush() override;

    virtual aaudio_result_t requestStop() override;

    // TODO use aaudio_clockid_t all the way down to AudioClock
    virtual aaudio_result_t getTimestamp(clockid_t clockId,
                                       int64_t *framePosition,
                                       int64_t *timeNanoseconds) override;


    virtual aaudio_result_t updateStateWhileWaiting() override;
    // =========== End ABSTRACT methods ===========================

    virtual aaudio_result_t open(const AudioStreamBuilder &builder) override;

    virtual aaudio_result_t close() override;

    virtual aaudio_result_t write(const void *buffer,
                             int32_t numFrames,
                             int64_t timeoutNanoseconds) override;

    virtual aaudio_result_t setBufferSize(int32_t requestedFrames) override;

    virtual int32_t getBufferSize() const override;

    virtual int32_t getBufferCapacity() const override;

    virtual int32_t getFramesPerBurst() const override;

    virtual int64_t getFramesRead() override;

    virtual int32_t getXRunCount() const override {
        return mXRunCount;
    }

    virtual aaudio_result_t registerThread() override;

    virtual aaudio_result_t unregisterThread() override;

    // Called internally from 'C'
    void *callbackLoop();

protected:

    aaudio_result_t processCommands();

    aaudio_result_t requestPauseInternal();

    aaudio_result_t stopCallback();

/**
 * Low level write that will not block. It will just write as much as it can.
 *
 * It passed back a recommended time to wake up if wakeTimePtr is not NULL.
 *
 * @return the number of frames written or a negative error code.
 */
    virtual aaudio_result_t writeNow(const void *buffer,
                                int32_t numFrames,
                                int64_t currentTimeNanos,
                                int64_t *wakeTimePtr);

    void onFlushFromServer();

    aaudio_result_t onEventFromServer(AAudioServiceMessage *message);

    aaudio_result_t onTimestampFromServer(AAudioServiceMessage *message);

    // Calculate timeout for an operation involving framesPerOperation.
    int64_t calculateReasonableTimeout(int32_t framesPerOperation);

private:
    IsochronousClockModel    mClockModel;
    AudioEndpoint            mAudioEndpoint;
    aaudio_handle_t          mServiceStreamHandle;
    EndpointDescriptor       mEndpointDescriptor;
    uint8_t                 *mCallbackBuffer = nullptr;
    int32_t                  mCallbackFrames = 0;

    // Offset from underlying frame position.
    int64_t                  mFramesOffsetFromService = 0;
    int64_t                  mLastFramesRead = 0;
    int32_t                  mFramesPerBurst;
    int32_t                  mXRunCount = 0;
    void processTimestamp(uint64_t position, int64_t time);
};

} /* namespace aaudio */

#endif //AAUDIO_AUDIOSTREAMINTERNAL_H
