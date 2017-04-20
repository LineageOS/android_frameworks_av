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
#include "binding/AAudioServiceInterface.h"
#include "client/IsochronousClockModel.h"
#include "client/AudioEndpoint.h"
#include "core/AudioStream.h"
#include "utility/LinearRamp.h"

using android::sp;
using android::IAAudioService;

namespace aaudio {

// A stream that talks to the AAudioService or directly to a HAL.
class AudioStreamInternal : public AudioStream {

public:
    AudioStreamInternal(AAudioServiceInterface  &serviceInterface, bool inService = false);
    virtual ~AudioStreamInternal();

    // =========== Begin ABSTRACT methods ===========================
    aaudio_result_t requestStart() override;

    aaudio_result_t requestPause() override;

    aaudio_result_t requestFlush() override;

    aaudio_result_t requestStop() override;

    // TODO use aaudio_clockid_t all the way down to AudioClock
    aaudio_result_t getTimestamp(clockid_t clockId,
                                       int64_t *framePosition,
                                       int64_t *timeNanoseconds) override;



    virtual aaudio_result_t updateStateWhileWaiting() override;

    // =========== End ABSTRACT methods ===========================

    aaudio_result_t open(const AudioStreamBuilder &builder) override;

    aaudio_result_t close() override;

    aaudio_result_t write(const void *buffer,
                             int32_t numFrames,
                             int64_t timeoutNanoseconds) override;

    aaudio_result_t setBufferSize(int32_t requestedFrames) override;

    int32_t getBufferSize() const override;

    int32_t getBufferCapacity() const override;

    int32_t getFramesPerBurst() const override;

    int64_t getFramesRead() override;

    int32_t getXRunCount() const override {
        return mXRunCount;
    }

    aaudio_result_t registerThread() override;

    aaudio_result_t unregisterThread() override;

    // Called internally from 'C'
    void *callbackLoop();

protected:

    aaudio_result_t processCommands();

    aaudio_result_t requestPauseInternal();
    aaudio_result_t requestStopInternal();

    aaudio_result_t stopCallback();

/**
 * Low level write that will not block. It will just write as much as it can.
 *
 * It passed back a recommended time to wake up if wakeTimePtr is not NULL.
 *
 * @return the number of frames written or a negative error code.
 */
    aaudio_result_t writeNow(const void *buffer,
                                     int32_t numFrames,
                                     int64_t currentTimeNanos,
                                     int64_t *wakeTimePtr);

    void onFlushFromServer();

    aaudio_result_t onEventFromServer(AAudioServiceMessage *message);

    aaudio_result_t onTimestampFromServer(AAudioServiceMessage *message);

    // Calculate timeout for an operation involving framesPerOperation.
    int64_t calculateReasonableTimeout(int32_t framesPerOperation);

private:
    /*
     * Asynchronous write with data conversion.
     * @param buffer
     * @param numFrames
     * @return fdrames written or negative error
     */
    aaudio_result_t writeNowWithConversion(const void *buffer,
                                     int32_t numFrames);
    void processTimestamp(uint64_t position, int64_t time);


    const char *getLocationName() const {
        return mInService ? "SERVICE" : "CLIENT";
    }

    // Adjust timing model based on timestamp from service.

    IsochronousClockModel    mClockModel;      // timing model for chasing the HAL
    AudioEndpoint            mAudioEndpoint;   // sink for writes
    aaudio_handle_t          mServiceStreamHandle; // opaque handle returned from service

    AudioEndpointParcelable  mEndPointParcelable; // description of the buffers filled by service
    EndpointDescriptor       mEndpointDescriptor; // buffer description with resolved addresses

    aaudio_audio_format_t    mDeviceFormat = AAUDIO_FORMAT_UNSPECIFIED;

    uint8_t                 *mCallbackBuffer = nullptr;
    int32_t                  mCallbackFrames = 0;

    // Offset from underlying frame position.
    int64_t                  mFramesOffsetFromService = 0; // offset for timestamps
    int64_t                  mLastFramesRead = 0; // used to prevent retrograde motion
    int32_t                  mFramesPerBurst;     // frames per HAL transfer
    int32_t                  mXRunCount = 0;      // how many underrun events?
    LinearRamp               mVolumeRamp;

    AAudioServiceInterface  &mServiceInterface;   // abstract interface to the service

    // The service uses this for SHARED mode.
    bool                     mInService = false;  // Are running in the client or the service?
};

} /* namespace aaudio */

#endif //AAUDIO_AUDIOSTREAMINTERNAL_H
