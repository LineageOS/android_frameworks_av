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

#ifndef AAUDIO_AAUDIO_SERVICE_STREAM_FAKE_HAL_H
#define AAUDIO_AAUDIO_SERVICE_STREAM_FAKE_HAL_H

#include "AAudioServiceDefinitions.h"
#include "AAudioServiceStreamBase.h"
#include "FakeAudioHal.h"
#include "MonotonicCounter.h"
#include "AudioEndpointParcelable.h"
#include "TimestampScheduler.h"

namespace aaudio {

class AAudioServiceStreamFakeHal
    : public AAudioServiceStreamBase
    , public Runnable {

public:
    AAudioServiceStreamFakeHal();
    virtual ~AAudioServiceStreamFakeHal();

    virtual aaudio_result_t getDescription(AudioEndpointParcelable &parcelable) override;

    virtual aaudio_result_t open(aaudio::AAudioStreamRequest &request,
                                 aaudio::AAudioStreamConfiguration &configurationOutput) override;

    /**
     * Start the flow of data.
     */
    virtual aaudio_result_t start() override;

    /**
     * Stop the flow of data such that start() can resume with loss of data.
     */
    virtual aaudio_result_t pause() override;

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual aaudio_result_t flush() override;

    virtual aaudio_result_t close() override;

    void sendCurrentTimestamp();

    virtual void run() override; // to implement Runnable

private:
    fake_hal_stream_ptr    mStreamId; // Move to HAL

    MonotonicCounter       mFramesWritten;
    MonotonicCounter       mFramesRead;
    int                    mHalFileDescriptor = -1;
    int                    mPreviousFrameCounter = 0;   // from HAL

    aaudio_stream_state_t    mState = AAUDIO_STREAM_STATE_UNINITIALIZED;

    AAudioThread             mAAudioThread;
    std::atomic<bool>      mThreadEnabled;
};

} // namespace aaudio

#endif //AAUDIO_AAUDIO_SERVICE_STREAM_FAKE_HAL_H
