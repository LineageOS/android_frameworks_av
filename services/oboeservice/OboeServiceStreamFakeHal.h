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

#ifndef OBOE_OBOE_SERVICE_STREAM_FAKE_HAL_H
#define OBOE_OBOE_SERVICE_STREAM_FAKE_HAL_H

#include "OboeService.h"
#include "OboeServiceStreamBase.h"
#include "FakeAudioHal.h"
#include "MonotonicCounter.h"
#include "AudioEndpointParcelable.h"
#include "TimestampScheduler.h"

namespace oboe {

class OboeServiceStreamFakeHal
    : public OboeServiceStreamBase
    , public Runnable {

public:
    OboeServiceStreamFakeHal();
    virtual ~OboeServiceStreamFakeHal();

    virtual oboe_result_t getDescription(AudioEndpointParcelable &parcelable) override;

    virtual oboe_result_t open(oboe::OboeStreamRequest &request,
                               oboe::OboeStreamConfiguration &configuration) override;

    /**
     * Start the flow of data.
     */
    virtual oboe_result_t start() override;

    /**
     * Stop the flow of data such that start() can resume with loss of data.
     */
    virtual oboe_result_t pause() override;

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual oboe_result_t flush() override;

    virtual oboe_result_t close() override;

    void sendCurrentTimestamp();

    virtual void run() override; // to implement Runnable

private:
    fake_hal_stream_ptr    mStreamId; // Move to HAL

    MonotonicCounter       mFramesWritten;
    MonotonicCounter       mFramesRead;
    int                    mHalFileDescriptor = -1;
    int                    mPreviousFrameCounter = 0;   // from HAL

    oboe_stream_state_t    mState = OBOE_STREAM_STATE_UNINITIALIZED;

    OboeThread             mOboeThread;
    std::atomic<bool>      mThreadEnabled;
};

} // namespace oboe

#endif //OBOE_OBOE_SERVICE_STREAM_FAKE_HAL_H
