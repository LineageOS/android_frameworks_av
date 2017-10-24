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

#include <assert.h>
#include <mutex>

#include <utils/RefBase.h>

#include "fifo/FifoBuffer.h"
#include "binding/IAAudioService.h"
#include "binding/AudioEndpointParcelable.h"
#include "binding/AAudioServiceMessage.h"
#include "utility/AAudioUtilities.h"
#include <media/AudioClient.h>

#include "SharedRingBuffer.h"
#include "AAudioThread.h"

namespace aaudio {

// We expect the queue to only have a few commands.
// This should be way more than we need.
#define QUEUE_UP_CAPACITY_COMMANDS (128)

/**
 * Base class for a stream in the AAudio service.
 */
class AAudioServiceStreamBase
    : public virtual android::RefBase
    , public Runnable  {

public:
    AAudioServiceStreamBase();
    virtual ~AAudioServiceStreamBase();

    enum {
        ILLEGAL_THREAD_ID = 0
    };

    std::string dump() const;

    // -------------------------------------------------------------------
    /**
     * Open the device.
     */
    virtual aaudio_result_t open(const aaudio::AAudioStreamRequest &request,
                                 aaudio::AAudioStreamConfiguration &configurationOutput) = 0;

    virtual aaudio_result_t close();

    /**
     * Start the flow of data.
     */
    virtual aaudio_result_t start();

    /**
     * Stop the flow of data such that start() can resume with loss of data.
     */
    virtual aaudio_result_t pause();

    /**
     * Stop the flow of data after data in buffer has played.
     */
    virtual aaudio_result_t stop();

    aaudio_result_t stopTimestampThread();

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual aaudio_result_t flush();

    virtual aaudio_result_t startClient(const android::AudioClient& client __unused,
                                        audio_port_handle_t *clientHandle __unused) {
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    virtual aaudio_result_t stopClient(audio_port_handle_t clientHandle __unused) {
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    bool isRunning() const {
        return mState == AAUDIO_STREAM_STATE_STARTED;
    }

    // -------------------------------------------------------------------

    /**
     * Send a message to the client.
     */
    aaudio_result_t sendServiceEvent(aaudio_service_event_t event,
                                     double  dataDouble = 0.0,
                                     int64_t dataLong = 0);

    /**
     * Fill in a parcelable description of stream.
     */
    aaudio_result_t getDescription(AudioEndpointParcelable &parcelable);


    void setRegisteredThread(pid_t pid) {
        mRegisteredClientThread = pid;
    }

    pid_t getRegisteredThread() const {
        return mRegisteredClientThread;
    }

    int32_t getFramesPerBurst() const {
        return mFramesPerBurst;
    }

    int32_t calculateBytesPerFrame() const {
        return mSamplesPerFrame * AAudioConvert_formatToSizeInBytes(mAudioFormat);
    }

    void run() override; // to implement Runnable

    void disconnect();

    uid_t getOwnerUserId() const {
        return mMmapClient.clientUid;
    }

    pid_t getOwnerProcessId() const {
        return mMmapClient.clientPid;
    }

    aaudio_handle_t getHandle() const {
        return mHandle;
    }
    void setHandle(aaudio_handle_t handle) {
        mHandle = handle;
    }

    aaudio_stream_state_t getState() const {
        return mState;
    }

protected:

    void setState(aaudio_stream_state_t state) {
        mState = state;
    }

    aaudio_result_t writeUpMessageQueue(AAudioServiceMessage *command);

    aaudio_result_t sendCurrentTimestamp();

    /**
     * @param positionFrames
     * @param timeNanos
     * @return AAUDIO_OK or AAUDIO_ERROR_UNAVAILABLE or other negative error
     */
    virtual aaudio_result_t getFreeRunningPosition(int64_t *positionFrames, int64_t *timeNanos) = 0;

    virtual aaudio_result_t getDownDataDescription(AudioEndpointParcelable &parcelable) = 0;

    aaudio_stream_state_t   mState = AAUDIO_STREAM_STATE_UNINITIALIZED;

    pid_t                   mRegisteredClientThread = ILLEGAL_THREAD_ID;

    SharedRingBuffer*       mUpMessageQueue;
    std::mutex              mLockUpMessageQueue;

    AAudioThread            mAAudioThread;
    // This is used by one thread to tell another thread to exit. So it must be atomic.
    std::atomic<bool>       mThreadEnabled;

    aaudio_format_t         mAudioFormat = AAUDIO_FORMAT_UNSPECIFIED;
    int32_t                 mFramesPerBurst = 0;
    int32_t                 mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    int32_t                 mSampleRate = AAUDIO_UNSPECIFIED;
    int32_t                 mCapacityInFrames = AAUDIO_UNSPECIFIED;
    android::AudioClient    mMmapClient;
    audio_port_handle_t     mClientHandle = AUDIO_PORT_HANDLE_NONE;

private:
    aaudio_handle_t         mHandle = -1;
};

} /* namespace aaudio */

#endif //AAUDIO_AAUDIO_SERVICE_STREAM_BASE_H
