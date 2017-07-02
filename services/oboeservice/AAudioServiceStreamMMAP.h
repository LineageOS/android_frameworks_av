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

#ifndef AAUDIO_AAUDIO_SERVICE_STREAM_MMAP_H
#define AAUDIO_AAUDIO_SERVICE_STREAM_MMAP_H

#include <atomic>

#include <media/audiohal/StreamHalInterface.h>
#include <media/MmapStreamCallback.h>
#include <media/MmapStreamInterface.h>
#include <utils/RefBase.h>
#include <utils/String16.h>
#include <utils/Vector.h>

#include "binding/AAudioServiceMessage.h"
#include "AAudioServiceStreamBase.h"
#include "binding/AudioEndpointParcelable.h"
#include "SharedMemoryProxy.h"
#include "TimestampScheduler.h"
#include "utility/MonotonicCounter.h"

namespace aaudio {

    /**
     * Manage one memory mapped buffer that originated from a HAL.
     */
class AAudioServiceStreamMMAP
    : public AAudioServiceStreamBase
    , public android::MmapStreamCallback {

public:
    AAudioServiceStreamMMAP(const android::AudioClient& serviceClient, bool inService);
    virtual ~AAudioServiceStreamMMAP() = default;

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

    aaudio_result_t stop() override;

    /**
     *  Discard any data held by the underlying HAL or Service.
     *
     * This is not guaranteed to be synchronous but it currently is.
     * An AAUDIO_SERVICE_EVENT_FLUSHED will be sent to the client when complete.
     */
    aaudio_result_t flush() override;

    aaudio_result_t close() override;

    virtual aaudio_result_t startClient(const android::AudioClient& client,
                                        audio_port_handle_t *clientHandle);

    virtual aaudio_result_t stopClient(audio_port_handle_t clientHandle);

    /**
     * Send a MMAP/NOIRQ buffer timestamp to the client.
     */
    aaudio_result_t sendCurrentTimestamp();

    // -------------- Callback functions ---------------------
    void onTearDown() override;

    void onVolumeChanged(audio_channel_mask_t channels,
                         android::Vector<float> values) override;

    void onRoutingChanged(audio_port_handle_t deviceId) override;

protected:

    aaudio_result_t getDownDataDescription(AudioEndpointParcelable &parcelable) override;

    aaudio_result_t getFreeRunningPosition(int64_t *positionFrames, int64_t *timeNanos) override;

private:
    // This proxy class was needed to prevent a crash in AudioFlinger
    // when the stream was closed.
    class MyMmapStreamCallback : public android::MmapStreamCallback {
    public:
        explicit MyMmapStreamCallback(android::MmapStreamCallback &serviceCallback)
            : mServiceCallback(serviceCallback){}
        virtual ~MyMmapStreamCallback() = default;

        void onTearDown() override {
            mServiceCallback.onTearDown();
        };

        void onVolumeChanged(audio_channel_mask_t channels, android::Vector<float> values) override
        {
            mServiceCallback.onVolumeChanged(channels, values);
        };

        void onRoutingChanged(audio_port_handle_t deviceId) override {
            mServiceCallback.onRoutingChanged(deviceId);
        };

    private:
        android::MmapStreamCallback &mServiceCallback;
    };

    android::sp<MyMmapStreamCallback>   mMmapStreamCallback;
    MonotonicCounter                    mFramesWritten;
    MonotonicCounter                    mFramesRead;
    int32_t                             mPreviousFrameCounter = 0;   // from HAL
    int                                 mAudioDataFileDescriptor = -1;

    // Interface to the AudioFlinger MMAP support.
    android::sp<android::MmapStreamInterface> mMmapStream;
    struct audio_mmap_buffer_info             mMmapBufferinfo;
    audio_port_handle_t                       mPortHandle = AUDIO_PORT_HANDLE_NONE;
    audio_port_handle_t                       mDeviceId = AUDIO_PORT_HANDLE_NONE;
    android::AudioClient                      mServiceClient;
    bool                                      mInService = false;
};

} // namespace aaudio

#endif //AAUDIO_AAUDIO_SERVICE_STREAM_MMAP_H
