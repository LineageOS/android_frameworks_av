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

#ifndef AAUDIO_SERVICE_ENDPOINT_H
#define AAUDIO_SERVICE_ENDPOINT_H

#include <atomic>
#include <functional>
#include <mutex>
#include <vector>

#include "client/AudioStreamInternal.h"
#include "client/AudioStreamInternalPlay.h"
#include "core/AAudioStreamParameters.h"
#include "binding/AAudioServiceMessage.h"
#include "binding/AAudioStreamConfiguration.h"

#include "AAudioServiceStreamBase.h"

namespace aaudio {

/**
 * AAudioServiceEndpoint is used by a subclass of AAudioServiceStreamBase
 * to communicate with the underlying audio device or port.
 */
class AAudioServiceEndpoint
        : public virtual android::RefBase
        , public AAudioStreamParameters {
public:

    virtual ~AAudioServiceEndpoint() = default;

    virtual std::string dump() const;

    virtual aaudio_result_t open(const aaudio::AAudioStreamRequest &request) = 0;

    /*
     * Perform any cleanup necessary before deleting the stream.
     * This might include releasing and closing internal streams.
     */
    virtual void close() = 0;

    aaudio_result_t registerStream(android::sp<AAudioServiceStreamBase> stream);

    aaudio_result_t unregisterStream(android::sp<AAudioServiceStreamBase> stream);

    virtual aaudio_result_t startStream(android::sp<AAudioServiceStreamBase> stream,
                                        audio_port_handle_t *clientHandle) = 0;

    virtual aaudio_result_t stopStream(android::sp<AAudioServiceStreamBase> stream,
                                       audio_port_handle_t clientHandle) = 0;

    virtual aaudio_result_t startClient(const android::AudioClient& client,
                                        const audio_attributes_t *attr,
                                        audio_port_handle_t *clientHandle) {
        ALOGD("AAudioServiceEndpoint::startClient(...) AAUDIO_ERROR_UNAVAILABLE");
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    virtual aaudio_result_t stopClient(audio_port_handle_t clientHandle) {
        ALOGD("AAudioServiceEndpoint::stopClient(...) AAUDIO_ERROR_UNAVAILABLE");
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    /**
     * @param positionFrames
     * @param timeNanos
     * @return AAUDIO_OK or AAUDIO_ERROR_UNAVAILABLE or other negative error
     */
    virtual aaudio_result_t getFreeRunningPosition(int64_t *positionFrames, int64_t *timeNanos) = 0;

    /**
     * Set time that the associated frame was presented to the hardware.
     *
     * @param positionFrames receive position, input value is ignored
     * @param timeNanos receive time, input value is ignored
     * @return AAUDIO_OK or AAUDIO_ERROR_UNAVAILABLE or other negative error
     */
    virtual aaudio_result_t getTimestamp(int64_t *positionFrames, int64_t *timeNanos) = 0;

    int32_t getFramesPerBurst() const {
        return mFramesPerBurst;
    }

    int32_t getRequestedDeviceId() const { return mRequestedDeviceId; }

    bool matches(const AAudioStreamConfiguration& configuration);

    // This should only be called from the AAudioEndpointManager under a mutex.
    int32_t getOpenCount() const {
        return mOpenCount;
    }

    // This should only be called from the AAudioEndpointManager under a mutex.
    void setOpenCount(int32_t count) {
        mOpenCount = count;
    }

    bool isConnected() const {
        return mConnected;
    }

    static audio_attributes_t getAudioAttributesFrom(const AAudioStreamParameters *params);

    // Stop, disconnect and release any streams registered on this endpoint.
    void releaseRegisteredStreams();

    bool isForSharing() const {
        return mForSharing;
    }

    /**
     *
     * @param flag true if this endpoint is to be shared between multiple streams
     */
    void setForSharing(bool flag) {
        mForSharing = flag;
    }

protected:

    /**
     * @param portHandle
     * @return return true if a stream with the given portHandle is registered
     */
    bool                     isStreamRegistered(audio_port_handle_t portHandle);

    std::vector<android::sp<AAudioServiceStreamBase>> disconnectRegisteredStreams();

    mutable std::mutex       mLockStreams;
    std::vector<android::sp<AAudioServiceStreamBase>> mRegisteredStreams;

    SimpleDoubleBuffer<Timestamp>  mAtomicEndpointTimestamp;

    android::AudioClient     mMmapClient;   // set in open, used in open and startStream

    int32_t                  mFramesPerBurst = 0;
    int32_t                  mOpenCount = 0;
    int32_t                  mRequestedDeviceId = 0;

    // True if this will be shared by one or more other streams.
    bool                     mForSharing = false;

    std::atomic<bool>        mConnected{true};

};

} /* namespace aaudio */


#endif //AAUDIO_SERVICE_ENDPOINT_H
