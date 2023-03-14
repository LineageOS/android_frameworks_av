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

#ifndef ANDROID_AAUDIO_BINDING_AAUDIO_SERVICE_INTERFACE_H
#define ANDROID_AAUDIO_BINDING_AAUDIO_SERVICE_INTERFACE_H

#include <utils/StrongPointer.h>
#include <media/AudioClient.h>

#include "aaudio/IAAudioClient.h"
#include "binding/AAudioServiceDefinitions.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioStreamConfiguration.h"
#include "binding/AudioEndpointParcelable.h"

/**
 * This has the same methods as IAAudioService but without the Binder features.
 *
 * It allows us to abstract the Binder interface and use an AudioStreamInternal
 * both in the client and in the service.
 */
namespace aaudio {

class AAudioServiceInterface {
public:

    AAudioServiceInterface() = default;
    virtual ~AAudioServiceInterface() = default;

    virtual void registerClient(const android::sp<IAAudioClient>& client) = 0;

    /**
     * @param request info needed to create the stream
     * @param configuration contains information about the created stream
     * @return an object for aaudio handle information, which includes the connected
     *         aaudio service lifetime id to recognize the connected aaudio service
     *         and aaudio handle to recognize the stream. If an error occurs, the
     *         aaudio handle will be set as the negative error.
     */
    virtual AAudioHandleInfo openStream(const AAudioStreamRequest &request,
                                        AAudioStreamConfiguration &configuration) = 0;

    virtual aaudio_result_t closeStream(const AAudioHandleInfo& streamHandleInfo) = 0;

    /* Get an immutable description of the in-memory queues
    * used to communicate with the underlying HAL or Service.
    */
    virtual aaudio_result_t getStreamDescription(const AAudioHandleInfo& streamHandleInfo,
                                                 AudioEndpointParcelable &parcelable) = 0;

    /**
     * Start the flow of data.
     */
    virtual aaudio_result_t startStream(const AAudioHandleInfo& streamHandleInfo) = 0;

    /**
     * Stop the flow of data such that start() can resume without loss of data.
     */
    virtual aaudio_result_t pauseStream(const AAudioHandleInfo& streamHandleInfo) = 0;

    /**
     * Stop the flow of data after data currently in the buffer has played.
     */
    virtual aaudio_result_t stopStream(const AAudioHandleInfo& streamHandleInfo) = 0;

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual aaudio_result_t flushStream(const AAudioHandleInfo& streamHandleInfo) = 0;

    /**
     * Manage the specified thread as a low latency audio thread.
     */
    virtual aaudio_result_t registerAudioThread(const AAudioHandleInfo& streamHandleInfo,
                                                pid_t clientThreadId,
                                                int64_t periodNanoseconds) = 0;

    virtual aaudio_result_t unregisterAudioThread(const AAudioHandleInfo& streamHandleInfo,
                                                  pid_t clientThreadId) = 0;

    virtual aaudio_result_t startClient(const AAudioHandleInfo& streamHandleInfo,
                                        const android::AudioClient& client,
                                        const audio_attributes_t *attr,
                                        audio_port_handle_t *clientHandle) = 0;

    virtual aaudio_result_t stopClient(const AAudioHandleInfo& streamHandleInfo,
                                       audio_port_handle_t clientHandle) = 0;

    /**
     * Exit the standby mode.
     *
     * @param streamHandle the stream handle
     * @param parcelable contains new data queue information
     * @return the result of the execution
     */
    virtual aaudio_result_t exitStandby(const AAudioHandleInfo& streamHandleInfo,
                                        AudioEndpointParcelable &parcelable) = 0;
};

} /* namespace aaudio */

#endif //ANDROID_AAUDIO_BINDING_AAUDIO_SERVICE_INTERFACE_H
