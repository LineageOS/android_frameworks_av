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

#ifndef BINDING_IAAUDIOSERVICE_H
#define BINDING_IAAUDIOSERVICE_H

#include <stdint.h>
#include <utils/RefBase.h>
#include <binder/TextOutput.h>
#include <binder/IInterface.h>

#include <aaudio/AAudio.h>

#include "binding/AAudioServiceDefinitions.h"
#include "binding/AudioEndpointParcelable.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioStreamConfiguration.h"


namespace android {

// Interface (our AIDL) - Shared by server and client
class IAAudioService : public IInterface {
public:

    DECLARE_META_INTERFACE(AAudioService);

    virtual aaudio_handle_t openStream(aaudio::AAudioStreamRequest &request,
                                     aaudio::AAudioStreamConfiguration &configuration) = 0;

    virtual aaudio_result_t closeStream(aaudio_handle_t streamHandle) = 0;

    /* Get an immutable description of the in-memory queues
    * used to communicate with the underlying HAL or Service.
    */
    virtual aaudio_result_t getStreamDescription(aaudio_handle_t streamHandle,
                                               aaudio::AudioEndpointParcelable &parcelable) = 0;

    /**
     * Start the flow of data.
     */
    virtual aaudio_result_t startStream(aaudio_handle_t streamHandle) = 0;

    /**
     * Stop the flow of data such that start() can resume without loss of data.
     */
    virtual aaudio_result_t pauseStream(aaudio_handle_t streamHandle) = 0;

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual aaudio_result_t flushStream(aaudio_handle_t streamHandle) = 0;

    /**
     * Manage the specified thread as a low latency audio thread.
     */
    virtual aaudio_result_t registerAudioThread(aaudio_handle_t streamHandle, pid_t clientThreadId,
                                              aaudio_nanoseconds_t periodNanoseconds) = 0;

    virtual aaudio_result_t unregisterAudioThread(aaudio_handle_t streamHandle,
                                                pid_t clientThreadId) = 0;
};

class BnAAudioService : public BnInterface<IAAudioService> {
public:
    virtual status_t onTransact(uint32_t code, const Parcel& data,
                                Parcel* reply, uint32_t flags = 0);

};

} /* namespace android */

#endif //BINDING_IAAUDIOSERVICE_H
