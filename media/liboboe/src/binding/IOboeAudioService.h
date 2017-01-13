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

#ifndef BINDING_IOBOEAUDIOSERVICE_H
#define BINDING_IOBOEAUDIOSERVICE_H

#include <stdint.h>
#include <utils/RefBase.h>
#include <binder/TextOutput.h>
#include <binder/IInterface.h>

#include <oboe/OboeAudio.h>

#include "binding/OboeServiceDefinitions.h"
#include "binding/AudioEndpointParcelable.h"
#include "binding/OboeStreamRequest.h"
#include "binding/OboeStreamConfiguration.h"

//using android::status_t;
//using android::IInterface;
//using android::BnInterface;

using oboe::AudioEndpointParcelable;
using oboe::OboeStreamRequest;
using oboe::OboeStreamConfiguration;

namespace android {

// Interface (our AIDL) - Shared by server and client
class IOboeAudioService : public IInterface {
public:

    DECLARE_META_INTERFACE(OboeAudioService);

    virtual oboe_handle_t openStream(OboeStreamRequest &request,
                                     OboeStreamConfiguration &configuration) = 0;

    virtual oboe_result_t closeStream(int32_t streamHandle) = 0;

    /* Get an immutable description of the in-memory queues
    * used to communicate with the underlying HAL or Service.
    */
    virtual oboe_result_t getStreamDescription(oboe_handle_t streamHandle,
                                               AudioEndpointParcelable &parcelable) = 0;

    /**
     * Start the flow of data.
     */
    virtual oboe_result_t startStream(oboe_handle_t streamHandle) = 0;

    /**
     * Stop the flow of data such that start() can resume without loss of data.
     */
    virtual oboe_result_t pauseStream(oboe_handle_t streamHandle) = 0;

    /**
     *  Discard any data held by the underlying HAL or Service.
     */
    virtual oboe_result_t flushStream(oboe_handle_t streamHandle) = 0;

    /**
     * Manage the specified thread as a low latency audio thread.
     */
    virtual oboe_result_t registerAudioThread(oboe_handle_t streamHandle, pid_t clientThreadId,
                                              oboe_nanoseconds_t periodNanoseconds) = 0;

    virtual oboe_result_t unregisterAudioThread(oboe_handle_t streamHandle,
                                                pid_t clientThreadId) = 0;

    /**
     * Poke server instead of running a background thread.
     * Cooperative multi-tasking for early development only.
     * TODO remove tickle() when service has its own thread.
     */
    virtual void tickle() { };

};

class BnOboeAudioService : public BnInterface<IOboeAudioService> {
public:
    virtual status_t onTransact(uint32_t code, const Parcel& data,
                                Parcel* reply, uint32_t flags = 0);

};

} /* namespace android */

#endif //BINDING_IOBOEAUDIOSERVICE_H
