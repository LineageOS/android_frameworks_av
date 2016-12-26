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

#ifndef OBOE_OBOE_AUDIO_SERVICE_H
#define OBOE_OBOE_AUDIO_SERVICE_H

#include <time.h>
#include <pthread.h>

#include <binder/BinderService.h>

#include <oboe/OboeDefinitions.h>
#include <oboe/OboeAudio.h>
#include "HandleTracker.h"
#include "IOboeAudioService.h"
#include "OboeService.h"
#include "OboeServiceStreamBase.h"

using namespace android;
namespace oboe {

class OboeAudioService :
    public BinderService<OboeAudioService>,
    public BnOboeAudioService
{
    friend class BinderService<OboeAudioService>;   // for OboeAudioService()
public:
// TODO why does this fail?    static const char* getServiceName() ANDROID_API { return "media.audio_oboe"; }
    static const char* getServiceName() { return "media.audio_oboe"; }

    virtual oboe_handle_t openStream(OboeStreamRequest &request,
                                     OboeStreamConfiguration &configuration);

    virtual oboe_result_t closeStream(oboe_handle_t streamHandle);

    virtual oboe_result_t getStreamDescription(
                oboe_handle_t streamHandle,
                AudioEndpointParcelable &parcelable);

    virtual oboe_result_t startStream(oboe_handle_t streamHandle);

    virtual oboe_result_t pauseStream(oboe_handle_t streamHandle);

    virtual oboe_result_t flushStream(oboe_handle_t streamHandle);

    virtual oboe_result_t registerAudioThread(oboe_handle_t streamHandle,
                                              pid_t pid, oboe_nanoseconds_t periodNanoseconds) ;

    virtual oboe_result_t unregisterAudioThread(oboe_handle_t streamHandle, pid_t pid);

    virtual void tickle();

private:

    OboeServiceStreamBase *convertHandleToServiceStream(oboe_handle_t streamHandle) const;

    HandleTracker mHandleTracker;
    oboe_handle_t mLatestHandle = OBOE_ERROR_INVALID_HANDLE; // TODO until we have service threads
};

} /* namespace oboe */

#endif //OBOE_OBOE_AUDIO_SERVICE_H
