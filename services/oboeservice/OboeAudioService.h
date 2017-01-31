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
#include "utility/HandleTracker.h"
#include "IOboeAudioService.h"
#include "OboeServiceStreamBase.h"

namespace android {

class OboeAudioService :
    public BinderService<OboeAudioService>,
    public BnOboeAudioService
{
    friend class BinderService<OboeAudioService>;

public:
    OboeAudioService();
    virtual ~OboeAudioService();

    static const char* getServiceName() { return "media.audio_oboe"; }

    virtual oboe_handle_t openStream(oboe::OboeStreamRequest &request,
                                     oboe::OboeStreamConfiguration &configuration);

    virtual oboe_result_t closeStream(oboe_handle_t streamHandle);

    virtual oboe_result_t getStreamDescription(
                oboe_handle_t streamHandle,
                oboe::AudioEndpointParcelable &parcelable);

    virtual oboe_result_t startStream(oboe_handle_t streamHandle);

    virtual oboe_result_t pauseStream(oboe_handle_t streamHandle);

    virtual oboe_result_t flushStream(oboe_handle_t streamHandle);

    virtual oboe_result_t registerAudioThread(oboe_handle_t streamHandle,
                                              pid_t pid, oboe_nanoseconds_t periodNanoseconds) ;

    virtual oboe_result_t unregisterAudioThread(oboe_handle_t streamHandle, pid_t pid);

private:

    oboe::OboeServiceStreamBase *convertHandleToServiceStream(oboe_handle_t streamHandle) const;

    HandleTracker mHandleTracker;

};

} /* namespace android */

#endif //OBOE_OBOE_AUDIO_SERVICE_H
