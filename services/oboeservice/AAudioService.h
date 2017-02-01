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

#ifndef AAUDIO_AAUDIO_AUDIO_SERVICE_H
#define AAUDIO_AAUDIO_AUDIO_SERVICE_H

#include <time.h>
#include <pthread.h>

#include <binder/BinderService.h>

#include <aaudio/AAudioDefinitions.h>
#include <aaudio/AAudio.h>
#include "utility/HandleTracker.h"
#include "IAAudioService.h"
#include "AAudioServiceStreamBase.h"

namespace android {

class AAudioService :
    public BinderService<AAudioService>,
    public BnAAudioService
{
    friend class BinderService<AAudioService>;

public:
    AAudioService();
    virtual ~AAudioService();

    static const char* getServiceName() { return "media.audio_aaudio"; }

    virtual aaudio_handle_t openStream(aaudio::AAudioStreamRequest &request,
                                     aaudio::AAudioStreamConfiguration &configuration);

    virtual aaudio_result_t closeStream(aaudio_handle_t streamHandle);

    virtual aaudio_result_t getStreamDescription(
                aaudio_handle_t streamHandle,
                aaudio::AudioEndpointParcelable &parcelable);

    virtual aaudio_result_t startStream(aaudio_handle_t streamHandle);

    virtual aaudio_result_t pauseStream(aaudio_handle_t streamHandle);

    virtual aaudio_result_t flushStream(aaudio_handle_t streamHandle);

    virtual aaudio_result_t registerAudioThread(aaudio_handle_t streamHandle,
                                              pid_t pid, aaudio_nanoseconds_t periodNanoseconds) ;

    virtual aaudio_result_t unregisterAudioThread(aaudio_handle_t streamHandle, pid_t pid);

private:

    aaudio::AAudioServiceStreamBase *convertHandleToServiceStream(aaudio_handle_t streamHandle) const;

    HandleTracker mHandleTracker;

};

} /* namespace android */

#endif //AAUDIO_AAUDIO_AUDIO_SERVICE_H
