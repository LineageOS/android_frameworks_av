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

#ifndef AAUDIO_AAUDIO_SERVICE_H
#define AAUDIO_AAUDIO_SERVICE_H

#include <time.h>
#include <pthread.h>

#include <binder/BinderService.h>
#include <media/AudioClient.h>

#include <aaudio/AAudio.h>

#include "binding/AAudioCommon.h"
#include "binding/AAudioServiceInterface.h"
#include "binding/IAAudioService.h"

#include "AAudioServiceStreamBase.h"
#include "AAudioStreamTracker.h"

namespace android {

class AAudioService :
    public BinderService<AAudioService>,
    public BnAAudioService,
    public aaudio::AAudioServiceInterface
{
    friend class BinderService<AAudioService>;

public:
    AAudioService();
    virtual ~AAudioService();

    static const char* getServiceName() { return AAUDIO_SERVICE_NAME; }

    virtual status_t        dump(int fd, const Vector<String16>& args) override;

    virtual void            registerClient(const sp<IAAudioClient>& client);

    aaudio::aaudio_handle_t openStream(const aaudio::AAudioStreamRequest &request,
                                       aaudio::AAudioStreamConfiguration &configurationOutput)
                                       override;

    /*
     * This is called from Binder. It checks for permissions
     * and converts the handle passed through Binder to a stream pointer.
     */
    aaudio_result_t closeStream(aaudio::aaudio_handle_t streamHandle) override;

    aaudio_result_t getStreamDescription(
                aaudio::aaudio_handle_t streamHandle,
                aaudio::AudioEndpointParcelable &parcelable) override;

    aaudio_result_t startStream(aaudio::aaudio_handle_t streamHandle) override;

    aaudio_result_t pauseStream(aaudio::aaudio_handle_t streamHandle) override;

    aaudio_result_t stopStream(aaudio::aaudio_handle_t streamHandle) override;

    aaudio_result_t flushStream(aaudio::aaudio_handle_t streamHandle) override;

    aaudio_result_t registerAudioThread(aaudio::aaudio_handle_t streamHandle,
                                                pid_t tid,
                                                int64_t periodNanoseconds) override;

    aaudio_result_t unregisterAudioThread(aaudio::aaudio_handle_t streamHandle,
                                                  pid_t tid) override;

    aaudio_result_t startClient(aaudio::aaudio_handle_t streamHandle,
                                const android::AudioClient& client,
                                const audio_attributes_t *attr,
                                audio_port_handle_t *clientHandle) override;

    aaudio_result_t stopClient(aaudio::aaudio_handle_t streamHandle,
                                       audio_port_handle_t clientHandle) override;

 // ===============================================================================
 // The following public methods are only called from the service and NOT by Binder.
 // ===============================================================================

    aaudio_result_t disconnectStreamByPortHandle(audio_port_handle_t portHandle);

    /*
     * This is only called from within the Service.
     * It bypasses the permission checks in closeStream(handle).
     */
    aaudio_result_t closeStream(sp<aaudio::AAudioServiceStreamBase> serviceStream);

private:

    /** @return true if the client is the audioserver
     */
    bool isCallerInService();

    /**
     * Lookup stream and then validate access to the stream.
     * @param streamHandle
     * @return
     */
    sp<aaudio::AAudioServiceStreamBase> convertHandleToServiceStream(
            aaudio::aaudio_handle_t streamHandle);

    android::AudioClient            mAudioClient;

    aaudio::AAudioStreamTracker     mStreamTracker;

    // We use a lock to prevent thread A from reopening an exclusive stream
    // after thread B steals thread A's exclusive MMAP resource stream.
    std::recursive_mutex            mOpenLock;

    // TODO  Extract the priority constants from services/audioflinger/Threads.cpp
    // and share them with this code. Look for "kPriorityFastMixer".
    static constexpr int32_t        kRealTimeAudioPriorityClient = 2;
    static constexpr int32_t        kRealTimeAudioPriorityService = 3;

};

} /* namespace android */

#endif //AAUDIO_AAUDIO_SERVICE_H
