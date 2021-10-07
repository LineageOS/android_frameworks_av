/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TRANSCODER_INTERFACE_H
#define ANDROID_MEDIA_TRANSCODER_INTERFACE_H

#include <aidl/android/media/ITranscodingClientCallback.h>
#include <aidl/android/media/TranscodingErrorCode.h>
#include <aidl/android/media/TranscodingRequestParcel.h>
#include <media/TranscodingDefs.h>

namespace android {

using ::aidl::android::media::ITranscodingClientCallback;
using ::aidl::android::media::TranscodingErrorCode;
using ::aidl::android::media::TranscodingRequestParcel;
class TranscoderCallbackInterface;

// Interface for the controller to call the transcoder to take actions.
class TranscoderInterface {
public:
    virtual void start(ClientIdType clientId, SessionIdType sessionId,
                       const TranscodingRequestParcel& request, uid_t callingUid,
                       const std::shared_ptr<ITranscodingClientCallback>& clientCallback) = 0;
    virtual void pause(ClientIdType clientId, SessionIdType sessionId) = 0;
    virtual void resume(ClientIdType clientId, SessionIdType sessionId,
                        const TranscodingRequestParcel& request, uid_t callingUid,
                        const std::shared_ptr<ITranscodingClientCallback>& clientCallback) = 0;
    // Stop the specified session. If abandon is true, the transcoder wrapper will be discarded
    // after the session stops.
    virtual void stop(ClientIdType clientId, SessionIdType sessionId, bool abandon = false) = 0;

protected:
    virtual ~TranscoderInterface() = default;
};

// Interface for the transcoder to notify the controller of the status of
// the currently running session, or temporary loss of transcoding resources.
class TranscoderCallbackInterface {
public:
    // TODO(chz): determine what parameters are needed here.
    virtual void onStarted(ClientIdType clientId, SessionIdType sessionId) = 0;
    virtual void onPaused(ClientIdType clientId, SessionIdType sessionId) = 0;
    virtual void onResumed(ClientIdType clientId, SessionIdType sessionId) = 0;
    virtual void onFinish(ClientIdType clientId, SessionIdType sessionId) = 0;
    virtual void onError(ClientIdType clientId, SessionIdType sessionId,
                         TranscodingErrorCode err) = 0;
    virtual void onProgressUpdate(ClientIdType clientId, SessionIdType sessionId,
                                  int32_t progress) = 0;
    virtual void onHeartBeat(ClientIdType clientId, SessionIdType sessionId) = 0;

    // Called when transcoding becomes temporarily inaccessible due to loss of resource.
    // If there is any session currently running, it will be paused. When resource contention
    // is solved, the controller should call TranscoderInterface's to either start a new session,
    // or resume a paused session.
    virtual void onResourceLost(ClientIdType clientId, SessionIdType sessionId) = 0;

protected:
    virtual ~TranscoderCallbackInterface() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODER_INTERFACE_H
