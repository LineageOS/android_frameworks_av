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

#ifndef ANDROID_TRANSCODER_WRAPPER_H
#define ANDROID_TRANSCODER_WRAPPER_H

#include <media/NdkMediaError.h>
#include <media/NdkMediaFormat.h>
#include <media/TranscoderInterface.h>
#include <media/TranscodingLogger.h>

#include <chrono>
#include <list>
#include <map>
#include <mutex>

namespace android {

class MediaTranscoder;
class Parcelable;

/*
 * Wrapper class around MediaTranscoder.
 * Implements TranscoderInterface for TranscodingSessionController to use.
 */
class TranscoderWrapper : public TranscoderInterface,
                          public std::enable_shared_from_this<TranscoderWrapper> {
public:
    TranscoderWrapper(const std::shared_ptr<TranscoderCallbackInterface>& cb,
                      const std::shared_ptr<TranscodingLogger>& logger,
                      int64_t heartBeatIntervalUs);
    ~TranscoderWrapper();

    // TranscoderInterface
    void start(ClientIdType clientId, SessionIdType sessionId,
               const TranscodingRequestParcel& request, uid_t callingUid,
               const std::shared_ptr<ITranscodingClientCallback>& clientCallback) override;
    void pause(ClientIdType clientId, SessionIdType sessionId) override;
    void resume(ClientIdType clientId, SessionIdType sessionId,
                const TranscodingRequestParcel& request, uid_t callingUid,
                const std::shared_ptr<ITranscodingClientCallback>& clientCallback) override;
    void stop(ClientIdType clientId, SessionIdType sessionId, bool abandon = false) override;
    // ~TranscoderInterface

private:
    class CallbackImpl;
    struct Event {
        enum Type {
            NoEvent,
            Start,
            Pause,
            Resume,
            Stop,
            Finish,
            Error,
            Progress,
            HeartBeat,
            Abandon
        } type;
        ClientIdType clientId;
        SessionIdType sessionId;
        std::function<void()> runnable;
        int32_t arg;
    };
    using SessionKeyType = std::pair<ClientIdType, SessionIdType>;

    std::shared_ptr<CallbackImpl> mTranscoderCb;
    std::shared_ptr<MediaTranscoder> mTranscoder;
    std::weak_ptr<TranscoderCallbackInterface> mCallback;
    std::shared_ptr<TranscodingLogger> mLogger;
    std::shared_ptr<AMediaFormat> mSrcFormat;
    std::shared_ptr<AMediaFormat> mDstFormat;
    int64_t mHeartBeatIntervalUs;
    std::mutex mLock;
    std::condition_variable mCondition;
    std::list<Event> mQueue;  // GUARDED_BY(mLock);
    std::map<SessionKeyType, std::shared_ptr<ndk::ScopedAParcel>> mPausedStateMap;
    ClientIdType mCurrentClientId;
    SessionIdType mCurrentSessionId;
    uid_t mCurrentCallingUid;
    std::chrono::steady_clock::time_point mTranscodeStartTime;

    // Whether the looper has been created.
    bool mLooperReady;

    static std::string toString(const Event& event);
    void onFinish(ClientIdType clientId, SessionIdType sessionId);
    void onError(ClientIdType clientId, SessionIdType sessionId, media_status_t status);
    void onProgress(ClientIdType clientId, SessionIdType sessionId, int32_t progress);
    void onHeartBeat(ClientIdType clientId, SessionIdType sessionId);

    media_status_t handleStart(ClientIdType clientId, SessionIdType sessionId,
                               const TranscodingRequestParcel& request, uid_t callingUid,
                               const std::shared_ptr<ITranscodingClientCallback>& callback);
    media_status_t handlePause(ClientIdType clientId, SessionIdType sessionId);
    media_status_t handleResume(ClientIdType clientId, SessionIdType sessionId,
                                const TranscodingRequestParcel& request, uid_t callingUid,
                                const std::shared_ptr<ITranscodingClientCallback>& callback);
    media_status_t setupTranscoder(
            ClientIdType clientId, SessionIdType sessionId, const TranscodingRequestParcel& request,
            uid_t callingUid, const std::shared_ptr<ITranscodingClientCallback>& callback,
            TranscodingLogger::SessionEndedReason* failureReason /* nonnull */,
            const std::shared_ptr<ndk::ScopedAParcel>& pausedState = nullptr);

    void cleanup();
    void logSessionEnded(const TranscodingLogger::SessionEndedReason& reason, int error);
    void reportError(ClientIdType clientId, SessionIdType sessionId, media_status_t err);
    void queueEvent(Event::Type type, ClientIdType clientId, SessionIdType sessionId,
                    const std::function<void()> runnable, int32_t arg = 0);
    void threadLoop();
};

}  // namespace android
#endif  // ANDROID_TRANSCODER_WRAPPER_H
