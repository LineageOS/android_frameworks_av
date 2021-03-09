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

#ifndef ANDROID_MEDIA_SIMULATED_TRANSCODER_H
#define ANDROID_MEDIA_SIMULATED_TRANSCODER_H

#include <android-base/thread_annotations.h>
#include <media/TranscoderInterface.h>

#include <list>
#include <map>
#include <mutex>

namespace android {

/**
 * SimulatedTranscoder is currently used to instantiate MediaTranscodingService
 * on service side for testing, so that we could actually test the IPC calls of
 * MediaTranscodingService to expose issues that's observable only over IPC.
 * SimulatedTranscoder is used when useSimulatedTranscoder in TranscodingTestConfig
 * is set to true.
 *
 * SimulatedTranscoder simulates session execution by reporting finish after kSessionDurationUs.
 * Session lifecycle events are reported via progress updates with special progress
 * numbers (equal to the Event's type).
 */
class SimulatedTranscoder : public TranscoderInterface,
                            public std::enable_shared_from_this<SimulatedTranscoder> {
public:
    struct Event {
        enum Type { NoEvent, Start, Pause, Resume, Stop, Finished, Failed, Abandon } type;
        ClientIdType clientId;
        SessionIdType sessionId;
        std::function<void()> runnable;
    };

    static constexpr int64_t kSessionDurationUs = 1000000;

    SimulatedTranscoder(const std::shared_ptr<TranscoderCallbackInterface>& cb);
    ~SimulatedTranscoder();

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
    std::weak_ptr<TranscoderCallbackInterface> mCallback;
    std::mutex mLock;
    std::condition_variable mCondition;
    std::list<Event> mQueue GUARDED_BY(mLock);
    bool mLooperReady;

    using SessionKeyType = std::pair<ClientIdType, SessionIdType>;
    // map of session's remaining time in microsec.
    std::map<SessionKeyType, std::chrono::microseconds> mRemainingTimeMap;

    static const char* toString(Event::Type type);
    void queueEvent(Event::Type type, ClientIdType clientId, SessionIdType sessionId,
                    std::function<void()> runnable);
    void threadLoop();
};

}  // namespace android

#endif  // ANDROID_MEDIA_SIMULATED_TRANSCODER_H
