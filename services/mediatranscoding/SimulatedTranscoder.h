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
#include <mutex>

namespace android {

/**
 * SimulatedTranscoder is currently used to instantiate MediaTranscodingService
 * on service side for testing, so that we could actually test the IPC calls of
 * MediaTranscodingService to expose issues that's observable only over IPC.
 * SimulatedTranscoder is used when useSimulatedTranscoder in TranscodingTestConfig
 * is set to true.
 *
 * SimulatedTranscoder simulates job execution by reporting finish after kJobDurationUs.
 * Job lifecycle events are reported via progress updates with special progress
 * numbers (equal to the Event's type).
 */
class SimulatedTranscoder : public TranscoderInterface {
public:
    struct Event {
        enum Type { NoEvent, Start, Pause, Resume, Stop, Finished, Failed } type;
        ClientIdType clientId;
        JobIdType jobId;
        std::function<void()> runnable;
    };

    static constexpr int64_t kJobDurationUs = 1000000;

    SimulatedTranscoder();

    // TranscoderInterface
    void setCallback(const std::shared_ptr<TranscoderCallbackInterface>& cb) override;
    void start(ClientIdType clientId, JobIdType jobId, const TranscodingRequestParcel& request,
               const std::shared_ptr<ITranscodingClientCallback>& clientCallback) override;
    void pause(ClientIdType clientId, JobIdType jobId) override;
    void resume(ClientIdType clientId, JobIdType jobId) override;
    void stop(ClientIdType clientId, JobIdType jobId) override;
    // ~TranscoderInterface

private:
    std::weak_ptr<TranscoderCallbackInterface> mCallback;
    std::mutex mLock;
    std::condition_variable mCondition;
    std::list<Event> mQueue GUARDED_BY(mLock);

    // Minimum time spent on transcode the video. This is used just for testing.
    int64_t mJobProcessingTimeMs = kJobDurationUs / 1000;

    static const char* toString(Event::Type type);
    void queueEvent(Event::Type type, ClientIdType clientId, JobIdType jobId,
                    std::function<void()> runnable);
    void threadLoop();
};

}  // namespace android

#endif  // ANDROID_MEDIA_SIMULATED_TRANSCODER_H
