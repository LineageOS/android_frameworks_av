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

#include <android-base/thread_annotations.h>
#include <media/TranscoderInterface.h>

#include <list>
#include <mutex>

namespace android {

class MediaTranscoder;

/*
 * Wrapper class around MediaTranscoder.
 * Implements TranscoderInterface for TranscodingJobScheduler to use.
 */
class TranscoderWrapper : public TranscoderInterface,
                          public std::enable_shared_from_this<TranscoderWrapper> {
public:
    TranscoderWrapper();

    virtual void setCallback(const std::shared_ptr<TranscoderCallbackInterface>& cb) override;
    virtual void start(ClientIdType clientId, JobIdType jobId,
                       const TranscodingRequestParcel& request,
                       const std::shared_ptr<ITranscodingClientCallback>& clientCallback) override;
    virtual void pause(ClientIdType clientId, JobIdType jobId) override;
    virtual void resume(ClientIdType clientId, JobIdType jobId) override;
    virtual void stop(ClientIdType clientId, JobIdType jobId) override;

private:
    class CallbackImpl;
    struct Event {
        enum Type { NoEvent, Start, Pause, Resume, Stop, Finish, Error } type;
        ClientIdType clientId;
        JobIdType jobId;
        std::function<void()> runnable;
    };
    std::shared_ptr<CallbackImpl> mTranscoderCb;
    std::shared_ptr<MediaTranscoder> mTranscoder;
    std::weak_ptr<TranscoderCallbackInterface> mCallback;
    std::mutex mLock;
    std::condition_variable mCondition;
    std::list<Event> mQueue;  // GUARDED_BY(mLock);
    ClientIdType mCurrentClientId;
    JobIdType mCurrentJobId;

    static const char* toString(Event::Type type);
    void onFinish(ClientIdType clientId, JobIdType jobId);
    void onError(ClientIdType clientId, JobIdType jobId, TranscodingErrorCode error);

    TranscodingErrorCode handleStart(ClientIdType clientId, JobIdType jobId,
                                     const TranscodingRequestParcel& request,
                                     const std::shared_ptr<ITranscodingClientCallback>& callback);

    void cleanup();
    void queueEvent(Event::Type type, ClientIdType clientId, JobIdType jobId,
                    const std::function<void()> runnable);
    void threadLoop();
};

}  // namespace android
#endif  // ANDROID_TRANSCODER_WRAPPER_H
