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

#ifndef ANDROID_MEDIA_TRANSCODING_JOB_SCHEDULER_H
#define ANDROID_MEDIA_TRANSCODING_JOB_SCHEDULER_H

#include <aidl/android/media/TranscodingJobPriority.h>
#include <media/ProcessInfoInterface.h>
#include <media/SchedulerClientInterface.h>
#include <media/TranscoderInterface.h>
#include <media/TranscodingRequest.h>
#include <utils/String8.h>

#include <list>
#include <map>
#include <mutex>

namespace android {
using ::aidl::android::media::TranscodingJobPriority;
using ::aidl::android::media::TranscodingResultParcel;

class TranscodingJobScheduler : public ProcessInfoCallbackInterface,
                                public SchedulerClientInterface,
                                public TranscoderCallbackInterface {
public:
    virtual ~TranscodingJobScheduler();

    // SchedulerClientInterface
    bool submit(ClientIdType clientId, int32_t jobId, pid_t pid,
                const TranscodingRequestParcel& request,
                const std::weak_ptr<ITranscodingClientCallback>& clientCallback) override;
    bool cancel(ClientIdType clientId, int32_t jobId) override;
    bool getJob(ClientIdType clientId, int32_t jobId, TranscodingRequestParcel* request) override;
    // ~SchedulerClientInterface

    // TranscoderCallbackInterface
    void onFinish(ClientIdType clientId, int32_t jobId) override;
    void onError(int64_t clientId, int32_t jobId, TranscodingErrorCode err) override;
    void onResourceLost() override;
    // ~TranscoderCallbackInterface

    // ProcessInfoCallbackInterface
    void onTopProcessChanged(int32_t pid) override;
    void onResourceAvailable() override;
    // ~ProcessInfoCallbackInterface

private:
    friend class MediaTranscodingService;
    friend class TranscodingJobSchedulerTest;

    using JobKeyType = std::pair<ClientIdType, int32_t /*jobId*/>;
    using JobQueueType = std::list<JobKeyType>;

    struct Job {
        JobKeyType key;
        pid_t pid;
        enum JobState {
            NOT_STARTED,
            RUNNING,
            PAUSED,
        } state;
        TranscodingRequest request;
        std::weak_ptr<ITranscodingClientCallback> callback;
    };

    // TODO(chz): call transcoder without global lock.
    // Use mLock for all entrypoints for now.
    mutable std::mutex mLock;

    std::map<JobKeyType, Job> mJobMap;

    // Pid->JobQueue map (pid == -1: offline queue)
    std::map<pid_t, JobQueueType> mJobQueues;

    // Pids, with the head being the most-recently-top app, 2nd item is the
    // previous top app, etc.
    std::list<pid_t> mPidSortedList;
    std::list<pid_t>::iterator mOfflinePidIterator;

    std::shared_ptr<TranscoderInterface> mTranscoder;
    std::shared_ptr<ProcessInfoInterface> mProcInfo;

    Job* mCurrentJob;
    bool mResourceLost;

    // Only allow MediaTranscodingService and unit tests to instantiate.
    TranscodingJobScheduler(const std::shared_ptr<TranscoderInterface>& transcoder,
                            const std::shared_ptr<ProcessInfoInterface>& procInfo);

    Job* getTopJob_l();
    void updateCurrentJob_l();
    void removeJob_l(const JobKeyType& jobKey);

    // Internal state verifier (debug only)
    void validateState_l();

    static String8 jobToString(const JobKeyType& jobKey);
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_JOB_SCHEDULER_H
