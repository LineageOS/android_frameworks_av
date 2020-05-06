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
#include <media/SchedulerClientInterface.h>
#include <media/TranscoderInterface.h>
#include <media/TranscodingRequest.h>
#include <media/UidPolicyInterface.h>
#include <utils/String8.h>

#include <list>
#include <map>
#include <mutex>

namespace android {
using ::aidl::android::media::TranscodingJobPriority;
using ::aidl::android::media::TranscodingResultParcel;

class TranscodingJobScheduler : public UidPolicyCallbackInterface,
                                public SchedulerClientInterface,
                                public TranscoderCallbackInterface {
public:
    virtual ~TranscodingJobScheduler();

    // SchedulerClientInterface
    bool submit(ClientIdType clientId, JobIdType jobId, uid_t uid,
                const TranscodingRequestParcel& request,
                const std::weak_ptr<ITranscodingClientCallback>& clientCallback) override;
    bool cancel(ClientIdType clientId, JobIdType jobId) override;
    bool getJob(ClientIdType clientId, JobIdType jobId, TranscodingRequestParcel* request) override;
    // ~SchedulerClientInterface

    // TranscoderCallbackInterface
    void onFinish(ClientIdType clientId, JobIdType jobId) override;
    void onError(ClientIdType clientId, JobIdType jobId, TranscodingErrorCode err) override;
    void onProgressUpdate(ClientIdType clientId, JobIdType jobId, int32_t progress) override;
    void onResourceLost() override;
    // ~TranscoderCallbackInterface

    // UidPolicyCallbackInterface
    void onTopUidsChanged(const std::unordered_set<uid_t>& uids) override;
    void onResourceAvailable() override;
    // ~UidPolicyCallbackInterface

private:
    friend class MediaTranscodingService;
    friend class TranscodingJobSchedulerTest;

    using JobKeyType = std::pair<ClientIdType, JobIdType>;
    using JobQueueType = std::list<JobKeyType>;

    struct Job {
        JobKeyType key;
        uid_t uid;
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

    // uid->JobQueue map (uid == -1: offline queue)
    std::map<uid_t, JobQueueType> mJobQueues;

    // uids, with the head being the most-recently-top app, 2nd item is the
    // previous top app, etc.
    std::list<uid_t> mUidSortedList;
    std::list<uid_t>::iterator mOfflineUidIterator;

    std::shared_ptr<TranscoderInterface> mTranscoder;
    std::shared_ptr<UidPolicyInterface> mUidPolicy;

    Job* mCurrentJob;
    bool mResourceLost;

    // Only allow MediaTranscodingService and unit tests to instantiate.
    TranscodingJobScheduler(const std::shared_ptr<TranscoderInterface>& transcoder,
                            const std::shared_ptr<UidPolicyInterface>& uidPolicy);

    Job* getTopJob_l();
    void updateCurrentJob_l();
    void removeJob_l(const JobKeyType& jobKey);
    void moveUidsToTop_l(const std::unordered_set<uid_t>& uids, bool preserveTopUid);

    // Internal state verifier (debug only)
    void validateState_l();

    static String8 jobToString(const JobKeyType& jobKey);
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_JOB_SCHEDULER_H
