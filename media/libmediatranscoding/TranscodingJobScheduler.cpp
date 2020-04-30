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

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingJobScheduler"

#define VALIDATE_STATE 1

#include <inttypes.h>
#include <media/TranscodingJobScheduler.h>
#include <utils/Log.h>

#include <utility>

namespace android {

constexpr static uid_t OFFLINE_UID = -1;

//static
String8 TranscodingJobScheduler::jobToString(const JobKeyType& jobKey) {
    return String8::format("{client:%lld, job:%d}", (long long)jobKey.first, jobKey.second);
}

TranscodingJobScheduler::TranscodingJobScheduler(
        const std::shared_ptr<TranscoderInterface>& transcoder,
        const std::shared_ptr<UidPolicyInterface>& uidPolicy)
      : mTranscoder(transcoder), mUidPolicy(uidPolicy), mCurrentJob(nullptr), mResourceLost(false) {
    // Only push empty offline queue initially. Realtime queues are added when requests come in.
    mUidSortedList.push_back(OFFLINE_UID);
    mOfflineUidIterator = mUidSortedList.begin();
    mJobQueues.emplace(OFFLINE_UID, JobQueueType());
}

TranscodingJobScheduler::~TranscodingJobScheduler() {}

TranscodingJobScheduler::Job* TranscodingJobScheduler::getTopJob_l() {
    if (mJobMap.empty()) {
        return nullptr;
    }
    uid_t topUid = *mUidSortedList.begin();
    JobKeyType topJobKey = *mJobQueues[topUid].begin();
    return &mJobMap[topJobKey];
}

void TranscodingJobScheduler::updateCurrentJob_l() {
    Job* topJob = getTopJob_l();
    Job* curJob = mCurrentJob;
    ALOGV("updateCurrentJob: topJob is %s, curJob is %s",
          topJob == nullptr ? "null" : jobToString(topJob->key).c_str(),
          curJob == nullptr ? "null" : jobToString(curJob->key).c_str());

    // If we found a topJob that should be run, and it's not already running,
    // take some actions to ensure it's running.
    if (topJob != nullptr && (topJob != curJob || topJob->state != Job::RUNNING)) {
        // If another job is currently running, pause it first.
        if (curJob != nullptr && curJob->state == Job::RUNNING) {
            mTranscoder->pause(curJob->key.first, curJob->key.second);
            curJob->state = Job::PAUSED;
        }
        // If we are not experiencing resource loss, we can start or resume
        // the topJob now.
        if (!mResourceLost) {
            if (topJob->state == Job::NOT_STARTED) {
                mTranscoder->start(topJob->key.first, topJob->key.second);
            } else if (topJob->state == Job::PAUSED) {
                mTranscoder->resume(topJob->key.first, topJob->key.second);
            }
            topJob->state = Job::RUNNING;
        }
    }
    mCurrentJob = topJob;
}

void TranscodingJobScheduler::removeJob_l(const JobKeyType& jobKey) {
    ALOGV("%s: job %s", __FUNCTION__, jobToString(jobKey).c_str());

    if (mJobMap.count(jobKey) == 0) {
        ALOGE("job %s doesn't exist", jobToString(jobKey).c_str());
        return;
    }

    // Remove job from uid's queue.
    const uid_t uid = mJobMap[jobKey].uid;
    JobQueueType& jobQueue = mJobQueues[uid];
    auto it = std::find(jobQueue.begin(), jobQueue.end(), jobKey);
    if (it == jobQueue.end()) {
        ALOGE("couldn't find job %s in queue for uid %d", jobToString(jobKey).c_str(), uid);
        return;
    }
    jobQueue.erase(it);

    // If this is the last job in a real-time queue, remove this uid's queue.
    if (uid != OFFLINE_UID && jobQueue.empty()) {
        mUidSortedList.remove(uid);
        mJobQueues.erase(uid);
    }

    // Clear current job.
    if (mCurrentJob == &mJobMap[jobKey]) {
        mCurrentJob = nullptr;
    }

    // Remove job from job map.
    mJobMap.erase(jobKey);
}

bool TranscodingJobScheduler::submit(ClientIdType clientId, int32_t jobId, uid_t uid,
                                     const TranscodingRequestParcel& request,
                                     const std::weak_ptr<ITranscodingClientCallback>& callback) {
    JobKeyType jobKey = std::make_pair(clientId, jobId);

    ALOGV("%s: job %s, uid %d, prioirty %d", __FUNCTION__, jobToString(jobKey).c_str(), uid,
          (int32_t)request.priority);

    std::scoped_lock lock{mLock};

    if (mJobMap.count(jobKey) > 0) {
        ALOGE("job %s already exists", jobToString(jobKey).c_str());
        return false;
    }

    // TODO(chz): only support offline vs real-time for now. All kUnspecified jobs
    // go to offline queue.
    if (request.priority == TranscodingJobPriority::kUnspecified) {
        uid = OFFLINE_UID;
    }

    // Add job to job map.
    mJobMap[jobKey].key = jobKey;
    mJobMap[jobKey].uid = uid;
    mJobMap[jobKey].state = Job::NOT_STARTED;
    mJobMap[jobKey].request = request;
    mJobMap[jobKey].callback = callback;

    // If it's an offline job, the queue was already added in constructor.
    // If it's a real-time jobs, check if a queue is already present for the uid,
    // and add a new queue if needed.
    if (uid != OFFLINE_UID) {
        if (mJobQueues.count(uid) == 0) {
            if (mUidPolicy->isUidOnTop(uid)) {
                mUidSortedList.push_front(uid);
            } else {
                // Shouldn't be submitting real-time requests from non-top app,
                // put it in front of the offline queue.
                mUidSortedList.insert(mOfflineUidIterator, uid);
            }
        } else if (uid != *mUidSortedList.begin()) {
            if (mUidPolicy->isUidOnTop(uid)) {
                mUidSortedList.remove(uid);
                mUidSortedList.push_front(uid);
            }
        }
    }
    // Append this job to the uid's queue.
    mJobQueues[uid].push_back(jobKey);

    updateCurrentJob_l();

    validateState_l();
    return true;
}

bool TranscodingJobScheduler::cancel(ClientIdType clientId, int32_t jobId) {
    JobKeyType jobKey = std::make_pair(clientId, jobId);

    ALOGV("%s: job %s", __FUNCTION__, jobToString(jobKey).c_str());

    std::scoped_lock lock{mLock};

    if (mJobMap.count(jobKey) == 0) {
        ALOGE("job %s doesn't exist", jobToString(jobKey).c_str());
        return false;
    }
    // If the job is running, pause it first.
    if (mJobMap[jobKey].state == Job::RUNNING) {
        mTranscoder->pause(clientId, jobId);
    }

    // Remove the job.
    removeJob_l(jobKey);

    // Start next job.
    updateCurrentJob_l();

    validateState_l();
    return true;
}

bool TranscodingJobScheduler::getJob(ClientIdType clientId, int32_t jobId,
                                     TranscodingRequestParcel* request) {
    JobKeyType jobKey = std::make_pair(clientId, jobId);

    std::scoped_lock lock{mLock};

    if (mJobMap.count(jobKey) == 0) {
        ALOGE("job %s doesn't exist", jobToString(jobKey).c_str());
        return false;
    }

    *(TranscodingRequest*)request = mJobMap[jobKey].request;
    return true;
}

void TranscodingJobScheduler::onFinish(ClientIdType clientId, int32_t jobId) {
    JobKeyType jobKey = std::make_pair(clientId, jobId);

    ALOGV("%s: job %s", __FUNCTION__, jobToString(jobKey).c_str());

    std::scoped_lock lock{mLock};

    if (mJobMap.count(jobKey) == 0) {
        ALOGW("ignoring abort for non-existent job");
        return;
    }

    // Only ignore if job was never started. In particular, propagate the status
    // to client if the job is paused. Transcoder could have posted finish when
    // we're pausing it, and the finish arrived after we changed current job.
    if (mJobMap[jobKey].state == Job::NOT_STARTED) {
        ALOGW("ignoring abort for job that was never started");
        return;
    }

    {
        auto clientCallback = mJobMap[jobKey].callback.lock();
        if (clientCallback != nullptr) {
            clientCallback->onTranscodingFinished(jobId, TranscodingResultParcel({jobId, 0}));
        }
    }

    // Remove the job.
    removeJob_l(jobKey);

    // Start next job.
    updateCurrentJob_l();

    validateState_l();
}

void TranscodingJobScheduler::onError(int64_t clientId, int32_t jobId, TranscodingErrorCode err) {
    JobKeyType jobKey = std::make_pair(clientId, jobId);

    ALOGV("%s: job %s, err %d", __FUNCTION__, jobToString(jobKey).c_str(), (int32_t)err);

    std::scoped_lock lock{mLock};

    if (mJobMap.count(jobKey) == 0) {
        ALOGW("ignoring abort for non-existent job");
        return;
    }

    // Only ignore if job was never started. In particular, propagate the status
    // to client if the job is paused. Transcoder could have posted finish when
    // we're pausing it, and the finish arrived after we changed current job.
    if (mJobMap[jobKey].state == Job::NOT_STARTED) {
        ALOGW("ignoring abort for job that was never started");
        return;
    }

    {
        auto clientCallback = mJobMap[jobKey].callback.lock();
        if (clientCallback != nullptr) {
            clientCallback->onTranscodingFailed(jobId, err);
        }
    }

    // Remove the job.
    removeJob_l(jobKey);

    // Start next job.
    updateCurrentJob_l();

    validateState_l();
}

void TranscodingJobScheduler::onResourceLost() {
    ALOGV("%s", __FUNCTION__);

    std::scoped_lock lock{mLock};

    // If we receive a resource loss event, the TranscoderLibrary already paused
    // the transcoding, so we don't need to call onPaused to notify it to pause.
    // Only need to update the job state here.
    if (mCurrentJob != nullptr && mCurrentJob->state == Job::RUNNING) {
        mCurrentJob->state = Job::PAUSED;
    }
    mResourceLost = true;

    validateState_l();
}

void TranscodingJobScheduler::onTopUidChanged(uid_t uid) {
    ALOGV("%s: uid %d", __FUNCTION__, uid);

    std::scoped_lock lock{mLock};

    if (uid == OFFLINE_UID) {
        ALOGW("%s: ignoring invalid uid %d", __FUNCTION__, uid);
        return;
    }
    // If this uid doesn't have any jobs, we don't care about it.
    if (mJobQueues.count(uid) == 0) {
        ALOGW("%s: ignoring uid %d without any jobs", __FUNCTION__, uid);
        return;
    }
    // If this uid is already top, don't do anything.
    if (uid == *mUidSortedList.begin()) {
        ALOGW("%s: uid %d is already top", __FUNCTION__, uid);
        return;
    }

    mUidSortedList.remove(uid);
    mUidSortedList.push_front(uid);

    updateCurrentJob_l();

    validateState_l();
}

void TranscodingJobScheduler::onResourceAvailable() {
    ALOGV("%s", __FUNCTION__);

    std::scoped_lock lock{mLock};

    mResourceLost = false;
    updateCurrentJob_l();

    validateState_l();
}

void TranscodingJobScheduler::validateState_l() {
#ifdef VALIDATE_STATE
    LOG_ALWAYS_FATAL_IF(mJobQueues.count(OFFLINE_UID) != 1,
                        "mJobQueues offline queue number is not 1");
    LOG_ALWAYS_FATAL_IF(*mOfflineUidIterator != OFFLINE_UID,
                        "mOfflineUidIterator not pointing to offline uid");
    LOG_ALWAYS_FATAL_IF(mUidSortedList.size() != mJobQueues.size(),
                        "mUidList and mJobQueues size mismatch");

    int32_t totalJobs = 0;
    for (auto uidIt = mUidSortedList.begin(); uidIt != mUidSortedList.end(); uidIt++) {
        LOG_ALWAYS_FATAL_IF(mJobQueues.count(*uidIt) != 1, "mJobQueues count for uid %d is not 1",
                            *uidIt);
        for (auto jobIt = mJobQueues[*uidIt].begin(); jobIt != mJobQueues[*uidIt].end(); jobIt++) {
            LOG_ALWAYS_FATAL_IF(mJobMap.count(*jobIt) != 1, "mJobs count for job %s is not 1",
                                jobToString(*jobIt).c_str());
        }

        totalJobs += mJobQueues[*uidIt].size();
    }
    LOG_ALWAYS_FATAL_IF(mJobMap.size() != totalJobs,
                        "mJobs size doesn't match total jobs counted from uid queues");
#endif  // VALIDATE_STATE
}

}  // namespace android
