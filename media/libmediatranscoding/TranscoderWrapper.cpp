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

//#define LOG_NDEBUG 0
#define LOG_TAG "TranscoderWrapper"

#include <aidl/android/media/TranscodingErrorCode.h>
#include <aidl/android/media/TranscodingRequestParcel.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>
#include <media/TranscoderWrapper.h>
#include <utils/Log.h>

#include <thread>

namespace android {
using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::TranscodingErrorCode;
using ::aidl::android::media::TranscodingVideoCodecType;
using ::aidl::android::media::TranscodingVideoTrackFormat;

static TranscodingErrorCode toTranscodingError(media_status_t status) {
    switch (status) {
    case AMEDIA_OK:
        return TranscodingErrorCode::kNoError;
    case AMEDIACODEC_ERROR_INSUFFICIENT_RESOURCE:  // FALLTHRU
    case AMEDIACODEC_ERROR_RECLAIMED:
        return TranscodingErrorCode::kInsufficientResources;
    case AMEDIA_ERROR_MALFORMED:
        return TranscodingErrorCode::kMalformed;
    case AMEDIA_ERROR_UNSUPPORTED:
        return TranscodingErrorCode::kUnsupported;
    case AMEDIA_ERROR_INVALID_OBJECT:  // FALLTHRU
    case AMEDIA_ERROR_INVALID_PARAMETER:
        return TranscodingErrorCode::kInvalidParameter;
    case AMEDIA_ERROR_INVALID_OPERATION:
        return TranscodingErrorCode::kInvalidOperation;
    case AMEDIA_ERROR_IO:
        return TranscodingErrorCode::kErrorIO;
    case AMEDIA_ERROR_UNKNOWN:  // FALLTHRU
    default:
        return TranscodingErrorCode::kUnknown;
    }
}

static AMediaFormat* getVideoFormat(
        const char* originalMime,
        const std::optional<TranscodingVideoTrackFormat>& requestedFormat) {
    if (requestedFormat == std::nullopt) {
        return nullptr;
    }

    AMediaFormat* format = AMediaFormat_new();
    bool changed = false;
    if (requestedFormat->codecType == TranscodingVideoCodecType::kHevc &&
        strcmp(originalMime, AMEDIA_MIMETYPE_VIDEO_HEVC)) {
        AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, AMEDIA_MIMETYPE_VIDEO_HEVC);
        changed = true;
    } else if (requestedFormat->codecType == TranscodingVideoCodecType::kAvc &&
               strcmp(originalMime, AMEDIA_MIMETYPE_VIDEO_AVC)) {
        AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, AMEDIA_MIMETYPE_VIDEO_AVC);
        changed = true;
    }
    if (requestedFormat->bitrateBps > 0) {
        AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, requestedFormat->bitrateBps);
        changed = true;
    }
    // TODO: translate other fields from requestedFormat to the format for MediaTranscoder.
    // Also need to determine more settings to expose in TranscodingVideoTrackFormat.
    if (!changed) {
        AMediaFormat_delete(format);
        // Use null format for passthru.
        format = nullptr;
    }
    return format;
}

//static
const char* TranscoderWrapper::toString(Event::Type type) {
    switch (type) {
    case Event::Start:
        return "Start";
    case Event::Pause:
        return "Pause";
    case Event::Resume:
        return "Resume";
    case Event::Stop:
        return "Stop";
    case Event::Finish:
        return "Finish";
    case Event::Error:
        return "Error";
    default:
        break;
    }
    return "(unknown)";
}

class TranscoderWrapper::CallbackImpl : public MediaTranscoder::CallbackInterface {
public:
    CallbackImpl(const std::shared_ptr<TranscoderWrapper>& owner, ClientIdType clientId,
                 JobIdType jobId)
          : mOwner(owner), mClientId(clientId), mJobId(jobId) {}

    virtual void onFinished(const MediaTranscoder* transcoder __unused) override {
        auto owner = mOwner.lock();
        if (owner != nullptr) {
            owner->onFinish(mClientId, mJobId);
        }
    }

    virtual void onError(const MediaTranscoder* transcoder __unused,
                         media_status_t error) override {
        auto owner = mOwner.lock();
        if (owner != nullptr) {
            owner->onError(mClientId, mJobId, toTranscodingError(error));
        }
    }

    virtual void onProgressUpdate(const MediaTranscoder* transcoder __unused,
                                  int32_t progress) override {
        ALOGV("%s: job {%lld, %d}, progress %d", __FUNCTION__, (long long)mClientId, mJobId,
              progress);
    }

    virtual void onCodecResourceLost(const MediaTranscoder* transcoder __unused,
                                     const std::shared_ptr<const Parcel>& pausedState
                                             __unused) override {
        ALOGV("%s: job {%lld, %d}", __FUNCTION__, (long long)mClientId, mJobId);
    }

private:
    std::weak_ptr<TranscoderWrapper> mOwner;
    ClientIdType mClientId;
    JobIdType mJobId;
};

TranscoderWrapper::TranscoderWrapper() : mCurrentClientId(0), mCurrentJobId(-1) {
    std::thread(&TranscoderWrapper::threadLoop, this).detach();
}

void TranscoderWrapper::setCallback(const std::shared_ptr<TranscoderCallbackInterface>& cb) {
    mCallback = cb;
}

void TranscoderWrapper::start(ClientIdType clientId, JobIdType jobId,
                              const TranscodingRequestParcel& request,
                              const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    queueEvent(Event::Start, clientId, jobId, [=] {
        TranscodingErrorCode err = handleStart(clientId, jobId, request, clientCb);

        auto callback = mCallback.lock();
        if (err != TranscodingErrorCode::kNoError) {
            cleanup();

            if (callback != nullptr) {
                callback->onError(clientId, jobId, err);
            }
        } else {
            if (callback != nullptr) {
                callback->onStarted(clientId, jobId);
            }
        }
    });
}

void TranscoderWrapper::pause(ClientIdType clientId, JobIdType jobId) {
    queueEvent(Event::Pause, clientId, jobId, [=] {
        TranscodingErrorCode err = handlePause(clientId, jobId);

        cleanup();

        auto callback = mCallback.lock();
        if (callback != nullptr) {
            if (err != TranscodingErrorCode::kNoError) {
                callback->onError(clientId, jobId, err);
            } else {
                callback->onPaused(clientId, jobId);
            }
        }
    });
}

void TranscoderWrapper::resume(ClientIdType clientId, JobIdType jobId,
                               const TranscodingRequestParcel& request,
                               const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    queueEvent(Event::Resume, clientId, jobId, [=] {
        TranscodingErrorCode err = handleResume(clientId, jobId, request, clientCb);

        auto callback = mCallback.lock();
        if (err != TranscodingErrorCode::kNoError) {
            cleanup();

            if (callback != nullptr) {
                callback->onError(clientId, jobId, err);
            }
        } else {
            if (callback != nullptr) {
                callback->onResumed(clientId, jobId);
            }
        }
    });
}

void TranscoderWrapper::stop(ClientIdType clientId, JobIdType jobId) {
    queueEvent(Event::Stop, clientId, jobId, [=] {
        if (mTranscoder != nullptr && clientId == mCurrentClientId && jobId == mCurrentJobId) {
            // Cancelling the currently running job.
            media_status_t err = mTranscoder->cancel();
            if (err != AMEDIA_OK) {
                ALOGE("failed to stop transcoder: %d", err);
            } else {
                ALOGI("transcoder stopped");
            }
            cleanup();
        } else {
            // For jobs that's not currently running, release any pausedState for the job.
            mPausedStateMap.erase(JobKeyType(clientId, jobId));
        }
        // No callback needed for stop.
    });
}

void TranscoderWrapper::onFinish(ClientIdType clientId, JobIdType jobId) {
    queueEvent(Event::Finish, clientId, jobId, [=] {
        if (mTranscoder != nullptr && clientId == mCurrentClientId && jobId == mCurrentJobId) {
            cleanup();
        }

        auto callback = mCallback.lock();
        if (callback != nullptr) {
            callback->onFinish(clientId, jobId);
        }
    });
}

void TranscoderWrapper::onError(ClientIdType clientId, JobIdType jobId,
                                TranscodingErrorCode error) {
    queueEvent(Event::Error, clientId, jobId, [=] {
        if (mTranscoder != nullptr && clientId == mCurrentClientId && jobId == mCurrentJobId) {
            cleanup();
        }

        auto callback = mCallback.lock();
        if (callback != nullptr) {
            callback->onError(clientId, jobId, error);
        }
    });
}

TranscodingErrorCode TranscoderWrapper::setupTranscoder(
        ClientIdType clientId, JobIdType jobId, const TranscodingRequestParcel& request,
        const std::shared_ptr<ITranscodingClientCallback>& clientCb,
        const std::shared_ptr<const Parcel>& pausedState) {
    if (clientCb == nullptr) {
        ALOGE("client callback is null");
        return TranscodingErrorCode::kInvalidParameter;
    }

    if (mTranscoder != nullptr) {
        ALOGE("transcoder already running");
        return TranscodingErrorCode::kInvalidOperation;
    }

    Status status;
    ::ndk::ScopedFileDescriptor srcFd, dstFd;
    status = clientCb->openFileDescriptor(request.sourceFilePath, "r", &srcFd);
    if (!status.isOk() || srcFd.get() < 0) {
        ALOGE("failed to open source");
        return TranscodingErrorCode::kErrorIO;
    }

    // Open dest file with "rw", as the transcoder could potentially reuse part of it
    // for resume case. We might want the further differentiate and open with "w" only
    // for start.
    status = clientCb->openFileDescriptor(request.destinationFilePath, "rw", &dstFd);
    if (!status.isOk() || dstFd.get() < 0) {
        ALOGE("failed to open destination");
        return TranscodingErrorCode::kErrorIO;
    }

    mCurrentClientId = clientId;
    mCurrentJobId = jobId;
    mTranscoderCb = std::make_shared<CallbackImpl>(shared_from_this(), clientId, jobId);
    mTranscoder = MediaTranscoder::create(mTranscoderCb, pausedState);
    if (mTranscoder == nullptr) {
        ALOGE("failed to create transcoder");
        return TranscodingErrorCode::kUnknown;
    }

    media_status_t err = mTranscoder->configureSource(srcFd.get());
    if (err != AMEDIA_OK) {
        ALOGE("failed to configure source: %d", err);
        return toTranscodingError(err);
    }

    std::vector<std::shared_ptr<AMediaFormat>> trackFormats = mTranscoder->getTrackFormats();
    if (trackFormats.size() == 0) {
        ALOGE("failed to get track formats!");
        return TranscodingErrorCode::kMalformed;
    }

    for (int i = 0; i < trackFormats.size(); ++i) {
        AMediaFormat* format = nullptr;
        const char* mime = nullptr;
        AMediaFormat_getString(trackFormats[i].get(), AMEDIAFORMAT_KEY_MIME, &mime);

        if (!strncmp(mime, "video/", 6)) {
            format = getVideoFormat(mime, request.requestedVideoTrackFormat);
        }

        err = mTranscoder->configureTrackFormat(i, format);
        if (format != nullptr) {
            AMediaFormat_delete(format);
        }
        if (err != AMEDIA_OK) {
            ALOGE("failed to configure track format for track %d: %d", i, err);
            return toTranscodingError(err);
        }
    }

    err = mTranscoder->configureDestination(dstFd.get());
    if (err != AMEDIA_OK) {
        ALOGE("failed to configure dest: %d", err);
        return toTranscodingError(err);
    }

    return TranscodingErrorCode::kNoError;
}

TranscodingErrorCode TranscoderWrapper::handleStart(
        ClientIdType clientId, JobIdType jobId, const TranscodingRequestParcel& request,
        const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    ALOGI("setting up transcoder for start");
    TranscodingErrorCode err = setupTranscoder(clientId, jobId, request, clientCb);
    if (err != TranscodingErrorCode::kNoError) {
        ALOGI("%s: failed to setup transcoder", __FUNCTION__);
        return err;
    }

    media_status_t status = mTranscoder->start();
    if (status != AMEDIA_OK) {
        ALOGE("%s: failed to start transcoder: %d", __FUNCTION__, err);
        return toTranscodingError(status);
    }

    ALOGI("%s: transcoder started", __FUNCTION__);
    return TranscodingErrorCode::kNoError;
}

TranscodingErrorCode TranscoderWrapper::handlePause(ClientIdType clientId, JobIdType jobId) {
    if (mTranscoder == nullptr) {
        ALOGE("%s: transcoder is not running", __FUNCTION__);
        return TranscodingErrorCode::kInvalidOperation;
    }

    if (clientId != mCurrentClientId || jobId != mCurrentJobId) {
        ALOGW("%s: stopping job {%lld, %d} that's not current job {%lld, %d}", __FUNCTION__,
              (long long)clientId, jobId, (long long)mCurrentClientId, mCurrentJobId);
    }

    std::shared_ptr<const Parcel> pauseStates;
    media_status_t err = mTranscoder->pause(&pauseStates);
    if (err != AMEDIA_OK) {
        ALOGE("%s: failed to pause transcoder: %d", __FUNCTION__, err);
        return toTranscodingError(err);
    }
    mPausedStateMap[JobKeyType(clientId, jobId)] = pauseStates;

    ALOGI("%s: transcoder paused", __FUNCTION__);
    return TranscodingErrorCode::kNoError;
}

TranscodingErrorCode TranscoderWrapper::handleResume(
        ClientIdType clientId, JobIdType jobId, const TranscodingRequestParcel& request,
        const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    std::shared_ptr<const Parcel> pausedState;
    auto it = mPausedStateMap.find(JobKeyType(clientId, jobId));
    if (it != mPausedStateMap.end()) {
        pausedState = it->second;
        mPausedStateMap.erase(it);
    } else {
        ALOGE("%s: can't find paused state", __FUNCTION__);
        return TranscodingErrorCode::kInvalidOperation;
    }

    ALOGI("setting up transcoder for resume");
    TranscodingErrorCode err = setupTranscoder(clientId, jobId, request, clientCb, pausedState);
    if (err != TranscodingErrorCode::kNoError) {
        ALOGE("%s: failed to setup transcoder", __FUNCTION__);
        return err;
    }

    media_status_t status = mTranscoder->resume();
    if (status != AMEDIA_OK) {
        ALOGE("%s: failed to resume transcoder: %d", __FUNCTION__, err);
        return toTranscodingError(status);
    }

    ALOGI("%s: transcoder resumed", __FUNCTION__);
    return TranscodingErrorCode::kNoError;
}

void TranscoderWrapper::cleanup() {
    mCurrentClientId = 0;
    mCurrentJobId = -1;
    mTranscoderCb = nullptr;
    mTranscoder = nullptr;
}

void TranscoderWrapper::queueEvent(Event::Type type, ClientIdType clientId, JobIdType jobId,
                                   const std::function<void()> runnable) {
    ALOGV("%s: job {%lld, %d}: %s", __FUNCTION__, (long long)clientId, jobId, toString(type));

    std::scoped_lock lock{mLock};

    mQueue.push_back({type, clientId, jobId, runnable});
    mCondition.notify_one();
}

void TranscoderWrapper::threadLoop() {
    std::unique_lock<std::mutex> lock{mLock};
    // TranscoderWrapper currently lives in the transcoding service, as long as
    // MediaTranscodingService itself.
    while (true) {
        // Wait for the next event.
        while (mQueue.empty()) {
            mCondition.wait(lock);
        }

        Event event = *mQueue.begin();
        mQueue.pop_front();

        ALOGD("%s: job {%lld, %d}: %s", __FUNCTION__, (long long)event.clientId, event.jobId,
              toString(event.type));

        lock.unlock();
        event.runnable();
        lock.lock();
    }
}

}  // namespace android
