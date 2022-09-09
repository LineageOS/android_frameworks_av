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
#include <media/TranscodingRequest.h>
#include <utils/AndroidThreads.h>
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

static std::shared_ptr<AMediaFormat> getVideoFormat(
        const char* originalMime,
        const std::optional<TranscodingVideoTrackFormat>& requestedFormat) {
    if (requestedFormat == std::nullopt) {
        return nullptr;
    }

    std::shared_ptr<AMediaFormat> format =
            std::shared_ptr<AMediaFormat>(AMediaFormat_new(), &AMediaFormat_delete);
    bool changed = false;
    if (requestedFormat->codecType == TranscodingVideoCodecType::kHevc &&
        strcmp(originalMime, AMEDIA_MIMETYPE_VIDEO_HEVC)) {
        AMediaFormat_setString(format.get(), AMEDIAFORMAT_KEY_MIME, AMEDIA_MIMETYPE_VIDEO_HEVC);
        changed = true;
    } else if (requestedFormat->codecType == TranscodingVideoCodecType::kAvc &&
               strcmp(originalMime, AMEDIA_MIMETYPE_VIDEO_AVC)) {
        AMediaFormat_setString(format.get(), AMEDIAFORMAT_KEY_MIME, AMEDIA_MIMETYPE_VIDEO_AVC);
        changed = true;
    }
    if (requestedFormat->bitrateBps > 0) {
        AMediaFormat_setInt32(format.get(), AMEDIAFORMAT_KEY_BIT_RATE, requestedFormat->bitrateBps);
        changed = true;
    }
    // TODO: translate other fields from requestedFormat to the format for MediaTranscoder.
    // Also need to determine more settings to expose in TranscodingVideoTrackFormat.
    if (!changed) {
        // Use null format for passthru.
        format.reset();
    }
    return format;
}

//static
std::string TranscoderWrapper::toString(const Event& event) {
    std::string typeStr;
    switch (event.type) {
    case Event::Start:
        typeStr = "Start";
        break;
    case Event::Pause:
        typeStr = "Pause";
        break;
    case Event::Resume:
        typeStr = "Resume";
        break;
    case Event::Stop:
        typeStr = "Stop";
        break;
    case Event::Finish:
        typeStr = "Finish";
        break;
    case Event::Error:
        typeStr = "Error";
        break;
    case Event::Progress:
        typeStr = "Progress";
        break;
    case Event::HeartBeat:
        typeStr = "HeartBeat";
        break;
    case Event::Abandon:
        typeStr = "Abandon";
        break;
    default:
        return "(unknown)";
    }
    std::string result;
    result = "session {" + std::to_string(event.clientId) + "," + std::to_string(event.sessionId) +
             "}: " + typeStr;
    if (event.type == Event::Error || event.type == Event::Progress) {
        result += " " + std::to_string(event.arg);
    }
    return result;
}

class TranscoderWrapper::CallbackImpl : public MediaTranscoder::CallbackInterface {
public:
    CallbackImpl(const std::shared_ptr<TranscoderWrapper>& owner, ClientIdType clientId,
                 SessionIdType sessionId)
          : mOwner(owner), mClientId(clientId), mSessionId(sessionId) {}

    virtual void onFinished(const MediaTranscoder* transcoder __unused) override {
        auto owner = mOwner.lock();
        if (owner != nullptr) {
            owner->onFinish(mClientId, mSessionId);
        }
    }

    virtual void onError(const MediaTranscoder* transcoder __unused,
                         media_status_t error) override {
        auto owner = mOwner.lock();
        if (owner != nullptr) {
            owner->onError(mClientId, mSessionId, error);
        }
    }

    virtual void onProgressUpdate(const MediaTranscoder* transcoder __unused,
                                  int32_t progress) override {
        auto owner = mOwner.lock();
        if (owner != nullptr) {
            owner->onProgress(mClientId, mSessionId, progress);
        }
    }

    virtual void onHeartBeat(const MediaTranscoder* transcoder __unused) override {
        auto owner = mOwner.lock();
        if (owner != nullptr) {
            owner->onHeartBeat(mClientId, mSessionId);
        }
    }

    virtual void onCodecResourceLost(const MediaTranscoder* transcoder __unused,
                                     const std::shared_ptr<ndk::ScopedAParcel>& pausedState
                                             __unused) override {
        ALOGV("%s: session {%lld, %d}", __FUNCTION__, (long long)mClientId, mSessionId);
    }

private:
    std::weak_ptr<TranscoderWrapper> mOwner;
    ClientIdType mClientId;
    SessionIdType mSessionId;
};

TranscoderWrapper::TranscoderWrapper(const std::shared_ptr<TranscoderCallbackInterface>& cb,
                                     const std::shared_ptr<TranscodingLogger>& logger,
                                     int64_t heartBeatIntervalUs)
      : mCallback(cb),
        mLogger(logger),
        mHeartBeatIntervalUs(heartBeatIntervalUs),
        mCurrentClientId(0),
        mCurrentSessionId(-1),
        mLooperReady(false) {
    ALOGV("TranscoderWrapper CTOR: %p", this);
}

TranscoderWrapper::~TranscoderWrapper() {
    ALOGV("TranscoderWrapper DTOR: %p", this);
}

static bool isResourceError(media_status_t err) {
    return err == AMEDIACODEC_ERROR_RECLAIMED || err == AMEDIACODEC_ERROR_INSUFFICIENT_RESOURCE;
}

void TranscoderWrapper::reportError(ClientIdType clientId, SessionIdType sessionId,
                                    media_status_t err) {
    auto callback = mCallback.lock();
    if (callback != nullptr) {
        if (isResourceError(err)) {
            // Add a placeholder pause state to mPausedStateMap. This is required when resuming.
            // TODO: remove this when transcoder pause/resume logic is ready. New logic will
            // no longer use the pause states.
            auto it = mPausedStateMap.find(SessionKeyType(clientId, sessionId));
            if (it == mPausedStateMap.end()) {
                mPausedStateMap.emplace(SessionKeyType(clientId, sessionId),
                                        new ndk::ScopedAParcel());
            }

            callback->onResourceLost(clientId, sessionId);
        } else {
            callback->onError(clientId, sessionId, toTranscodingError(err));
        }
    }
}

void TranscoderWrapper::start(ClientIdType clientId, SessionIdType sessionId,
                              const TranscodingRequestParcel& requestParcel, uid_t callingUid,
                              const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    TranscodingRequest request{requestParcel};
    queueEvent(Event::Start, clientId, sessionId, [=] {
        media_status_t err = handleStart(clientId, sessionId, request, callingUid, clientCb);
        if (err != AMEDIA_OK) {
            cleanup();
            reportError(clientId, sessionId, err);
        } else {
            auto callback = mCallback.lock();
            if (callback != nullptr) {
                callback->onStarted(clientId, sessionId);
            }
        }
    });
}

void TranscoderWrapper::pause(ClientIdType clientId, SessionIdType sessionId) {
    queueEvent(Event::Pause, clientId, sessionId, [=] {
        media_status_t err = handlePause(clientId, sessionId);

        cleanup();

        if (err != AMEDIA_OK) {
            reportError(clientId, sessionId, err);
        } else {
            auto callback = mCallback.lock();
            if (callback != nullptr) {
                callback->onPaused(clientId, sessionId);
            }
        }
    });
}

void TranscoderWrapper::resume(ClientIdType clientId, SessionIdType sessionId,
                               const TranscodingRequestParcel& requestParcel, uid_t callingUid,
                               const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    TranscodingRequest request{requestParcel};
    queueEvent(Event::Resume, clientId, sessionId, [=] {
        media_status_t err = handleResume(clientId, sessionId, request, callingUid, clientCb);
        if (err != AMEDIA_OK) {
            cleanup();
            reportError(clientId, sessionId, err);
        } else {
            auto callback = mCallback.lock();
            if (callback != nullptr) {
                callback->onResumed(clientId, sessionId);
            }
        }
    });
}

void TranscoderWrapper::stop(ClientIdType clientId, SessionIdType sessionId, bool abandon) {
    queueEvent(Event::Stop, clientId, sessionId, [=] {
        if (mTranscoder != nullptr && clientId == mCurrentClientId &&
            sessionId == mCurrentSessionId) {
            // Cancelling the currently running session.
            media_status_t err = mTranscoder->cancel();
            if (err != AMEDIA_OK) {
                ALOGW("failed to stop transcoder: %d", err);
            } else {
                ALOGI("transcoder stopped");
            }
            logSessionEnded(TranscodingLogger::SessionEndedReason::CANCELLED, err);
            cleanup();
        } else {
            // For sessions that's not currently running, release any pausedState for the session.
            mPausedStateMap.erase(SessionKeyType(clientId, sessionId));
        }
        // No callback needed for stop.
    });

    if (abandon) {
        queueEvent(Event::Abandon, 0, 0, nullptr);
    }
}

void TranscoderWrapper::onFinish(ClientIdType clientId, SessionIdType sessionId) {
    queueEvent(Event::Finish, clientId, sessionId, [=] {
        if (mTranscoder != nullptr && clientId == mCurrentClientId &&
            sessionId == mCurrentSessionId) {
            logSessionEnded(TranscodingLogger::SessionEndedReason::FINISHED, AMEDIA_OK);
            cleanup();
        }

        auto callback = mCallback.lock();
        if (callback != nullptr) {
            callback->onFinish(clientId, sessionId);
        }
    });
}

void TranscoderWrapper::onError(ClientIdType clientId, SessionIdType sessionId,
                                media_status_t error) {
    queueEvent(
            Event::Error, clientId, sessionId,
            [=] {
                if (mTranscoder != nullptr && clientId == mCurrentClientId &&
                    sessionId == mCurrentSessionId) {
                    logSessionEnded(TranscodingLogger::SessionEndedReason::ERROR, error);
                    cleanup();
                }
                reportError(clientId, sessionId, error);
            },
            error);
}

void TranscoderWrapper::onProgress(ClientIdType clientId, SessionIdType sessionId,
                                   int32_t progress) {
    queueEvent(
            Event::Progress, clientId, sessionId,
            [=] {
                auto callback = mCallback.lock();
                if (callback != nullptr) {
                    callback->onProgressUpdate(clientId, sessionId, progress);
                }
            },
            progress);
}

void TranscoderWrapper::onHeartBeat(ClientIdType clientId, SessionIdType sessionId) {
    queueEvent(Event::HeartBeat, clientId, sessionId, [=] {
        auto callback = mCallback.lock();
        if (callback != nullptr) {
            callback->onHeartBeat(clientId, sessionId);
        }
    });
}

media_status_t TranscoderWrapper::setupTranscoder(
        ClientIdType clientId, SessionIdType sessionId, const TranscodingRequestParcel& request,
        uid_t callingUid, const std::shared_ptr<ITranscodingClientCallback>& clientCb,
        TranscodingLogger::SessionEndedReason* failureReason,
        const std::shared_ptr<ndk::ScopedAParcel>& pausedState) {
    if (clientCb == nullptr) {
        ALOGE("client callback is null");
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    if (mTranscoder != nullptr) {
        ALOGE("transcoder already running");
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    // Unwrap the callback and send heartbeats to the client after each operation during setup.
    auto callback = mCallback.lock();
    if (callback == nullptr) {
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    Status status;
    ::ndk::ScopedFileDescriptor srcFd, dstFd;
    int srcFdInt = request.sourceFd.get();
    if (srcFdInt < 0) {
        status = clientCb->openFileDescriptor(request.sourceFilePath, "r", &srcFd);
        if (!status.isOk() || srcFd.get() < 0) {
            ALOGE("failed to open source");
            *failureReason = TranscodingLogger::SessionEndedReason::OPEN_SRC_FD_FAILED;
            return AMEDIA_ERROR_IO;
        }
        srcFdInt = srcFd.get();
    }

    callback->onHeartBeat(clientId, sessionId);

    int dstFdInt = request.destinationFd.get();
    if (dstFdInt < 0) {
        // Open dest file with "rw", as the transcoder could potentially reuse part of it
        // for resume case. We might want the further differentiate and open with "w" only
        // for start.
        status = clientCb->openFileDescriptor(request.destinationFilePath, "rw", &dstFd);
        if (!status.isOk() || dstFd.get() < 0) {
            ALOGE("failed to open destination");
            *failureReason = TranscodingLogger::SessionEndedReason::OPEN_DST_FD_FAILED;
            return AMEDIA_ERROR_IO;
        }
        dstFdInt = dstFd.get();
    }

    callback->onHeartBeat(clientId, sessionId);

    mCurrentClientId = clientId;
    mCurrentSessionId = sessionId;
    mCurrentCallingUid = callingUid;
    mTranscoderCb = std::make_shared<CallbackImpl>(shared_from_this(), clientId, sessionId);
    mTranscoder = MediaTranscoder::create(mTranscoderCb, mHeartBeatIntervalUs, request.clientPid,
                                          request.clientUid, pausedState);
    if (mTranscoder == nullptr) {
        ALOGE("failed to create transcoder");
        *failureReason = TranscodingLogger::SessionEndedReason::CREATE_FAILED;
        return AMEDIA_ERROR_UNKNOWN;
    }

    callback->onHeartBeat(clientId, sessionId);

    media_status_t err = mTranscoder->configureSource(srcFdInt);
    if (err != AMEDIA_OK) {
        ALOGE("failed to configure source: %d", err);
        *failureReason = TranscodingLogger::SessionEndedReason::CONFIG_SRC_FAILED;
        return err;
    }

    callback->onHeartBeat(clientId, sessionId);

    std::vector<std::shared_ptr<AMediaFormat>> trackFormats = mTranscoder->getTrackFormats();
    if (trackFormats.size() == 0) {
        ALOGE("failed to get track formats!");
        *failureReason = TranscodingLogger::SessionEndedReason::NO_TRACKS;
        return AMEDIA_ERROR_MALFORMED;
    }

    callback->onHeartBeat(clientId, sessionId);

    for (int i = 0; i < trackFormats.size(); ++i) {
        std::shared_ptr<AMediaFormat> format;
        const char* mime = nullptr;
        AMediaFormat_getString(trackFormats[i].get(), AMEDIAFORMAT_KEY_MIME, &mime);

        if (!strncmp(mime, "video/", 6)) {
            format = getVideoFormat(mime, request.requestedVideoTrackFormat);

            mSrcFormat = trackFormats[i];
            mDstFormat = format;
        }

        err = mTranscoder->configureTrackFormat(i, format.get());
        if (err != AMEDIA_OK) {
            ALOGE("failed to configure track format for track %d: %d", i, err);
            *failureReason = TranscodingLogger::SessionEndedReason::CONFIG_TRACK_FAILED;
            return err;
        }

        callback->onHeartBeat(clientId, sessionId);
    }

    err = mTranscoder->configureDestination(dstFdInt);
    if (err != AMEDIA_OK) {
        ALOGE("failed to configure dest: %d", err);
        *failureReason = TranscodingLogger::SessionEndedReason::CONFIG_DST_FAILED;
        return err;
    }

    callback->onHeartBeat(clientId, sessionId);

    return AMEDIA_OK;
}

media_status_t TranscoderWrapper::handleStart(
        ClientIdType clientId, SessionIdType sessionId, const TranscodingRequestParcel& request,
        uid_t callingUid, const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    ALOGI("%s: setting up transcoder for start", __FUNCTION__);
    TranscodingLogger::SessionEndedReason reason = TranscodingLogger::SessionEndedReason::UNKNOWN;
    media_status_t err =
            setupTranscoder(clientId, sessionId, request, callingUid, clientCb, &reason);
    if (err != AMEDIA_OK) {
        ALOGE("%s: failed to setup transcoder", __FUNCTION__);
        logSessionEnded(reason, err);
        return err;
    }

    mTranscodeStartTime = std::chrono::steady_clock::now();

    err = mTranscoder->start();
    if (err != AMEDIA_OK) {
        ALOGE("%s: failed to start transcoder: %d", __FUNCTION__, err);
        logSessionEnded(TranscodingLogger::SessionEndedReason::START_FAILED, err);
        return err;
    }

    ALOGI("%s: transcoder started", __FUNCTION__);
    return AMEDIA_OK;
}

media_status_t TranscoderWrapper::handlePause(ClientIdType clientId, SessionIdType sessionId) {
    if (mTranscoder == nullptr) {
        ALOGE("%s: transcoder is not running", __FUNCTION__);
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    if (clientId != mCurrentClientId || sessionId != mCurrentSessionId) {
        ALOGW("%s: stopping session {%lld, %d} that's not current session {%lld, %d}", __FUNCTION__,
              (long long)clientId, sessionId, (long long)mCurrentClientId, mCurrentSessionId);
    }

    ALOGI("%s: pausing transcoder", __FUNCTION__);

    std::shared_ptr<ndk::ScopedAParcel> pauseStates;
    media_status_t err = mTranscoder->pause(&pauseStates);
    logSessionEnded(TranscodingLogger::SessionEndedReason::PAUSED, err);
    if (err != AMEDIA_OK) {
        ALOGE("%s: failed to pause transcoder: %d", __FUNCTION__, err);
        return err;
    }
    mPausedStateMap[SessionKeyType(clientId, sessionId)] = pauseStates;

    ALOGI("%s: transcoder paused", __FUNCTION__);
    return AMEDIA_OK;
}

media_status_t TranscoderWrapper::handleResume(
        ClientIdType clientId, SessionIdType sessionId, const TranscodingRequestParcel& request,
        uid_t callingUid, const std::shared_ptr<ITranscodingClientCallback>& clientCb) {
    std::shared_ptr<ndk::ScopedAParcel> pausedState;
    auto it = mPausedStateMap.find(SessionKeyType(clientId, sessionId));
    if (it != mPausedStateMap.end()) {
        pausedState = it->second;
        mPausedStateMap.erase(it);
    } else {
        ALOGE("%s: can't find paused state", __FUNCTION__);
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    ALOGI("%s: setting up transcoder for resume", __FUNCTION__);
    TranscodingLogger::SessionEndedReason reason = TranscodingLogger::SessionEndedReason::UNKNOWN;
    media_status_t err = setupTranscoder(clientId, sessionId, request, callingUid, clientCb,
                                         &reason, pausedState);
    if (err != AMEDIA_OK) {
        ALOGE("%s: failed to setup transcoder: %d", __FUNCTION__, err);
        logSessionEnded(reason, err);
        return err;
    }

    // Note: For now resume() will just restart transcoding from the beginning, so there is no need
    // to distinguish between resume and start from a performance perspective.
    mTranscodeStartTime = std::chrono::steady_clock::now();

    err = mTranscoder->resume();
    if (err != AMEDIA_OK) {
        ALOGE("%s: failed to resume transcoder: %d", __FUNCTION__, err);
        logSessionEnded(TranscodingLogger::SessionEndedReason::RESUME_FAILED, err);
        return err;
    }

    ALOGI("%s: transcoder resumed", __FUNCTION__);
    return AMEDIA_OK;
}

void TranscoderWrapper::cleanup() {
    mCurrentClientId = 0;
    mCurrentSessionId = -1;
    mCurrentCallingUid = -1;
    mTranscoderCb = nullptr;
    mTranscoder = nullptr;
    mSrcFormat = nullptr;
    mDstFormat = nullptr;
}

void TranscoderWrapper::logSessionEnded(const TranscodingLogger::SessionEndedReason& reason,
                                        int error) {
    std::chrono::microseconds transcodeDuration(-1);
    if (reason == TranscodingLogger::SessionEndedReason::FINISHED && error == AMEDIA_OK) {
        transcodeDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - mTranscodeStartTime);
    }

    mLogger->logSessionEnded(reason, mCurrentCallingUid, error, transcodeDuration, mSrcFormat.get(),
                             mDstFormat.get());
}

void TranscoderWrapper::queueEvent(Event::Type type, ClientIdType clientId, SessionIdType sessionId,
                                   const std::function<void()> runnable, int32_t arg) {
    std::scoped_lock lock{mLock};

    if (!mLooperReady) {
        // A shared_ptr to ourselves is given to the thread's stack, so that the TranscoderWrapper
        // object doesn't go away until the thread exits. When a watchdog timeout happens, this
        // allows the session controller to release its reference to the TranscoderWrapper object
        // without blocking on the thread exits.
        std::thread([owner = shared_from_this()]() { owner->threadLoop(); }).detach();
        mLooperReady = true;
    }

    mQueue.push_back({type, clientId, sessionId, runnable, arg});
    mCondition.notify_one();
}

void TranscoderWrapper::threadLoop() {
    androidSetThreadPriority(0 /*tid (0 = current) */, ANDROID_PRIORITY_BACKGROUND);
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

        ALOGV("%s: %s", __FUNCTION__, toString(event).c_str());

        if (event.type == Event::Abandon) {
            break;
        }

        lock.unlock();
        event.runnable();
        lock.lock();
    }
}
}  // namespace android
