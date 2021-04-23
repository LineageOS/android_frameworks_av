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
#define LOG_TAG "MediaTranscoder"

#include <android-base/logging.h>
#include <fcntl.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/MediaSampleWriter.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>
#include <media/PassthroughTrackTranscoder.h>
#include <media/VideoTrackTranscoder.h>
#include <sys/prctl.h>
#include <unistd.h>

namespace android {

static std::shared_ptr<AMediaFormat> createVideoTrackFormat(AMediaFormat* srcFormat,
                                                            AMediaFormat* options) {
    if (srcFormat == nullptr || options == nullptr) {
        LOG(ERROR) << "Cannot merge null formats";
        return nullptr;
    }

    // ------- Define parameters to copy from the source track format -------
    std::vector<AMediaFormatUtils::EntryCopier> srcParamsToCopy{
            ENTRY_COPIER(AMEDIAFORMAT_KEY_MIME, String),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_DURATION, Int64),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_WIDTH, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_HEIGHT, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_FRAME_RATE, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_COLOR_RANGE, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_COLOR_STANDARD, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_COLOR_TRANSFER, Int32),
    };

    // If the destination codec is the same as the source codec, we can preserve profile and level
    // from the source track as default values. Otherwise leave them unspecified.
    const char *srcMime, *dstMime;
    AMediaFormat_getString(srcFormat, AMEDIAFORMAT_KEY_MIME, &srcMime);
    if (!AMediaFormat_getString(options, AMEDIAFORMAT_KEY_MIME, &dstMime) ||
        strcmp(srcMime, dstMime) == 0) {
        srcParamsToCopy.push_back(ENTRY_COPIER(AMEDIAFORMAT_KEY_PROFILE, String));
        srcParamsToCopy.push_back(ENTRY_COPIER(AMEDIAFORMAT_KEY_LEVEL, String));
    }

    // ------- Define parameters to copy from the caller's options -------
    static const std::vector<AMediaFormatUtils::EntryCopier> kSupportedOptions{
            ENTRY_COPIER(AMEDIAFORMAT_KEY_MIME, String),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_DURATION, Int64),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_WIDTH, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_HEIGHT, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_BIT_RATE, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_PROFILE, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_LEVEL, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_COLOR_RANGE, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_COLOR_STANDARD, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_COLOR_TRANSFER, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_FRAME_RATE, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, Int32),
            ENTRY_COPIER(AMEDIAFORMAT_KEY_PRIORITY, Int32),
            ENTRY_COPIER2(AMEDIAFORMAT_KEY_OPERATING_RATE, Float, Int32),
    };

    // ------- Copy parameters from source and options to the destination -------
    auto trackFormat = std::shared_ptr<AMediaFormat>(AMediaFormat_new(), &AMediaFormat_delete);
    AMediaFormatUtils::CopyFormatEntries(srcFormat, trackFormat.get(), srcParamsToCopy);
    AMediaFormatUtils::CopyFormatEntries(options, trackFormat.get(), kSupportedOptions);
    return trackFormat;
}

void MediaTranscoder::onThreadFinished(const void* thread, media_status_t threadStatus,
                                       bool threadStopped) {
    LOG(DEBUG) << "Thread " << thread << " finished with status " << threadStatus << " stopped "
               << threadStopped;

    // Stop all threads if one reports an error.
    if (threadStatus != AMEDIA_OK) {
        requestStop(false /* stopOnSync */);
    }

    std::scoped_lock lock{mThreadStateMutex};

    // Record the change.
    mThreadStates[thread] = DONE;
    if (threadStatus != AMEDIA_OK && mTranscoderStatus == AMEDIA_OK) {
        mTranscoderStatus = threadStatus;
    }

    mTranscoderStopped |= threadStopped;

    // Check if all threads are done. Note that if all transcoders have stopped but the sample
    // writer has not yet started, it never will.
    bool transcodersDone = true;
    ThreadState sampleWriterState = PENDING;
    for (const auto& it : mThreadStates) {
        LOG(DEBUG) << "  Thread " << it.first << " state" << it.second;
        if (it.first == static_cast<const void*>(mSampleWriter.get())) {
            sampleWriterState = it.second;
        } else {
            transcodersDone &= (it.second == DONE);
        }
    }
    if (!transcodersDone || sampleWriterState == RUNNING) {
        return;
    }

    // All done. Send callback asynchronously and wake up threads waiting in cancel/pause.
    mThreadsDone = true;
    if (!mCallbackSent) {
        std::thread asyncNotificationThread{[this, self = shared_from_this(),
                                             status = mTranscoderStatus,
                                             stopped = mTranscoderStopped] {
            prctl(PR_SET_NAME, (unsigned long)"TranscodCallbk", 0, 0, 0);

            // If the transcoder was stopped that means a caller is waiting in stop or pause
            // in which case we don't send a callback.
            if (status != AMEDIA_OK) {
                mCallbacks->onError(this, status);
            } else if (!stopped) {
                mCallbacks->onFinished(this);
            }
            mThreadsDoneSignal.notify_all();
        }};
        asyncNotificationThread.detach();
        mCallbackSent = true;
    }
}

void MediaTranscoder::onTrackFormatAvailable(const MediaTrackTranscoder* transcoder) {
    LOG(DEBUG) << "TrackTranscoder " << transcoder << " format available.";

    std::scoped_lock lock{mTracksAddedMutex};
    const void* sampleWriterPtr = static_cast<const void*>(mSampleWriter.get());

    // Ignore duplicate format change.
    if (mTracksAdded.count(transcoder) > 0) {
        return;
    }

    // Add track to the writer.
    auto consumer = mSampleWriter->addTrack(transcoder->getOutputFormat());
    if (consumer == nullptr) {
        LOG(ERROR) << "Unable to add track to sample writer.";
        onThreadFinished(sampleWriterPtr, AMEDIA_ERROR_UNKNOWN, false /* stopped */);
        return;
    }

    // The sample writer is not yet started so notify the caller that progress is still made.
    if (mHeartBeatIntervalUs > 0) {
        mCallbacks->onHeartBeat(this);
    }

    MediaTrackTranscoder* mutableTranscoder = const_cast<MediaTrackTranscoder*>(transcoder);
    mutableTranscoder->setSampleConsumer(consumer);

    mTracksAdded.insert(transcoder);
    bool errorStarting = false;
    if (mTracksAdded.size() == mTrackTranscoders.size()) {
        // Enable sequential access mode on the sample reader to achieve optimal read performance.
        // This has to wait until all tracks have delivered their output formats and the sample
        // writer is started. Otherwise the tracks will not get their output sample queues drained
        // and the transcoder could hang due to one track running out of buffers and blocking the
        // other tracks from reading source samples before they could output their formats.

        std::scoped_lock lock{mThreadStateMutex};
        // Don't start the sample writer if a stop already has been requested.
        if (!mSampleWriterStopped) {
            if (!mCancelled) {
                mSampleReader->setEnforceSequentialAccess(true);
            }
            LOG(DEBUG) << "Starting sample writer.";
            errorStarting = !mSampleWriter->start();
            if (!errorStarting) {
                mThreadStates[sampleWriterPtr] = RUNNING;
            }
        }
    }

    if (errorStarting) {
        LOG(ERROR) << "Unable to start sample writer.";
        onThreadFinished(sampleWriterPtr, AMEDIA_ERROR_UNKNOWN, false /* stopped */);
    }
}

void MediaTranscoder::onTrackFinished(const MediaTrackTranscoder* transcoder) {
    LOG(DEBUG) << "TrackTranscoder " << transcoder << " finished";
    onThreadFinished(static_cast<const void*>(transcoder), AMEDIA_OK, false /* stopped */);
}

void MediaTranscoder::onTrackStopped(const MediaTrackTranscoder* transcoder) {
    LOG(DEBUG) << "TrackTranscoder " << transcoder << " stopped";
    onThreadFinished(static_cast<const void*>(transcoder), AMEDIA_OK, true /* stopped */);
}

void MediaTranscoder::onTrackError(const MediaTrackTranscoder* transcoder, media_status_t status) {
    LOG(ERROR) << "TrackTranscoder " << transcoder << " returned error " << status;
    onThreadFinished(static_cast<const void*>(transcoder), status, false /* stopped */);
}

void MediaTranscoder::onFinished(const MediaSampleWriter* writer, media_status_t status) {
    LOG(status == AMEDIA_OK ? DEBUG : ERROR) << "Sample writer finished with status " << status;
    onThreadFinished(static_cast<const void*>(writer), status, false /* stopped */);
}

void MediaTranscoder::onStopped(const MediaSampleWriter* writer) {
    LOG(DEBUG) << "Sample writer " << writer << " stopped";
    onThreadFinished(static_cast<const void*>(writer), AMEDIA_OK, true /* stopped */);
}

void MediaTranscoder::onProgressUpdate(const MediaSampleWriter* writer __unused, int32_t progress) {
    // Dispatch progress updated to the client.
    mCallbacks->onProgressUpdate(this, progress);
}

void MediaTranscoder::onHeartBeat(const MediaSampleWriter* writer __unused) {
    // Signal heart-beat to the client.
    mCallbacks->onHeartBeat(this);
}

MediaTranscoder::MediaTranscoder(const std::shared_ptr<CallbackInterface>& callbacks,
                                 int64_t heartBeatIntervalUs, pid_t pid, uid_t uid)
      : mCallbacks(callbacks), mHeartBeatIntervalUs(heartBeatIntervalUs), mPid(pid), mUid(uid) {}

std::shared_ptr<MediaTranscoder> MediaTranscoder::create(
        const std::shared_ptr<CallbackInterface>& callbacks, int64_t heartBeatIntervalUs, pid_t pid,
        uid_t uid, const std::shared_ptr<ndk::ScopedAParcel>& pausedState) {
    if (pausedState != nullptr) {
        LOG(INFO) << "Initializing from paused state.";
    }
    if (callbacks == nullptr) {
        LOG(ERROR) << "Callbacks cannot be null";
        return nullptr;
    }

    return std::shared_ptr<MediaTranscoder>(
            new MediaTranscoder(callbacks, heartBeatIntervalUs, pid, uid));
}

media_status_t MediaTranscoder::configureSource(int fd) {
    if (fd < 0) {
        LOG(ERROR) << "Invalid source fd: " << fd;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    const size_t fileSize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    mSampleReader = MediaSampleReaderNDK::createFromFd(fd, 0 /* offset */, fileSize);
    if (mSampleReader == nullptr) {
        LOG(ERROR) << "Unable to parse source fd: " << fd;
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    const size_t trackCount = mSampleReader->getTrackCount();
    for (size_t trackIndex = 0; trackIndex < trackCount; ++trackIndex) {
        AMediaFormat* trackFormat = mSampleReader->getTrackFormat(static_cast<int>(trackIndex));
        if (trackFormat == nullptr) {
            LOG(ERROR) << "Track #" << trackIndex << " has no format";
            return AMEDIA_ERROR_MALFORMED;
        }

        mSourceTrackFormats.emplace_back(trackFormat, &AMediaFormat_delete);
    }

    return AMEDIA_OK;
}

std::vector<std::shared_ptr<AMediaFormat>> MediaTranscoder::getTrackFormats() const {
    // Return a deep copy of the formats to avoid the caller modifying our internal formats.
    std::vector<std::shared_ptr<AMediaFormat>> trackFormats;
    for (const std::shared_ptr<AMediaFormat>& sourceFormat : mSourceTrackFormats) {
        AMediaFormat* copy = AMediaFormat_new();
        AMediaFormat_copy(copy, sourceFormat.get());
        trackFormats.emplace_back(copy, &AMediaFormat_delete);
    }
    return trackFormats;
}

media_status_t MediaTranscoder::configureTrackFormat(size_t trackIndex,
                                                     AMediaFormat* destinationOptions) {
    if (mSampleReader == nullptr) {
        LOG(ERROR) << "Source must be configured before tracks";
        return AMEDIA_ERROR_INVALID_OPERATION;
    } else if (trackIndex >= mSourceTrackFormats.size()) {
        LOG(ERROR) << "Track index " << trackIndex
                   << " is out of bounds. Track count: " << mSourceTrackFormats.size();
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    std::shared_ptr<MediaTrackTranscoder> transcoder;
    std::shared_ptr<AMediaFormat> trackFormat;

    if (destinationOptions == nullptr) {
        transcoder = std::make_shared<PassthroughTrackTranscoder>(shared_from_this());
    } else {
        AMediaFormat* srcTrackFormat = mSourceTrackFormats[trackIndex].get();

        const char* srcMime = nullptr;
        if (!AMediaFormat_getString(srcTrackFormat, AMEDIAFORMAT_KEY_MIME, &srcMime)) {
            LOG(ERROR) << "Source track #" << trackIndex << " has no mime type";
            return AMEDIA_ERROR_MALFORMED;
        }

        if (strncmp(srcMime, "video/", 6) != 0) {
            LOG(ERROR) << "Only video tracks are supported for transcoding. Unable to configure "
                          "track #"
                       << trackIndex << " with mime " << srcMime;
            return AMEDIA_ERROR_UNSUPPORTED;
        }

        const char* dstMime = nullptr;
        if (AMediaFormat_getString(destinationOptions, AMEDIAFORMAT_KEY_MIME, &dstMime)) {
            if (strncmp(dstMime, "video/", 6) != 0) {
                LOG(ERROR) << "Unable to convert media types for track #" << trackIndex << ", from "
                           << srcMime << " to " << dstMime;
                return AMEDIA_ERROR_UNSUPPORTED;
            }
        }

        transcoder = VideoTrackTranscoder::create(shared_from_this(), mPid, mUid);

        trackFormat = createVideoTrackFormat(srcTrackFormat, destinationOptions);
        if (trackFormat == nullptr) {
            LOG(ERROR) << "Unable to create video track format";
            return AMEDIA_ERROR_UNKNOWN;
        }
    }

    media_status_t status = mSampleReader->selectTrack(trackIndex);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to select track " << trackIndex;
        return status;
    }

    status = transcoder->configure(mSampleReader, trackIndex, trackFormat);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Configure track transcoder for track #" << trackIndex << " returned error "
                   << status;
        mSampleReader->unselectTrack(trackIndex);
        return status;
    }

    std::scoped_lock lock{mThreadStateMutex};
    mThreadStates[static_cast<const void*>(transcoder.get())] = PENDING;

    mTrackTranscoders.emplace_back(std::move(transcoder));
    return AMEDIA_OK;
}

media_status_t MediaTranscoder::configureDestination(int fd) {
    if (fd < 0) {
        LOG(ERROR) << "Invalid destination fd: " << fd;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    if (mSampleWriter != nullptr) {
        LOG(ERROR) << "Destination is already configured.";
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    mSampleWriter = MediaSampleWriter::Create();
    const bool initOk = mSampleWriter->init(fd, shared_from_this(), mHeartBeatIntervalUs);

    if (!initOk) {
        LOG(ERROR) << "Unable to initialize sample writer with destination fd: " << fd;
        mSampleWriter.reset();
        return AMEDIA_ERROR_UNKNOWN;
    }

    std::scoped_lock lock{mThreadStateMutex};
    mThreadStates[static_cast<const void*>(mSampleWriter.get())] = PENDING;
    return AMEDIA_OK;
}

media_status_t MediaTranscoder::start() {
    if (mTrackTranscoders.size() < 1) {
        LOG(ERROR) << "Unable to start, no tracks are configured.";
        return AMEDIA_ERROR_INVALID_OPERATION;
    } else if (mSampleWriter == nullptr) {
        LOG(ERROR) << "Unable to start, destination is not configured";
        return AMEDIA_ERROR_INVALID_OPERATION;
    }

    // Start transcoders
    bool started = true;
    {
        std::scoped_lock lock{mThreadStateMutex};
        for (auto& transcoder : mTrackTranscoders) {
            if (!(started = transcoder->start())) {
                break;
            }
            mThreadStates[static_cast<const void*>(transcoder.get())] = RUNNING;
        }
    }
    if (!started) {
        LOG(ERROR) << "Unable to start track transcoder.";
        cancel();
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t MediaTranscoder::requestStop(bool stopOnSync) {
    std::scoped_lock lock{mThreadStateMutex};
    if (mCancelled) {
        LOG(DEBUG) << "MediaTranscoder already cancelled";
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    if (!stopOnSync) {
        mSampleWriterStopped = true;
        mSampleWriter->stop();
    }

    mSampleReader->setEnforceSequentialAccess(false);
    for (auto& transcoder : mTrackTranscoders) {
        transcoder->stop(stopOnSync);
    }

    mCancelled = true;
    return AMEDIA_OK;
}

void MediaTranscoder::waitForThreads() NO_THREAD_SAFETY_ANALYSIS {
    std::unique_lock lock{mThreadStateMutex};
    while (!mThreadsDone) {
        mThreadsDoneSignal.wait(lock);
    }
}

media_status_t MediaTranscoder::pause(std::shared_ptr<ndk::ScopedAParcel>* pausedState) {
    media_status_t status = requestStop(true /* stopOnSync */);
    if (status != AMEDIA_OK) {
        return status;
    }

    waitForThreads();

    // TODO: write internal states to parcel.
    *pausedState = std::shared_ptr<::ndk::ScopedAParcel>(new ::ndk::ScopedAParcel());
    return AMEDIA_OK;
}

media_status_t MediaTranscoder::cancel() {
    media_status_t status = requestStop(false /* stopOnSync */);
    if (status != AMEDIA_OK) {
        return status;
    }

    waitForThreads();

    // TODO: Release transcoders?
    return AMEDIA_OK;
}

media_status_t MediaTranscoder::resume() {
    // TODO: restore internal states from parcel.
    return start();
}

}  // namespace android
