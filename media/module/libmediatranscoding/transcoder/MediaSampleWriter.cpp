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
#define LOG_TAG "MediaSampleWriter"

#include <android-base/logging.h>
#include <media/MediaSampleWriter.h>
#include <media/NdkCommon.h>
#include <media/NdkMediaMuxer.h>
#include <sys/prctl.h>
#include <utils/AndroidThreads.h>

namespace android {

class DefaultMuxer : public MediaSampleWriterMuxerInterface {
public:
    // MediaSampleWriterMuxerInterface
    ssize_t addTrack(AMediaFormat* trackFormat) override {
        // If the track format has rotation, need to call AMediaMuxer_setOrientationHint
        // to set the rotation. Muxer doesn't take rotation specified on the track.
        const char* mime;
        if (AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime) &&
            strncmp(mime, "video/", 6) == 0) {
            int32_t rotation;
            if (AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_ROTATION, &rotation) &&
                (rotation != 0)) {
                AMediaMuxer_setOrientationHint(mMuxer, rotation);
            }
        }

        return AMediaMuxer_addTrack(mMuxer, trackFormat);
    }
    media_status_t start() override { return AMediaMuxer_start(mMuxer); }
    media_status_t writeSampleData(size_t trackIndex, const uint8_t* data,
                                   const AMediaCodecBufferInfo* info) override {
        return AMediaMuxer_writeSampleData(mMuxer, trackIndex, data, info);
    }
    media_status_t stop() override { return AMediaMuxer_stop(mMuxer); }
    // ~MediaSampleWriterMuxerInterface

    static std::shared_ptr<DefaultMuxer> create(int fd) {
        AMediaMuxer* ndkMuxer = AMediaMuxer_new(fd, AMEDIAMUXER_OUTPUT_FORMAT_MPEG_4);
        if (ndkMuxer == nullptr) {
            LOG(ERROR) << "Unable to create AMediaMuxer";
            return nullptr;
        }

        return std::make_shared<DefaultMuxer>(ndkMuxer);
    }

    ~DefaultMuxer() {
        if (mMuxer != nullptr) {
            AMediaMuxer_delete(mMuxer);
        }
    }

    DefaultMuxer(AMediaMuxer* muxer) : mMuxer(muxer){};
    DefaultMuxer() = delete;

private:
    AMediaMuxer* mMuxer;
};

// static
std::shared_ptr<MediaSampleWriter> MediaSampleWriter::Create() {
    return std::shared_ptr<MediaSampleWriter>(new MediaSampleWriter());
}

MediaSampleWriter::~MediaSampleWriter() {
    if (mState == STARTED) {
        stop();
    }
}

bool MediaSampleWriter::init(int fd, const std::weak_ptr<CallbackInterface>& callbacks,
                             int64_t heartBeatIntervalUs) {
    return init(DefaultMuxer::create(fd), callbacks, heartBeatIntervalUs);
}

bool MediaSampleWriter::init(const std::shared_ptr<MediaSampleWriterMuxerInterface>& muxer,
                             const std::weak_ptr<CallbackInterface>& callbacks,
                             int64_t heartBeatIntervalUs) {
    if (callbacks.lock() == nullptr) {
        LOG(ERROR) << "Callback object cannot be null";
        return false;
    } else if (muxer == nullptr) {
        LOG(ERROR) << "Muxer cannot be null";
        return false;
    }

    std::scoped_lock lock(mMutex);
    if (mState != UNINITIALIZED) {
        LOG(ERROR) << "Sample writer is already initialized";
        return false;
    }

    mState = INITIALIZED;
    mMuxer = muxer;
    mCallbacks = callbacks;
    mHeartBeatIntervalUs = heartBeatIntervalUs;
    return true;
}

MediaSampleWriter::MediaSampleConsumerFunction MediaSampleWriter::addTrack(
        const std::shared_ptr<AMediaFormat>& trackFormat) {
    if (trackFormat == nullptr) {
        LOG(ERROR) << "Track format must be non-null";
        return nullptr;
    }

    std::scoped_lock lock(mMutex);
    if (mState != INITIALIZED) {
        LOG(ERROR) << "Muxer needs to be initialized when adding tracks.";
        return nullptr;
    }

    AMediaFormat* trackFormatCopy = AMediaFormat_new();
    AMediaFormat_copy(trackFormatCopy, trackFormat.get());
    // Request muxer to use background priorities by default.
    AMediaFormatUtils::SetDefaultFormatValueInt32(TBD_AMEDIACODEC_PARAMETER_KEY_BACKGROUND_MODE,
                                                  trackFormatCopy, 1 /* true */);

    ssize_t trackIndexOrError = mMuxer->addTrack(trackFormatCopy);
    AMediaFormat_delete(trackFormatCopy);
    if (trackIndexOrError < 0) {
        LOG(ERROR) << "Failed to add media track to muxer: " << trackIndexOrError;
        return nullptr;
    }
    const size_t trackIndex = static_cast<size_t>(trackIndexOrError);

    int64_t durationUs;
    if (!AMediaFormat_getInt64(trackFormat.get(), AMEDIAFORMAT_KEY_DURATION, &durationUs)) {
        durationUs = 0;
    }

    mTracks.emplace(trackIndex, durationUs);
    std::shared_ptr<MediaSampleWriter> thisWriter = shared_from_this();

    return [self = shared_from_this(), trackIndex](const std::shared_ptr<MediaSample>& sample) {
        self->addSampleToTrack(trackIndex, sample);
    };
}

void MediaSampleWriter::addSampleToTrack(size_t trackIndex,
                                         const std::shared_ptr<MediaSample>& sample) {
    if (sample == nullptr) return;

    bool wasEmpty;
    {
        std::scoped_lock lock(mMutex);
        wasEmpty = mSampleQueue.empty();
        mSampleQueue.push(std::make_pair(trackIndex, sample));
    }

    if (wasEmpty) {
        mSampleSignal.notify_one();
    }
}

bool MediaSampleWriter::start() {
    std::scoped_lock lock(mMutex);

    if (mTracks.size() == 0) {
        LOG(ERROR) << "No tracks to write.";
        return false;
    } else if (mState != INITIALIZED) {
        LOG(ERROR) << "Sample writer is not initialized";
        return false;
    }

    mState = STARTED;
    std::thread([this] {
        androidSetThreadPriority(0 /* tid (0 = current) */, ANDROID_PRIORITY_BACKGROUND);
        prctl(PR_SET_NAME, (unsigned long)"SampleWriterTrd", 0, 0, 0);

        bool wasStopped = false;
        media_status_t status = writeSamples(&wasStopped);
        if (auto callbacks = mCallbacks.lock()) {
            if (wasStopped && status == AMEDIA_OK) {
                callbacks->onStopped(this);
            } else {
                callbacks->onFinished(this, status);
            }
        }
    }).detach();
    return true;
}

void MediaSampleWriter::stop() {
    {
        std::scoped_lock lock(mMutex);
        if (mState != STARTED) {
            LOG(ERROR) << "Sample writer is not started.";
            return;
        }
        mState = STOPPED;
    }

    mSampleSignal.notify_all();
}

media_status_t MediaSampleWriter::writeSamples(bool* wasStopped) {
    media_status_t muxerStatus = mMuxer->start();
    if (muxerStatus != AMEDIA_OK) {
        LOG(ERROR) << "Error starting muxer: " << muxerStatus;
        return muxerStatus;
    }

    media_status_t writeStatus = runWriterLoop(wasStopped);
    if (writeStatus != AMEDIA_OK) {
        LOG(ERROR) << "Error writing samples: " << writeStatus;
    }

    muxerStatus = mMuxer->stop();
    if (muxerStatus != AMEDIA_OK) {
        LOG(ERROR) << "Error stopping muxer: " << muxerStatus;
    }

    return writeStatus != AMEDIA_OK ? writeStatus : muxerStatus;
}

media_status_t MediaSampleWriter::runWriterLoop(bool* wasStopped) NO_THREAD_SAFETY_ANALYSIS {
    AMediaCodecBufferInfo bufferInfo;
    int32_t lastProgressUpdate = 0;
    bool progressSinceLastReport = false;
    int trackEosCount = 0;

    // Set the "primary" track that will be used to determine progress to the track with longest
    // duration.
    int primaryTrackIndex = -1;
    int64_t longestDurationUs = 0;
    for (auto it = mTracks.begin(); it != mTracks.end(); ++it) {
        if (it->second.mDurationUs > longestDurationUs) {
            primaryTrackIndex = it->first;
            longestDurationUs = it->second.mDurationUs;
        }
    }

    std::chrono::microseconds updateInterval(mHeartBeatIntervalUs);
    std::chrono::steady_clock::time_point nextUpdateTime =
            std::chrono::steady_clock::now() + updateInterval;

    while (true) {
        if (trackEosCount >= mTracks.size()) {
            break;
        }

        size_t trackIndex;
        std::shared_ptr<MediaSample> sample;
        {
            std::unique_lock lock(mMutex);
            while (mSampleQueue.empty() && mState == STARTED) {
                if (mHeartBeatIntervalUs <= 0) {
                    mSampleSignal.wait(lock);
                    continue;
                }

                if (mSampleSignal.wait_until(lock, nextUpdateTime) == std::cv_status::timeout) {
                    // Send heart-beat if there is any progress since last update time.
                    if (progressSinceLastReport) {
                        if (auto callbacks = mCallbacks.lock()) {
                            callbacks->onHeartBeat(this);
                        }
                        progressSinceLastReport = false;
                    }
                    nextUpdateTime += updateInterval;
                }
            }

            if (mState == STOPPED) {
                *wasStopped = true;
                return AMEDIA_OK;
            }

            auto& topEntry = mSampleQueue.top();
            trackIndex = topEntry.first;
            sample = topEntry.second;
            mSampleQueue.pop();
        }

        TrackRecord& track = mTracks[trackIndex];

        if (sample->info.flags & SAMPLE_FLAG_END_OF_STREAM) {
            if (track.mReachedEos) {
                continue;
            }

            // Track reached end of stream.
            track.mReachedEos = true;
            trackEosCount++;

            // Preserve source track duration by setting the appropriate timestamp on the
            // empty End-Of-Stream sample.
            if (track.mDurationUs > 0 && track.mFirstSampleTimeSet) {
                sample->info.presentationTimeUs = track.mDurationUs + track.mFirstSampleTimeUs;
            }
        }

        track.mPrevSampleTimeUs = sample->info.presentationTimeUs;
        if (!track.mFirstSampleTimeSet) {
            // Record the first sample's timestamp in order to translate duration to EOS
            // time for tracks that does not start at 0.
            track.mFirstSampleTimeUs = sample->info.presentationTimeUs;
            track.mFirstSampleTimeSet = true;
        }

        bufferInfo.offset = sample->dataOffset;
        bufferInfo.size = sample->info.size;
        bufferInfo.flags = sample->info.flags;
        bufferInfo.presentationTimeUs = sample->info.presentationTimeUs;

        media_status_t status = mMuxer->writeSampleData(trackIndex, sample->buffer, &bufferInfo);
        if (status != AMEDIA_OK) {
            LOG(ERROR) << "writeSampleData returned " << status;
            return status;
        }
        sample.reset();

        // TODO(lnilsson): Add option to toggle progress reporting on/off.
        if (trackIndex == primaryTrackIndex) {
            const int64_t elapsed = track.mPrevSampleTimeUs - track.mFirstSampleTimeUs;
            int32_t progress = (elapsed * 100) / track.mDurationUs;
            progress = std::clamp(progress, 0, 100);

            if (progress > lastProgressUpdate) {
                if (auto callbacks = mCallbacks.lock()) {
                    callbacks->onProgressUpdate(this, progress);
                }
                lastProgressUpdate = progress;
            }
        }
        progressSinceLastReport = true;
    }

    return AMEDIA_OK;
}
}  // namespace android
