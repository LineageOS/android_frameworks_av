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
#define LOG_TAG "MediaTrackTranscoder"

#include <android-base/logging.h>
#include <media/MediaTrackTranscoder.h>
#include <media/MediaTrackTranscoderCallback.h>
#include <utils/AndroidThreads.h>

namespace android {

media_status_t MediaTrackTranscoder::configure(
        const std::shared_ptr<MediaSampleReader>& mediaSampleReader, int trackIndex,
        const std::shared_ptr<AMediaFormat>& destinationFormat) {
    std::scoped_lock lock{mStateMutex};

    if (mState != UNINITIALIZED) {
        LOG(ERROR) << "Configure can only be called once";
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    if (mediaSampleReader == nullptr) {
        LOG(ERROR) << "MediaSampleReader is null";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    if (trackIndex < 0 || trackIndex >= mediaSampleReader->getTrackCount()) {
        LOG(ERROR) << "TrackIndex is invalid " << trackIndex;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    mMediaSampleReader = mediaSampleReader;
    mTrackIndex = trackIndex;

    mSourceFormat = std::shared_ptr<AMediaFormat>(mMediaSampleReader->getTrackFormat(mTrackIndex),
                                                  &AMediaFormat_delete);
    if (mSourceFormat == nullptr) {
        LOG(ERROR) << "Unable to get format for track #" << mTrackIndex;
        return AMEDIA_ERROR_MALFORMED;
    }

    media_status_t status = configureDestinationFormat(destinationFormat);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "configure failed with error " << status;
        return status;
    }

    mState = CONFIGURED;
    return AMEDIA_OK;
}

bool MediaTrackTranscoder::start() {
    std::scoped_lock lock{mStateMutex};

    if (mState != CONFIGURED) {
        LOG(ERROR) << "TrackTranscoder must be configured before started";
        return false;
    }
    mState = STARTED;

    std::thread([this] {
        androidSetThreadPriority(0 /* tid (0 = current) */, ANDROID_PRIORITY_BACKGROUND);
        bool stopped = false;
        media_status_t status = runTranscodeLoop(&stopped);

        // Output an EOS sample if the transcoder was stopped.
        if (stopped) {
            auto sample = std::make_shared<MediaSample>();
            sample->info.flags = SAMPLE_FLAG_END_OF_STREAM;
            onOutputSampleAvailable(sample);
        }

        // Notify the client.
        if (auto callbacks = mTranscoderCallback.lock()) {
            if (stopped) {
                callbacks->onTrackStopped(this);
            } else if (status == AMEDIA_OK) {
                callbacks->onTrackFinished(this);
            } else {
                callbacks->onTrackError(this, status);
            }
        }
    }).detach();

    return true;
}

void MediaTrackTranscoder::stop(bool stopOnSyncSample) {
    std::scoped_lock lock{mStateMutex};

    if (mState == STARTED || (mStopRequest == STOP_ON_SYNC && !stopOnSyncSample)) {
        mStopRequest = stopOnSyncSample ? STOP_ON_SYNC : STOP_NOW;
        abortTranscodeLoop();
        mState = STOPPED;
    } else {
        LOG(WARNING) << "TrackTranscoder must be started before stopped";
    }
}

void MediaTrackTranscoder::notifyTrackFormatAvailable() {
    if (auto callbacks = mTranscoderCallback.lock()) {
        callbacks->onTrackFormatAvailable(this);
    }
}

void MediaTrackTranscoder::onOutputSampleAvailable(const std::shared_ptr<MediaSample>& sample) {
    std::scoped_lock lock{mSampleMutex};
    if (mSampleConsumer == nullptr) {
        mSampleQueue.enqueue(sample);
    } else {
        mSampleConsumer(sample);
    }
}

void MediaTrackTranscoder::setSampleConsumer(
        const MediaSampleWriter::MediaSampleConsumerFunction& sampleConsumer) {
    std::scoped_lock lock{mSampleMutex};
    mSampleConsumer = sampleConsumer;

    std::shared_ptr<MediaSample> sample;
    while (!mSampleQueue.isEmpty() && !mSampleQueue.dequeue(&sample)) {
        mSampleConsumer(sample);
    }
}

}  // namespace android
