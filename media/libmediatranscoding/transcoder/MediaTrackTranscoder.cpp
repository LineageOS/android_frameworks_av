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

    mSourceFormat =
            std::shared_ptr<AMediaFormat>(mMediaSampleReader->getTrackFormat(mTrackIndex),
                                          std::bind(AMediaFormat_delete, std::placeholders::_1));
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

    mTranscodingThread = std::thread([this] {
        media_status_t status = runTranscodeLoop();

        // Notify the client.
        if (auto callbacks = mTranscoderCallback.lock()) {
            if (status != AMEDIA_OK) {
                callbacks->onTrackError(this, status);
            } else {
                callbacks->onTrackFinished(this);
            }
        }
    });

    mState = STARTED;
    return true;
}

bool MediaTrackTranscoder::stop() {
    std::scoped_lock lock{mStateMutex};

    if (mState == STARTED) {
        abortTranscodeLoop();
        mTranscodingThread.join();
        mState = STOPPED;
        return true;
    }

    LOG(ERROR) << "TrackTranscoder must be started before stopped";
    return false;
}

}  // namespace android