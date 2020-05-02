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
#define LOG_TAG "MediaSampleReader"

#include <android-base/logging.h>
#include <media/MediaSampleReaderNDK.h>

#include <algorithm>
#include <vector>

namespace android {

// Check that the extractor sample flags have the expected NDK meaning.
static_assert(SAMPLE_FLAG_SYNC_SAMPLE == AMEDIAEXTRACTOR_SAMPLE_FLAG_SYNC,
              "Sample flag mismatch: SYNC_SAMPLE");

// static
std::shared_ptr<MediaSampleReader> MediaSampleReaderNDK::createFromFd(int fd, size_t offset,
                                                                      size_t size) {
    AMediaExtractor* extractor = AMediaExtractor_new();
    if (extractor == nullptr) {
        LOG(ERROR) << "Unable to allocate AMediaExtractor";
        return nullptr;
    }

    media_status_t status = AMediaExtractor_setDataSourceFd(extractor, fd, offset, size);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "AMediaExtractor_setDataSourceFd returned error: " << status;
        AMediaExtractor_delete(extractor);
        return nullptr;
    }

    auto sampleReader = std::shared_ptr<MediaSampleReaderNDK>(new MediaSampleReaderNDK(extractor));
    status = sampleReader->init();
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "MediaSampleReaderNDK::init returned error: " << status;
        return nullptr;
    }

    return sampleReader;
}

MediaSampleReaderNDK::MediaSampleReaderNDK(AMediaExtractor* extractor)
      : mExtractor(extractor), mTrackCount(AMediaExtractor_getTrackCount(mExtractor)) {
    if (mTrackCount > 0) {
        mTrackCursors.resize(mTrackCount);
        mTrackCursors.resize(mTrackCount);
    }
}

media_status_t MediaSampleReaderNDK::init() {
    for (size_t trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
        media_status_t status = AMediaExtractor_selectTrack(mExtractor, trackIndex);
        if (status != AMEDIA_OK) {
            LOG(ERROR) << "AMediaExtractor_selectTrack returned error: " << status;
            return status;
        }
    }

    mExtractorTrackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
    if (mExtractorTrackIndex >= 0) {
        mTrackCursors[mExtractorTrackIndex].current.set(mExtractorSampleIndex,
                                                        AMediaExtractor_getSampleTime(mExtractor));
    } else if (mTrackCount > 0) {
        // The extractor track index is only allowed to be invalid if there are no tracks.
        LOG(ERROR) << "Track index " << mExtractorTrackIndex << " is invalid for track count "
                   << mTrackCount;
        return AMEDIA_ERROR_MALFORMED;
    }

    return AMEDIA_OK;
}

MediaSampleReaderNDK::~MediaSampleReaderNDK() {
    if (mExtractor != nullptr) {
        AMediaExtractor_delete(mExtractor);
    }
}

bool MediaSampleReaderNDK::advanceExtractor_l() {
    // Reset the "next" sample time whenever the extractor advances past a sample that is current,
    // to ensure that "next" is appropriately updated when the extractor advances over the next
    // sample of that track.
    if (mTrackCursors[mExtractorTrackIndex].current.isSet &&
        mTrackCursors[mExtractorTrackIndex].current.index == mExtractorSampleIndex) {
        mTrackCursors[mExtractorTrackIndex].next.reset();
    }

    if (!AMediaExtractor_advance(mExtractor)) {
        return false;
    }

    mExtractorTrackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
    mExtractorSampleIndex++;

    SampleCursor& cursor = mTrackCursors[mExtractorTrackIndex];
    if (mExtractorSampleIndex > cursor.previous.index) {
        if (!cursor.current.isSet) {
            cursor.current.set(mExtractorSampleIndex, AMediaExtractor_getSampleTime(mExtractor));
        } else if (!cursor.next.isSet && mExtractorSampleIndex > cursor.current.index) {
            cursor.next.set(mExtractorSampleIndex, AMediaExtractor_getSampleTime(mExtractor));
        }
    }
    return true;
}

media_status_t MediaSampleReaderNDK::seekExtractorBackwards_l(int64_t targetTimeUs,
                                                              int targetTrackIndex,
                                                              uint64_t targetSampleIndex) {
    if (targetSampleIndex > mExtractorSampleIndex) {
        LOG(ERROR) << "Error: Forward seek is not supported";
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    // AMediaExtractor supports reading negative timestamps but does not support seeking to them.
    const int64_t seekToTimeUs = std::max(targetTimeUs, (int64_t)0);
    media_status_t status =
            AMediaExtractor_seekTo(mExtractor, seekToTimeUs, AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to seek to " << seekToTimeUs << ", target " << targetTimeUs;
        return status;
    }
    mExtractorTrackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
    int64_t sampleTimeUs = AMediaExtractor_getSampleTime(mExtractor);

    while (sampleTimeUs != targetTimeUs || mExtractorTrackIndex != targetTrackIndex) {
        if (!AMediaExtractor_advance(mExtractor)) {
            return AMEDIA_ERROR_END_OF_STREAM;
        }
        mExtractorTrackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
        sampleTimeUs = AMediaExtractor_getSampleTime(mExtractor);
    }
    mExtractorSampleIndex = targetSampleIndex;
    return AMEDIA_OK;
}

void MediaSampleReaderNDK::advanceTrack(int trackIndex) {
    std::scoped_lock lock(mExtractorMutex);

    if (trackIndex < 0 || trackIndex >= mTrackCount) {
        LOG(ERROR) << "Invalid trackIndex " << trackIndex << " for trackCount " << mTrackCount;
        return;
    }

    // Note: Positioning the extractor before advancing the track is needed for two reasons:
    // 1. To enable multiple advances without explicitly letting the extractor catch up.
    // 2. To prevent the extractor from being farther than "next".
    (void)positionExtractorForTrack_l(trackIndex);

    SampleCursor& cursor = mTrackCursors[trackIndex];
    cursor.previous = cursor.current;
    cursor.current = cursor.next;
    cursor.next.reset();
}

media_status_t MediaSampleReaderNDK::positionExtractorForTrack_l(int trackIndex) {
    media_status_t status = AMEDIA_OK;
    const SampleCursor& cursor = mTrackCursors[trackIndex];

    // Seek backwards if the extractor is ahead of the current time.
    if (cursor.current.isSet && mExtractorSampleIndex > cursor.current.index) {
        status = seekExtractorBackwards_l(cursor.current.timeStampUs, trackIndex,
                                          cursor.current.index);
        if (status != AMEDIA_OK) return status;
    }

    // Advance until extractor points to the current sample.
    while (!(cursor.current.isSet && cursor.current.index == mExtractorSampleIndex)) {
        if (!advanceExtractor_l()) {
            return AMEDIA_ERROR_END_OF_STREAM;
        }
    }

    return AMEDIA_OK;
}

media_status_t MediaSampleReaderNDK::getSampleInfoForTrack(int trackIndex, MediaSampleInfo* info) {
    std::scoped_lock lock(mExtractorMutex);

    if (trackIndex < 0 || trackIndex >= mTrackCount) {
        LOG(ERROR) << "Invalid trackIndex " << trackIndex << " for trackCount " << mTrackCount;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (info == nullptr) {
        LOG(ERROR) << "MediaSampleInfo pointer is NULL.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    media_status_t status = positionExtractorForTrack_l(trackIndex);
    if (status == AMEDIA_OK) {
        info->presentationTimeUs = AMediaExtractor_getSampleTime(mExtractor);
        info->flags = AMediaExtractor_getSampleFlags(mExtractor);
        info->size = AMediaExtractor_getSampleSize(mExtractor);
    } else if (status == AMEDIA_ERROR_END_OF_STREAM) {
        info->presentationTimeUs = 0;
        info->flags = SAMPLE_FLAG_END_OF_STREAM;
        info->size = 0;
    }

    return status;
}

media_status_t MediaSampleReaderNDK::readSampleDataForTrack(int trackIndex, uint8_t* buffer,
                                                            size_t bufferSize) {
    std::scoped_lock lock(mExtractorMutex);

    if (trackIndex < 0 || trackIndex >= mTrackCount) {
        LOG(ERROR) << "Invalid trackIndex " << trackIndex << " for trackCount " << mTrackCount;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (buffer == nullptr) {
        LOG(ERROR) << "buffer pointer is NULL";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    media_status_t status = positionExtractorForTrack_l(trackIndex);
    if (status != AMEDIA_OK) return status;

    ssize_t sampleSize = AMediaExtractor_getSampleSize(mExtractor);
    if (bufferSize < sampleSize) {
        LOG(ERROR) << "Buffer is too small for sample, " << bufferSize << " vs " << sampleSize;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    ssize_t bytesRead = AMediaExtractor_readSampleData(mExtractor, buffer, bufferSize);
    if (bytesRead < sampleSize) {
        LOG(ERROR) << "Unable to read full sample, " << bytesRead << " vs " << sampleSize;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    return AMEDIA_OK;
}

AMediaFormat* MediaSampleReaderNDK::getFileFormat() {
    return AMediaExtractor_getFileFormat(mExtractor);
}

size_t MediaSampleReaderNDK::getTrackCount() const {
    return mTrackCount;
}

AMediaFormat* MediaSampleReaderNDK::getTrackFormat(int trackIndex) {
    if (trackIndex < 0 || trackIndex >= mTrackCount) {
        LOG(ERROR) << "Invalid trackIndex " << trackIndex << " for trackCount " << mTrackCount;
        return AMediaFormat_new();
    }

    return AMediaExtractor_getTrackFormat(mExtractor, trackIndex);
}

}  // namespace android
