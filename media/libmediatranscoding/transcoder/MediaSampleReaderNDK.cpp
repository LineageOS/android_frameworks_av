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
#include <cmath>

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
    return sampleReader;
}

MediaSampleReaderNDK::MediaSampleReaderNDK(AMediaExtractor* extractor)
      : mExtractor(extractor), mTrackCount(AMediaExtractor_getTrackCount(mExtractor)) {
    if (mTrackCount > 0) {
        mTrackCursors.resize(mTrackCount);
    }
}

MediaSampleReaderNDK::~MediaSampleReaderNDK() {
    if (mExtractor != nullptr) {
        AMediaExtractor_delete(mExtractor);
    }
}

void MediaSampleReaderNDK::advanceTrack_l(int trackIndex) {
    if (!mEnforceSequentialAccess) {
        // Note: Positioning the extractor before advancing the track is needed for two reasons:
        // 1. To enable multiple advances without explicitly letting the extractor catch up.
        // 2. To prevent the extractor from being farther than "next".
        (void)moveToTrack_l(trackIndex);
    }

    SampleCursor& cursor = mTrackCursors[trackIndex];
    cursor.previous = cursor.current;
    cursor.current = cursor.next;
    cursor.next.reset();

    if (mEnforceSequentialAccess && trackIndex == mExtractorTrackIndex) {
        while (advanceExtractor_l()) {
            SampleCursor& cursor = mTrackCursors[mExtractorTrackIndex];
            if (cursor.current.isSet && cursor.current.index == mExtractorSampleIndex) {
                if (mExtractorTrackIndex != trackIndex) {
                    mTrackSignals[mExtractorTrackIndex].notify_all();
                }
                break;
            }
        }
    }
    return;
}

bool MediaSampleReaderNDK::advanceExtractor_l() {
    // Reset the "next" sample time whenever the extractor advances past a sample that is current,
    // to ensure that "next" is appropriately updated when the extractor advances over the next
    // sample of that track.
    if (mTrackCursors[mExtractorTrackIndex].current.isSet &&
        mTrackCursors[mExtractorTrackIndex].current.index == mExtractorSampleIndex) {
        mTrackCursors[mExtractorTrackIndex].next.reset();
    }

    // Update the extractor's sample index even if this track reaches EOS, so that the other tracks
    // are not given an incorrect extractor position.
    mExtractorSampleIndex++;
    if (!AMediaExtractor_advance(mExtractor)) {
        LOG(DEBUG) << "  EOS in advanceExtractor_l";
        mEosReached = true;
        for (auto it = mTrackSignals.begin(); it != mTrackSignals.end(); ++it) {
            it->second.notify_all();
        }
        return false;
    }

    mExtractorTrackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);

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

    mEosReached = false;
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

media_status_t MediaSampleReaderNDK::moveToSample_l(SamplePosition& pos, int trackIndex) {
    // Seek backwards if the extractor is ahead of the sample.
    if (pos.isSet && mExtractorSampleIndex > pos.index) {
        media_status_t status = seekExtractorBackwards_l(pos.timeStampUs, trackIndex, pos.index);
        if (status != AMEDIA_OK) return status;
    }

    // Advance until extractor points to the sample.
    while (!(pos.isSet && pos.index == mExtractorSampleIndex)) {
        if (!advanceExtractor_l()) {
            return AMEDIA_ERROR_END_OF_STREAM;
        }
    }

    return AMEDIA_OK;
}

media_status_t MediaSampleReaderNDK::moveToTrack_l(int trackIndex) {
    return moveToSample_l(mTrackCursors[trackIndex].current, trackIndex);
}

media_status_t MediaSampleReaderNDK::waitForTrack_l(int trackIndex,
                                                    std::unique_lock<std::mutex>& lockHeld) {
    while (trackIndex != mExtractorTrackIndex && !mEosReached && mEnforceSequentialAccess) {
        mTrackSignals[trackIndex].wait(lockHeld);
    }

    if (mEosReached) {
        return AMEDIA_ERROR_END_OF_STREAM;
    }

    if (!mEnforceSequentialAccess) {
        return moveToTrack_l(trackIndex);
    }

    return AMEDIA_OK;
}

media_status_t MediaSampleReaderNDK::primeExtractorForTrack_l(
        int trackIndex, std::unique_lock<std::mutex>& lockHeld) {
    if (mExtractorTrackIndex < 0) {
        mExtractorTrackIndex = AMediaExtractor_getSampleTrackIndex(mExtractor);
        if (mExtractorTrackIndex < 0) {
            return AMEDIA_ERROR_END_OF_STREAM;
        }
        mTrackCursors[mExtractorTrackIndex].current.set(mExtractorSampleIndex,
                                                        AMediaExtractor_getSampleTime(mExtractor));
    }

    if (mEnforceSequentialAccess) {
        return waitForTrack_l(trackIndex, lockHeld);
    } else {
        return moveToTrack_l(trackIndex);
    }
}

media_status_t MediaSampleReaderNDK::selectTrack(int trackIndex) {
    std::scoped_lock lock(mExtractorMutex);

    if (trackIndex < 0 || trackIndex >= mTrackCount) {
        LOG(ERROR) << "Invalid trackIndex " << trackIndex << " for trackCount " << mTrackCount;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (mTrackSignals.find(trackIndex) != mTrackSignals.end()) {
        LOG(ERROR) << "TrackIndex " << trackIndex << " already selected";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (mExtractorTrackIndex >= 0) {
        LOG(ERROR) << "Tracks must be selected before sample reading begins.";
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    media_status_t status = AMediaExtractor_selectTrack(mExtractor, trackIndex);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "AMediaExtractor_selectTrack returned error: " << status;
        return status;
    }

    mTrackSignals.emplace(std::piecewise_construct, std::forward_as_tuple(trackIndex),
                          std::forward_as_tuple());
    return AMEDIA_OK;
}

media_status_t MediaSampleReaderNDK::unselectTrack(int trackIndex) {
    std::scoped_lock lock(mExtractorMutex);

    if (trackIndex < 0 || trackIndex >= mTrackCount) {
        LOG(ERROR) << "Invalid trackIndex " << trackIndex << " for trackCount " << mTrackCount;
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (mExtractorTrackIndex >= 0) {
        LOG(ERROR) << "unselectTrack must be called before sample reading begins.";
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    auto it = mTrackSignals.find(trackIndex);
    if (it == mTrackSignals.end()) {
        LOG(ERROR) << "TrackIndex " << trackIndex << " is not selected";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    mTrackSignals.erase(it);

    media_status_t status = AMediaExtractor_unselectTrack(mExtractor, trackIndex);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "AMediaExtractor_selectTrack returned error: " << status;
        return status;
    }

    return AMEDIA_OK;
}

media_status_t MediaSampleReaderNDK::setEnforceSequentialAccess(bool enforce) {
    LOG(DEBUG) << "setEnforceSequentialAccess( " << enforce << " )";

    std::scoped_lock lock(mExtractorMutex);

    if (mEnforceSequentialAccess && !enforce) {
        // If switching from enforcing to not enforcing sequential access there may be threads
        // waiting that needs to be woken up.
        for (auto it = mTrackSignals.begin(); it != mTrackSignals.end(); ++it) {
            it->second.notify_all();
        }
    } else if (!mEnforceSequentialAccess && enforce && mExtractorTrackIndex >= 0) {
        // If switching from not enforcing to enforcing sequential access the extractor needs to be
        // positioned for the track farthest behind so that it won't get stuck waiting.
        struct {
            SamplePosition* pos = nullptr;
            int trackIndex = -1;
        } earliestSample;

        for (int trackIndex = 0; trackIndex < mTrackCount; ++trackIndex) {
            SamplePosition& lastKnownTrackPosition = mTrackCursors[trackIndex].current.isSet
                                                             ? mTrackCursors[trackIndex].current
                                                             : mTrackCursors[trackIndex].previous;

            if (lastKnownTrackPosition.isSet) {
                if (earliestSample.pos == nullptr ||
                    earliestSample.pos->index > lastKnownTrackPosition.index) {
                    earliestSample.pos = &lastKnownTrackPosition;
                    earliestSample.trackIndex = trackIndex;
                }
            }
        }

        if (earliestSample.pos == nullptr) {
            LOG(ERROR) << "No known sample position found";
            return AMEDIA_ERROR_UNKNOWN;
        }

        media_status_t status = moveToSample_l(*earliestSample.pos, earliestSample.trackIndex);
        if (status != AMEDIA_OK) return status;

        while (!(mTrackCursors[mExtractorTrackIndex].current.isSet &&
                 mTrackCursors[mExtractorTrackIndex].current.index == mExtractorSampleIndex)) {
            if (!advanceExtractor_l()) {
                return AMEDIA_ERROR_END_OF_STREAM;
            }
        }
    }

    mEnforceSequentialAccess = enforce;
    return AMEDIA_OK;
}

media_status_t MediaSampleReaderNDK::getEstimatedBitrateForTrack(int trackIndex, int32_t* bitrate) {
    std::scoped_lock lock(mExtractorMutex);
    media_status_t status = AMEDIA_OK;

    if (mTrackSignals.find(trackIndex) == mTrackSignals.end()) {
        LOG(ERROR) << "Track is not selected.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (bitrate == nullptr) {
        LOG(ERROR) << "bitrate pointer is NULL.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (mExtractorTrackIndex >= 0) {
        LOG(ERROR) << "getEstimatedBitrateForTrack must be called before sample reading begins.";
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    // Sample the track.
    static constexpr int64_t kSamplingDurationUs = 10 * 1000 * 1000;  // 10 seconds
    size_t lastSampleSize = 0;
    size_t totalSampleSize = 0;
    int64_t firstSampleTimeUs = 0;
    int64_t lastSampleTimeUs = 0;

    do {
        if (AMediaExtractor_getSampleTrackIndex(mExtractor) == trackIndex) {
            lastSampleTimeUs = AMediaExtractor_getSampleTime(mExtractor);
            if (totalSampleSize == 0) {
                firstSampleTimeUs = lastSampleTimeUs;
            }

            lastSampleSize = AMediaExtractor_getSampleSize(mExtractor);
            totalSampleSize += lastSampleSize;
        }
    } while ((lastSampleTimeUs - firstSampleTimeUs) < kSamplingDurationUs &&
             AMediaExtractor_advance(mExtractor));

    // Reset the extractor to the beginning.
    status = AMediaExtractor_seekTo(mExtractor, 0, AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to reset extractor: " << status;
        return status;
    }

    int64_t durationUs = 0;
    const int64_t sampledDurationUs = lastSampleTimeUs - firstSampleTimeUs;

    if (sampledDurationUs < kSamplingDurationUs) {
        // Track is shorter than the sampling duration so use the full track duration to get better
        // accuracy (i.e. don't skip the last sample).
        AMediaFormat* trackFormat = getTrackFormat(trackIndex);
        if (!AMediaFormat_getInt64(trackFormat, AMEDIAFORMAT_KEY_DURATION, &durationUs)) {
            durationUs = 0;
        }
        AMediaFormat_delete(trackFormat);
    }

    if (durationUs == 0) {
        // The sampled duration does not account for the last sample's duration so its size should
        // not be included either.
        totalSampleSize -= lastSampleSize;
        durationUs = sampledDurationUs;
    }

    if (totalSampleSize == 0 || durationUs <= 0) {
        LOG(ERROR) << "Unable to estimate track bitrate";
        return AMEDIA_ERROR_MALFORMED;
    }

    *bitrate = roundf((float)totalSampleSize * 8 * 1000000 / durationUs);
    return AMEDIA_OK;
}

media_status_t MediaSampleReaderNDK::getSampleInfoForTrack(int trackIndex, MediaSampleInfo* info) {
    std::unique_lock<std::mutex> lock(mExtractorMutex);

    if (mTrackSignals.find(trackIndex) == mTrackSignals.end()) {
        LOG(ERROR) << "Track not selected.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (info == nullptr) {
        LOG(ERROR) << "MediaSampleInfo pointer is NULL.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    media_status_t status = primeExtractorForTrack_l(trackIndex, lock);
    if (status == AMEDIA_OK) {
        info->presentationTimeUs = AMediaExtractor_getSampleTime(mExtractor);
        info->flags = AMediaExtractor_getSampleFlags(mExtractor);
        info->size = AMediaExtractor_getSampleSize(mExtractor);
    } else if (status == AMEDIA_ERROR_END_OF_STREAM) {
        info->presentationTimeUs = 0;
        info->flags = SAMPLE_FLAG_END_OF_STREAM;
        info->size = 0;
        LOG(DEBUG) << "  getSampleInfoForTrack #" << trackIndex << ": End Of Stream";
    } else {
        LOG(ERROR) << "  getSampleInfoForTrack #" << trackIndex << ": Error " << status;
    }

    return status;
}

media_status_t MediaSampleReaderNDK::readSampleDataForTrack(int trackIndex, uint8_t* buffer,
                                                            size_t bufferSize) {
    std::unique_lock<std::mutex> lock(mExtractorMutex);

    if (mTrackSignals.find(trackIndex) == mTrackSignals.end()) {
        LOG(ERROR) << "Track not selected.";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    } else if (buffer == nullptr) {
        LOG(ERROR) << "buffer pointer is NULL";
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    media_status_t status = primeExtractorForTrack_l(trackIndex, lock);
    if (status != AMEDIA_OK) {
        return status;
    }

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

    advanceTrack_l(trackIndex);

    return AMEDIA_OK;
}

void MediaSampleReaderNDK::advanceTrack(int trackIndex) {
    std::scoped_lock lock(mExtractorMutex);

    if (mTrackSignals.find(trackIndex) != mTrackSignals.end()) {
        advanceTrack_l(trackIndex);
    } else {
        LOG(ERROR) << "Trying to advance a track that is not selected (#" << trackIndex << ")";
    }
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
