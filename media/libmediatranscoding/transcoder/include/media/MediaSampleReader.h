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

#ifndef ANDROID_MEDIA_SAMPLE_READER_H
#define ANDROID_MEDIA_SAMPLE_READER_H

#include <media/MediaSample.h>
#include <media/NdkMediaError.h>
#include <media/NdkMediaFormat.h>

namespace android {

/**
 * MediaSampleReader is an interface for reading media samples from a container.
 * MediaSampleReader allows for reading samples from multiple tracks independently of each other
 * while preserving the order of samples within each individual track.
 * MediaSampleReader implementations are thread safe and can be used by multiple threads
 * concurrently. But note that MediaSampleReader only maintains one state per track so concurrent
 * usage of the same track from multiple threads has no benefit.
 */
class MediaSampleReader {
public:
    /**
     * Returns the file format of the media container as a AMediaFormat.
     * The caller is responsible for releasing the format when finished with it using
     * AMediaFormat_delete().
     * @return The file media format.
     */
    virtual AMediaFormat* getFileFormat() = 0;

    /**
     * Returns the number of tracks in the media container.
     * @return The number of tracks.
     */
    virtual size_t getTrackCount() const = 0;

    /**
     * Returns the media format of a specific track as a AMediaFormat.
     * The caller is responsible for releasing the format when finished with it using
     * AMediaFormat_delete().
     * @param trackIndex The track index (zero-based).
     * @return The track media format.
     */
    virtual AMediaFormat* getTrackFormat(int trackIndex) = 0;

    /**
     * Returns the sample information for the current sample in the specified track.
     * @param trackIndex The track index (zero-based).
     * @param info Pointer to a MediaSampleInfo object where the sample information is written.
     * @return AMEDIA_OK on success, AMEDIA_ERROR_END_OF_STREAM if there are no more samples to read
     * from the track and AMEDIA_ERROR_INVALID_PARAMETER if trackIndex is out of bounds or the
     * info pointer is NULL. Other AMEDIA_ERROR_* return values may not be recoverable.
     */
    virtual media_status_t getSampleInfoForTrack(int trackIndex, MediaSampleInfo* info) = 0;

    /**
     * Reads the current sample's data into the supplied buffer.
     * @param trackIndex The track index (zero-based).
     * @param buffer The buffer to write the sample's data to.
     * @param bufferSize The size of the supplied buffer.
     * @return AMEDIA_OK on success, AMEDIA_ERROR_END_OF_STREAM if there are no more samples to read
     * from the track and AMEDIA_ERROR_INVALID_PARAMETER if trackIndex is out of bounds, if the
     * buffer pointer is NULL or if bufferSize is too small for the sample. Other AMEDIA_ERROR_*
     * return values may not be recoverable.
     */
    virtual media_status_t readSampleDataForTrack(int trackIndex, uint8_t* buffer,
                                                  size_t bufferSize) = 0;

    /**
     * Advance the specified track to the next sample.
     * @param trackIndex The track index (zero-based).
     */
    virtual void advanceTrack(int trackIndex) = 0;

    /** Destructor. */
    virtual ~MediaSampleReader() = default;

    /** Constructor. */
    MediaSampleReader() = default;

private:
    MediaSampleReader(const MediaSampleReader&) = delete;
    MediaSampleReader& operator=(const MediaSampleReader&) = delete;
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_READER_H
