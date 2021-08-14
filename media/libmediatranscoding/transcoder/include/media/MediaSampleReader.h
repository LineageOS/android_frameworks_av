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
 * MediaSampleReader is an interface for reading media samples from a container. MediaSampleReader
 * allows for reading samples from multiple tracks on individual threads independently of each other
 * while preserving the order of samples. Due to poor non-sequential access performance of the
 * underlying extractor, MediaSampleReader can optionally enforce sequential sample access by
 * blocking requests for tracks that the underlying extractor does not currently point to. Waiting
 * threads are serviced once the reader advances to a sample from the specified track. Due to this
 * it is important to read samples and advance the reader from all selected tracks to avoid hanging
 * other tracks. MediaSampleReader implementations are thread safe and sample access should be done
 * on one thread per selected track.
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
     * Select a track for sample access. Tracks must be selected in order for sample information and
     * sample data to be available for that track. Samples for selected tracks must be accessed on
     * its own thread to avoid blocking other tracks.
     * @param trackIndex The track to select.
     * @return AMEDIA_OK on success.
     */
    virtual media_status_t selectTrack(int trackIndex) = 0;

    /**
     * Undo a track selection.
     * @param trackIndex The track to un-select.
     * @return AMEDIA_OK on success.
     */
    virtual media_status_t unselectTrack(int trackIndex) = 0;

    /**
     * Toggles sequential access enforcement on or off. When the reader enforces sequential access
     * calls to read sample information will block unless the underlying extractor points to the
     * specified track.
     * @param enforce True to enforce sequential access.
     * @return AMEDIA_OK on success.
     */
    virtual media_status_t setEnforceSequentialAccess(bool enforce) = 0;

    /**
     * Estimates the bitrate of a source track by sampling sample sizes. The bitrate is returned in
     * megabits per second (Mbps). This method will fail if the track only contains a single sample
     * and does not have an associated duration.
     * @param trackIndex The source track index.
     * @param bitrate Output param for the bitrate.
     * @return AMEDIA_OK on success.
     */
    virtual media_status_t getEstimatedBitrateForTrack(int trackIndex, int32_t* bitrate);

    /**
     * Returns the sample information for the current sample in the specified track. Note that this
     * method will block until the reader advances to a sample belonging to the requested track if
     * the reader is in sequential access mode.
     * @param trackIndex The track index (zero-based).
     * @param info Pointer to a MediaSampleInfo object where the sample information is written.
     * @return AMEDIA_OK on success, AMEDIA_ERROR_END_OF_STREAM if there are no more samples to read
     * from the track and AMEDIA_ERROR_INVALID_PARAMETER if trackIndex is out of bounds or the
     * info pointer is NULL. Other AMEDIA_ERROR_* return values may not be recoverable.
     */
    virtual media_status_t getSampleInfoForTrack(int trackIndex, MediaSampleInfo* info) = 0;

    /**
     * Returns the sample data for the current sample in the specified track into the supplied
     * buffer. Note that this method will block until the reader advances to a sample belonging to
     * the requested track if the reader is in sequential access mode. Upon successful return this
     * method will also advance the specified track to the next sample.
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
     * Advance the specified track to the next sample. If the reader is in sequential access mode
     * and the current sample belongs to the specified track, the reader will also advance to the
     * next sample and wake up any threads waiting on the new track.
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
