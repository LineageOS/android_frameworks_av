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

#ifndef ANDROID_MEDIA_SAMPLE_READER_NDK_H
#define ANDROID_MEDIA_SAMPLE_READER_NDK_H

#include <media/MediaSampleReader.h>
#include <media/NdkMediaExtractor.h>

#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace android {

/**
 * MediaSampleReaderNDK is a concrete implementation of the MediaSampleReader interface based on the
 * media NDK extractor.
 */
class MediaSampleReaderNDK : public MediaSampleReader {
public:
    /**
     * Creates a new MediaSampleReaderNDK instance wrapped in a shared pointer.
     * @param fd Source file descriptor. The caller is responsible for closing the fd and it is safe
     *           to do so when this method returns.
     * @param offset Source data offset.
     * @param size Source data size.
     * @return A shared pointer referencing the new MediaSampleReaderNDK instance on success, or an
     *         empty shared pointer if an error occurred.
     */
    static std::shared_ptr<MediaSampleReader> createFromFd(int fd, size_t offset, size_t size);

    AMediaFormat* getFileFormat() override;
    size_t getTrackCount() const override;
    AMediaFormat* getTrackFormat(int trackIndex) override;
    media_status_t selectTrack(int trackIndex) override;
    media_status_t unselectTrack(int trackIndex) override;
    media_status_t setEnforceSequentialAccess(bool enforce) override;
    media_status_t getEstimatedBitrateForTrack(int trackIndex, int32_t* bitrate) override;
    media_status_t getSampleInfoForTrack(int trackIndex, MediaSampleInfo* info) override;
    media_status_t readSampleDataForTrack(int trackIndex, uint8_t* buffer,
                                          size_t bufferSize) override;
    void advanceTrack(int trackIndex) override;

    virtual ~MediaSampleReaderNDK() override;

private:
    /**
     * SamplePosition describes the position of a single sample in the media file using its
     * timestamp and index in the file.
     */
    struct SamplePosition {
        uint64_t index = 0;
        int64_t timeStampUs = 0;
        bool isSet = false;

        void set(uint64_t sampleIndex, int64_t sampleTimeUs) {
            index = sampleIndex;
            timeStampUs = sampleTimeUs;
            isSet = true;
        }

        void reset() { isSet = false; }
    };

    /**
     * SampleCursor keeps track of the sample position for a specific track. When the track is
     * advanced, previous is set to current, current to next and next is reset. As the extractor
     * advances over the combined timeline of tracks, it updates current and next for the track it
     * points to if they are not already set.
     */
    struct SampleCursor {
        SamplePosition previous;
        SamplePosition current;
        SamplePosition next;
    };

    /**
     * Creates a new MediaSampleReaderNDK object from an AMediaExtractor. The extractor needs to be
     * initialized with a valid data source before attempting to create a MediaSampleReaderNDK.
     * @param extractor The initialized media extractor.
     */
    MediaSampleReaderNDK(AMediaExtractor* extractor);

    /** Advances the track to next sample. */
    void advanceTrack_l(int trackIndex);

    /** Advances the extractor to next sample. */
    bool advanceExtractor_l();

    /** Moves the extractor backwards to the specified sample. */
    media_status_t seekExtractorBackwards_l(int64_t targetTimeUs, int targetTrackIndex,
                                            uint64_t targetSampleIndex);

    /** Moves the extractor to the specified sample. */
    media_status_t moveToSample_l(SamplePosition& pos, int trackIndex);

    /** Moves the extractor to the next sample of the specified track. */
    media_status_t moveToTrack_l(int trackIndex);

    /** In sequential mode, waits for the extractor to reach the next sample for the track. */
    media_status_t waitForTrack_l(int trackIndex, std::unique_lock<std::mutex>& lockHeld);

    /**
     * Ensures the extractor is ready for the next sample of the track regardless of access mode.
     */
    media_status_t primeExtractorForTrack_l(int trackIndex, std::unique_lock<std::mutex>& lockHeld);

    AMediaExtractor* mExtractor = nullptr;
    std::mutex mExtractorMutex;
    const size_t mTrackCount;

    int mExtractorTrackIndex = -1;
    uint64_t mExtractorSampleIndex = 0;

    bool mEosReached = false;
    bool mEnforceSequentialAccess = false;

    // Maps selected track indices to condition variables for sequential sample access control.
    std::map<int, std::condition_variable> mTrackSignals;

    // Samples cursor for each track in the file.
    std::vector<SampleCursor> mTrackCursors;
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_READER_NDK_H
