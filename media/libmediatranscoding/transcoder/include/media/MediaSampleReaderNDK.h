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
    media_status_t getSampleInfoForTrack(int trackIndex, MediaSampleInfo* info) override;
    media_status_t readSampleDataForTrack(int trackIndex, uint8_t* buffer,
                                          size_t bufferSize) override;
    void advanceTrack(int trackIndex) override;

    virtual ~MediaSampleReaderNDK() override;

private:
    /**
     * Creates a new MediaSampleReaderNDK object from an AMediaExtractor. The extractor needs to be
     * initialized with a valid data source before attempting to create a MediaSampleReaderNDK.
     * @param extractor The initialized media extractor.
     */
    MediaSampleReaderNDK(AMediaExtractor* extractor);
    media_status_t init();

    AMediaExtractor* mExtractor = nullptr;
    std::mutex mExtractorMutex;
    const size_t mTrackCount;

    int mExtractorTrackIndex = -1;
    uint64_t mExtractorSampleIndex = 0;

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

    /** Samples cursor for each track in the file. */
    std::vector<SampleCursor> mTrackCursors;

    bool advanceExtractor_l();
    media_status_t positionExtractorForTrack_l(int trackIndex);
    media_status_t seekExtractorBackwards_l(int64_t targetTimeUs, int targetTrackIndex,
                                            uint64_t targetSampleIndex);
};

}  // namespace android
#endif  // ANDROID_MEDIA_SAMPLE_READER_NDK_H
