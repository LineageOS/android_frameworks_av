/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_APPENDER_H
#define ANDROID_MEDIA_APPENDER_H

#include <media/stagefright/MediaMuxer.h>
#include <media/stagefright/NuMediaExtractor.h>
#include <stack>

namespace android {

struct MediaAppender : public MediaMuxerBase {
public:
    enum AppendMode {
        APPEND_MODE_FIRST = 0,
        APPEND_MODE_IGNORE_LAST_VIDEO_GOP = APPEND_MODE_FIRST,
        APPEND_MODE_ADD_TO_EXISTING_DATA = 1,
        APPEND_MODE_LAST = APPEND_MODE_ADD_TO_EXISTING_DATA,
    };

    static sp<MediaAppender> create(int fd, AppendMode mode);

    virtual ~MediaAppender();

    status_t init();

    status_t start();

    status_t stop();

    status_t writeSampleData(const sp<ABuffer>& buffer, size_t trackIndex, int64_t timeUs,
                             uint32_t flags);

    status_t setOrientationHint(int degrees);

    status_t setLocation(int latitude, int longitude);

    ssize_t addTrack(const sp<AMessage> &format);

    ssize_t getTrackCount();

    sp<AMessage> getTrackFormat(size_t idx);

private:
    MediaAppender(int fd, AppendMode mode);

    int mFd;
    MediaMuxer::OutputFormat mFormat;
    AppendMode mMode;
    sp<NuMediaExtractor> mExtractor;
    sp<MediaMuxer> mMuxer;
    size_t mTrackCount;
    // Map track index given by extractor to the ones received from muxer.
    std::map<size_t, ssize_t> mTrackIndexMap;
    // Count of the samples in each track, indexed by extractor track ids.
    std::vector<size_t> mSampleCountVect;
    // Extractor track index of samples.
    std::vector<size_t> mSampleIndexVect;
    // Track format indexed by extractor track ids.
    std::map<size_t, sp<AMessage>> mFmtIndexMap;
    // Size of samples.
    std::vector<size_t> mSampleSizeVect;
    // Presentation time stamp of samples.
    std::vector<int64_t> mSampleTimeVect;
    // Timestamp of last sample of tracks.
    std::vector<int64_t> mMaxTimestampVect;
    // Metadata of samples.
    std::vector<sp<MetaData>> mSampleMetaVect;
    std::mutex mMutex;
    // Timestamp of the last sync sample of tracks.
    std::vector<int64_t> mLastSyncSampleTimeVect;

    struct sampleDataInfo;
    std::vector<sampleDataInfo> mSDI;

    enum : int {
        UNINITIALIZED,
        INITIALIZED,
        STARTED,
        STOPPED,
        ERROR,
    } mState GUARDED_BY(mMutex);
};

}  // namespace android
#endif  // ANDROID_MEDIA_APPENDER_H