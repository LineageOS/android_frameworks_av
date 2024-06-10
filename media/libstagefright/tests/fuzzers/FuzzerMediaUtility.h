/*
 * Copyright 2020 The Android Open Source Project
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

#pragma once

#include <fuzzer/FuzzedDataProvider.h>

#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaWriter.h>

namespace android {
class FuzzSource : public MediaSource {
  public:
    FuzzSource(sp<MetaData> meta, FuzzedDataProvider* fdp) : mMetaData(meta), mFdp(fdp) {}

    status_t start(MetaData*) { return OK; }

    virtual status_t stop() { return OK; }

    status_t read(MediaBufferBase** buffer, const ReadOptions*) {
        // Ensuring that mBuffer has at least two bytes to avoid check failure
        // in MPEG2TSWriter::SourceInfo::onMessageReceived().
        if (mFdp->remaining_bytes() > 2) {
            auto size = mFdp->ConsumeIntegralInRange<uint8_t>(2, INT8_MAX);
            mBuffer = mFdp->ConsumeBytes<uint8_t>(size);
            MediaBufferBase* mbb = new MediaBuffer(mBuffer.data(), mBuffer.size());

            size_t length = mFdp->ConsumeIntegralInRange<size_t>(2, mbb->size());
            size_t offset = mFdp->ConsumeIntegralInRange<size_t>(0, mbb->size() - length);
            mbb->set_range(offset, length);

            mbb->meta_data().setInt32(kKeyIsEndOfStream, mFdp->ConsumeBool());
            mbb->meta_data().setInt64(kKeyTime, mFdp->ConsumeIntegral<uint32_t>() / 2);
            *buffer = mbb;

            return OK;
        }

        return ERROR_END_OF_STREAM;
    }

    sp<MetaData> getFormat() { return mMetaData; }

  private:
    sp<MetaData> mMetaData = nullptr;
    FuzzedDataProvider* mFdp = nullptr;
    std::vector<uint8_t> mBuffer;
};

enum StandardWriters {
    OGG,
    AAC,
    AAC_ADTS,
    WEBM,
    MPEG4,
    AMR_NB,
    AMR_WB,
    MPEG2TS,
    // Allows FuzzedDataProvider to find the end of this enum.
    kMaxValue = MPEG2TS,
};

static const uint32_t kSampleRateTable[] = {
        8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000,
};
static const std::string kMpeg4MimeTypes[] = {
        MEDIA_MIMETYPE_IMAGE_ANDROID_HEIC, MEDIA_MIMETYPE_IMAGE_AVIF,

        MEDIA_MIMETYPE_VIDEO_AV1,          MEDIA_MIMETYPE_VIDEO_AVC,
        MEDIA_MIMETYPE_VIDEO_HEVC,         MEDIA_MIMETYPE_VIDEO_MPEG4,
        MEDIA_MIMETYPE_VIDEO_H263,         MEDIA_MIMETYPE_VIDEO_DOLBY_VISION,

        MEDIA_MIMETYPE_AUDIO_AMR_NB,       MEDIA_MIMETYPE_AUDIO_AMR_WB,
        MEDIA_MIMETYPE_AUDIO_AAC,
};

sp<MediaWriter> createWriter(int32_t fd, StandardWriters writerType, sp<MetaData> writerMeta,
                             FuzzedDataProvider* fdp);

sp<FuzzSource> createSource(StandardWriters writerType, FuzzedDataProvider* fdp);
}  // namespace android
