/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <StagefrightMetadataRetriever.h>
#include <binder/ProcessState.h>
#include <datasource/FileSource.h>
#include <media/IMediaHTTPService.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/foundation/base64.h>

#include <fuzzer/FuzzedDataProvider.h>

using namespace std;
using namespace android;

const char *kMimeTypes[] = {MEDIA_MIMETYPE_IMAGE_JPEG,         MEDIA_MIMETYPE_IMAGE_ANDROID_HEIC,
                            MEDIA_MIMETYPE_VIDEO_VP8,          MEDIA_MIMETYPE_VIDEO_VP9,
                            MEDIA_MIMETYPE_VIDEO_AV1,          MEDIA_MIMETYPE_VIDEO_AVC,
                            MEDIA_MIMETYPE_VIDEO_HEVC,         MEDIA_MIMETYPE_VIDEO_MPEG4,
                            MEDIA_MIMETYPE_VIDEO_H263,         MEDIA_MIMETYPE_VIDEO_MPEG2,
                            MEDIA_MIMETYPE_VIDEO_RAW,          MEDIA_MIMETYPE_VIDEO_DOLBY_VISION,
                            MEDIA_MIMETYPE_VIDEO_SCRAMBLED,    MEDIA_MIMETYPE_VIDEO_DIVX,
                            MEDIA_MIMETYPE_VIDEO_DIVX3,        MEDIA_MIMETYPE_VIDEO_XVID,
                            MEDIA_MIMETYPE_VIDEO_MJPEG,        MEDIA_MIMETYPE_AUDIO_AMR_NB,
                            MEDIA_MIMETYPE_AUDIO_AMR_WB,       MEDIA_MIMETYPE_AUDIO_MPEG,
                            MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_I, MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_II,
                            MEDIA_MIMETYPE_AUDIO_MIDI,         MEDIA_MIMETYPE_AUDIO_AAC,
                            MEDIA_MIMETYPE_AUDIO_QCELP,        MEDIA_MIMETYPE_AUDIO_VORBIS,
                            MEDIA_MIMETYPE_AUDIO_OPUS,         MEDIA_MIMETYPE_AUDIO_G711_ALAW,
                            MEDIA_MIMETYPE_AUDIO_G711_MLAW,    MEDIA_MIMETYPE_AUDIO_RAW,
                            MEDIA_MIMETYPE_AUDIO_FLAC,         MEDIA_MIMETYPE_AUDIO_AAC_ADTS,
                            MEDIA_MIMETYPE_AUDIO_MSGSM,        MEDIA_MIMETYPE_AUDIO_AC3,
                            MEDIA_MIMETYPE_AUDIO_EAC3,         MEDIA_MIMETYPE_AUDIO_EAC3_JOC,
                            MEDIA_MIMETYPE_AUDIO_AC4,          MEDIA_MIMETYPE_AUDIO_SCRAMBLED,
                            MEDIA_MIMETYPE_AUDIO_ALAC,         MEDIA_MIMETYPE_AUDIO_WMA,
                            MEDIA_MIMETYPE_AUDIO_MS_ADPCM,     MEDIA_MIMETYPE_AUDIO_DVI_IMA_ADPCM,
                            MEDIA_MIMETYPE_CONTAINER_MPEG4,    MEDIA_MIMETYPE_CONTAINER_WAV,
                            MEDIA_MIMETYPE_CONTAINER_OGG,      MEDIA_MIMETYPE_CONTAINER_MATROSKA,
                            MEDIA_MIMETYPE_CONTAINER_MPEG2TS,  MEDIA_MIMETYPE_CONTAINER_AVI,
                            MEDIA_MIMETYPE_CONTAINER_MPEG2PS,  MEDIA_MIMETYPE_CONTAINER_HEIF,
                            MEDIA_MIMETYPE_TEXT_3GPP,          MEDIA_MIMETYPE_TEXT_SUBRIP,
                            MEDIA_MIMETYPE_TEXT_VTT,           MEDIA_MIMETYPE_TEXT_CEA_608,
                            MEDIA_MIMETYPE_TEXT_CEA_708,       MEDIA_MIMETYPE_DATA_TIMED_ID3};

class MetadataRetrieverFuzzer {
   public:
    MetadataRetrieverFuzzer(const uint8_t *data, size_t size)
        : mFdp(data, size),
          mMdRetriever(new StagefrightMetadataRetriever()),
          mDataSourceFd(memfd_create("InputFile", MFD_ALLOW_SEALING)) {}
    ~MetadataRetrieverFuzzer() { close(mDataSourceFd); }
    bool setDataSource(const uint8_t *data, size_t size);
    void getData();

   private:
    FuzzedDataProvider mFdp;
    sp<StagefrightMetadataRetriever> mMdRetriever = nullptr;
    const int32_t mDataSourceFd;
};

void MetadataRetrieverFuzzer::getData() {
    int64_t timeUs = mFdp.ConsumeIntegral<int64_t>();
    int32_t option = mFdp.ConsumeIntegral<int32_t>();
    int32_t colorFormat = mFdp.ConsumeIntegral<int32_t>();
    bool metaOnly = mFdp.ConsumeBool();
    mMdRetriever->getFrameAtTime(timeUs, option, colorFormat, metaOnly);

    int32_t index = mFdp.ConsumeIntegral<int32_t>();
    colorFormat = mFdp.ConsumeIntegral<int32_t>();
    metaOnly = mFdp.ConsumeBool();
    bool thumbnail = mFdp.ConsumeBool();
    mMdRetriever->getImageAtIndex(index, colorFormat, metaOnly, thumbnail);

    index = mFdp.ConsumeIntegral<int32_t>();
    colorFormat = mFdp.ConsumeIntegral<int32_t>();
    int32_t left = mFdp.ConsumeIntegral<int32_t>();
    int32_t top = mFdp.ConsumeIntegral<int32_t>();
    int32_t right = mFdp.ConsumeIntegral<int32_t>();
    int32_t bottom = mFdp.ConsumeIntegral<int32_t>();
    mMdRetriever->getImageRectAtIndex(index, colorFormat, left, top, right, bottom);

    index = mFdp.ConsumeIntegral<int32_t>();
    colorFormat = mFdp.ConsumeIntegral<int32_t>();
    metaOnly = mFdp.ConsumeBool();
    mMdRetriever->getFrameAtIndex(index, colorFormat, metaOnly);

    mMdRetriever->extractAlbumArt();

    int32_t keyCode = mFdp.ConsumeIntegral<int32_t>();
    mMdRetriever->extractMetadata(keyCode);
}

bool MetadataRetrieverFuzzer::setDataSource(const uint8_t *data, size_t size) {
    status_t status = -1;

    enum DataSourceChoice {FromHttp, FromFd, FromFileSource, kMaxValue = FromFileSource};
    switch (mFdp.ConsumeEnum<DataSourceChoice>()) {
        case FromHttp: {
            KeyedVector<String8, String8> mHeaders;
            mHeaders.add(String8(mFdp.ConsumeRandomLengthString().c_str()),
                         String8(mFdp.ConsumeRandomLengthString().c_str()));

            uint32_t dataBlobSize = mFdp.ConsumeIntegralInRange<uint16_t>(0, size);
            vector<uint8_t> uriSuffix = mFdp.ConsumeBytes<uint8_t>(dataBlobSize);

            string uri("data:");
            uri += ";base64,";
            AString out;
            encodeBase64(uriSuffix.data(), uriSuffix.size(), &out);
            uri += out.c_str();
            status = mMdRetriever->setDataSource(nullptr /*httpService*/, uri.c_str(), &mHeaders);
            break;
        }
        case FromFd: {
            write(mDataSourceFd, data, size);

            status = mMdRetriever->setDataSource(mDataSourceFd, 0, size);
            break;
        }
        case FromFileSource: {
            write(mDataSourceFd, data, size);

            sp<DataSource> dataSource = new FileSource(dup(mDataSourceFd), 0, size);
            status = mMdRetriever->setDataSource(dataSource, mFdp.PickValueInArray(kMimeTypes));
            break;
        }
    }

    if (status != 0) {
        return false;
    }
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MetadataRetrieverFuzzer mrtFuzzer(data, size);
    ProcessState::self()->startThreadPool();
    if (mrtFuzzer.setDataSource(data, size)) {
        mrtFuzzer.getData();
    }
    return 0;
}
