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

#include "FuzzerMediaUtility.h"

#include <media/stagefright/AACWriter.h>
#include <media/stagefright/AMRWriter.h>
#include <media/stagefright/MPEG2TSWriter.h>
#include <media/stagefright/MPEG4Writer.h>
#include <media/stagefright/OggWriter.h>

#include "MediaMimeTypes.h"
#include "webm/WebmWriter.h"

namespace android {
std::string genMimeType(FuzzedDataProvider *dataProvider) {
    uint8_t idx = dataProvider->ConsumeIntegralInRange<uint8_t>(0, kMimeTypes.size() - 1);
    return std::string(kMimeTypes[idx]);
}

sp<IMediaExtractor> genMediaExtractor(FuzzedDataProvider *dataProvider, std::string mimeType,
                                      uint16_t maxDataAmount) {
    uint32_t dataBlobSize = dataProvider->ConsumeIntegralInRange<uint16_t>(0, maxDataAmount);
    std::vector<uint8_t> data = dataProvider->ConsumeBytes<uint8_t>(dataBlobSize);
    // data:[<mediatype>][;base64],<data>
    std::string uri("data:");
    uri += mimeType;
    // Currently libstagefright only accepts base64 uris
    uri += ";base64,";
    android::AString out;
    android::encodeBase64(data.data(), data.size(), &out);
    uri += out.c_str();

    sp<DataSource> source =
        DataSourceFactory::getInstance()->CreateFromURI(NULL /* httpService */, uri.c_str());

    if (source == NULL) {
        return NULL;
    }

    return MediaExtractorFactory::Create(source);
}

sp<MediaSource> genMediaSource(FuzzedDataProvider *dataProvider, uint16_t maxMediaBlobSize) {
    std::string mime = genMimeType(dataProvider);
    sp<IMediaExtractor> extractor = genMediaExtractor(dataProvider, mime, maxMediaBlobSize);

    if (extractor == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < extractor->countTracks(); ++i) {
        sp<MetaData> meta = extractor->getTrackMetaData(i);

        const char *trackMime;
        if (!strcasecmp(mime.c_str(), trackMime)) {
            sp<IMediaSource> track = extractor->getTrack(i);
            if (track == NULL) {
                return NULL;
            }
            return new CallbackMediaSource(track);
        }
    }

    return NULL;
}

sp<MediaWriter> createWriter(int fd, StandardWriters writerType, sp<MetaData> fileMeta) {
    sp<MediaWriter> writer;
    switch (writerType) {
        case OGG:
            writer = new OggWriter(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_OGG);
            break;
        case AAC:
            writer = new AACWriter(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADIF);
            break;
        case AAC_ADTS:
            writer = new AACWriter(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADTS);
            break;
        case WEBM:
            writer = new WebmWriter(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_WEBM);
            break;
        case MPEG4:
            writer = new MPEG4Writer(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG_4);
            break;
        case AMR_NB:
            writer = new AMRWriter(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_NB);
            break;
        case AMR_WB:
            writer = new AMRWriter(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_WB);
            break;
        case MPEG2TS:
            writer = new MPEG2TSWriter(fd);
            fileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG2TS);
            break;
        default:
            return nullptr;
    }
    if (writer != nullptr) {
        fileMeta->setInt32(kKeyRealTimeRecording, false);
    }
    return writer;
}
}  // namespace android