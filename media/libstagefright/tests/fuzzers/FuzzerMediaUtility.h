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
#include <datasource/DataSourceFactory.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <android/IMediaExtractor.h>
#include <media/IMediaHTTPService.h>
#include <media/mediarecorder.h>
#include <media/stagefright/CallbackMediaSource.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaExtractorFactory.h>
#include <media/stagefright/MediaWriter.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/foundation/base64.h>
#include <utils/StrongPointer.h>

namespace android {
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

static std::string kTestedMimeTypes[] = {"audio/3gpp",
                                         "audio/amr-wb",
                                         "audio/vorbis",
                                         "audio/opus",
                                         "audio/mp4a-latm",
                                         "audio/mpeg",
                                         "audio/mpeg-L1",
                                         "audio/mpeg-L2",
                                         "audio/midi",
                                         "audio/qcelp",
                                         "audio/g711-alaw",
                                         "audio/g711-mlaw",
                                         "audio/flac",
                                         "audio/aac-adts",
                                         "audio/gsm",
                                         "audio/ac3",
                                         "audio/eac3",
                                         "audio/eac3-joc",
                                         "audio/ac4",
                                         "audio/scrambled",
                                         "audio/alac",
                                         "audio/x-ms-wma",
                                         "audio/x-adpcm-ms",
                                         "audio/x-adpcm-dvi-ima",
                                         "video/avc",
                                         "video/hevc",
                                         "video/mp4v-es",
                                         "video/3gpp",
                                         "video/x-vnd.on2.vp8",
                                         "video/x-vnd.on2.vp9",
                                         "video/av01",
                                         "video/mpeg2",
                                         "video/dolby-vision",
                                         "video/scrambled",
                                         "video/divx",
                                         "video/divx3",
                                         "video/xvid",
                                         "video/x-motion-jpeg",
                                         "text/3gpp-tt",
                                         "application/x-subrip",
                                         "text/vtt",
                                         "text/cea-608",
                                         "text/cea-708",
                                         "application/x-id3v4"};

std::string genMimeType(FuzzedDataProvider *dataProvider);
sp<IMediaExtractor> genMediaExtractor(FuzzedDataProvider *dataProvider, uint16_t dataAmount);
sp<MediaSource> genMediaSource(FuzzedDataProvider *dataProvider, uint16_t maxMediaBlobSize);

sp<MediaWriter> createWriter(int32_t fd, StandardWriters writerType, sp<MetaData> fileMeta);
}  // namespace android
