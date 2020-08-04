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

#ifndef ANDROID_MEDIA_TRANSCODING_NDK_COMMON_H
#define ANDROID_MEDIA_TRANSCODING_NDK_COMMON_H

#include <media/NdkMediaFormat.h>

extern const char* AMEDIA_MIMETYPE_VIDEO_VP8;
extern const char* AMEDIA_MIMETYPE_VIDEO_VP9;
extern const char* AMEDIA_MIMETYPE_VIDEO_AV1;
extern const char* AMEDIA_MIMETYPE_VIDEO_AVC;
extern const char* AMEDIA_MIMETYPE_VIDEO_HEVC;
extern const char* AMEDIA_MIMETYPE_VIDEO_MPEG4;
extern const char* AMEDIA_MIMETYPE_VIDEO_H263;

// TODO(b/146420990)
// TODO: make MediaTranscoder use the consts from this header.
typedef enum {
    OUTPUT_FORMAT_START = 0,
    OUTPUT_FORMAT_MPEG_4 = OUTPUT_FORMAT_START,
    OUTPUT_FORMAT_WEBM = OUTPUT_FORMAT_START + 1,
    OUTPUT_FORMAT_THREE_GPP = OUTPUT_FORMAT_START + 2,
    OUTPUT_FORMAT_HEIF = OUTPUT_FORMAT_START + 3,
    OUTPUT_FORMAT_OGG = OUTPUT_FORMAT_START + 4,
    OUTPUT_FORMAT_LIST_END = OUTPUT_FORMAT_START + 4,
} MuxerFormat;

// Color formats supported by encoder - should mirror supportedColorList
// from MediaCodecConstants.h (are these going to be deprecated)
static constexpr int COLOR_FormatYUV420SemiPlanar = 21;
static constexpr int COLOR_FormatYUV420Flexible = 0x7F420888;
static constexpr int COLOR_FormatSurface = 0x7f000789;

// constants not defined in NDK
extern const char* TBD_AMEDIACODEC_PARAMETER_KEY_ALLOW_FRAME_DROP;
extern const char* TBD_AMEDIACODEC_PARAMETER_KEY_REQUEST_SYNC_FRAME;
extern const char* TBD_AMEDIACODEC_PARAMETER_KEY_VIDEO_BITRATE;
extern const char* TBD_AMEDIACODEC_PARAMETER_KEY_MAX_B_FRAMES;
static constexpr int TBD_AMEDIACODEC_BUFFER_FLAG_KEY_FRAME = 0x1;

static constexpr int kBitrateModeConstant = 2;

#endif  // ANDROID_MEDIA_TRANSCODING_NDK_COMMON_H
