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
//#define LOG_NDEBUG 0
#define LOG_TAG "NdkCommon"

#include <android-base/logging.h>
#include <media/NdkCommon.h>

#include <cstdio>
#include <cstring>
#include <utility>

/* TODO(b/153592281)
 * Note: constants used by the native media tests but not available in media ndk api
 */
const char* AMEDIA_MIMETYPE_VIDEO_VP8 = "video/x-vnd.on2.vp8";
const char* AMEDIA_MIMETYPE_VIDEO_VP9 = "video/x-vnd.on2.vp9";
const char* AMEDIA_MIMETYPE_VIDEO_AV1 = "video/av01";
const char* AMEDIA_MIMETYPE_VIDEO_AVC = "video/avc";
const char* AMEDIA_MIMETYPE_VIDEO_HEVC = "video/hevc";
const char* AMEDIA_MIMETYPE_VIDEO_MPEG4 = "video/mp4v-es";
const char* AMEDIA_MIMETYPE_VIDEO_H263 = "video/3gpp";

/* TODO(b/153592281) */
const char* TBD_AMEDIACODEC_PARAMETER_KEY_ALLOW_FRAME_DROP = "allow-frame-drop";
const char* TBD_AMEDIACODEC_PARAMETER_KEY_REQUEST_SYNC_FRAME = "request-sync";
const char* TBD_AMEDIACODEC_PARAMETER_KEY_VIDEO_BITRATE = "video-bitrate";
const char* TBD_AMEDIACODEC_PARAMETER_KEY_MAX_B_FRAMES = "max-bframes";

/* TODO(lnilsson): Finalize value or adopt AMediaFormat key once available. */
const char* TBD_AMEDIACODEC_PARAMETER_KEY_COLOR_TRANSFER_REQUEST = "color-transfer-request";
const char* TBD_AMEDIACODEC_PARAMETER_KEY_BACKGROUND_MODE = "android._background-mode";

namespace AMediaFormatUtils {

#define DEFINE_FORMAT_VALUE_COPY_FUNC(_type, _typeName)                                      \
    bool CopyFormatEntry##_typeName(const char* key, AMediaFormat* from, AMediaFormat* to) { \
        _type value;                                                                         \
        if (AMediaFormat_get##_typeName(from, key, &value)) {                                \
            AMediaFormat_set##_typeName(to, key, value);                                     \
            return true;                                                                     \
        }                                                                                    \
        return false;                                                                        \
    }

DEFINE_FORMAT_VALUE_COPY_FUNC(const char*, String);
DEFINE_FORMAT_VALUE_COPY_FUNC(int64_t, Int64);
DEFINE_FORMAT_VALUE_COPY_FUNC(int32_t, Int32);
DEFINE_FORMAT_VALUE_COPY_FUNC(float, Float);

void CopyFormatEntries(AMediaFormat* from, AMediaFormat* to,
                       const std::vector<EntryCopier>& entries) {
    if (from == nullptr || to == nullptr) {
        LOG(ERROR) << "Cannot copy null formats";
        return;
    } else if (entries.empty()) {
        LOG(WARNING) << "No entries to copy";
        return;
    }

    for (auto& entry : entries) {
        if (!entry.copy(entry.key, from, to) && entry.copy2 != nullptr) {
            entry.copy2(entry.key, from, to);
        }
    }
}

#define DEFINE_SET_DEFAULT_FORMAT_VALUE_FUNC(_type, _typeName)                                  \
    bool SetDefaultFormatValue##_typeName(const char* key, AMediaFormat* format, _type value) { \
        _type tmp;                                                                              \
        if (!AMediaFormat_get##_typeName(format, key, &tmp)) {                                  \
            AMediaFormat_set##_typeName(format, key, value);                                    \
            return true;                                                                        \
        }                                                                                       \
        return false;                                                                           \
    }

DEFINE_SET_DEFAULT_FORMAT_VALUE_FUNC(float, Float);
DEFINE_SET_DEFAULT_FORMAT_VALUE_FUNC(int32_t, Int32);

// Determines whether a track format describes HDR video content or not. The
// logic is based on isHdr() in libstagefright/Utils.cpp.
bool VideoIsHdr(AMediaFormat* format) {
    // If VUI signals HDR content, this internal flag is set by the extractor.
    int32_t isHdr;
    if (AMediaFormat_getInt32(format, "android._is-hdr", &isHdr)) {
        return isHdr;
    }

    // If container supplied HDR static info without transfer set, assume HDR.
    const char* hdrInfo;
    int32_t transfer;
    if ((AMediaFormat_getString(format, AMEDIAFORMAT_KEY_HDR_STATIC_INFO, &hdrInfo) ||
         AMediaFormat_getString(format, "hdr10-plus-info", &hdrInfo)) &&
        !AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_COLOR_TRANSFER, &transfer)) {
        return true;
    }

    // Otherwise, check if an HDR transfer function is set.
    if (AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_COLOR_TRANSFER, &transfer)) {
        return transfer == COLOR_TRANSFER_ST2084 || transfer == COLOR_TRANSFER_HLG;
    }

    return false;
}
}  // namespace AMediaFormatUtils
