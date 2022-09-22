/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <NdkMediaCodecFuzzerBase.h>

static const std::string kMimeTypes[] = {
        MIMETYPE_AUDIO_AMR_NB, MIMETYPE_AUDIO_AMR_WB,    MIMETYPE_AUDIO_MPEG,
        MIMETYPE_AUDIO_AAC,    MIMETYPE_AUDIO_FLAC,      MIMETYPE_AUDIO_VORBIS,
        MIMETYPE_AUDIO_OPUS,   MIMETYPE_AUDIO_RAW,       MIMETYPE_AUDIO_MSGSM,
        MIMETYPE_AUDIO_EAC3,   MIMETYPE_AUDIO_SCRAMBLED, MIMETYPE_VIDEO_VP8,
        MIMETYPE_VIDEO_VP9,    MIMETYPE_VIDEO_AV1,       MIMETYPE_VIDEO_AVC,
        MIMETYPE_VIDEO_HEVC,   MIMETYPE_VIDEO_MPEG4,     MIMETYPE_VIDEO_H263,
        MIMETYPE_VIDEO_MPEG2,  MIMETYPE_VIDEO_RAW,       MIMETYPE_VIDEO_SCRAMBLED};

static const std::string kEncoderNames[] = {
        "c2.android.avc.encoder",    "c2.android.vp8.encoder",   "c2.android.vp9.encoder",
        "c2.android.hevc.encoder",   "c2.android.mpeg2.encoder", "c2.android.mpeg4.encoder",
        "c2.android.opus.encoder",   "c2.android.amrnb.encoder", "c2.android.flac.encoder",
        "c2.android.av1-aom.encoder"};

static const std::string kDecoderNames[] = {"c2.android.avc.decoder",
                                            "c2.android.vp8.decoder",
                                            "c2.android.vp9.decoder"
                                            "c2.android.hevc.decoder",
                                            "c2.android.mpeg2.decoder",
                                            "c2.android.mpeg4.decoder",
                                            "c2.android.opus.decoder",
                                            "c2.android.amrnb.decoder",
                                            "c2.android.flac.decoder",
                                            "c2.android.av1-aom.decoder"};

static const std::string kFormatIntKeys[] = {AMEDIAFORMAT_KEY_BIT_RATE,
                                             AMEDIAFORMAT_KEY_SAMPLE_RATE,
                                             AMEDIAFORMAT_KEY_FLAC_COMPRESSION_LEVEL,
                                             AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                             AMEDIAFORMAT_KEY_WIDTH,
                                             AMEDIAFORMAT_KEY_HEIGHT,
                                             AMEDIAFORMAT_KEY_FRAME_RATE,
                                             AMEDIAFORMAT_KEY_COLOR_FORMAT,
                                             AMEDIAFORMAT_VIDEO_QP_P_MIN,
                                             AMEDIAFORMAT_VIDEO_QP_P_MAX,
                                             AMEDIAFORMAT_VIDEO_QP_MIN,
                                             AMEDIAFORMAT_VIDEO_QP_MAX,
                                             AMEDIAFORMAT_VIDEO_QP_I_MIN,
                                             AMEDIAFORMAT_VIDEO_QP_I_MAX,
                                             AMEDIAFORMAT_VIDEO_QP_B_MIN,
                                             AMEDIAFORMAT_VIDEO_QP_B_MAX,
                                             AMEDIAFORMAT_KEY_VIDEO_QP_AVERAGE,
                                             AMEDIAFORMAT_KEY_VIDEO_ENCODING_STATISTICS_LEVEL,
                                             AMEDIAFORMAT_KEY_VALID_SAMPLES,
                                             AMEDIAFORMAT_KEY_TRACK_INDEX,
                                             AMEDIAFORMAT_KEY_TRACK_ID,
                                             AMEDIAFORMAT_KEY_TILE_WIDTH,
                                             AMEDIAFORMAT_KEY_TILE_HEIGHT,
                                             AMEDIAFORMAT_KEY_THUMBNAIL_WIDTH,
                                             AMEDIAFORMAT_KEY_THUMBNAIL_HEIGHT,
                                             AMEDIAFORMAT_KEY_TEMPORAL_LAYER_ID,
                                             AMEDIAFORMAT_KEY_TEMPORAL_LAYER_COUNT,
                                             AMEDIAFORMAT_KEY_STRIDE,
                                             AMEDIAFORMAT_KEY_SLICE_HEIGHT,
                                             AMEDIAFORMAT_KEY_SAR_WIDTH,
                                             AMEDIAFORMAT_KEY_SAR_HEIGHT,
                                             AMEDIAFORMAT_KEY_ROTATION,
                                             AMEDIAFORMAT_KEY_PCM_BIG_ENDIAN,
                                             AMEDIAFORMAT_KEY_PROFILE,
                                             AMEDIAFORMAT_KEY_PRIORITY,
                                             AMEDIAFORMAT_KEY_PICTURE_TYPE,
                                             AMEDIAFORMAT_KEY_PCM_ENCODING,
                                             AMEDIAFORMAT_KEY_OPERATING_RATE,
                                             AMEDIAFORMAT_KEY_MPEGH_REFERENCE_CHANNEL_LAYOUT,
                                             AMEDIAFORMAT_KEY_MPEGH_PROFILE_LEVEL_INDICATION,
                                             AMEDIAFORMAT_KEY_MAX_PTS_GAP_TO_ENCODER,
                                             AMEDIAFORMAT_KEY_MAX_INPUT_SIZE,
                                             AMEDIAFORMAT_KEY_MAX_FPS_TO_ENCODER,
                                             AMEDIAFORMAT_KEY_LOW_LATENCY,
                                             AMEDIAFORMAT_KEY_LOOP,
                                             AMEDIAFORMAT_KEY_LEVEL,
                                             AMEDIAFORMAT_KEY_LATENCY,
                                             AMEDIAFORMAT_KEY_IS_SYNC_FRAME,
                                             AMEDIAFORMAT_KEY_IS_DEFAULT,
                                             AMEDIAFORMAT_KEY_INTRA_REFRESH_PERIOD,
                                             AMEDIAFORMAT_KEY_HAPTIC_CHANNEL_COUNT,
                                             AMEDIAFORMAT_KEY_GRID_ROWS,
                                             AMEDIAFORMAT_KEY_GRID_COLUMNS,
                                             AMEDIAFORMAT_KEY_FRAME_COUNT,
                                             AMEDIAFORMAT_KEY_ENCODER_PADDING,
                                             AMEDIAFORMAT_KEY_ENCODER_DELAY,
                                             AMEDIAFORMAT_KEY_DISPLAY_WIDTH,
                                             AMEDIAFORMAT_KEY_DISPLAY_HEIGHT,
                                             AMEDIAFORMAT_KEY_DISPLAY_CROP,
                                             AMEDIAFORMAT_KEY_CRYPTO_SKIP_BYTE_BLOCK,
                                             AMEDIAFORMAT_KEY_CRYPTO_MODE,
                                             AMEDIAFORMAT_KEY_CRYPTO_ENCRYPTED_BYTE_BLOCK,
                                             AMEDIAFORMAT_KEY_CRYPTO_DEFAULT_IV_SIZE,
                                             AMEDIAFORMAT_KEY_COLOR_TRANSFER,
                                             AMEDIAFORMAT_KEY_COLOR_STANDARD,
                                             AMEDIAFORMAT_KEY_COLOR_RANGE,
                                             AMEDIAFORMAT_KEY_CHANNEL_MASK,
                                             AMEDIAFORMAT_KEY_BITS_PER_SAMPLE,
                                             AMEDIAFORMAT_KEY_BITRATE_MODE,
                                             AMEDIAFORMAT_KEY_AUDIO_SESSION_ID,
                                             AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_PROGRAM_ID,
                                             AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_PRESENTATION_ID,
                                             AMEDIAFORMAT_KEY_AAC_SBR_MODE,
                                             AMEDIAFORMAT_KEY_AAC_PROFILE,
                                             AMEDIAFORMAT_KEY_AAC_MAX_OUTPUT_CHANNEL_COUNT,
                                             AMEDIAFORMAT_KEY_AAC_ENCODED_TARGET_LEVEL,
                                             AMEDIAFORMAT_KEY_AAC_DRC_TARGET_REFERENCE_LEVEL,
                                             AMEDIAFORMAT_KEY_AAC_DRC_HEAVY_COMPRESSION,
                                             AMEDIAFORMAT_KEY_AAC_DRC_BOOST_FACTOR,
                                             AMEDIAFORMAT_KEY_AAC_DRC_ATTENUATION_FACTOR,
                                             AMEDIAFORMAT_KEY_XMP_SIZE,
                                             AMEDIAFORMAT_KEY_XMP_OFFSET,
                                             AMEDIAFORMAT_KEY_TIME_US,
                                             AMEDIAFORMAT_KEY_THUMBNAIL_TIME,
                                             AMEDIAFORMAT_KEY_TARGET_TIME,
                                             AMEDIAFORMAT_KEY_SAMPLE_TIME_BEFORE_APPEND,
                                             AMEDIAFORMAT_KEY_SAMPLE_FILE_OFFSET,
                                             AMEDIAFORMAT_KEY_LAST_SAMPLE_INDEX_IN_CHUNK,
                                             AMEDIAFORMAT_KEY_EXIF_SIZE,
                                             AMEDIAFORMAT_KEY_EXIF_OFFSET,
                                             AMEDIAFORMAT_KEY_DURATION};

static const std::string kFormatBufferKeys[] = {
        AMEDIAFORMAT_KEY_THUMBNAIL_CSD_HEVC,
        AMEDIAFORMAT_KEY_THUMBNAIL_CSD_AV1C,
        AMEDIAFORMAT_KEY_TEXT_FORMAT_DATA,
        AMEDIAFORMAT_KEY_SEI,
        AMEDIAFORMAT_KEY_PUSH_BLANK_BUFFERS_ON_STOP,
        AMEDIAFORMAT_KEY_PSSH,
        AMEDIAFORMAT_KEY_MPEGH_COMPATIBLE_SETS,
        AMEDIAFORMAT_KEY_MPEG2_STREAM_HEADER,
        AMEDIAFORMAT_KEY_MPEG_USER_DATA,
        AMEDIAFORMAT_KEY_ICC_PROFILE,
        AMEDIAFORMAT_KEY_HDR10_PLUS_INFO,
        AMEDIAFORMAT_KEY_HDR_STATIC_INFO,
        AMEDIAFORMAT_KEY_ESDS,
        AMEDIAFORMAT_KEY_D263,
        AMEDIAFORMAT_KEY_CSD_HEVC,
        AMEDIAFORMAT_KEY_CSD_AVC,
        AMEDIAFORMAT_KEY_CSD_2,
        AMEDIAFORMAT_KEY_CSD_1,
        AMEDIAFORMAT_KEY_CSD_0,
        AMEDIAFORMAT_KEY_CSD,
        AMEDIAFORMAT_KEY_CRYPTO_PLAIN_SIZES,
        AMEDIAFORMAT_KEY_CRYPTO_KEY,
        AMEDIAFORMAT_KEY_CRYPTO_IV,
        AMEDIAFORMAT_KEY_CRYPTO_ENCRYPTED_SIZES,
        AMEDIAFORMAT_KEY_CREATE_INPUT_SURFACE_SUSPENDED,
        AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_INFO,
        AMEDIAFORMAT_KEY_ALBUMART,
};

static const std::string kFormatFloatKeys[] = {AMEDIAFORMAT_KEY_I_FRAME_INTERVAL,
                                               AMEDIAFORMAT_KEY_CAPTURE_RATE};

static const std::string kFormatStringKeys[] = {AMEDIAFORMAT_KEY_YEAR,
                                                AMEDIAFORMAT_KEY_TITLE,
                                                AMEDIAFORMAT_KEY_TEMPORAL_LAYERING,
                                                AMEDIAFORMAT_KEY_SLOW_MOTION_MARKERS,
                                                AMEDIAFORMAT_KEY_REPEAT_PREVIOUS_FRAME_AFTER,
                                                AMEDIAFORMAT_KEY_MANUFACTURER,
                                                AMEDIAFORMAT_KEY_LYRICIST,
                                                AMEDIAFORMAT_KEY_LOCATION,
                                                AMEDIAFORMAT_KEY_LANGUAGE,
                                                AMEDIAFORMAT_KEY_IS_FORCED_SUBTITLE,
                                                AMEDIAFORMAT_KEY_IS_AUTOSELECT,
                                                AMEDIAFORMAT_KEY_IS_ADTS,
                                                AMEDIAFORMAT_KEY_GENRE,
                                                AMEDIAFORMAT_KEY_DISCNUMBER,
                                                AMEDIAFORMAT_KEY_DATE,
                                                AMEDIAFORMAT_KEY_COMPOSER,
                                                AMEDIAFORMAT_KEY_COMPILATION,
                                                AMEDIAFORMAT_KEY_COMPLEXITY,
                                                AMEDIAFORMAT_KEY_CDTRACKNUMBER,
                                                AMEDIAFORMAT_KEY_AUTHOR,
                                                AMEDIAFORMAT_KEY_ARTIST,
                                                AMEDIAFORMAT_KEY_ALBUMARTIST,
                                                AMEDIAFORMAT_KEY_ALBUM};

void formatSetString(AMediaFormat* format, const char* AMEDIAFORMAT_KEY, FuzzedDataProvider* fdp) {
    if (fdp->ConsumeBool()) {
        std::string keyValue = fdp->ConsumeRandomLengthString(kMaxBytes);
        AMediaFormat_setString(format, AMEDIAFORMAT_KEY, keyValue.c_str());
    }
}

void formatSetInt(AMediaFormat* format, const char* AMEDIAFORMAT_KEY, FuzzedDataProvider* fdp) {
    if (fdp->ConsumeBool()) {
        int32_t keyValue = fdp->ConsumeIntegralInRange<size_t>(kMinIntKeyValue, kMaxIntKeyValue);
        AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY, keyValue);
    }
}

void formatSetFloat(AMediaFormat* format, const char* AMEDIAFORMAT_KEY, FuzzedDataProvider* fdp) {
    if (fdp->ConsumeBool()) {
        float keyValue =
                fdp->ConsumeFloatingPointInRange<float>(kMinFloatKeyValue, kMaxFloatKeyValue);
        AMediaFormat_setFloat(format, AMEDIAFORMAT_KEY, keyValue);
    }
}

void formatSetBuffer(AMediaFormat* format, const char* AMEDIAFORMAT_KEY, FuzzedDataProvider* fdp) {
    if (fdp->ConsumeBool()) {
        std::vector<uint8_t> buffer = fdp->ConsumeBytes<uint8_t>(
                fdp->ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
        AMediaFormat_setBuffer(format, AMEDIAFORMAT_KEY, buffer.data(), buffer.size());
    }
}

AMediaCodec* NdkMediaCodecFuzzerBase::createAMediaCodecByname(bool isEncoder,
                                                              bool isCodecForClient) {
    std::string name;
    if (isEncoder) {
        name = mFdp->ConsumeBool() ? mFdp->PickValueInArray(kEncoderNames)
                                   : mFdp->ConsumeRandomLengthString(kMaxBytes);
    } else {
        name = mFdp->ConsumeBool() ? mFdp->PickValueInArray(kDecoderNames)
                                   : mFdp->ConsumeRandomLengthString(kMaxBytes);
    }

    if (isCodecForClient) {
        pid_t pid = mFdp->ConsumeIntegral<pid_t>();
        uid_t uid = mFdp->ConsumeIntegral<uid_t>();
        return AMediaCodec_createCodecByNameForClient(name.c_str(), pid, uid);

    } else {
        return AMediaCodec_createCodecByName(name.c_str());
    }
}

AMediaCodec* NdkMediaCodecFuzzerBase::createAMediaCodecByType(bool isEncoder,
                                                              bool isCodecForClient) {
    std::string mimeType;
    const char* mime = nullptr;

    if (mFdp->ConsumeBool()) {
        mimeType = mFdp->ConsumeRandomLengthString(kMaxBytes);
        mime = mimeType.c_str();
    } else {
        AMediaFormat_getString(mFormat, AMEDIAFORMAT_KEY_MIME, &mime);
    }

    if (isCodecForClient) {
        pid_t pid = mFdp->ConsumeIntegral<pid_t>();
        uid_t uid = mFdp->ConsumeIntegral<uid_t>();
        return isEncoder ? AMediaCodec_createEncoderByTypeForClient(mime, pid, uid)
                         : AMediaCodec_createDecoderByTypeForClient(mime, pid, uid);
    } else {
        return isEncoder ? AMediaCodec_createEncoderByType(mime)
                         : AMediaCodec_createDecoderByType(mime);
    }
}

void NdkMediaCodecFuzzerBase::setCodecFormat() {
    std::string value;
    int32_t count = 0;
    int32_t maxFormatKeys = 0;
    AMediaFormat_clear(mFormat);

    /*set mimeType*/
    if (mFdp->ConsumeBool()) {
        value = mFdp->ConsumeRandomLengthString(kMaxBytes);
    } else {
        value = mFdp->PickValueInArray(kMimeTypes);
    }
    if (mFdp->ConsumeBool()) {
        AMediaFormat_setString(mFormat, AMEDIAFORMAT_KEY_MIME, value.c_str());
    }

    maxFormatKeys = mFdp->ConsumeIntegralInRange<int32_t>(0, std::size(kFormatStringKeys));
    for (count = 0; count < maxFormatKeys; ++count) {
        std::string formatKey = mFdp->PickValueInArray(kFormatStringKeys);
        formatSetString(mFormat, formatKey.c_str(), mFdp);
    }

    maxFormatKeys = mFdp->ConsumeIntegralInRange<int32_t>(0, std::size(kFormatIntKeys));
    for (count = 0; count < maxFormatKeys; ++count) {
        std::string formatKey = mFdp->PickValueInArray(kFormatIntKeys);
        formatSetInt(mFormat, formatKey.c_str(), mFdp);
    }

    maxFormatKeys = mFdp->ConsumeIntegralInRange<int32_t>(0, std::size(kFormatFloatKeys));
    for (count = 0; count < maxFormatKeys; ++count) {
        std::string formatKey = mFdp->PickValueInArray(kFormatFloatKeys);
        formatSetFloat(mFormat, formatKey.c_str(), mFdp);
    }

    maxFormatKeys = mFdp->ConsumeIntegralInRange<int32_t>(0, std::size(kFormatBufferKeys));
    for (count = 0; count < maxFormatKeys; ++count) {
        std::string formatKey = mFdp->PickValueInArray(kFormatBufferKeys);
        formatSetBuffer(mFormat, formatKey.c_str(), mFdp);
    }
}

AMediaCodec* NdkMediaCodecFuzzerBase::createCodec(bool isEncoder, bool isCodecForClient) {
    setCodecFormat();
    return (mFdp->ConsumeBool() ? createAMediaCodecByname(isEncoder, isCodecForClient)
                                : createAMediaCodecByType(isEncoder, isCodecForClient));
}

void NdkMediaCodecFuzzerBase::invokeCodecFormatAPI(AMediaCodec* codec) {
    AMediaFormat* codecFormat = nullptr;
    size_t codecFormatAPI = mFdp->ConsumeIntegralInRange<size_t>(kMinAPICase, kMaxCodecFormatAPIs);
    switch (codecFormatAPI) {
        case 0: {
            codecFormat = AMediaCodec_getInputFormat(codec);
            break;
        }
        case 1: {
            codecFormat = AMediaCodec_getOutputFormat(codec);
            break;
        }
        case 2:
        default: {
            AMediaCodecBufferInfo info;
            int64_t timeOutUs = mFdp->ConsumeIntegralInRange<size_t>(kMinTimeOutUs, kMaxTimeOutUs);
            ssize_t bufferIndex = 0;
            if (mFdp->ConsumeBool()) {
                bufferIndex = AMediaCodec_dequeueOutputBuffer(codec, &info, timeOutUs);
            } else {
                bufferIndex =
                        mFdp->ConsumeIntegralInRange<size_t>(kMinBufferIndex, kMaxBufferIndex);
            }
            codecFormat = AMediaCodec_getBufferFormat(codec, bufferIndex);
            break;
        }
    }
    if (codecFormat) {
        AMediaFormat_delete(codecFormat);
    }
}

void NdkMediaCodecFuzzerBase::invokeInputBufferOperationAPI(AMediaCodec* codec) {
    size_t bufferSize = 0;
    ssize_t bufferIndex = 0;
    int64_t timeOutUs = mFdp->ConsumeIntegralInRange<size_t>(kMinTimeOutUs, kMaxTimeOutUs);
    if (mFdp->ConsumeBool()) {
        bufferIndex = AMediaCodec_dequeueInputBuffer(codec, timeOutUs);
    } else {
        bufferIndex = mFdp->ConsumeIntegralInRange<size_t>(kMinBufferIndex, kMaxBufferIndex);
    }

    uint8_t* buffer = AMediaCodec_getInputBuffer(codec, bufferIndex, &bufferSize);
    if (buffer) {
        std::vector<uint8_t> bytesRead = mFdp->ConsumeBytes<uint8_t>(
                std::min(mFdp->ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes), bufferSize));
        memcpy(buffer, bytesRead.data(), bytesRead.size());
        bufferSize = bytesRead.size();
    }

    int32_t flag = mFdp->ConsumeIntegralInRange<size_t>(AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG,
                                                        AMEDIACODEC_BUFFER_FLAG_PARTIAL_FRAME);
    if (mFdp->ConsumeBool()) {
        AMediaCodec_queueInputBuffer(codec, bufferIndex, 0 /* offset */, bufferSize, 0 /* time */,
                                     flag);
    } else {
        AMediaCodecCryptoInfo* cryptoInfo = getAMediaCodecCryptoInfo();
        AMediaCodec_queueSecureInputBuffer(codec, bufferIndex, 0 /* offset */, cryptoInfo,
                                           0 /* time */, flag);
        AMediaCodecCryptoInfo_delete(cryptoInfo);
    }
}

void NdkMediaCodecFuzzerBase::invokeOutputBufferOperationAPI(AMediaCodec* codec) {
    ssize_t bufferIndex = 0;
    int64_t timeOutUs = mFdp->ConsumeIntegralInRange<size_t>(kMinTimeOutUs, kMaxTimeOutUs);
    if (mFdp->ConsumeBool()) {
        AMediaCodecBufferInfo info;
        bufferIndex = AMediaCodec_dequeueOutputBuffer(codec, &info, timeOutUs);
    } else {
        bufferIndex = mFdp->ConsumeIntegralInRange<size_t>(kMinBufferIndex, kMaxBufferIndex);
    }

    if (mFdp->ConsumeBool()) {
        size_t bufferSize = 0;
        (void)AMediaCodec_getOutputBuffer(codec, bufferIndex, &bufferSize);
    }

    if (mFdp->ConsumeBool()) {
        AMediaCodec_releaseOutputBuffer(codec, bufferIndex, mFdp->ConsumeBool());
    } else {
        AMediaCodec_releaseOutputBufferAtTime(codec, bufferIndex, timeOutUs);
    }
}

AMediaCodecCryptoInfo* NdkMediaCodecFuzzerBase::getAMediaCodecCryptoInfo() {
    uint8_t key[kMaxCryptoKey];
    uint8_t iv[kMaxCryptoKey];
    size_t clearBytes[kMaxCryptoKey];
    size_t encryptedBytes[kMaxCryptoKey];

    for (int32_t i = 0; i < kMaxCryptoKey; ++i) {
        key[i] = mFdp->ConsumeIntegral<uint8_t>();
        iv[i] = mFdp->ConsumeIntegral<uint8_t>();
        clearBytes[i] = mFdp->ConsumeIntegral<size_t>();
        encryptedBytes[i] = mFdp->ConsumeIntegral<size_t>();
    }

    return AMediaCodecCryptoInfo_new(kMaxCryptoKey, key, iv, AMEDIACODECRYPTOINFO_MODE_CLEAR,
                                     clearBytes, encryptedBytes);
}
