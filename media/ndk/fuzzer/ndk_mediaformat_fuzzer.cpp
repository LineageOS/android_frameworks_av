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

#include <datasource/FileSource.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/NdkMediaFormat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <utils/Log.h>
#include <fstream>

const char* kValidKeys[] = {
        AMEDIAFORMAT_KEY_AAC_DRC_ATTENUATION_FACTOR,
        AMEDIAFORMAT_KEY_AAC_DRC_BOOST_FACTOR,
        AMEDIAFORMAT_KEY_AAC_DRC_HEAVY_COMPRESSION,
        AMEDIAFORMAT_KEY_AAC_DRC_TARGET_REFERENCE_LEVEL,
        AMEDIAFORMAT_KEY_AAC_ENCODED_TARGET_LEVEL,
        AMEDIAFORMAT_KEY_AAC_MAX_OUTPUT_CHANNEL_COUNT,
        AMEDIAFORMAT_KEY_AAC_PROFILE,
        AMEDIAFORMAT_KEY_AAC_SBR_MODE,
        AMEDIAFORMAT_KEY_ALBUM,
        AMEDIAFORMAT_KEY_ALBUMART,
        AMEDIAFORMAT_KEY_ALBUMARTIST,
        AMEDIAFORMAT_KEY_ARTIST,
        AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_INFO,
        AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_PRESENTATION_ID,
        AMEDIAFORMAT_KEY_AUDIO_PRESENTATION_PROGRAM_ID,
        AMEDIAFORMAT_KEY_AUDIO_SESSION_ID,
        AMEDIAFORMAT_KEY_AUTHOR,
        AMEDIAFORMAT_KEY_BITRATE_MODE,
        AMEDIAFORMAT_KEY_BIT_RATE,
        AMEDIAFORMAT_KEY_BITS_PER_SAMPLE,
        AMEDIAFORMAT_KEY_CAPTURE_RATE,
        AMEDIAFORMAT_KEY_CDTRACKNUMBER,
        AMEDIAFORMAT_KEY_CHANNEL_COUNT,
        AMEDIAFORMAT_KEY_CHANNEL_MASK,
        AMEDIAFORMAT_KEY_COLOR_FORMAT,
        AMEDIAFORMAT_KEY_COLOR_RANGE,
        AMEDIAFORMAT_KEY_COLOR_STANDARD,
        AMEDIAFORMAT_KEY_COLOR_TRANSFER,
        AMEDIAFORMAT_KEY_COMPILATION,
        AMEDIAFORMAT_KEY_COMPLEXITY,
        AMEDIAFORMAT_KEY_COMPOSER,
        AMEDIAFORMAT_KEY_CREATE_INPUT_SURFACE_SUSPENDED,
        AMEDIAFORMAT_KEY_CRYPTO_DEFAULT_IV_SIZE,
        AMEDIAFORMAT_KEY_CRYPTO_ENCRYPTED_BYTE_BLOCK,
        AMEDIAFORMAT_KEY_CRYPTO_ENCRYPTED_SIZES,
        AMEDIAFORMAT_KEY_CRYPTO_IV,
        AMEDIAFORMAT_KEY_CRYPTO_KEY,
        AMEDIAFORMAT_KEY_CRYPTO_MODE,
        AMEDIAFORMAT_KEY_CRYPTO_PLAIN_SIZES,
        AMEDIAFORMAT_KEY_CRYPTO_SKIP_BYTE_BLOCK,
        AMEDIAFORMAT_KEY_CSD,
        AMEDIAFORMAT_KEY_CSD_0,
        AMEDIAFORMAT_KEY_CSD_1,
        AMEDIAFORMAT_KEY_CSD_2,
        AMEDIAFORMAT_KEY_CSD_AVC,
        AMEDIAFORMAT_KEY_CSD_HEVC,
        AMEDIAFORMAT_KEY_D263,
        AMEDIAFORMAT_KEY_DATE,
        AMEDIAFORMAT_KEY_DISCNUMBER,
        AMEDIAFORMAT_KEY_DISPLAY_CROP,
        AMEDIAFORMAT_KEY_DISPLAY_HEIGHT,
        AMEDIAFORMAT_KEY_DISPLAY_WIDTH,
        AMEDIAFORMAT_KEY_DURATION,
        AMEDIAFORMAT_KEY_ENCODER_DELAY,
        AMEDIAFORMAT_KEY_ENCODER_PADDING,
        AMEDIAFORMAT_KEY_ESDS,
        AMEDIAFORMAT_KEY_EXIF_OFFSET,
        AMEDIAFORMAT_KEY_EXIF_SIZE,
        AMEDIAFORMAT_KEY_FLAC_COMPRESSION_LEVEL,
        AMEDIAFORMAT_KEY_FRAME_COUNT,
        AMEDIAFORMAT_KEY_FRAME_RATE,
        AMEDIAFORMAT_KEY_GENRE,
        AMEDIAFORMAT_KEY_GRID_COLUMNS,
        AMEDIAFORMAT_KEY_GRID_ROWS,
        AMEDIAFORMAT_KEY_HAPTIC_CHANNEL_COUNT,
        AMEDIAFORMAT_KEY_HDR_STATIC_INFO,
        AMEDIAFORMAT_KEY_HDR10_PLUS_INFO,
        AMEDIAFORMAT_KEY_HEIGHT,
        AMEDIAFORMAT_KEY_ICC_PROFILE,
        AMEDIAFORMAT_KEY_INTRA_REFRESH_PERIOD,
        AMEDIAFORMAT_KEY_IS_ADTS,
        AMEDIAFORMAT_KEY_IS_AUTOSELECT,
        AMEDIAFORMAT_KEY_IS_DEFAULT,
        AMEDIAFORMAT_KEY_IS_FORCED_SUBTITLE,
        AMEDIAFORMAT_KEY_IS_SYNC_FRAME,
        AMEDIAFORMAT_KEY_I_FRAME_INTERVAL,
        AMEDIAFORMAT_KEY_LANGUAGE,
        AMEDIAFORMAT_KEY_LAST_SAMPLE_INDEX_IN_CHUNK,
        AMEDIAFORMAT_KEY_LATENCY,
        AMEDIAFORMAT_KEY_LEVEL,
        AMEDIAFORMAT_KEY_LOCATION,
        AMEDIAFORMAT_KEY_LOOP,
        AMEDIAFORMAT_KEY_LOW_LATENCY,
        AMEDIAFORMAT_KEY_LYRICIST,
        AMEDIAFORMAT_KEY_MANUFACTURER,
        AMEDIAFORMAT_KEY_MAX_BIT_RATE,
        AMEDIAFORMAT_KEY_MAX_FPS_TO_ENCODER,
        AMEDIAFORMAT_KEY_MAX_HEIGHT,
        AMEDIAFORMAT_KEY_MAX_INPUT_SIZE,
        AMEDIAFORMAT_KEY_MAX_PTS_GAP_TO_ENCODER,
        AMEDIAFORMAT_KEY_MAX_WIDTH,
        AMEDIAFORMAT_KEY_MIME,
        AMEDIAFORMAT_KEY_MPEG_USER_DATA,
        AMEDIAFORMAT_KEY_MPEG2_STREAM_HEADER,
        AMEDIAFORMAT_KEY_MPEGH_COMPATIBLE_SETS,
        AMEDIAFORMAT_KEY_MPEGH_PROFILE_LEVEL_INDICATION,
        AMEDIAFORMAT_KEY_MPEGH_REFERENCE_CHANNEL_LAYOUT,
        AMEDIAFORMAT_KEY_OPERATING_RATE,
        AMEDIAFORMAT_KEY_PCM_ENCODING,
        AMEDIAFORMAT_KEY_PICTURE_TYPE,
        AMEDIAFORMAT_KEY_PRIORITY,
        AMEDIAFORMAT_KEY_PROFILE,
        AMEDIAFORMAT_KEY_PCM_BIG_ENDIAN,
        AMEDIAFORMAT_KEY_PSSH,
        AMEDIAFORMAT_KEY_PUSH_BLANK_BUFFERS_ON_STOP,
        AMEDIAFORMAT_KEY_REPEAT_PREVIOUS_FRAME_AFTER,
        AMEDIAFORMAT_KEY_ROTATION,
        AMEDIAFORMAT_KEY_SAMPLE_FILE_OFFSET,
        AMEDIAFORMAT_KEY_SAMPLE_RATE,
        AMEDIAFORMAT_KEY_SAMPLE_TIME_BEFORE_APPEND,
        AMEDIAFORMAT_KEY_SAR_HEIGHT,
        AMEDIAFORMAT_KEY_SAR_WIDTH,
        AMEDIAFORMAT_KEY_SEI,
        AMEDIAFORMAT_KEY_SLICE_HEIGHT,
        AMEDIAFORMAT_KEY_SLOW_MOTION_MARKERS,
        AMEDIAFORMAT_KEY_STRIDE,
        AMEDIAFORMAT_KEY_TARGET_TIME,
        AMEDIAFORMAT_KEY_TEMPORAL_LAYER_COUNT,
        AMEDIAFORMAT_KEY_TEMPORAL_LAYER_ID,
        AMEDIAFORMAT_KEY_TEMPORAL_LAYERING,
        AMEDIAFORMAT_KEY_TEXT_FORMAT_DATA,
        AMEDIAFORMAT_KEY_THUMBNAIL_CSD_AV1C,
        AMEDIAFORMAT_KEY_THUMBNAIL_CSD_HEVC,
        AMEDIAFORMAT_KEY_THUMBNAIL_HEIGHT,
        AMEDIAFORMAT_KEY_THUMBNAIL_TIME,
        AMEDIAFORMAT_KEY_THUMBNAIL_WIDTH,
        AMEDIAFORMAT_KEY_TILE_HEIGHT,
        AMEDIAFORMAT_KEY_TILE_WIDTH,
        AMEDIAFORMAT_KEY_TIME_US,
        AMEDIAFORMAT_KEY_TITLE,
        AMEDIAFORMAT_KEY_TRACK_ID,
        AMEDIAFORMAT_KEY_TRACK_INDEX,
        AMEDIAFORMAT_KEY_VALID_SAMPLES,
        AMEDIAFORMAT_KEY_VIDEO_ENCODING_STATISTICS_LEVEL,
        AMEDIAFORMAT_KEY_VIDEO_QP_AVERAGE,
        AMEDIAFORMAT_VIDEO_QP_B_MAX,
        AMEDIAFORMAT_VIDEO_QP_B_MIN,
        AMEDIAFORMAT_VIDEO_QP_I_MAX,
        AMEDIAFORMAT_VIDEO_QP_I_MIN,
        AMEDIAFORMAT_VIDEO_QP_MAX,
        AMEDIAFORMAT_VIDEO_QP_MIN,
        AMEDIAFORMAT_VIDEO_QP_P_MAX,
        AMEDIAFORMAT_VIDEO_QP_P_MIN,
        AMEDIAFORMAT_KEY_WIDTH,
        AMEDIAFORMAT_KEY_XMP_OFFSET,
        AMEDIAFORMAT_KEY_XMP_SIZE,
        AMEDIAFORMAT_KEY_YEAR,
};
constexpr size_t kMinBytes = 0;
constexpr size_t kMaxBytes = 1000;
constexpr size_t kMinChoice = 0;
constexpr size_t kMaxChoice = 9;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    AMediaFormat* mediaFormat = AMediaFormat_new();
    while (fdp.remaining_bytes()) {
        const char* name = nullptr;
        std::string nameString;
        if (fdp.ConsumeBool()) {
            nameString =
                    fdp.ConsumeBool()
                            ? fdp.PickValueInArray(kValidKeys)
                            : fdp.ConsumeRandomLengthString(
                                      fdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
            name = nameString.c_str();
        }
        switch (fdp.ConsumeIntegralInRange<int32_t>(kMinChoice, kMaxChoice)) {
            case 0: {
                AMediaFormat_setInt32(mediaFormat, name,
                                      fdp.ConsumeIntegral<int32_t>() /* value */);
                break;
            }
            case 1: {
                AMediaFormat_setInt64(mediaFormat, name,
                                      fdp.ConsumeIntegral<int64_t>() /* value */);
                break;
            }
            case 2: {
                AMediaFormat_setFloat(mediaFormat, name,
                                      fdp.ConsumeFloatingPoint<float>() /* value */);
                break;
            }
            case 3: {
                AMediaFormat_setDouble(mediaFormat, name,
                                       fdp.ConsumeFloatingPoint<double>() /* value */);
                break;
            }
            case 4: {
                AMediaFormat_setSize(mediaFormat, name, fdp.ConsumeIntegral<size_t>() /* value */);
                break;
            }
            case 5: {
                std::string value;
                if (fdp.ConsumeBool()) {
                    value = fdp.ConsumeRandomLengthString(
                            fdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
                }
                AMediaFormat_setString(mediaFormat, name,
                                       fdp.ConsumeBool() ? nullptr : value.c_str());
                break;
            }
            case 6: {
                AMediaFormat_setRect(mediaFormat, name, fdp.ConsumeIntegral<int32_t>() /* left */,
                                     fdp.ConsumeIntegral<int32_t>() /* top */,
                                     fdp.ConsumeIntegral<int32_t>() /* bottom */,
                                     fdp.ConsumeIntegral<int32_t>() /* right */);
                break;
            }
            case 7: {
                std::vector<uint8_t> bufferData = fdp.ConsumeBytes<uint8_t>(
                        fdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
                AMediaFormat_setBuffer(mediaFormat, name, bufferData.data(), bufferData.size());
                break;
            }
            case 8: {
                AMediaFormat_toString(mediaFormat);
                break;
            }
            default: {
                AMediaFormat* format = fdp.ConsumeBool() ? nullptr : AMediaFormat_new();
                AMediaFormat_copy(format, mediaFormat);
                AMediaFormat_delete(format);
                break;
            }
        }
    }
    AMediaFormat_clear(mediaFormat);
    AMediaFormat_delete(mediaFormat);
    return 0;
}
