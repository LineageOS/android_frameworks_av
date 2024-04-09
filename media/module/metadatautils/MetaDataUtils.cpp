/*
 * Copyright 2018 The Android Open Source Project
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
#define LOG_TAG "MetaDataUtils"
#include <utils/Log.h>

#include <media/stagefright/foundation/avc_utils.h>
#include <media/stagefright/foundation/base64.h>
#include <media/stagefright/foundation/ABitReader.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ByteUtils.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataUtils.h>
#include <media/NdkMediaFormat.h>

namespace android {

bool MakeAVCCodecSpecificData(MetaDataBase &meta, const uint8_t *data, size_t size) {
    if (data == nullptr || size == 0) {
        return false;
    }

    int32_t width;
    int32_t height;
    int32_t sarWidth;
    int32_t sarHeight;
    sp<ABuffer> accessUnit = new ABuffer((void*)data,  size);
    sp<ABuffer> csd = MakeAVCCodecSpecificData(accessUnit, &width, &height, &sarWidth, &sarHeight);
    if (csd == nullptr) {
        return false;
    }
    meta.setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);

    meta.setData(kKeyAVCC, kTypeAVCC, csd->data(), csd->size());
    meta.setInt32(kKeyWidth, width);
    meta.setInt32(kKeyHeight, height);
    if (sarWidth > 0 && sarHeight > 0) {
        meta.setInt32(kKeySARWidth, sarWidth);
        meta.setInt32(kKeySARHeight, sarHeight);
    }
    return true;
}

bool MakeAVCCodecSpecificData(AMediaFormat *meta, const uint8_t *data, size_t size) {
    if (meta == nullptr || data == nullptr || size == 0) {
        return false;
    }

    int32_t width;
    int32_t height;
    int32_t sarWidth;
    int32_t sarHeight;
    sp<ABuffer> accessUnit = new ABuffer((void*)data,  size);
    sp<ABuffer> csd = MakeAVCCodecSpecificData(accessUnit, &width, &height, &sarWidth, &sarHeight);
    if (csd == nullptr) {
        return false;
    }
    AMediaFormat_setString(meta, AMEDIAFORMAT_KEY_MIME, MEDIA_MIMETYPE_VIDEO_AVC);

    AMediaFormat_setBuffer(meta, AMEDIAFORMAT_KEY_CSD_AVC, csd->data(), csd->size());
    AMediaFormat_setInt32(meta, AMEDIAFORMAT_KEY_WIDTH, width);
    AMediaFormat_setInt32(meta, AMEDIAFORMAT_KEY_HEIGHT, height);
    if (sarWidth > 0 && sarHeight > 0) {
        AMediaFormat_setInt32(meta, AMEDIAFORMAT_KEY_SAR_WIDTH, sarWidth);
        AMediaFormat_setInt32(meta, AMEDIAFORMAT_KEY_SAR_HEIGHT, sarHeight);
    }
    return true;
}

// Check if the next 24 bits are VP9 SYNC_CODE
static bool isVp9SyncCode(ABitReader &bits) {
    if (bits.numBitsLeft() < 24) {
        return false;
    }
    return bits.getBits(24) == 0x498342;
}

// This parses bitdepth and subsampling in a VP9 uncompressed header
// (refer section bitdepth_colorspace_sampling in 6.2 of the VP9 bitstream spec)
static bool getVp9BitdepthChromaSubSampling(ABitReader &bits,
        int32_t profile,
        int32_t *bitDepth,
        int32_t *chromaSubsampling) {
    if (profile >= 2) {
        if (bits.numBitsLeft() < 1) {
            return false;
        }
        *bitDepth = bits.getBits(1) ? 12 : 10;
    } else {
        *bitDepth = 8;
    }

    uint32_t colorspace;
    if (!bits.getBitsGraceful(3, &colorspace)) {
        return false;
    }

    *chromaSubsampling = -1;
    if (colorspace != 7 /*SRGB*/) {
        // Skip yuv_range_flag
        if (!bits.skipBits(1)) {
            return false;
        }
        // Check for subsampling only for profiles 1 and 3.
        if (profile == 1 || profile == 3) {
            uint32_t ss_x;
            uint32_t ss_y;
            if (bits.getBitsGraceful(1, &ss_x) && bits.getBitsGraceful(1, &ss_y)) {
                *chromaSubsampling = ss_x << 1 & ss_y;
            } else {
                return false;
            }
        } else {
            *chromaSubsampling = 3;
        }
    } else {
        if (profile == 1 || profile == 3) {
            *chromaSubsampling = 0;
        }
    }
    return true;
}
// The param data contains the first frame data, starting with the uncompressed frame
// header. This uncompressed header (refer section 6.2 of the VP9 bitstream spec) is
// used to parse profile, bitdepth and subsampling.
bool MakeVP9CodecSpecificData(AMediaFormat* meta, const uint8_t* data, size_t size) {
    if (meta == nullptr || data == nullptr || size == 0) {
        return false;
    }

    ABitReader bits(data, size);

    // First 2 bits of the uncompressed header should be the frame_marker.
    if (bits.getBits(2) != 0b10) {
        return false;
    }

    int32_t profileLowBit = bits.getBits(1);
    int32_t profileHighBit = bits.getBits(1);
    int32_t profile = profileHighBit * 2 + profileLowBit;

    // One reserved '0' bit if profile is 3.
    if (profile == 3 && bits.getBits(1) != 0) {
        return false;
    }

    // If show_existing_frame is set, we get no more data. Since this is
    // expected to be the first frame, we can return false which will cascade
    // into ERROR_MALFORMED.
    if (bits.getBits(1)) {
        return false;
    }

    int32_t frame_type = bits.getBits(1);

    // Upto 7 bits could be read till now, which were guaranteed to be available
    // since size > 0. Check for bits available before reading them from now on.
    if (bits.numBitsLeft() < 2) {
        return false;
    }

    int32_t show_frame = bits.getBits(1);
    int32_t error_resilient_mode = bits.getBits(1);
    int32_t bitDepth = 8;
    int32_t chromaSubsampling = -1;

    if (frame_type == 0 /* KEY_FRAME */) {
        // Check for sync code.
        if (!isVp9SyncCode(bits)) {
            return false;
        }

        if (!getVp9BitdepthChromaSubSampling(bits, profile, &bitDepth, &chromaSubsampling)) {
            return false;
        }
    } else {
        int32_t intra_only = 0;
        if (!show_frame) {
            if (bits.numBitsLeft() < 1) {
                return false;
            }
            intra_only = bits.getBits(1);
        }

        if (!error_resilient_mode) {
            if (bits.numBitsLeft() < 2) {
                return false;
            }
            // ignore reset_frame_context
            bits.skipBits(2);
        }

        if (!intra_only) {
            // Require first frame to be either KEY_FRAME or INTER_FRAME with intra_only set to true
            return false;
        }

        // Check for sync code.
        if (!isVp9SyncCode(bits)) {
            return false;
        }

        if (profile > 0) {
            if (!getVp9BitdepthChromaSubSampling(bits, profile, &bitDepth, &chromaSubsampling)) {
                return false;
            }
        } else {
            bitDepth = 8;
            chromaSubsampling = 3;
        }
    }
    int32_t csdSize = 6;
    if (chromaSubsampling != -1) {
        csdSize += 3;
    }

    // Create VP9 Codec Feature Metadata (CodecPrivate) that can be parsed
    // https://www.webmproject.org/docs/container/#vp9-codec-feature-metadata-codecprivate
    sp<ABuffer> csd = sp<ABuffer>::make(csdSize);
    uint8_t* csdData = csd->data();

    *csdData++ = 0x01 /* FEATURE PROFILE */;
    *csdData++ = 0x01 /* length */;
    *csdData++ = profile;

    *csdData++ = 0x03 /* FEATURE BITDEPTH */;
    *csdData++ = 0x01 /* length */;
    *csdData++ = bitDepth;

    // csdSize more than 6 means chroma subsampling data was found.
    if (csdSize > 6) {
        *csdData++ = 0x04 /* FEATURE SUBSAMPLING */;
        *csdData++ = 0x01 /* length */;
        *csdData++ = chromaSubsampling;
    }

    AMediaFormat_setBuffer(meta, AMEDIAFORMAT_KEY_CSD_0, csd->data(), csd->size());
    return true;
}

bool MakeAACCodecSpecificData(MetaDataBase &meta, const uint8_t *data, size_t size) {
    if (data == nullptr || size < 7) {
        return false;
    }

    ABitReader bits(data, size);

    // adts_fixed_header

    if (bits.getBits(12) != 0xfffu) {
        ALOGE("Wrong atds_fixed_header");
        return false;
    }

    bits.skipBits(4);  // ID, layer, protection_absent

    unsigned profile = bits.getBits(2);
    if (profile == 3u) {
        ALOGE("profile should not be 3");
        return false;
    }
    unsigned sampling_freq_index = bits.getBits(4);
    bits.getBits(1);  // private_bit
    unsigned channel_configuration = bits.getBits(3);
    if (channel_configuration == 0u) {
        ALOGE("channel_config should not be 0");
        return false;
    }

    if (!MakeAACCodecSpecificData(
            meta, profile, sampling_freq_index, channel_configuration)) {
        return false;
    }

    meta.setInt32(kKeyIsADTS, true);
    return true;
}

bool MakeAACCodecSpecificData(
        uint8_t *csd, /* out */
        size_t *esds_size, /* in/out */
        unsigned profile, /* in */
        unsigned sampling_freq_index, /* in */
        unsigned channel_configuration, /* in */
        int32_t *sampling_rate /* out */
) {
    if(sampling_freq_index > 11u) {
        return false;
    }
    static const int32_t kSamplingFreq[] = {
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
        16000, 12000, 11025, 8000
    };
    *sampling_rate = kSamplingFreq[sampling_freq_index];

    static const uint8_t kStaticESDS[] = {
        0x03, 22,
        0x00, 0x00,     // ES_ID
        0x00,           // streamDependenceFlag, URL_Flag, OCRstreamFlag

        0x04, 17,
        0x40,                       // Audio ISO/IEC 14496-3
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        0x05, 2,
        // AudioSpecificInfo follows

        // oooo offf fccc c000
        // o - audioObjectType
        // f - samplingFreqIndex
        // c - channelConfig
    };

    size_t csdSize = sizeof(kStaticESDS) + 2;
    if (csdSize > *esds_size) {
        return false;
    }
    memcpy(csd, kStaticESDS, sizeof(kStaticESDS));

    csd[sizeof(kStaticESDS)] =
        ((profile + 1) << 3) | (sampling_freq_index >> 1);

    csd[sizeof(kStaticESDS) + 1] =
        ((sampling_freq_index << 7) & 0x80) | (channel_configuration << 3);

    *esds_size = csdSize;
    return true;
}

bool MakeAACCodecSpecificData(AMediaFormat *meta, unsigned profile, unsigned sampling_freq_index,
        unsigned channel_configuration) {

    if(sampling_freq_index > 11u) {
        return false;
    }

    uint8_t csd[2];
    csd[0] = ((profile + 1) << 3) | (sampling_freq_index >> 1);
    csd[1] = ((sampling_freq_index << 7) & 0x80) | (channel_configuration << 3);

    static const int32_t kSamplingFreq[] = {
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
        16000, 12000, 11025, 8000
    };
    int32_t sampleRate = kSamplingFreq[sampling_freq_index];

    AMediaFormat_setBuffer(meta, AMEDIAFORMAT_KEY_CSD_0, csd, sizeof(csd));
    AMediaFormat_setString(meta, AMEDIAFORMAT_KEY_MIME, MEDIA_MIMETYPE_AUDIO_AAC);
    AMediaFormat_setInt32(meta, AMEDIAFORMAT_KEY_SAMPLE_RATE, sampleRate);
    AMediaFormat_setInt32(meta, AMEDIAFORMAT_KEY_CHANNEL_COUNT, channel_configuration);

    return true;
}

bool MakeAACCodecSpecificData(
        MetaDataBase &meta,
        unsigned profile, unsigned sampling_freq_index,
        unsigned channel_configuration) {

    uint8_t csd[24];
    size_t csdSize = sizeof(csd);
    int32_t sampleRate;

    if (!MakeAACCodecSpecificData(csd, &csdSize, profile, sampling_freq_index,
            channel_configuration, &sampleRate)) {
        return false;
    }

    meta.setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_AAC);

    meta.setInt32(kKeySampleRate, sampleRate);
    meta.setInt32(kKeyChannelCount, channel_configuration);
    meta.setData(kKeyESDS, 0, csd, csdSize);
    return true;
}


static void extractAlbumArt(
        AMediaFormat *fileMeta, const void *data, size_t size) {
    ALOGV("extractAlbumArt from '%s'", (const char *)data);

    size_t inLen = strnlen((const char *)data, size);
    size_t flacSize = inLen / 4 * 3;
    uint8_t *flac = new uint8_t[flacSize];
    if (!decodeBase64(flac, &flacSize, (const char*)data)) {
        ALOGE("malformed base64 encoded data.");
        delete[] flac;
        return;
    }

    ALOGV("got flac of size %zu", flacSize);

    uint32_t picType;
    uint32_t typeLen;
    uint32_t descLen;
    uint32_t dataLen;
    char type[128];

    if (flacSize < 8) {
        delete[] flac;
        return;
    }

    picType = U32_AT(flac);

    if (picType != 3) {
        // This is not a front cover.
        delete[] flac;
        return;
    }

    typeLen = U32_AT(&flac[4]);
    if (typeLen > sizeof(type) - 1) {
        delete[] flac;
        return;
    }

    // we've already checked above that flacSize >= 8
    if (flacSize - 8 < typeLen) {
        delete[] flac;
        return;
    }

    memcpy(type, &flac[8], typeLen);
    type[typeLen] = '\0';

    ALOGV("picType = %d, type = '%s'", picType, type);

    if (!strcmp(type, "-->")) {
        // This is not inline cover art, but an external url instead.
        delete[] flac;
        return;
    }

    if (flacSize < 32 || flacSize - 32 < typeLen) {
        delete[] flac;
        return;
    }

    descLen = U32_AT(&flac[8 + typeLen]);
    if (flacSize - 32 - typeLen < descLen) {
        delete[] flac;
        return;
    }

    dataLen = U32_AT(&flac[8 + typeLen + 4 + descLen + 16]);

    // we've already checked above that (flacSize - 32 - typeLen - descLen) >= 0
    if (flacSize - 32 - typeLen - descLen < dataLen) {
        delete[] flac;
        return;
    }

    ALOGV("got image data, %zu trailing bytes",
         flacSize - 32 - typeLen - descLen - dataLen);

    AMediaFormat_setBuffer(fileMeta, AMEDIAFORMAT_KEY_ALBUMART,
            &flac[8 + typeLen + 4 + descLen + 20], dataLen);

    delete[] flac;
}

void parseVorbisComment(
        AMediaFormat *fileMeta, const char *comment, size_t commentLength) {
    // Haptic tag is only kept here as it will only be used in extractor to generate channel mask.
    struct {
        const char *const mTag;
        const char *mKey;
    } kMap[] = {
        { "TITLE", AMEDIAFORMAT_KEY_TITLE },
        { "ARTIST", AMEDIAFORMAT_KEY_ARTIST },
        { "ALBUMARTIST", AMEDIAFORMAT_KEY_ALBUMARTIST },
        { "ALBUM ARTIST", AMEDIAFORMAT_KEY_ALBUMARTIST },
        { "COMPILATION", AMEDIAFORMAT_KEY_COMPILATION },
        { "ALBUM", AMEDIAFORMAT_KEY_ALBUM },
        { "COMPOSER", AMEDIAFORMAT_KEY_COMPOSER },
        { "GENRE", AMEDIAFORMAT_KEY_GENRE },
        { "AUTHOR", AMEDIAFORMAT_KEY_AUTHOR },
        { "TRACKNUMBER", AMEDIAFORMAT_KEY_CDTRACKNUMBER },
        { "DISCNUMBER", AMEDIAFORMAT_KEY_DISCNUMBER },
        { "DATE", AMEDIAFORMAT_KEY_DATE },
        { "YEAR", AMEDIAFORMAT_KEY_YEAR },
        { "LYRICIST", AMEDIAFORMAT_KEY_LYRICIST },
        { "METADATA_BLOCK_PICTURE", AMEDIAFORMAT_KEY_ALBUMART },
        { "ANDROID_LOOP", AMEDIAFORMAT_KEY_LOOP },
        { "ANDROID_HAPTIC", AMEDIAFORMAT_KEY_HAPTIC_CHANNEL_COUNT },
    };

        for (size_t j = 0; j < sizeof(kMap) / sizeof(kMap[0]); ++j) {
            size_t tagLen = strlen(kMap[j].mTag);
            if (!strncasecmp(kMap[j].mTag, comment, tagLen)
                    && comment[tagLen] == '=') {
                if (kMap[j].mKey == AMEDIAFORMAT_KEY_ALBUMART) {
                    extractAlbumArt(
                            fileMeta,
                            &comment[tagLen + 1],
                            commentLength - tagLen - 1);
                } else if (kMap[j].mKey == AMEDIAFORMAT_KEY_LOOP) {
                    if (!strcasecmp(&comment[tagLen + 1], "true")) {
                        AMediaFormat_setInt32(fileMeta, AMEDIAFORMAT_KEY_LOOP, 1);
                    }
                } else if (kMap[j].mKey == AMEDIAFORMAT_KEY_HAPTIC_CHANNEL_COUNT) {
                    char *end;
                    errno = 0;
                    const int hapticChannelCount = strtol(&comment[tagLen + 1], &end, 10);
                    if (errno == 0) {
                        AMediaFormat_setInt32(fileMeta, kMap[j].mKey, hapticChannelCount);
                    } else {
                        ALOGE("Error(%d) when parsing haptic channel count", errno);
                    }
                } else {
                    AMediaFormat_setString(fileMeta, kMap[j].mKey, &comment[tagLen + 1]);
                }
            }
        }

}

}  // namespace android
