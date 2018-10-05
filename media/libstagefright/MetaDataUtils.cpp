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
#include <media/stagefright/foundation/ABitReader.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataUtils.h>
#include <media/stagefright/Utils.h>
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

}  // namespace android
