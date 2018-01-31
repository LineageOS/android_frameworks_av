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

#include <media/stagefright/foundation/avc_utils.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataUtils.h>

namespace android {

sp<MetaData> MakeAVCCodecSpecificData(const sp<ABuffer> &accessUnit) {
    int32_t width;
    int32_t height;
    int32_t sarWidth;
    int32_t sarHeight;
    sp<ABuffer> csd = MakeAVCCodecSpecificData(accessUnit, &width, &height, &sarWidth, &sarHeight);
    if (csd == nullptr) {
        return nullptr;
    }
    sp<MetaData> meta = new MetaData;
    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);

    meta->setData(kKeyAVCC, kTypeAVCC, csd->data(), csd->size());
    meta->setInt32(kKeyWidth, width);
    meta->setInt32(kKeyHeight, height);
    if (sarWidth > 0 && sarHeight > 0) {
        meta->setInt32(kKeySARWidth, sarWidth);
        meta->setInt32(kKeySARHeight, sarHeight);
    }
    return meta;
}

sp<MetaData> MakeAACCodecSpecificData(
        unsigned profile, unsigned sampling_freq_index,
        unsigned channel_configuration) {
    int32_t sampleRate;
    int32_t channelCount;
    sp<ABuffer> csd = MakeAACCodecSpecificData(profile, sampling_freq_index,
            channel_configuration, &sampleRate, &channelCount);
    if (csd == nullptr) {
        return nullptr;
    }
    sp<MetaData> meta = new MetaData;
    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_AAC);

    meta->setInt32(kKeySampleRate, sampleRate);
    meta->setInt32(kKeyChannelCount, channelCount);

    meta->setData(kKeyESDS, 0, csd->data(), csd->size());
    return meta;
}

}  // namespace android
