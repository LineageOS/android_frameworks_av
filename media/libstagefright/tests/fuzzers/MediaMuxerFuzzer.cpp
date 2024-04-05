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

#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/MediaMuxer.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/MediaDefs.h>

namespace android {
const uint8_t kMinSize = 0;
const uint8_t kMinTrackCount = 0;

enum kBufferFlags { BUFFER_FLAG_SYNCFRAME = 1, BUFFER_FLAG_CODECCONFIG = 2, BUFFER_FLAG_EOS = 4 };

constexpr char kMuxerFile[] = "MediaMuxer";

const std::string kAudioMimeTypes[] = {
        MEDIA_MIMETYPE_AUDIO_AMR_NB,
        MEDIA_MIMETYPE_AUDIO_AMR_WB,
        MEDIA_MIMETYPE_AUDIO_MPEG,
        MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_I,
        MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_II,
        MEDIA_MIMETYPE_AUDIO_MIDI,
        MEDIA_MIMETYPE_AUDIO_AAC,
        MEDIA_MIMETYPE_AUDIO_QCELP,
        MEDIA_MIMETYPE_AUDIO_VORBIS,
        MEDIA_MIMETYPE_AUDIO_OPUS,
        MEDIA_MIMETYPE_AUDIO_G711_ALAW,
        MEDIA_MIMETYPE_AUDIO_G711_MLAW,
        MEDIA_MIMETYPE_AUDIO_RAW,
        MEDIA_MIMETYPE_AUDIO_FLAC,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS,
        MEDIA_MIMETYPE_AUDIO_MSGSM,
        MEDIA_MIMETYPE_AUDIO_AC3,
        MEDIA_MIMETYPE_AUDIO_EAC3,
        MEDIA_MIMETYPE_AUDIO_EAC3_JOC,
        MEDIA_MIMETYPE_AUDIO_AC4,
        MEDIA_MIMETYPE_AUDIO_MPEGH_MHA1,
        MEDIA_MIMETYPE_AUDIO_MPEGH_MHM1,
        MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L3,
        MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L4,
        MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L3,
        MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L4,
        MEDIA_MIMETYPE_AUDIO_SCRAMBLED,
        MEDIA_MIMETYPE_AUDIO_ALAC,
        MEDIA_MIMETYPE_AUDIO_WMA,
        MEDIA_MIMETYPE_AUDIO_MS_ADPCM,
        MEDIA_MIMETYPE_AUDIO_DVI_IMA_ADPCM,
        MEDIA_MIMETYPE_AUDIO_DTS,
        MEDIA_MIMETYPE_AUDIO_DTS_HD,
        MEDIA_MIMETYPE_AUDIO_DTS_HD_MA,
        MEDIA_MIMETYPE_AUDIO_DTS_UHD,
        MEDIA_MIMETYPE_AUDIO_DTS_UHD_P1,
        MEDIA_MIMETYPE_AUDIO_DTS_UHD_P2,
        MEDIA_MIMETYPE_AUDIO_EVRC,
        MEDIA_MIMETYPE_AUDIO_EVRCB,
        MEDIA_MIMETYPE_AUDIO_EVRCWB,
        MEDIA_MIMETYPE_AUDIO_EVRCNW,
        MEDIA_MIMETYPE_AUDIO_AMR_WB_PLUS,
        MEDIA_MIMETYPE_AUDIO_APTX,
        MEDIA_MIMETYPE_AUDIO_DRA,
        MEDIA_MIMETYPE_AUDIO_DOLBY_MAT,
        MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_1_0,
        MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_2_0,
        MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_2_1,
        MEDIA_MIMETYPE_AUDIO_DOLBY_TRUEHD,
        MEDIA_MIMETYPE_AUDIO_AAC_MP4,
        MEDIA_MIMETYPE_AUDIO_AAC_MAIN,
        MEDIA_MIMETYPE_AUDIO_AAC_LC,
        MEDIA_MIMETYPE_AUDIO_AAC_SSR,
        MEDIA_MIMETYPE_AUDIO_AAC_LTP,
        MEDIA_MIMETYPE_AUDIO_AAC_HE_V1,
        MEDIA_MIMETYPE_AUDIO_AAC_SCALABLE,
        MEDIA_MIMETYPE_AUDIO_AAC_ERLC,
        MEDIA_MIMETYPE_AUDIO_AAC_LD,
        MEDIA_MIMETYPE_AUDIO_AAC_HE_V2,
        MEDIA_MIMETYPE_AUDIO_AAC_ELD,
        MEDIA_MIMETYPE_AUDIO_AAC_XHE,
        MEDIA_MIMETYPE_AUDIO_AAC_ADIF,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_MAIN,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LC,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SSR,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LTP,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V1,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SCALABLE,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ERLC,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LD,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V2,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ELD,
        MEDIA_MIMETYPE_AUDIO_AAC_ADTS_XHE,
        MEDIA_MIMETYPE_AUDIO_AAC_LATM_LC,
        MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V1,
        MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V2,
        MEDIA_MIMETYPE_AUDIO_IEC61937,
        MEDIA_MIMETYPE_AUDIO_IEC60958,
};

const std::string kVideoMimeTypes[] = {
        MEDIA_MIMETYPE_VIDEO_VP8,       MEDIA_MIMETYPE_VIDEO_VP9,
        MEDIA_MIMETYPE_VIDEO_AV1,       MEDIA_MIMETYPE_VIDEO_AVC,
        MEDIA_MIMETYPE_VIDEO_HEVC,      MEDIA_MIMETYPE_VIDEO_MPEG4,
        MEDIA_MIMETYPE_VIDEO_H263,      MEDIA_MIMETYPE_VIDEO_MPEG2,
        MEDIA_MIMETYPE_VIDEO_RAW,       MEDIA_MIMETYPE_VIDEO_DOLBY_VISION,
        MEDIA_MIMETYPE_VIDEO_SCRAMBLED, MEDIA_MIMETYPE_VIDEO_DIVX,
        MEDIA_MIMETYPE_VIDEO_DIVX3,     MEDIA_MIMETYPE_VIDEO_XVID,
        MEDIA_MIMETYPE_VIDEO_MJPEG,
};

void getSampleAudioFormat(FuzzedDataProvider& fdp, AMessage* format) {
    std::string mimeType = fdp.PickValueInArray(kAudioMimeTypes);
    format->setString("mime", mimeType.c_str(), mimeType.length());
    format->setInt32("sample-rate", fdp.ConsumeIntegral<int32_t>());
    format->setInt32("channel-count", fdp.ConsumeIntegral<int32_t>());
}

void getSampleVideoFormat(FuzzedDataProvider& fdp, AMessage* format) {
    std::string mimeType = fdp.PickValueInArray(kVideoMimeTypes);
    format->setString("mime", mimeType.c_str(), mimeType.length());
    format->setInt32("height", fdp.ConsumeIntegral<int32_t>());
    format->setInt32("width", fdp.ConsumeIntegral<int32_t>());
    format->setInt32("time-lapse-fps", fdp.ConsumeIntegral<int32_t>());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // memfd_create() creates an anonymous file and returns a file
    // descriptor that refers to it. MFD_ALLOW_SEALING allows sealing
    // operations on this file.
    int32_t fd = memfd_create(kMuxerFile, MFD_ALLOW_SEALING);
    if (fd == -1) {
        ALOGE("memfd_create failed: %s", strerror(errno));
        return 0;
    }

    auto outputFormat = (MediaMuxer::OutputFormat)fdp.ConsumeIntegralInRange<int32_t>(
            MediaMuxer::OutputFormat::OUTPUT_FORMAT_MPEG_4,
            MediaMuxer::OutputFormat::OUTPUT_FORMAT_LIST_END);

    sp<MediaMuxer> mMuxer = MediaMuxer::create(fd, outputFormat);
    if (mMuxer == nullptr) {
        close(fd);
        return 0;
    }

    // Used to consume a maximum of 80% of the data to send buffer data to writeSampleData().
    // This ensures that we don't completely exhaust data and use the rest 20% for fuzzing
    // of APIs.
    const size_t kMaxSize = (size * 80) / 100;
    while (fdp.remaining_bytes()) {
        auto invokeMediaMuxerAPI = fdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    // Using 'return' here due to a timeout bug present in OGGWriter.cpp
                    // (b/310316183).
                    if (outputFormat == MediaMuxer::OutputFormat::OUTPUT_FORMAT_OGG) {
                        return;
                    }

                    sp<AMessage> format = sp<AMessage>::make();
                    fdp.ConsumeBool() ? getSampleAudioFormat(fdp, format.get())
                                      : getSampleVideoFormat(fdp, format.get());

                    mMuxer->addTrack(fdp.ConsumeBool() ? format : nullptr);
                },
                [&]() {
                    mMuxer->setLocation(fdp.ConsumeIntegral<int32_t>() /* latitude */,
                                        fdp.ConsumeIntegral<int32_t>() /* longitude */);
                },
                [&]() { mMuxer->setOrientationHint(fdp.ConsumeIntegral<int32_t>() /* degrees */); },
                [&]() { mMuxer->start(); },
                [&]() {
                    std::vector<uint8_t> sample = fdp.ConsumeBytes<uint8_t>(
                            fdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize));
                    sp<ABuffer> buffer = sp<ABuffer>::make(sample.data(), sample.size());

                    size_t offset = fdp.ConsumeIntegralInRange<size_t>(kMinSize, sample.size());
                    size_t length =
                            fdp.ConsumeIntegralInRange<size_t>(kMinSize, buffer->size() - offset);
                    buffer->setRange(offset, length);

                    sp<AMessage> meta = buffer->meta();
                    meta->setInt64("sample-file-offset", fdp.ConsumeIntegral<int64_t>());
                    meta->setInt64("last-sample-index-in-chunk", fdp.ConsumeIntegral<int64_t>());

                    uint32_t flags = 0;
                    if (fdp.ConsumeBool()) {
                        flags |= kBufferFlags::BUFFER_FLAG_SYNCFRAME;
                    }
                    if (fdp.ConsumeBool()) {
                        flags |= kBufferFlags::BUFFER_FLAG_CODECCONFIG;
                    }
                    if (fdp.ConsumeBool()) {
                        flags |= kBufferFlags::BUFFER_FLAG_EOS;
                    }

                    size_t trackIndex = fdp.ConsumeBool()
                                                ? fdp.ConsumeIntegralInRange<size_t>(
                                                          kMinTrackCount, mMuxer->getTrackCount())
                                                : fdp.ConsumeIntegral<size_t>();
                    int64_t timeUs = fdp.ConsumeIntegral<int64_t>();
                    mMuxer->writeSampleData(fdp.ConsumeBool() ? buffer : nullptr, trackIndex,
                                            timeUs, flags);
                },
                [&]() {
                    mMuxer->getTrackFormat(
                            fdp.ConsumeBool() ? fdp.ConsumeIntegralInRange<size_t>(
                                                        kMinTrackCount, mMuxer->getTrackCount())
                                              : fdp.ConsumeIntegral<size_t>() /* idx */);
                },
                [&]() { mMuxer->stop(); },
        });

        invokeMediaMuxerAPI();
    }

    close(fd);
    return 0;
}
} // namespace android
