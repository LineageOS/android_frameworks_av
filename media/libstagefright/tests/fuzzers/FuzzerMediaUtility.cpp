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
#include <webm/WebmWriter.h>

namespace android {

sp<MediaWriter> createWriter(int fd, StandardWriters writerType, sp<MetaData> writerMeta,
                             FuzzedDataProvider* fdp) {
    sp<MediaWriter> writer;

    if (fdp->ConsumeBool()) {
        writerMeta->setInt32(kKeyRealTimeRecording, fdp->ConsumeBool());
    }

    switch (writerType) {
        case AAC:
            writer = sp<AACWriter>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADIF);
            }
            break;
        case AAC_ADTS:
            writer = sp<AACWriter>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADTS);
            }
            break;
        case AMR_NB:
            writer = sp<AMRWriter>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_NB);
            }
            break;
        case AMR_WB:
            writer = sp<AMRWriter>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_WB);
            }
            break;
        case MPEG2TS:
            writer = sp<MPEG2TSWriter>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG2TS);
            }
            break;
        case MPEG4:
            writer = sp<MPEG4Writer>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG_4);
            } else if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_HEIF);
            } else if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_THREE_GPP);
            }

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKey2ByteNalLength, fdp->ConsumeBool());
            }

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyTimeScale,
                                     fdp->ConsumeIntegralInRange<int32_t>(600, 96000));
            }

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKey4BitTrackIds, fdp->ConsumeBool());
            }

            if (fdp->ConsumeBool()) {
                writerMeta->setInt64(kKeyTrackTimeStatus, fdp->ConsumeIntegral<int64_t>());
            }

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyRotation, fdp->ConsumeIntegralInRange<uint8_t>(0, 3) * 90);
            }

            if (fdp->ConsumeBool()) {
                writerMeta->setInt64(kKeyTime, fdp->ConsumeIntegral<int64_t>());
            }
            break;
        case OGG:
            writer = sp<OggWriter>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_OGG);
            }
            break;
        case WEBM:
            writer = sp<WebmWriter>::make(fd);

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_WEBM);
            }

            if (fdp->ConsumeBool()) {
                writerMeta->setInt32(kKeyTimeScale,
                                     fdp->ConsumeIntegralInRange<int32_t>(600, 96000));
            }
            break;
    }

    return writer;
}

sp<FuzzSource> createSource(StandardWriters writerType, FuzzedDataProvider* fdp) {
    sp<MetaData> meta = sp<MetaData>::make();

    switch (writerType) {
        case AAC:
        case AAC_ADTS:
            meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_AAC);
            meta->setInt32(kKeyChannelCount, fdp->ConsumeIntegralInRange<uint8_t>(1, 7));
            meta->setInt32(kKeySampleRate, fdp->PickValueInArray<uint32_t>(kSampleRateTable));

            if (fdp->ConsumeBool()) {
                meta->setInt32(kKeyAACProfile, fdp->ConsumeIntegral<int32_t>());
            }
            break;
        case AMR_NB:
            meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_AMR_NB);
            meta->setInt32(kKeyChannelCount, 1);
            meta->setInt32(kKeySampleRate, 8000);
            break;
        case AMR_WB:
            meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_AMR_WB);
            meta->setInt32(kKeyChannelCount, 1);
            meta->setInt32(kKeySampleRate, 16000);
            break;
        case MPEG2TS:
            if (fdp->ConsumeBool()) {
                meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_AAC);
                meta->setInt32(kKeyChannelCount, fdp->ConsumeIntegral<int32_t>());
                meta->setInt32(kKeySampleRate, fdp->PickValueInArray<uint32_t>(kSampleRateTable));
            } else {
                meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);
                // The +1s ensure a minimum height and width of 1.
                meta->setInt32(kKeyWidth, fdp->ConsumeIntegral<uint16_t>() + 1);
                meta->setInt32(kKeyHeight, fdp->ConsumeIntegral<uint16_t>() + 1);
            }
            break;
        case MPEG4: {
            auto mime = fdp->PickValueInArray<std::string>(kMpeg4MimeTypes);
            meta->setCString(kKeyMIMEType, mime.c_str());

            if (fdp->ConsumeBool()) {
                meta->setInt32(kKeyBackgroundMode, fdp->ConsumeBool());
            }

            if (!strncasecmp(mime.c_str(), "audio/", 6)) {
                meta->setInt32(kKeyChannelCount, fdp->ConsumeIntegral<int32_t>());
                meta->setInt32(kKeySampleRate, fdp->PickValueInArray<uint32_t>(kSampleRateTable));

            } else {
                // The +1s ensure a minimum height and width of 1.
                meta->setInt32(kKeyWidth, fdp->ConsumeIntegral<uint16_t>() + 1);
                meta->setInt32(kKeyHeight, fdp->ConsumeIntegral<uint16_t>() + 1);

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyDisplayWidth, fdp->ConsumeIntegral<uint16_t>());
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyDisplayHeight, fdp->ConsumeIntegral<uint16_t>());
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyTileWidth, fdp->ConsumeIntegral<uint16_t>());
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyTileHeight, fdp->ConsumeIntegral<uint16_t>());
                }
                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyGridRows, fdp->ConsumeIntegral<uint8_t>());
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyGridCols, fdp->ConsumeIntegral<uint8_t>());
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyTemporalLayerCount, fdp->ConsumeIntegral<int32_t>());
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeySARWidth, fdp->ConsumeIntegral<uint16_t>());
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeySARHeight, fdp->ConsumeIntegral<uint16_t>());
                }
            }

            if (fdp->ConsumeBool()) {
                meta->setInt32(kKeyBitRate, fdp->ConsumeIntegral<int32_t>());
            }

            if (fdp->ConsumeBool()) {
                meta->setInt32(kKeyMaxBitRate, fdp->ConsumeIntegral<int32_t>());
            }

            if (fdp->ConsumeBool()) {
                meta->setInt32(kKeyTrackIsDefault, fdp->ConsumeBool());
            }
            break;
        }
        case OGG:
            meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_OPUS);

            if (fdp->ConsumeBool()) {
                meta->setInt32(kKeyChannelCount, fdp->ConsumeIntegral<int32_t>());
            }

            if (fdp->ConsumeBool()) {
                meta->setInt32(kKeySampleRate, fdp->PickValueInArray<uint32_t>(kSampleRateTable));
            }
            break;
        case WEBM:
            if (fdp->ConsumeBool()) {
                if (fdp->ConsumeBool()) {
                    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_VP8);
                } else {
                    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_VP9);
                }

                if (fdp->ConsumeBool()) {
                    // The +1s ensure a minimum height and width of 1.
                    meta->setInt32(kKeyWidth, fdp->ConsumeIntegral<uint16_t>() + 1);
                    meta->setInt32(kKeyHeight, fdp->ConsumeIntegral<uint16_t>() + 1);
                }
            } else {
                if (fdp->ConsumeBool()) {
                    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_VORBIS);
                } else {
                    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_AUDIO_OPUS);
                }

                if (fdp->ConsumeBool()) {
                    meta->setInt32(kKeyChannelCount, fdp->ConsumeIntegral<int32_t>());
                }
                meta->setInt32(kKeySampleRate, fdp->PickValueInArray<uint32_t>(kSampleRateTable));
            }

            break;
    }

    return sp<FuzzSource>::make(meta, fdp);
}
}  // namespace android
