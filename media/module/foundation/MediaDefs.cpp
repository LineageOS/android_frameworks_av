/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include <media/stagefright/foundation/MediaDefs.h>

namespace android {

const char *MEDIA_MIMETYPE_IMAGE_JPEG = "image/jpeg";
const char *MEDIA_MIMETYPE_IMAGE_ANDROID_HEIC = "image/vnd.android.heic";
const char *MEDIA_MIMETYPE_IMAGE_AVIF = "image/avif";

const char *MEDIA_MIMETYPE_VIDEO_VP8 = "video/x-vnd.on2.vp8";
const char *MEDIA_MIMETYPE_VIDEO_VP9 = "video/x-vnd.on2.vp9";
const char *MEDIA_MIMETYPE_VIDEO_AV1 = "video/av01";
const char *MEDIA_MIMETYPE_VIDEO_AVC = "video/avc";
const char *MEDIA_MIMETYPE_VIDEO_HEVC = "video/hevc";
const char *MEDIA_MIMETYPE_VIDEO_MPEG4 = "video/mp4v-es";
const char *MEDIA_MIMETYPE_VIDEO_H263 = "video/3gpp";
const char *MEDIA_MIMETYPE_VIDEO_MPEG2 = "video/mpeg2";
const char *MEDIA_MIMETYPE_VIDEO_RAW = "video/raw";
const char *MEDIA_MIMETYPE_VIDEO_DOLBY_VISION = "video/dolby-vision";
const char *MEDIA_MIMETYPE_VIDEO_SCRAMBLED = "video/scrambled";
const char *MEDIA_MIMETYPE_VIDEO_DIVX = "video/divx";
const char *MEDIA_MIMETYPE_VIDEO_DIVX3 = "video/divx3";
const char *MEDIA_MIMETYPE_VIDEO_XVID = "video/xvid";
const char *MEDIA_MIMETYPE_VIDEO_MJPEG = "video/x-motion-jpeg";

const char *MEDIA_MIMETYPE_AUDIO_AMR_NB = "audio/3gpp";
const char *MEDIA_MIMETYPE_AUDIO_AMR_WB = "audio/amr-wb";
const char *MEDIA_MIMETYPE_AUDIO_MPEG = "audio/mpeg";
const char *MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_I = "audio/mpeg-L1";
const char *MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_II = "audio/mpeg-L2";
const char *MEDIA_MIMETYPE_AUDIO_MIDI = "audio/midi";
const char *MEDIA_MIMETYPE_AUDIO_AAC = "audio/mp4a-latm";
const char *MEDIA_MIMETYPE_AUDIO_QCELP = "audio/qcelp";
const char *MEDIA_MIMETYPE_AUDIO_VORBIS = "audio/vorbis";
const char *MEDIA_MIMETYPE_AUDIO_OPUS = "audio/opus";
const char *MEDIA_MIMETYPE_AUDIO_G711_ALAW = "audio/g711-alaw";
const char *MEDIA_MIMETYPE_AUDIO_G711_MLAW = "audio/g711-mlaw";
const char *MEDIA_MIMETYPE_AUDIO_RAW = "audio/raw";
const char *MEDIA_MIMETYPE_AUDIO_FLAC = "audio/flac";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS = "audio/aac-adts";
const char *MEDIA_MIMETYPE_AUDIO_MSGSM = "audio/gsm";
const char *MEDIA_MIMETYPE_AUDIO_AC3 = "audio/ac3";
const char *MEDIA_MIMETYPE_AUDIO_EAC3 = "audio/eac3";
const char *MEDIA_MIMETYPE_AUDIO_EAC3_JOC = "audio/eac3-joc";
const char *MEDIA_MIMETYPE_AUDIO_AC4 = "audio/ac4";
const char *MEDIA_MIMETYPE_AUDIO_MPEGH_MHA1 = "audio/mha1";
const char *MEDIA_MIMETYPE_AUDIO_MPEGH_MHM1 = "audio/mhm1";
const char *MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L3 = "audio/mhm1.03";
const char *MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L4 = "audio/mhm1.04";
const char *MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L3 = "audio/mhm1.0d";
const char *MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L4 = "audio/mhm1.0e";
const char *MEDIA_MIMETYPE_AUDIO_SCRAMBLED = "audio/scrambled";
const char *MEDIA_MIMETYPE_AUDIO_ALAC = "audio/alac";
const char *MEDIA_MIMETYPE_AUDIO_WMA = "audio/x-ms-wma";
const char *MEDIA_MIMETYPE_AUDIO_MS_ADPCM = "audio/x-adpcm-ms";
const char *MEDIA_MIMETYPE_AUDIO_DVI_IMA_ADPCM = "audio/x-adpcm-dvi-ima";
const char *MEDIA_MIMETYPE_AUDIO_DTS = "audio/vnd.dts";
const char *MEDIA_MIMETYPE_AUDIO_DTS_HD = "audio/vnd.dts.hd";
const char *MEDIA_MIMETYPE_AUDIO_DTS_HD_MA = "audio/vnd.dts.hd;profile=dtsma";
const char *MEDIA_MIMETYPE_AUDIO_DTS_UHD = "audio/vnd.dts.uhd";
const char *MEDIA_MIMETYPE_AUDIO_DTS_UHD_P1 = "audio/vnd.dts.uhd;profile=p1";
const char *MEDIA_MIMETYPE_AUDIO_DTS_UHD_P2 = "audio/vnd.dts.uhd;profile=p2";
const char *MEDIA_MIMETYPE_AUDIO_EVRC = "audio/evrc";
const char *MEDIA_MIMETYPE_AUDIO_EVRCB = "audio/evrcb";
const char *MEDIA_MIMETYPE_AUDIO_EVRCWB = "audio/evrcwb";
const char *MEDIA_MIMETYPE_AUDIO_EVRCNW = "audio/evrcnw";
const char *MEDIA_MIMETYPE_AUDIO_AMR_WB_PLUS = "audio/amr-wb+";
const char *MEDIA_MIMETYPE_AUDIO_APTX = "audio/aptx";
const char *MEDIA_MIMETYPE_AUDIO_DRA = "audio/vnd.dra";
// Note: not in the IANA registry.
const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT = "audio/vnd.dolby.mat";
// Note: not in the IANA registry.
const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_1_0 = "audio/vnd.dolby.mat.1.0";
// Note: not in the IANA registry.
const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_2_0 = "audio/vnd.dolby.mat.2.0";
// Note: not in the IANA registry.
const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_2_1 = "audio/vnd.dolby.mat.2.1";
const char *MEDIA_MIMETYPE_AUDIO_DOLBY_TRUEHD = "audio/vnd.dolby.mlp";
const char *MEDIA_MIMETYPE_AUDIO_AAC_MP4 = "audio/mp4a.40";
const char *MEDIA_MIMETYPE_AUDIO_AAC_MAIN = "audio/mp4a.40.01";
const char *MEDIA_MIMETYPE_AUDIO_AAC_LC = "audio/mp4a.40.02";
const char *MEDIA_MIMETYPE_AUDIO_AAC_SSR = "audio/mp4a.40.03";
const char *MEDIA_MIMETYPE_AUDIO_AAC_LTP = "audio/mp4a.40.04";
const char *MEDIA_MIMETYPE_AUDIO_AAC_HE_V1 = "audio/mp4a.40.05";
const char *MEDIA_MIMETYPE_AUDIO_AAC_SCALABLE = "audio/mp4a.40.06";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ERLC = "audio/mp4a.40.17";
const char *MEDIA_MIMETYPE_AUDIO_AAC_LD = "audio/mp4a.40.23";
const char *MEDIA_MIMETYPE_AUDIO_AAC_HE_V2 = "audio/mp4a.40.29";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ELD = "audio/mp4a.40.39";
const char *MEDIA_MIMETYPE_AUDIO_AAC_XHE = "audio/mp4a.40.42";
// Note: not in the IANA registry.
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADIF = "audio/aac-adif";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_MAIN = "audio/aac-adts.01";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LC = "audio/aac-adts.02";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SSR = "audio/aac-adts.03";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LTP = "audio/aac-adts.04";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V1 = "audio/aac-adts.05";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SCALABLE = "audio/aac-adts.06";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ERLC = "audio/aac-adts.17";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LD = "audio/aac-adts.23";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V2 = "audio/aac-adts.29";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ELD = "audio/aac-adts.39";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_XHE = "audio/aac-adts.42";
const char *MEDIA_MIMETYPE_AUDIO_AAC_LATM_LC = "audio/mp4a-latm.02";
const char *MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V1 = "audio/mp4a-latm.05";
const char *MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V2 = "audio/mp4a-latm.29";
// Note: not in the IANA registry.
const char *MEDIA_MIMETYPE_AUDIO_IEC61937 = "audio/x-iec61937";
// Note: not in the IANA registry.
const char *MEDIA_MIMETYPE_AUDIO_IEC60958 = "audio/x-iec60958";

const char *MEDIA_MIMETYPE_CONTAINER_MPEG4 = "video/mp4";
const char *MEDIA_MIMETYPE_CONTAINER_WAV = "audio/x-wav";
const char *MEDIA_MIMETYPE_CONTAINER_OGG = "audio/ogg";
const char *MEDIA_MIMETYPE_CONTAINER_MATROSKA = "video/x-matroska";
const char *MEDIA_MIMETYPE_CONTAINER_MPEG2TS = "video/mp2ts";
const char *MEDIA_MIMETYPE_CONTAINER_AVI = "video/avi";
const char *MEDIA_MIMETYPE_CONTAINER_MPEG2PS = "video/mp2p";
const char *MEDIA_MIMETYPE_CONTAINER_HEIF = "image/heif";

const char *MEDIA_MIMETYPE_TEXT_3GPP = "text/3gpp-tt";
const char *MEDIA_MIMETYPE_TEXT_SUBRIP = "application/x-subrip";
const char *MEDIA_MIMETYPE_TEXT_VTT = "text/vtt";
const char *MEDIA_MIMETYPE_TEXT_CEA_608 = "text/cea-608";
const char *MEDIA_MIMETYPE_TEXT_CEA_708 = "text/cea-708";
const char *MEDIA_MIMETYPE_DATA_TIMED_ID3 = "application/x-id3v4";

}  // namespace android
