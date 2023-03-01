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

#ifndef MEDIA_DEFS_H_

#define MEDIA_DEFS_H_

namespace android {

extern const char *MEDIA_MIMETYPE_IMAGE_JPEG;
extern const char *MEDIA_MIMETYPE_IMAGE_ANDROID_HEIC;
extern const char *MEDIA_MIMETYPE_IMAGE_AVIF;

extern const char *MEDIA_MIMETYPE_VIDEO_VP8;
extern const char *MEDIA_MIMETYPE_VIDEO_VP9;
extern const char *MEDIA_MIMETYPE_VIDEO_AV1;
extern const char *MEDIA_MIMETYPE_VIDEO_AVC;
extern const char *MEDIA_MIMETYPE_VIDEO_HEVC;
extern const char *MEDIA_MIMETYPE_VIDEO_MPEG4;
extern const char *MEDIA_MIMETYPE_VIDEO_H263;
extern const char *MEDIA_MIMETYPE_VIDEO_MPEG2;
extern const char *MEDIA_MIMETYPE_VIDEO_RAW;
extern const char *MEDIA_MIMETYPE_VIDEO_DOLBY_VISION;
extern const char *MEDIA_MIMETYPE_VIDEO_SCRAMBLED;
extern const char *MEDIA_MIMETYPE_VIDEO_DIVX;
extern const char *MEDIA_MIMETYPE_VIDEO_DIVX3;
extern const char *MEDIA_MIMETYPE_VIDEO_XVID;
extern const char *MEDIA_MIMETYPE_VIDEO_MJPEG;

extern const char *MEDIA_MIMETYPE_AUDIO_AMR_NB;
extern const char *MEDIA_MIMETYPE_AUDIO_AMR_WB;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEG;           // layer III
extern const char *MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_I;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEG_LAYER_II;
extern const char *MEDIA_MIMETYPE_AUDIO_MIDI;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC;
extern const char *MEDIA_MIMETYPE_AUDIO_QCELP;
extern const char *MEDIA_MIMETYPE_AUDIO_VORBIS;
extern const char *MEDIA_MIMETYPE_AUDIO_OPUS;
extern const char *MEDIA_MIMETYPE_AUDIO_G711_ALAW;
extern const char *MEDIA_MIMETYPE_AUDIO_G711_MLAW;
extern const char *MEDIA_MIMETYPE_AUDIO_RAW;
extern const char *MEDIA_MIMETYPE_AUDIO_FLAC;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS;
extern const char *MEDIA_MIMETYPE_AUDIO_MSGSM;
extern const char *MEDIA_MIMETYPE_AUDIO_AC3;
extern const char *MEDIA_MIMETYPE_AUDIO_EAC3;
extern const char *MEDIA_MIMETYPE_AUDIO_EAC3_JOC;
extern const char *MEDIA_MIMETYPE_AUDIO_AC4;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEGH_MHA1;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEGH_MHM1;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L3;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEGH_BL_L4;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L3;
extern const char *MEDIA_MIMETYPE_AUDIO_MPEGH_LC_L4;
extern const char *MEDIA_MIMETYPE_AUDIO_SCRAMBLED;
extern const char *MEDIA_MIMETYPE_AUDIO_ALAC;
extern const char *MEDIA_MIMETYPE_AUDIO_WMA;
extern const char *MEDIA_MIMETYPE_AUDIO_MS_ADPCM;
extern const char *MEDIA_MIMETYPE_AUDIO_DVI_IMA_ADPCM;
extern const char *MEDIA_MIMETYPE_AUDIO_DTS;
extern const char *MEDIA_MIMETYPE_AUDIO_DTS_HD;
extern const char *MEDIA_MIMETYPE_AUDIO_DTS_HD_MA;
extern const char *MEDIA_MIMETYPE_AUDIO_DTS_UHD;
extern const char *MEDIA_MIMETYPE_AUDIO_DTS_UHD_P1;
extern const char *MEDIA_MIMETYPE_AUDIO_DTS_UHD_P2;
extern const char *MEDIA_MIMETYPE_AUDIO_EVRC;
extern const char *MEDIA_MIMETYPE_AUDIO_EVRCB;
extern const char *MEDIA_MIMETYPE_AUDIO_EVRCWB;
extern const char *MEDIA_MIMETYPE_AUDIO_EVRCNW;
extern const char *MEDIA_MIMETYPE_AUDIO_AMR_WB_PLUS;
extern const char *MEDIA_MIMETYPE_AUDIO_APTX;
extern const char *MEDIA_MIMETYPE_AUDIO_DRA;
extern const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT;
extern const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_1_0;
extern const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_2_0;
extern const char *MEDIA_MIMETYPE_AUDIO_DOLBY_MAT_2_1;
extern const char *MEDIA_MIMETYPE_AUDIO_DOLBY_TRUEHD;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_MP4;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_MAIN;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_LC;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_SSR;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_LTP;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_HE_V1;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_SCALABLE;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ERLC;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_LD;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_HE_V2;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ELD;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_XHE;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADIF;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_MAIN;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LC;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SSR;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LTP;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V1;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_SCALABLE;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ERLC;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_LD;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_HE_V2;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_ELD;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_ADTS_XHE;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_LATM_LC;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V1;
extern const char *MEDIA_MIMETYPE_AUDIO_AAC_LATM_HE_V2;
extern const char *MEDIA_MIMETYPE_AUDIO_IEC61937;
extern const char *MEDIA_MIMETYPE_AUDIO_IEC60958;

extern const char *MEDIA_MIMETYPE_CONTAINER_MPEG4;
extern const char *MEDIA_MIMETYPE_CONTAINER_WAV;
extern const char *MEDIA_MIMETYPE_CONTAINER_OGG;
extern const char *MEDIA_MIMETYPE_CONTAINER_MATROSKA;
extern const char *MEDIA_MIMETYPE_CONTAINER_MPEG2TS;
extern const char *MEDIA_MIMETYPE_CONTAINER_AVI;
extern const char *MEDIA_MIMETYPE_CONTAINER_MPEG2PS;
extern const char *MEDIA_MIMETYPE_CONTAINER_HEIF;

extern const char *MEDIA_MIMETYPE_TEXT_3GPP;
extern const char *MEDIA_MIMETYPE_TEXT_SUBRIP;
extern const char *MEDIA_MIMETYPE_TEXT_VTT;
extern const char *MEDIA_MIMETYPE_TEXT_CEA_608;
extern const char *MEDIA_MIMETYPE_TEXT_CEA_708;
extern const char *MEDIA_MIMETYPE_DATA_TIMED_ID3;

// These are values exported to JAVA API that need to be in sync with
// frameworks/base/media/java/android/media/AudioFormat.java. Unfortunately,
// they are not defined in frameworks/av, so defining them here.
enum AudioEncoding {
    kAudioEncodingPcm16bit = 2,
    kAudioEncodingPcm8bit = 3,
    kAudioEncodingPcmFloat = 4,
    kAudioEncodingPcm24bitPacked = 21,
    kAudioEncodingPcm32bit = 22,
};

}  // namespace android

#endif  // MEDIA_DEFS_H_
