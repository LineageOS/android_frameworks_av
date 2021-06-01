/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.media;

/**
 * Audio format  is a 32-bit word that consists of:
 *   main format field (upper 8 bits)
 *   sub format field (lower 24 bits).
 *
 * The main format indicates the main codec type. The sub format field indicates
 * options and parameters for each format. The sub format is mainly used for
 * record to indicate for instance the requested bitrate or profile.  It can
 * also be used for certain formats to give informations not present in the
 * encoded audio stream (e.g. octet alignement for AMR).
 *
 * This type corresponds to enums in system/audio.h, whereas 'AudioFormat.aidl'
 * located in frameworks/base/media/java/android/media is the type used by SDK.
 * Both types are in the 'android.media' package.
 *
 * {@hide}
 */
@Backing(type="int")
enum AudioFormatSys {
   /**
    * Framework use only, do not constitute valid formats.
    */
   MAIN_MASK = 0xFF000000,
   SUB_MASK = 0x00FFFFFF,
   INVALID = 0xFFFFFFFF,
   PCM = 0x00000000,

   DEFAULT = 0,

   PCM_16_BIT = 0x1,
   PCM_8_BIT = 0x2,
   PCM_32_BIT = 0x3,
   PCM_8_24_BIT = 0x4,
   PCM_FLOAT = 0x5,
   PCM_24_BIT_PACKED = 0x6,
   MP3 = 0x01000000,
   AMR_NB = 0x02000000,
   AMR_WB = 0x03000000,
   AAC = 0x04000000,
   AAC_MAIN = 0x04000001,
   AAC_LC = 0x04000002,
   AAC_SSR = 0x04000004,
   AAC_LTP = 0x04000008,
   AAC_HE_V1 = 0x04000010,
   AAC_SCALABLE = 0x04000020,
   AAC_ERLC = 0x04000040,
   AAC_LD = 0x04000080,
   AAC_HE_V2 = 0x040000100,
   AAC_ELD = 0x040000200,
   AAC_XHE = 0x040000300,
   /**
    * Deprecated, Use AAC_HE_V1.
    */
   HE_AAC_V1 = 0x05000000,
   /**
    * Deprecated, Use AAC_HE_V2.
    */
   HE_AAC_V2 = 0x06000000,
   VORBIS = 0x07000000,
   OPUS = 0x08000000,
   AC3 = 0x09000000,
   E_AC3 = 0x0A000000,
   E_AC3_JOC = 0x0A000001,
   DTS = 0x0B000000,
   DTS_HD = 0x0C000000,
   IEC61937 = 0x0D000000,
   DOLBY_TRUEHD = 0x0E000000,
   EVRC = 0x10000000,
   EVRCB = 0x11000000,
   EVRCWB = 0x12000000,
   EVRCNW = 0x13000000,
   AAC_ADIF = 0x14000000,
   WMA = 0x15000000,
   WMA_PRO = 0x16000000,
   AMR_WB_PLUS = 0x17000000,
   MP2 = 0x18000000,
   QCELP = 0x19000000,
   DSD = 0x1A000000,
   FLAC = 0x1B000000,
   ALAC = 0x1C000000,
   APE = 0x1D000000,
   AAC_ADTS = 0x1E000000,
   AAC_ADTS_MAIN = 0x1E000001,
   AAC_ADTS_LC = 0x1E000002,
   AAC_ADTS_SSR = 0x1E000004,
   AAC_ADTS_LTP = 0x1E000008,
   AAC_ADTS_HE_V1 = 0x1E000010,
   AAC_ADTS_SCALABLE = 0x1E000020,
   AAC_ADTS_ERLC = 0x1E000040,
   AAC_ADTS_LD = 0x1E000080,
   AAC_ADTS_HE_V2 = 0x1E000100,
   AAC_ADTS_ELD = 0x1E000200,
   AAC_ADTS_XHE = 0x1E000300,
   SBC = 0x1F000000,
   APTX = 0x20000000,
   APTX_HD = 0x21000000,
   AC4 = 0x22000000,
   LDAC = 0x23000000,
   MAT = 0x24000000,
   MAT_1_0 = 0x24000001,
   MAT_2_0 = 0x24000002,
   MAT_2_1 = 0x24000003,
   AAC_LATM = 0x25000000,
   AAC_LATM_LC = 0x25000002,
   AAC_LATM_HE_V1 = 0x25000010,
   AAC_LATM_HE_V2 = 0x25000100,
   CELT = 0x26000000,
   APTX_ADAPTIVE = 0x27000000,
   LHDC = 0x28000000,
   LHDC_LL = 0x29000000,
   APTX_TWSP = 0x2A000000,
   LC3 = 0x2B000000,
   MPEGH = 0x2C000000,
   MPEGH_BL_L3 = 0x2C000013,
   MPEGH_BL_L4 = 0x2C000014,
   MPEGH_LC_L3 = 0x2C000023,
   MPEGH_LC_L4 = 0x2C000024,
   IEC60958 = 0x2D000000,
   DTS_UHD = 0x2E000000,
   DRA = 0x2F000000,
   /**
    * Subformats.
    */
   AAC_SUB_MAIN = 0x1,
   AAC_SUB_LC = 0x2,
   AAC_SUB_SSR = 0x4,
   AAC_SUB_LTP = 0x8,
   AAC_SUB_HE_V1 = 0x10,
   AAC_SUB_SCALABLE = 0x20,
   AAC_SUB_ERLC = 0x40,
   AAC_SUB_LD = 0x80,
   AAC_SUB_HE_V2 = 0x100,
   AAC_SUB_ELD = 0x200,
   AAC_SUB_XHE = 0x300,
   E_AC3_SUB_JOC = 0x1,
   MAT_SUB_1_0 = 0x1,
   MAT_SUB_2_0 = 0x2,
   MAT_SUB_2_1 = 0x3,
   MPEGH_SUB_BL_L3 = 0x13,
   MPEGH_SUB_BL_L4 = 0x14,
   MPEGH_SUB_LC_L3 = 0x23,
   MPEGH_SUB_LC_L4 = 0x24,
}
