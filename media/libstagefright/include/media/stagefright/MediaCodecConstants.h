/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef MEDIA_CODEC_CONSTANTS_H_
#define MEDIA_CODEC_CONSTANTS_H_

namespace {

// from MediaCodecInfo.java
inline constexpr int32_t AVCProfileBaseline = 0x01;
inline constexpr int32_t AVCProfileMain     = 0x02;
inline constexpr int32_t AVCProfileExtended = 0x04;
inline constexpr int32_t AVCProfileHigh     = 0x08;
inline constexpr int32_t AVCProfileHigh10   = 0x10;
inline constexpr int32_t AVCProfileHigh422  = 0x20;
inline constexpr int32_t AVCProfileHigh444  = 0x40;
inline constexpr int32_t AVCProfileConstrainedBaseline = 0x10000;
inline constexpr int32_t AVCProfileConstrainedHigh     = 0x80000;

inline static const char *asString_AVCProfile(int32_t i, const char *def = "??") {
    switch (i) {
        case AVCProfileBaseline:            return "Baseline";
        case AVCProfileMain:                return "Main";
        case AVCProfileExtended:            return "Extended";
        case AVCProfileHigh:                return "High";
        case AVCProfileHigh10:              return "High10";
        case AVCProfileHigh422:             return "High422";
        case AVCProfileHigh444:             return "High444";
        case AVCProfileConstrainedBaseline: return "ConstrainedBaseline";
        case AVCProfileConstrainedHigh:     return "ConstrainedHigh";
        default:                            return def;
    }
}

inline constexpr int32_t AVCLevel1       = 0x01;
inline constexpr int32_t AVCLevel1b      = 0x02;
inline constexpr int32_t AVCLevel11      = 0x04;
inline constexpr int32_t AVCLevel12      = 0x08;
inline constexpr int32_t AVCLevel13      = 0x10;
inline constexpr int32_t AVCLevel2       = 0x20;
inline constexpr int32_t AVCLevel21      = 0x40;
inline constexpr int32_t AVCLevel22      = 0x80;
inline constexpr int32_t AVCLevel3       = 0x100;
inline constexpr int32_t AVCLevel31      = 0x200;
inline constexpr int32_t AVCLevel32      = 0x400;
inline constexpr int32_t AVCLevel4       = 0x800;
inline constexpr int32_t AVCLevel41      = 0x1000;
inline constexpr int32_t AVCLevel42      = 0x2000;
inline constexpr int32_t AVCLevel5       = 0x4000;
inline constexpr int32_t AVCLevel51      = 0x8000;
inline constexpr int32_t AVCLevel52      = 0x10000;
inline constexpr int32_t AVCLevel6       = 0x20000;
inline constexpr int32_t AVCLevel61      = 0x40000;
inline constexpr int32_t AVCLevel62      = 0x80000;

inline static const char *asString_AVCLevel(int32_t i, const char *def = "??") {
    switch (i) {
        case AVCLevel1:     return "1";
        case AVCLevel1b:    return "1b";
        case AVCLevel11:    return "1.1";
        case AVCLevel12:    return "1.2";
        case AVCLevel13:    return "1.3";
        case AVCLevel2:     return "2";
        case AVCLevel21:    return "2.1";
        case AVCLevel22:    return "2.2";
        case AVCLevel3:     return "3";
        case AVCLevel31:    return "3.1";
        case AVCLevel32:    return "3.2";
        case AVCLevel4:     return "4";
        case AVCLevel41:    return "4.1";
        case AVCLevel42:    return "4.2";
        case AVCLevel5:     return "5";
        case AVCLevel51:    return "5.1";
        case AVCLevel52:    return "5.2";
        case AVCLevel6:     return "6";
        case AVCLevel61:    return "6.1";
        case AVCLevel62:    return "6.2";
        default:            return def;
    }
}

inline constexpr int32_t H263ProfileBaseline             = 0x01;
inline constexpr int32_t H263ProfileH320Coding           = 0x02;
inline constexpr int32_t H263ProfileBackwardCompatible   = 0x04;
inline constexpr int32_t H263ProfileISWV2                = 0x08;
inline constexpr int32_t H263ProfileISWV3                = 0x10;
inline constexpr int32_t H263ProfileHighCompression      = 0x20;
inline constexpr int32_t H263ProfileInternet             = 0x40;
inline constexpr int32_t H263ProfileInterlace            = 0x80;
inline constexpr int32_t H263ProfileHighLatency          = 0x100;

inline static const char *asString_H263Profile(int32_t i, const char *def = "??") {
    switch (i) {
        case H263ProfileBaseline:           return "Baseline";
        case H263ProfileH320Coding:         return "H320Coding";
        case H263ProfileBackwardCompatible: return "BackwardCompatible";
        case H263ProfileISWV2:              return "ISWV2";
        case H263ProfileISWV3:              return "ISWV3";
        case H263ProfileHighCompression:    return "HighCompression";
        case H263ProfileInternet:           return "Internet";
        case H263ProfileInterlace:          return "Interlace";
        case H263ProfileHighLatency:        return "HighLatency";
        default:                            return def;
    }
}

inline constexpr int32_t H263Level10      = 0x01;
inline constexpr int32_t H263Level20      = 0x02;
inline constexpr int32_t H263Level30      = 0x04;
inline constexpr int32_t H263Level40      = 0x08;
inline constexpr int32_t H263Level45      = 0x10;
inline constexpr int32_t H263Level50      = 0x20;
inline constexpr int32_t H263Level60      = 0x40;
inline constexpr int32_t H263Level70      = 0x80;

inline static const char *asString_H263Level(int32_t i, const char *def = "??") {
    switch (i) {
        case H263Level10:   return "10";
        case H263Level20:   return "20";
        case H263Level30:   return "30";
        case H263Level40:   return "40";
        case H263Level45:   return "45";
        case H263Level50:   return "50";
        case H263Level60:   return "60";
        case H263Level70:   return "70";
        default:            return def;
    }
}

inline constexpr int32_t MPEG4ProfileSimple              = 0x01;
inline constexpr int32_t MPEG4ProfileSimpleScalable      = 0x02;
inline constexpr int32_t MPEG4ProfileCore                = 0x04;
inline constexpr int32_t MPEG4ProfileMain                = 0x08;
inline constexpr int32_t MPEG4ProfileNbit                = 0x10;
inline constexpr int32_t MPEG4ProfileScalableTexture     = 0x20;
inline constexpr int32_t MPEG4ProfileSimpleFace          = 0x40;
inline constexpr int32_t MPEG4ProfileSimpleFBA           = 0x80;
inline constexpr int32_t MPEG4ProfileBasicAnimated       = 0x100;
inline constexpr int32_t MPEG4ProfileHybrid              = 0x200;
inline constexpr int32_t MPEG4ProfileAdvancedRealTime    = 0x400;
inline constexpr int32_t MPEG4ProfileCoreScalable        = 0x800;
inline constexpr int32_t MPEG4ProfileAdvancedCoding      = 0x1000;
inline constexpr int32_t MPEG4ProfileAdvancedCore        = 0x2000;
inline constexpr int32_t MPEG4ProfileAdvancedScalable    = 0x4000;
inline constexpr int32_t MPEG4ProfileAdvancedSimple      = 0x8000;

inline static const char *asString_MPEG4Profile(int32_t i, const char *def = "??") {
    switch (i) {
        case MPEG4ProfileSimple:            return "Simple";
        case MPEG4ProfileSimpleScalable:    return "SimpleScalable";
        case MPEG4ProfileCore:              return "Core";
        case MPEG4ProfileMain:              return "Main";
        case MPEG4ProfileNbit:              return "Nbit";
        case MPEG4ProfileScalableTexture:   return "ScalableTexture";
        case MPEG4ProfileSimpleFace:        return "SimpleFace";
        case MPEG4ProfileSimpleFBA:         return "SimpleFBA";
        case MPEG4ProfileBasicAnimated:     return "BasicAnimated";
        case MPEG4ProfileHybrid:            return "Hybrid";
        case MPEG4ProfileAdvancedRealTime:  return "AdvancedRealTime";
        case MPEG4ProfileCoreScalable:      return "CoreScalable";
        case MPEG4ProfileAdvancedCoding:    return "AdvancedCoding";
        case MPEG4ProfileAdvancedCore:      return "AdvancedCore";
        case MPEG4ProfileAdvancedScalable:  return "AdvancedScalable";
        case MPEG4ProfileAdvancedSimple:    return "AdvancedSimple";
        default:                            return def;
    }
}

inline constexpr int32_t MPEG4Level0      = 0x01;
inline constexpr int32_t MPEG4Level0b     = 0x02;
inline constexpr int32_t MPEG4Level1      = 0x04;
inline constexpr int32_t MPEG4Level2      = 0x08;
inline constexpr int32_t MPEG4Level3      = 0x10;
inline constexpr int32_t MPEG4Level3b     = 0x18;
inline constexpr int32_t MPEG4Level4      = 0x20;
inline constexpr int32_t MPEG4Level4a     = 0x40;
inline constexpr int32_t MPEG4Level5      = 0x80;
inline constexpr int32_t MPEG4Level6      = 0x100;

inline static const char *asString_MPEG4Level(int32_t i, const char *def = "??") {
    switch (i) {
        case MPEG4Level0:   return "0";
        case MPEG4Level0b:  return "0b";
        case MPEG4Level1:   return "1";
        case MPEG4Level2:   return "2";
        case MPEG4Level3:   return "3";
        case MPEG4Level3b:  return "3b";
        case MPEG4Level4:   return "4";
        case MPEG4Level4a:  return "4a";
        case MPEG4Level5:   return "5";
        case MPEG4Level6:   return "6";
        default:            return def;
    }
}

inline constexpr int32_t MPEG2ProfileSimple              = 0x00;
inline constexpr int32_t MPEG2ProfileMain                = 0x01;
inline constexpr int32_t MPEG2Profile422                 = 0x02;
inline constexpr int32_t MPEG2ProfileSNR                 = 0x03;
inline constexpr int32_t MPEG2ProfileSpatial             = 0x04;
inline constexpr int32_t MPEG2ProfileHigh                = 0x05;

inline static const char *asString_MPEG2Profile(int32_t i, const char *def = "??") {
    switch (i) {
        case MPEG2ProfileSimple:    return "Simple";
        case MPEG2ProfileMain:      return "Main";
        case MPEG2Profile422:       return "422";
        case MPEG2ProfileSNR:       return "SNR";
        case MPEG2ProfileSpatial:   return "Spatial";
        case MPEG2ProfileHigh:      return "High";
        default:                    return def;
    }
}

inline constexpr int32_t MPEG2LevelLL     = 0x00;
inline constexpr int32_t MPEG2LevelML     = 0x01;
inline constexpr int32_t MPEG2LevelH14    = 0x02;
inline constexpr int32_t MPEG2LevelHL     = 0x03;
inline constexpr int32_t MPEG2LevelHP     = 0x04;

inline static const char *asString_MPEG2Level(int32_t i, const char *def = "??") {
    switch (i) {
        case MPEG2LevelLL:  return "LL";
        case MPEG2LevelML:  return "ML";
        case MPEG2LevelH14: return "H14";
        case MPEG2LevelHL:  return "HL";
        case MPEG2LevelHP:  return "HP";
        default:            return def;
    }
}

inline constexpr int32_t AACObjectMain       = 1;
inline constexpr int32_t AACObjectLC         = 2;
inline constexpr int32_t AACObjectSSR        = 3;
inline constexpr int32_t AACObjectLTP        = 4;
inline constexpr int32_t AACObjectHE         = 5;
inline constexpr int32_t AACObjectScalable   = 6;
inline constexpr int32_t AACObjectERLC       = 17;
inline constexpr int32_t AACObjectERScalable = 20;
inline constexpr int32_t AACObjectLD         = 23;
inline constexpr int32_t AACObjectHE_PS      = 29;
inline constexpr int32_t AACObjectELD        = 39;
inline constexpr int32_t AACObjectXHE        = 42;

inline static const char *asString_AACObject(int32_t i, const char *def = "??") {
    switch (i) {
        case AACObjectMain:         return "Main";
        case AACObjectLC:           return "LC";
        case AACObjectSSR:          return "SSR";
        case AACObjectLTP:          return "LTP";
        case AACObjectHE:           return "HE";
        case AACObjectScalable:     return "Scalable";
        case AACObjectERLC:         return "ERLC";
        case AACObjectERScalable:   return "ERScalable";
        case AACObjectLD:           return "LD";
        case AACObjectHE_PS:        return "HE_PS";
        case AACObjectELD:          return "ELD";
        case AACObjectXHE:          return "XHE";
        default:                    return def;
    }
}

inline constexpr int32_t VP8Level_Version0 = 0x01;
inline constexpr int32_t VP8Level_Version1 = 0x02;
inline constexpr int32_t VP8Level_Version2 = 0x04;
inline constexpr int32_t VP8Level_Version3 = 0x08;

inline static const char *asString_VP8Level(int32_t i, const char *def = "??") {
    switch (i) {
        case VP8Level_Version0: return "V0";
        case VP8Level_Version1: return "V1";
        case VP8Level_Version2: return "V2";
        case VP8Level_Version3: return "V3";
        default:                return def;
    }
}

inline constexpr int32_t VP8ProfileMain = 0x01;

inline static const char *asString_VP8Profile(int32_t i, const char *def = "??") {
    switch (i) {
        case VP8ProfileMain:    return "Main";
        default:                return def;
    }
}

inline constexpr int32_t VP9Profile0 = 0x01;
inline constexpr int32_t VP9Profile1 = 0x02;
inline constexpr int32_t VP9Profile2 = 0x04;
inline constexpr int32_t VP9Profile3 = 0x08;
inline constexpr int32_t VP9Profile2HDR = 0x1000;
inline constexpr int32_t VP9Profile3HDR = 0x2000;
inline constexpr int32_t VP9Profile2HDR10Plus = 0x4000;
inline constexpr int32_t VP9Profile3HDR10Plus = 0x8000;

inline static const char *asString_VP9Profile(int32_t i, const char *def = "??") {
    switch (i) {
        case VP9Profile0:           return "0";
        case VP9Profile1:           return "1";
        case VP9Profile2:           return "2";
        case VP9Profile3:           return "3";
        case VP9Profile2HDR:        return "2HDR";
        case VP9Profile3HDR:        return "3HDR";
        case VP9Profile2HDR10Plus:  return "2HDRPlus";
        case VP9Profile3HDR10Plus:  return "3HDRPlus";
        default:                    return def;
    }
}

inline constexpr int32_t VP9Level1  = 0x1;
inline constexpr int32_t VP9Level11 = 0x2;
inline constexpr int32_t VP9Level2  = 0x4;
inline constexpr int32_t VP9Level21 = 0x8;
inline constexpr int32_t VP9Level3  = 0x10;
inline constexpr int32_t VP9Level31 = 0x20;
inline constexpr int32_t VP9Level4  = 0x40;
inline constexpr int32_t VP9Level41 = 0x80;
inline constexpr int32_t VP9Level5  = 0x100;
inline constexpr int32_t VP9Level51 = 0x200;
inline constexpr int32_t VP9Level52 = 0x400;
inline constexpr int32_t VP9Level6  = 0x800;
inline constexpr int32_t VP9Level61 = 0x1000;
inline constexpr int32_t VP9Level62 = 0x2000;

inline static const char *asString_VP9Level(int32_t i, const char *def = "??") {
    switch (i) {
        case VP9Level1:     return "1";
        case VP9Level11:    return "1.1";
        case VP9Level2:     return "2";
        case VP9Level21:    return "2.1";
        case VP9Level3:     return "3";
        case VP9Level31:    return "3.1";
        case VP9Level4:     return "4";
        case VP9Level41:    return "4.1";
        case VP9Level5:     return "5";
        case VP9Level51:    return "5.1";
        case VP9Level52:    return "5.2";
        case VP9Level6:     return "6";
        case VP9Level61:    return "6.1";
        case VP9Level62:    return "6.2";
        default:            return def;
    }
}

inline constexpr int32_t AV1ProfileMain8 = 0x1;
inline constexpr int32_t AV1ProfileMain10 = 0x2;
inline constexpr int32_t AV1ProfileMain10HDR10 = 0x1000;
inline constexpr int32_t AV1ProfileMain10HDR10Plus = 0x2000;

inline static const char *asString_AV1Profile(int32_t i, const char *def = "??") {
    switch (i) {
        case AV1ProfileMain8:           return "Main8";
        case AV1ProfileMain10:          return "Main10";
        case AV1ProfileMain10HDR10:     return "Main10HDR10";
        case AV1ProfileMain10HDR10Plus: return "Main10HDRPlus";
        default:                        return def;
    }
}

inline constexpr int32_t AV1Level2  = 0x1;
inline constexpr int32_t AV1Level21 = 0x2;
inline constexpr int32_t AV1Level22 = 0x4;
inline constexpr int32_t AV1Level23 = 0x8;
inline constexpr int32_t AV1Level3  = 0x10;
inline constexpr int32_t AV1Level31 = 0x20;
inline constexpr int32_t AV1Level32 = 0x40;
inline constexpr int32_t AV1Level33 = 0x80;
inline constexpr int32_t AV1Level4  = 0x100;
inline constexpr int32_t AV1Level41 = 0x200;
inline constexpr int32_t AV1Level42 = 0x400;
inline constexpr int32_t AV1Level43 = 0x800;
inline constexpr int32_t AV1Level5  = 0x1000;
inline constexpr int32_t AV1Level51 = 0x2000;
inline constexpr int32_t AV1Level52 = 0x4000;
inline constexpr int32_t AV1Level53 = 0x8000;
inline constexpr int32_t AV1Level6  = 0x10000;
inline constexpr int32_t AV1Level61 = 0x20000;
inline constexpr int32_t AV1Level62 = 0x40000;
inline constexpr int32_t AV1Level63 = 0x80000;
inline constexpr int32_t AV1Level7  = 0x100000;
inline constexpr int32_t AV1Level71 = 0x200000;
inline constexpr int32_t AV1Level72 = 0x400000;
inline constexpr int32_t AV1Level73 = 0x800000;

inline static const char *asString_AV1Level(int32_t i, const char *def = "??") {
    switch (i) {
        case AV1Level2:     return "2";
        case AV1Level21:    return "2.1";
        case AV1Level22:    return "2.2";
        case AV1Level23:    return "2.3";
        case AV1Level3:     return "3";
        case AV1Level31:    return "3.1";
        case AV1Level32:    return "3.2";
        case AV1Level33:    return "3.3";
        case AV1Level4:     return "4";
        case AV1Level41:    return "4.1";
        case AV1Level42:    return "4.2";
        case AV1Level43:    return "4.3";
        case AV1Level5:     return "5";
        case AV1Level51:    return "5.1";
        case AV1Level52:    return "5.2";
        case AV1Level53:    return "5.3";
        case AV1Level6:     return "6";
        case AV1Level61:    return "6.1";
        case AV1Level62:    return "6.2";
        case AV1Level63:    return "6.3";
        case AV1Level7:     return "7";
        case AV1Level71:    return "7.1";
        case AV1Level72:    return "7.2";
        case AV1Level73:    return "7.3";
        default:            return def;
    }
}

inline constexpr int32_t HEVCProfileMain        = 0x01;
inline constexpr int32_t HEVCProfileMain10      = 0x02;
inline constexpr int32_t HEVCProfileMainStill   = 0x04;
inline constexpr int32_t HEVCProfileMain10HDR10 = 0x1000;
inline constexpr int32_t HEVCProfileMain10HDR10Plus = 0x2000;

inline static const char *asString_HEVCProfile(int32_t i, const char *def = "??") {
    switch (i) {
        case HEVCProfileMain:               return "Main";
        case HEVCProfileMain10:             return "Main10";
        case HEVCProfileMainStill:          return "MainStill";
        case HEVCProfileMain10HDR10:        return "Main10HDR10";
        case HEVCProfileMain10HDR10Plus:    return "Main10HDR10Plus";
        default:                            return def;
    }
}

inline constexpr int32_t HEVCMainTierLevel1  = 0x1;
inline constexpr int32_t HEVCHighTierLevel1  = 0x2;
inline constexpr int32_t HEVCMainTierLevel2  = 0x4;
inline constexpr int32_t HEVCHighTierLevel2  = 0x8;
inline constexpr int32_t HEVCMainTierLevel21 = 0x10;
inline constexpr int32_t HEVCHighTierLevel21 = 0x20;
inline constexpr int32_t HEVCMainTierLevel3  = 0x40;
inline constexpr int32_t HEVCHighTierLevel3  = 0x80;
inline constexpr int32_t HEVCMainTierLevel31 = 0x100;
inline constexpr int32_t HEVCHighTierLevel31 = 0x200;
inline constexpr int32_t HEVCMainTierLevel4  = 0x400;
inline constexpr int32_t HEVCHighTierLevel4  = 0x800;
inline constexpr int32_t HEVCMainTierLevel41 = 0x1000;
inline constexpr int32_t HEVCHighTierLevel41 = 0x2000;
inline constexpr int32_t HEVCMainTierLevel5  = 0x4000;
inline constexpr int32_t HEVCHighTierLevel5  = 0x8000;
inline constexpr int32_t HEVCMainTierLevel51 = 0x10000;
inline constexpr int32_t HEVCHighTierLevel51 = 0x20000;
inline constexpr int32_t HEVCMainTierLevel52 = 0x40000;
inline constexpr int32_t HEVCHighTierLevel52 = 0x80000;
inline constexpr int32_t HEVCMainTierLevel6  = 0x100000;
inline constexpr int32_t HEVCHighTierLevel6  = 0x200000;
inline constexpr int32_t HEVCMainTierLevel61 = 0x400000;
inline constexpr int32_t HEVCHighTierLevel61 = 0x800000;
inline constexpr int32_t HEVCMainTierLevel62 = 0x1000000;
inline constexpr int32_t HEVCHighTierLevel62 = 0x2000000;

inline static const char *asString_HEVCTierLevel(int32_t i, const char *def = "??") {
    switch (i) {
        case HEVCMainTierLevel1:    return "Main 1";
        case HEVCHighTierLevel1:    return "High 1";
        case HEVCMainTierLevel2:    return "Main 2";
        case HEVCHighTierLevel2:    return "High 2";
        case HEVCMainTierLevel21:   return "Main 2.1";
        case HEVCHighTierLevel21:   return "High 2.1";
        case HEVCMainTierLevel3:    return "Main 3";
        case HEVCHighTierLevel3:    return "High 3";
        case HEVCMainTierLevel31:   return "Main 3.1";
        case HEVCHighTierLevel31:   return "High 3.1";
        case HEVCMainTierLevel4:    return "Main 4";
        case HEVCHighTierLevel4:    return "High 4";
        case HEVCMainTierLevel41:   return "Main 4.1";
        case HEVCHighTierLevel41:   return "High 4.1";
        case HEVCMainTierLevel5:    return "Main 5";
        case HEVCHighTierLevel5:    return "High 5";
        case HEVCMainTierLevel51:   return "Main 5.1";
        case HEVCHighTierLevel51:   return "High 5.1";
        case HEVCMainTierLevel52:   return "Main 5.2";
        case HEVCHighTierLevel52:   return "High 5.2";
        case HEVCMainTierLevel6:    return "Main 6";
        case HEVCHighTierLevel6:    return "High 6";
        case HEVCMainTierLevel61:   return "Main 6.1";
        case HEVCHighTierLevel61:   return "High 6.1";
        case HEVCMainTierLevel62:   return "Main 6.2";
        case HEVCHighTierLevel62:   return "High 6.2";
        default:                    return def;
    }
}

inline constexpr int32_t DolbyVisionProfileDvavPer = 0x1;
inline constexpr int32_t DolbyVisionProfileDvavPen = 0x2;
inline constexpr int32_t DolbyVisionProfileDvheDer = 0x4;
inline constexpr int32_t DolbyVisionProfileDvheDen = 0x8;
inline constexpr int32_t DolbyVisionProfileDvheDtr = 0x10;
inline constexpr int32_t DolbyVisionProfileDvheStn = 0x20;
inline constexpr int32_t DolbyVisionProfileDvheDth = 0x40;
inline constexpr int32_t DolbyVisionProfileDvheDtb = 0x80;
inline constexpr int32_t DolbyVisionProfileDvheSt  = 0x100;
inline constexpr int32_t DolbyVisionProfileDvavSe  = 0x200;
inline constexpr int32_t DolbyVisionProfileDvav110 = 0x400;

inline static const char *asString_DolbyVisionProfile(int32_t i, const char *def = "??") {
    switch (i) {
        case DolbyVisionProfileDvavPer:  return "DvavPer";
        case DolbyVisionProfileDvavPen:  return "DvavPen";
        case DolbyVisionProfileDvheDer:  return "DvheDer";
        case DolbyVisionProfileDvheDen:  return "DvheDen";
        case DolbyVisionProfileDvheDtr:  return "DvheDtr";
        case DolbyVisionProfileDvheStn:  return "DvheStn";
        case DolbyVisionProfileDvheDth:  return "DvheDth";
        case DolbyVisionProfileDvheDtb:  return "DvheDtb";
        case DolbyVisionProfileDvheSt:   return "DvheSt";
        case DolbyVisionProfileDvavSe:   return "DvavSe";
        case DolbyVisionProfileDvav110:  return "Dav110";
        default:                         return def;
    }
}

inline constexpr int32_t DolbyVisionLevelHd24    = 0x1;
inline constexpr int32_t DolbyVisionLevelHd30    = 0x2;
inline constexpr int32_t DolbyVisionLevelFhd24   = 0x4;
inline constexpr int32_t DolbyVisionLevelFhd30   = 0x8;
inline constexpr int32_t DolbyVisionLevelFhd60   = 0x10;
inline constexpr int32_t DolbyVisionLevelUhd24   = 0x20;
inline constexpr int32_t DolbyVisionLevelUhd30   = 0x40;
inline constexpr int32_t DolbyVisionLevelUhd48   = 0x80;
inline constexpr int32_t DolbyVisionLevelUhd60   = 0x100;
inline constexpr int32_t DolbyVisionLevelUhd120  = 0x200;
inline constexpr int32_t DolbyVisionLevel8k30    = 0x400;
inline constexpr int32_t DolbyVisionLevel8k60    = 0x800;

inline static const char *asString_DolbyVisionLevel(int32_t i, const char *def = "??") {
    switch (i) {
        case DolbyVisionLevelHd24:  return "Hd24";
        case DolbyVisionLevelHd30:  return "Hd30";
        case DolbyVisionLevelFhd24: return "Fhd24";
        case DolbyVisionLevelFhd30: return "Fhd30";
        case DolbyVisionLevelFhd60: return "Fhd60";
        case DolbyVisionLevelUhd24: return "Uhd24";
        case DolbyVisionLevelUhd30: return "Uhd30";
        case DolbyVisionLevelUhd48: return "Uhd48";
        case DolbyVisionLevelUhd60: return "Uhd60";
        case DolbyVisionLevelUhd120: return "Uhd120";
        case DolbyVisionLevel8k30:  return "8k30";
        case DolbyVisionLevel8k60:  return "8k60";
        default:                    return def;
    }
}

inline constexpr int32_t BITRATE_MODE_CBR = 2;
inline constexpr int32_t BITRATE_MODE_CBR_FD = 3;
inline constexpr int32_t BITRATE_MODE_CQ = 0;
inline constexpr int32_t BITRATE_MODE_VBR = 1;

inline static const char *asString_BitrateMode(int32_t i, const char *def = "??") {
    switch (i) {
        case BITRATE_MODE_CBR:  return "CBR";
        case BITRATE_MODE_CBR_FD: return "CBR_FD";
        case BITRATE_MODE_CQ:   return "CQ";
        case BITRATE_MODE_VBR:  return "VBR";
        default:                return def;
    }
}

inline constexpr int32_t COLOR_Format12bitRGB444             = 3;
inline constexpr int32_t COLOR_Format16bitARGB1555           = 5;
inline constexpr int32_t COLOR_Format16bitARGB4444           = 4;
inline constexpr int32_t COLOR_Format16bitBGR565             = 7;
inline constexpr int32_t COLOR_Format16bitRGB565             = 6;
inline constexpr int32_t COLOR_Format18bitARGB1665           = 9;
inline constexpr int32_t COLOR_Format18BitBGR666             = 41;
inline constexpr int32_t COLOR_Format18bitRGB666             = 8;
inline constexpr int32_t COLOR_Format19bitARGB1666           = 10;
inline constexpr int32_t COLOR_Format24BitABGR6666           = 43;
inline constexpr int32_t COLOR_Format24bitARGB1887           = 13;
inline constexpr int32_t COLOR_Format24BitARGB6666           = 42;
inline constexpr int32_t COLOR_Format24bitBGR888             = 12;
inline constexpr int32_t COLOR_Format24bitRGB888             = 11;
inline constexpr int32_t COLOR_Format25bitARGB1888           = 14;
inline constexpr int32_t COLOR_Format32bitABGR2101010        = 0x7F00AAA2;
inline constexpr int32_t COLOR_Format32bitABGR8888           = 0x7F00A000;
inline constexpr int32_t COLOR_Format32bitARGB8888           = 16;
inline constexpr int32_t COLOR_Format32bitBGRA8888           = 15;
inline constexpr int32_t COLOR_Format64bitABGRFloat          = 0x7F000F16;
inline constexpr int32_t COLOR_Format8bitRGB332              = 2;
inline constexpr int32_t COLOR_FormatCbYCrY                  = 27;
inline constexpr int32_t COLOR_FormatCrYCbY                  = 28;
inline constexpr int32_t COLOR_FormatL16                     = 36;
inline constexpr int32_t COLOR_FormatL2                      = 33;
inline constexpr int32_t COLOR_FormatL24                     = 37;
inline constexpr int32_t COLOR_FormatL32                     = 38;
inline constexpr int32_t COLOR_FormatL4                      = 34;
inline constexpr int32_t COLOR_FormatL8                      = 35;
inline constexpr int32_t COLOR_FormatMonochrome              = 1;
inline constexpr int32_t COLOR_FormatRawBayer10bit           = 31;
inline constexpr int32_t COLOR_FormatRawBayer8bit            = 30;
inline constexpr int32_t COLOR_FormatRawBayer8bitcompressed  = 32;
inline constexpr int32_t COLOR_FormatRGBAFlexible            = 0x7F36A888;
inline constexpr int32_t COLOR_FormatRGBFlexible             = 0x7F36B888;
inline constexpr int32_t COLOR_FormatSurface                 = 0x7F000789;
inline constexpr int32_t COLOR_FormatYCbYCr                  = 25;
inline constexpr int32_t COLOR_FormatYCrYCb                  = 26;
inline constexpr int32_t COLOR_FormatYUV411PackedPlanar      = 18;
inline constexpr int32_t COLOR_FormatYUV411Planar            = 17;
inline constexpr int32_t COLOR_FormatYUV420Flexible          = 0x7F420888;
inline constexpr int32_t COLOR_FormatYUV420PackedPlanar      = 20;
inline constexpr int32_t COLOR_FormatYUV420PackedSemiPlanar  = 39;
inline constexpr int32_t COLOR_FormatYUV420Planar            = 19;
inline constexpr int32_t COLOR_FormatYUV420SemiPlanar        = 21;
inline constexpr int32_t COLOR_FormatYUV422Flexible          = 0x7F422888;
inline constexpr int32_t COLOR_FormatYUV422PackedPlanar      = 23;
inline constexpr int32_t COLOR_FormatYUV422PackedSemiPlanar  = 40;
inline constexpr int32_t COLOR_FormatYUV422Planar            = 22;
inline constexpr int32_t COLOR_FormatYUV422SemiPlanar        = 24;
inline constexpr int32_t COLOR_FormatYUV444Flexible          = 0x7F444888;
inline constexpr int32_t COLOR_FormatYUV444Interleaved       = 29;
inline constexpr int32_t COLOR_FormatYUVP010                 = 54;
inline constexpr int32_t COLOR_QCOM_FormatYUV420SemiPlanar   = 0x7fa30c00;
inline constexpr int32_t COLOR_TI_FormatYUV420PackedSemiPlanar = 0x7f000100;

inline static const char *asString_ColorFormat(int32_t i, const char *def = "??") {
    switch (i) {
        case COLOR_Format12bitRGB444:               return "12bitRGB444";
        case COLOR_Format16bitARGB1555:             return "16bitARGB1555";
        case COLOR_Format16bitARGB4444:             return "16bitARGB4444";
        case COLOR_Format16bitBGR565:               return "16bitBGR565";
        case COLOR_Format16bitRGB565:               return "16bitRGB565";
        case COLOR_Format18bitARGB1665:             return "18bitARGB1665";
        case COLOR_Format18BitBGR666:               return "18BitBGR666";
        case COLOR_Format18bitRGB666:               return "18bitRGB666";
        case COLOR_Format19bitARGB1666:             return "19bitARGB1666";
        case COLOR_Format24BitABGR6666:             return "24BitABGR6666";
        case COLOR_Format24bitARGB1887:             return "24bitARGB1887";
        case COLOR_Format24BitARGB6666:             return "24BitARGB6666";
        case COLOR_Format24bitBGR888:               return "24bitBGR888";
        case COLOR_Format24bitRGB888:               return "24bitRGB888";
        case COLOR_Format25bitARGB1888:             return "25bitARGB1888";
        case COLOR_Format32bitABGR2101010:          return "32bitABGR2101010";
        case COLOR_Format32bitABGR8888:             return "32bitABGR8888";
        case COLOR_Format32bitARGB8888:             return "32bitARGB8888";
        case COLOR_Format32bitBGRA8888:             return "32bitBGRA8888";
        case COLOR_Format64bitABGRFloat:            return "64bitABGRFloat";
        case COLOR_Format8bitRGB332:                return "8bitRGB332";
        case COLOR_FormatCbYCrY:                    return "CbYCrY";
        case COLOR_FormatCrYCbY:                    return "CrYCbY";
        case COLOR_FormatL16:                       return "L16";
        case COLOR_FormatL2:                        return "L2";
        case COLOR_FormatL24:                       return "L24";
        case COLOR_FormatL32:                       return "L32";
        case COLOR_FormatL4:                        return "L4";
        case COLOR_FormatL8:                        return "L8";
        case COLOR_FormatMonochrome:                return "Monochrome";
        case COLOR_FormatRawBayer10bit:             return "RawBayer10bit";
        case COLOR_FormatRawBayer8bit:              return "RawBayer8bit";
        case COLOR_FormatRawBayer8bitcompressed:    return "RawBayer8bitcompressed";
        case COLOR_FormatRGBAFlexible:              return "RGBAFlexible";
        case COLOR_FormatRGBFlexible:               return "RGBFlexible";
        case COLOR_FormatSurface:                   return "Surface";
        case COLOR_FormatYCbYCr:                    return "YCbYCr";
        case COLOR_FormatYCrYCb:                    return "YCrYCb";
        case COLOR_FormatYUV411PackedPlanar:        return "YUV411PackedPlanar";
        case COLOR_FormatYUV411Planar:              return "YUV411Planar";
        case COLOR_FormatYUV420Flexible:            return "YUV420Flexible";
        case COLOR_FormatYUV420PackedPlanar:        return "YUV420PackedPlanar";
        case COLOR_FormatYUV420PackedSemiPlanar:    return "YUV420PackedSemiPlanar";
        case COLOR_FormatYUV420Planar:              return "YUV420Planar";
        case COLOR_FormatYUV420SemiPlanar:          return "YUV420SemiPlanar";
        case COLOR_FormatYUV422Flexible:            return "YUV422Flexible";
        case COLOR_FormatYUV422PackedPlanar:        return "YUV422PackedPlanar";
        case COLOR_FormatYUV422PackedSemiPlanar:    return "YUV422PackedSemiPlanar";
        case COLOR_FormatYUV422Planar:              return "YUV422Planar";
        case COLOR_FormatYUV422SemiPlanar:          return "YUV422SemiPlanar";
        case COLOR_FormatYUV444Flexible:            return "YUV444Flexible";
        case COLOR_FormatYUV444Interleaved:         return "YUV444Interleaved";
        case COLOR_FormatYUVP010:                   return "YUVP010";
        case COLOR_QCOM_FormatYUV420SemiPlanar:     return "QCOM_YUV420SemiPlanar";
        case COLOR_TI_FormatYUV420PackedSemiPlanar: return "TI_YUV420PackedSemiPlanar";
        default:                                    return def;
    }
}

inline constexpr char FEATURE_AdaptivePlayback[]       = "adaptive-playback";
inline constexpr char FEATURE_EncodingStatistics[]     = "encoding-statistics";
inline constexpr char FEATURE_IntraRefresh[] = "intra-refresh";
inline constexpr char FEATURE_PartialFrame[] = "partial-frame";
inline constexpr char FEATURE_QpBounds[] = "qp-bounds";
inline constexpr char FEATURE_SecurePlayback[]         = "secure-playback";
inline constexpr char FEATURE_TunneledPlayback[]       = "tunneled-playback";

// from MediaFormat.java
inline constexpr char MIMETYPE_VIDEO_VP8[] = "video/x-vnd.on2.vp8";
inline constexpr char MIMETYPE_VIDEO_VP9[] = "video/x-vnd.on2.vp9";
inline constexpr char MIMETYPE_VIDEO_AV1[] = "video/av01";
inline constexpr char MIMETYPE_VIDEO_AVC[] = "video/avc";
inline constexpr char MIMETYPE_VIDEO_HEVC[] = "video/hevc";
inline constexpr char MIMETYPE_VIDEO_MPEG4[] = "video/mp4v-es";
inline constexpr char MIMETYPE_VIDEO_H263[] = "video/3gpp";
inline constexpr char MIMETYPE_VIDEO_MPEG2[] = "video/mpeg2";
inline constexpr char MIMETYPE_VIDEO_RAW[] = "video/raw";
inline constexpr char MIMETYPE_VIDEO_DOLBY_VISION[] = "video/dolby-vision";
inline constexpr char MIMETYPE_VIDEO_SCRAMBLED[] = "video/scrambled";

inline constexpr char MIMETYPE_AUDIO_AMR_NB[] = "audio/3gpp";
inline constexpr char MIMETYPE_AUDIO_AMR_WB[] = "audio/amr-wb";
inline constexpr char MIMETYPE_AUDIO_MPEG[] = "audio/mpeg";
inline constexpr char MIMETYPE_AUDIO_AAC[] = "audio/mp4a-latm";
inline constexpr char MIMETYPE_AUDIO_QCELP[] = "audio/qcelp";
inline constexpr char MIMETYPE_AUDIO_VORBIS[] = "audio/vorbis";
inline constexpr char MIMETYPE_AUDIO_OPUS[] = "audio/opus";
inline constexpr char MIMETYPE_AUDIO_G711_ALAW[] = "audio/g711-alaw";
inline constexpr char MIMETYPE_AUDIO_G711_MLAW[] = "audio/g711-mlaw";
inline constexpr char MIMETYPE_AUDIO_RAW[] = "audio/raw";
inline constexpr char MIMETYPE_AUDIO_FLAC[] = "audio/flac";
inline constexpr char MIMETYPE_AUDIO_MSGSM[] = "audio/gsm";
inline constexpr char MIMETYPE_AUDIO_AC3[] = "audio/ac3";
inline constexpr char MIMETYPE_AUDIO_EAC3[] = "audio/eac3";
inline constexpr char MIMETYPE_AUDIO_SCRAMBLED[] = "audio/scrambled";

inline constexpr char MIMETYPE_IMAGE_ANDROID_HEIC[] = "image/vnd.android.heic";

inline constexpr char MIMETYPE_TEXT_CEA_608[] = "text/cea-608";
inline constexpr char MIMETYPE_TEXT_CEA_708[] = "text/cea-708";
inline constexpr char MIMETYPE_TEXT_SUBRIP[] = "application/x-subrip";
inline constexpr char MIMETYPE_TEXT_VTT[] = "text/vtt";

inline constexpr int32_t COLOR_RANGE_FULL = 1;
inline constexpr int32_t COLOR_RANGE_LIMITED = 2;
inline constexpr int32_t COLOR_STANDARD_BT2020 = 6;
inline constexpr int32_t COLOR_STANDARD_BT601_NTSC = 4;
inline constexpr int32_t COLOR_STANDARD_BT601_PAL = 2;
inline constexpr int32_t COLOR_STANDARD_BT709 = 1;
inline constexpr int32_t COLOR_TRANSFER_HLG = 7;
inline constexpr int32_t COLOR_TRANSFER_LINEAR = 1;
inline constexpr int32_t COLOR_TRANSFER_SDR_VIDEO = 3;
inline constexpr int32_t COLOR_TRANSFER_ST2084 = 6;

inline constexpr int32_t PICTURE_TYPE_I = 1;
inline constexpr int32_t PICTURE_TYPE_P = 2;
inline constexpr int32_t PICTURE_TYPE_B = 3;
inline constexpr int32_t PICTURE_TYPE_UNKNOWN = 0;

inline constexpr int32_t VIDEO_ENCODING_STATISTICS_LEVEL_1 = 1;
inline constexpr int32_t VIDEO_ENCODING_STATISTICS_LEVEL_NONE = 0;

inline constexpr char KEY_AAC_DRC_ALBUM_MODE[] = "aac-drc-album-mode";
inline constexpr char KEY_AAC_DRC_ATTENUATION_FACTOR[] = "aac-drc-cut-level";
inline constexpr char KEY_AAC_DRC_BOOST_FACTOR[] = "aac-drc-boost-level";
inline constexpr char KEY_AAC_DRC_EFFECT_TYPE[] = "aac-drc-effect-type";
inline constexpr char KEY_AAC_DRC_HEAVY_COMPRESSION[] = "aac-drc-heavy-compression";
inline constexpr char KEY_AAC_DRC_OUTPUT_LOUDNESS[] = "aac-drc-output-loudness";
inline constexpr char KEY_AAC_DRC_TARGET_REFERENCE_LEVEL[] = "aac-target-ref-level";
inline constexpr char KEY_AAC_ENCODED_TARGET_LEVEL[] = "aac-encoded-target-level";
inline constexpr char KEY_AAC_MAX_OUTPUT_CHANNEL_COUNT[] = "aac-max-output-channel_count";
inline constexpr char KEY_AAC_PROFILE[] = "aac-profile";
inline constexpr char KEY_AAC_SBR_MODE[] = "aac-sbr-mode";
inline constexpr char KEY_ALLOW_FRAME_DROP[] = "allow-frame-drop";
inline constexpr char KEY_AUDIO_SESSION_ID[] = "audio-session-id";
inline constexpr char KEY_BIT_RATE[] = "bitrate";
inline constexpr char KEY_BITRATE_MODE[] = "bitrate-mode";
inline constexpr char KEY_CA_SESSION_ID[] = "ca-session-id";
inline constexpr char KEY_CA_SYSTEM_ID[] = "ca-system-id";
inline constexpr char KEY_CA_PRIVATE_DATA[] = "ca-private-data";
inline constexpr char KEY_CAPTURE_RATE[] = "capture-rate";
inline constexpr char KEY_CHANNEL_COUNT[] = "channel-count";   // value N, eq to range 1..N
inline constexpr char KEY_CHANNEL_MASK[] = "channel-mask";
inline constexpr char KEY_COLOR_FORMAT[] = "color-format";
inline constexpr char KEY_COLOR_RANGE[] = "color-range";
inline constexpr char KEY_COLOR_STANDARD[] = "color-standard";
inline constexpr char KEY_COLOR_TRANSFER[] = "color-transfer";
inline constexpr char KEY_COMPLEXITY[] = "complexity";
inline constexpr char KEY_CREATE_INPUT_SURFACE_SUSPENDED[] = "create-input-buffers-suspended";
inline constexpr char KEY_DURATION[] = "durationUs";
inline constexpr char KEY_FEATURE_[] = "feature-";
inline constexpr char KEY_FLAC_COMPRESSION_LEVEL[] = "flac-compression-level";
inline constexpr char KEY_FRAME_RATE[] = "frame-rate";
inline constexpr char KEY_GRID_COLUMNS[] = "grid-cols";
inline constexpr char KEY_GRID_ROWS[] = "grid-rows";
inline constexpr char KEY_HDR_STATIC_INFO[] = "hdr-static-info";
inline constexpr char KEY_HDR10_PLUS_INFO[] = "hdr10-plus-info";
inline constexpr char KEY_HEIGHT[] = "height";
inline constexpr char KEY_I_FRAME_INTERVAL[] = "i-frame-interval";
inline constexpr char KEY_IMPORTANCE[] = "importance";
inline constexpr char KEY_INTRA_REFRESH_PERIOD[] = "intra-refresh-period";
inline constexpr char KEY_IS_ADTS[] = "is-adts";
inline constexpr char KEY_IS_AUTOSELECT[] = "is-autoselect";
inline constexpr char KEY_IS_DEFAULT[] = "is-default";
inline constexpr char KEY_IS_FORCED_SUBTITLE[] = "is-forced-subtitle";
inline constexpr char KEY_IS_TIMED_TEXT[] = "is-timed-text";
inline constexpr char KEY_LANGUAGE[] = "language";
inline constexpr char KEY_LATENCY[] = "latency";
inline constexpr char KEY_LEVEL[] = "level";
inline constexpr char KEY_LOW_LATENCY[] = "low-latency";
inline constexpr char KEY_MAX_B_FRAMES[] = "max-bframes";
inline constexpr char KEY_MAX_BIT_RATE[] = "max-bitrate";
inline constexpr char KEY_MAX_FPS_TO_ENCODER[] = "max-fps-to-encoder";
inline constexpr char KEY_MAX_HEIGHT[] = "max-height";
inline constexpr char KEY_MAX_INPUT_SIZE[] = "max-input-size";
inline constexpr char KEY_BUFFER_BATCH_MAX_OUTPUT_SIZE[] = "buffer-batch-max-output-size";
inline constexpr char KEY_BUFFER_BATCH_THRESHOLD_OUTPUT_SIZE[] =
        "buffer-batch-threshold-output-size";
inline constexpr char KEY_MAX_OUTPUT_CHANNEL_COUNT[] = "max-output-channel-count";
inline constexpr char KEY_MAX_PTS_GAP_TO_ENCODER[] = "max-pts-gap-to-encoder";
inline constexpr char KEY_MAX_WIDTH[] = "max-width";
inline constexpr char KEY_MIME[] = "mime";
inline constexpr char KEY_OPERATING_RATE[] = "operating-rate";
inline constexpr char KEY_OUTPUT_REORDER_DEPTH[] = "output-reorder-depth";
inline constexpr char KEY_PCM_ENCODING[] = "pcm-encoding";
inline constexpr char KEY_PICTURE_TYPE[] = "picture-type";
inline constexpr char KEY_PIXEL_ASPECT_RATIO_HEIGHT[] = "sar-height";
inline constexpr char KEY_PIXEL_ASPECT_RATIO_WIDTH[] = "sar-width";
inline constexpr char KEY_PREPEND_HEADER_TO_SYNC_FRAMES[] = "prepend-sps-pps-to-idr-frames";
inline constexpr char KEY_PRIORITY[] = "priority";
inline constexpr char KEY_PROFILE[] = "profile";
inline constexpr char KEY_PUSH_BLANK_BUFFERS_ON_STOP[] = "push-blank-buffers-on-shutdown";
inline constexpr char KEY_QUALITY[] = "quality";
inline constexpr char KEY_REPEAT_PREVIOUS_FRAME_AFTER[] = "repeat-previous-frame-after";
inline constexpr char KEY_ROTATION[] = "rotation-degrees";
inline constexpr char KEY_SAMPLE_RATE[] = "sample-rate";
inline constexpr char KEY_SLICE_HEIGHT[] = "slice-height";
inline constexpr char KEY_STRIDE[] = "stride";
inline constexpr char KEY_TEMPORAL_LAYERING[] = "ts-schema";
inline constexpr char KEY_TILE_HEIGHT[] = "tile-height";
inline constexpr char KEY_TILE_WIDTH[] = "tile-width";
inline constexpr char KEY_TRACK_ID[] = "track-id";
inline constexpr char KEY_VIDEO_ENCODING_STATISTICS_LEVEL[] = "video-encoding-statistics-level";
inline constexpr char KEY_VIDEO_QP_AVERAGE[] = "video-qp-average";
inline constexpr char KEY_VIDEO_QP_B_MAX[] = "video-qp-b-max";
inline constexpr char KEY_VIDEO_QP_B_MIN[] = "video-qp-b-min";
inline constexpr char KEY_VIDEO_QP_I_MAX[] = "video-qp-i-max";
inline constexpr char KEY_VIDEO_QP_I_MIN[] = "video-qp-i-min";
inline constexpr char KEY_VIDEO_QP_MAX[] = "video-qp-max";
inline constexpr char KEY_VIDEO_QP_MIN[] = "video-qp-min";
inline constexpr char KEY_VIDEO_QP_P_MAX[] = "video-qp-p-max";
inline constexpr char KEY_VIDEO_QP_P_MIN[] = "video-qp-p-min";
inline constexpr char KEY_WIDTH[] = "width";

// from MediaCodec.java
inline constexpr int32_t ERROR_INSUFFICIENT_OUTPUT_PROTECTION = 4;
inline constexpr int32_t ERROR_INSUFFICIENT_RESOURCE = 1100;
inline constexpr int32_t ERROR_KEY_EXPIRED = 2;
inline constexpr int32_t ERROR_NO_KEY = 1;
inline constexpr int32_t ERROR_RECLAIMED = 1101;
inline constexpr int32_t ERROR_RESOURCE_BUSY = 3;
inline constexpr int32_t ERROR_SESSION_NOT_OPENED = 5;
inline constexpr int32_t ERROR_UNSUPPORTED_OPERATION = 6;
inline constexpr char CODEC[] = "android.media.mediacodec.codec";
inline constexpr char ENCODER[] = "android.media.mediacodec.encoder";
inline constexpr char HEIGHT[] = "android.media.mediacodec.height";
inline constexpr char MIME_TYPE[] = "android.media.mediacodec.mime";
inline constexpr char MODE[] = "android.media.mediacodec.mode";
inline constexpr char MODE_AUDIO[] = "audio";
inline constexpr char MODE_VIDEO[] = "video";
inline constexpr char ROTATION[] = "android.media.mediacodec.rotation";
inline constexpr char SECURE[] = "android.media.mediacodec.secure";
inline constexpr char WIDTH[] = "android.media.mediacodec.width";

inline constexpr int32_t BUFFER_FLAG_CODEC_CONFIG = 2;
inline constexpr int32_t BUFFER_FLAG_DECODE_ONLY = 32;
inline constexpr int32_t BUFFER_FLAG_END_OF_STREAM = 4;
inline constexpr int32_t BUFFER_FLAG_KEY_FRAME = 1;
inline constexpr int32_t BUFFER_FLAG_MUXER_DATA = 16;
inline constexpr int32_t BUFFER_FLAG_PARTIAL_FRAME = 8;
inline constexpr int32_t BUFFER_FLAG_SYNC_FRAME = 1;
inline constexpr int32_t CONFIGURE_FLAG_ENCODE = 1;
inline constexpr int32_t CONFIGURE_FLAG_USE_BLOCK_MODEL = 2;
inline constexpr int32_t CRYPTO_MODE_AES_CBC     = 2;
inline constexpr int32_t CRYPTO_MODE_AES_CTR     = 1;
inline constexpr int32_t CRYPTO_MODE_UNENCRYPTED = 0;
inline constexpr int32_t INFO_OUTPUT_BUFFERS_CHANGED = -3;
inline constexpr int32_t INFO_OUTPUT_FORMAT_CHANGED  = -2;
inline constexpr int32_t INFO_TRY_AGAIN_LATER        = -1;
inline constexpr int32_t VIDEO_SCALING_MODE_SCALE_TO_FIT               = 1;
inline constexpr int32_t VIDEO_SCALING_MODE_SCALE_TO_FIT_WITH_CROPPING = 2;
inline constexpr char PARAMETER_KEY_OFFSET_TIME[] = "time-offset-us";
inline constexpr char PARAMETER_KEY_REQUEST_SYNC_FRAME[] = "request-sync";
inline constexpr char PARAMETER_KEY_SUSPEND[] = "drop-input-frames";
inline constexpr char PARAMETER_KEY_SUSPEND_TIME[] = "drop-start-time-us";
inline constexpr char PARAMETER_KEY_TUNNEL_PEEK[] =  "tunnel-peek";
inline constexpr char PARAMETER_KEY_VIDEO_BITRATE[] = "video-bitrate";

}

#endif  // MEDIA_CODEC_CONSTANTS_H_
