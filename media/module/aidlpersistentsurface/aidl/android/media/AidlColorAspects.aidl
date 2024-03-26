/*
 * Copyright (C) 2024 The Android Open Source Project
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
 * Ref: frameworks/native/include/media/hardware/VideoAPI.h
 *
 * Framework defined color aspects. These are based mainly on ISO 23001-8 spec. As this standard
 * continues to evolve, new values may be defined in the future. Use OTHER for these future values
 * as well as for values not listed here, as those are not supported by the framework.
 */
parcelable AidlColorAspects {
    @Backing(type="int")
    enum Range {
        UNSPECIFIED,  // Unspecified
        FULL,         // Full range
        LIMITED,      // Limited range (if defined), or not full range

        OTHER = 0xff, // Not one of the above values
    }

    // Color primaries
    @Backing(type="int")
    enum Primaries {
        UNSPECIFIED,  // Unspecified
        BT709_5,      // Rec.ITU-R BT.709-5 or equivalent
        BT470_6M,     // Rec.ITU-R BT.470-6 System M or equivalent
        BT601_6_625,  // Rec.ITU-R BT.601-6 625 or equivalent
        BT601_6_525,  // Rec.ITU-R BT.601-6 525 or equivalent
        GENERIC_FILM, // Generic Film
        BT2020,       // Rec.ITU-R BT.2020 or equivalent

        OTHER = 0xff, // Not one of the above values
    }

    // Transfer characteristics
    @Backing(type="int")
    enum Transfer {
        UNSPECIFIED,  // Unspecified
        LINEAR,       // Linear transfer characteristics
        SRGB,         // sRGB or equivalent
        SMPTE170M,    // SMPTE 170M or equivalent (e.g. BT.601/709/2020)
        GAMMA22,      // Assumed display gamma 2.2
        GAMMA28,      // Assumed display gamma 2.8
        ST2084,       // SMPTE ST 2084 for 10/12/14/16 bit systems
        HLG,          // ARIB STD-B67 hybrid-log-gamma

        // values unlikely to be required by Android follow here
        SMPTE240M = 0x40, // SMPTE 240M
        XVYCC,        // IEC 61966-2-4
        BT1361,       // Rec.ITU-R BT.1361 extended gamut
        ST428,        // SMPTE ST 428-1

        OTHER = 0xff, // Not one of the above values
    }

    // YUV <-> RGB conversion
    @Backing(type="int")
    enum MatrixCoeffs {
        UNSPECIFIED,    // Unspecified
        BT709_5,        // Rec.ITU-R BT.709-5 or equivalent
        BT470_6M,       // KR=0.30, KB=0.11 or equivalent
        BT601_6,        // Rec.ITU-R BT.601-6 625 or equivalent
        SMPTE240M,      // SMPTE 240M or equivalent
        BT2020,         // Rec.ITU-R BT.2020 non-constant luminance
        BT2020CONSTANT, // Rec.ITU-R BT.2020 constant luminance

        OTHER = 0xff,   // Not one of the above values
    }

    Range range;
    Primaries primaries;
    Transfer transfer;
    MatrixCoeffs matrixCoeffs;
}
