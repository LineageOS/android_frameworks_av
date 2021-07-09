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
 * This structure describes a layout of a multi-channel stream.
 * There are two possible ways for representing a layout:
 *
 * - indexed mask, which tells what channels of an audio frame are used, but
 *   doesn't label them in any way, thus a correspondence between channels in
 *   the same position of frames originating from different streams must be
 *   established externally;
 *
 * - layout mask, which gives a label to each channel, thus allowing to
 *   match channels between streams of different layouts.
 *
 * Both representations are agnostic of the direction of audio transfer. Also,
 * by construction, the number of bits set to '1' in the mask indicates the
 * number of channels in the audio frame. A channel mask per se only defines the
 * presence or absence of a channel, not the order. Please see 'INTERLEAVE_*'
 * constants for the platform convention of order.
 */
union AudioChannelLayout {
    /**
     * This variant is used for representing the "null" ("none") value
     * for the channel layout. The field value must always be '0'.
     */
    int none = 0;
    /**
     * This variant is used for indicating an "invalid" layout for use by the
     * framework only. HAL implementations must not accept or emit
     * AudioChannelLayout values for this variant. The field value must always
     * be '0'.
     */
    int invalid = 0;
    /**
     * This variant is used for representing indexed masks. The value
     * must be one of the 'INDEX_MASK_*' constants. The 'indexMask' field
     * must have at least one bit set.
     */
    int indexMask;
    /**
     * This variant is used for representing layout masks.
     * It is recommended to use one of 'LAYOUT_*' values. The 'layoutMask' field
     * must have at least one bit set.
     */
    int layoutMask;

    /**
     * 'INDEX_MASK_' constants define how many channels are used.
     */
    const int INDEX_MASK_1 = (1 << 1) - 1;
    const int INDEX_MASK_2 = (1 << 2) - 1;
    const int INDEX_MASK_3 = (1 << 3) - 1;
    const int INDEX_MASK_4 = (1 << 4) - 1;
    const int INDEX_MASK_5 = (1 << 5) - 1;
    const int INDEX_MASK_6 = (1 << 6) - 1;
    const int INDEX_MASK_7 = (1 << 7) - 1;
    const int INDEX_MASK_8 = (1 << 8) - 1;
    const int INDEX_MASK_9 = (1 << 9) - 1;
    const int INDEX_MASK_10 = (1 << 10) - 1;
    const int INDEX_MASK_11 = (1 << 11) - 1;
    const int INDEX_MASK_12 = (1 << 12) - 1;
    const int INDEX_MASK_13 = (1 << 13) - 1;
    const int INDEX_MASK_14 = (1 << 14) - 1;
    const int INDEX_MASK_15 = (1 << 15) - 1;
    const int INDEX_MASK_16 = (1 << 16) - 1;
    const int INDEX_MASK_17 = (1 << 17) - 1;
    const int INDEX_MASK_18 = (1 << 18) - 1;
    const int INDEX_MASK_19 = (1 << 19) - 1;
    const int INDEX_MASK_20 = (1 << 20) - 1;
    const int INDEX_MASK_21 = (1 << 21) - 1;
    const int INDEX_MASK_22 = (1 << 22) - 1;
    const int INDEX_MASK_23 = (1 << 23) - 1;
    const int INDEX_MASK_24 = (1 << 24) - 1;

    /**
     * 'LAYOUT_*' constants define channel layouts recognized by
     * the audio system. The order of the channels in the frame is assumed
     * to be from the LSB to MSB for all the bits set to '1'.
     */
    const int LAYOUT_MONO = CHANNEL_FRONT_LEFT;
    const int LAYOUT_STEREO =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT;
    const int LAYOUT_2POINT1 =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT | CHANNEL_LOW_FREQUENCY;
    const int LAYOUT_TRI =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT | CHANNEL_FRONT_CENTER;
    const int LAYOUT_TRI_BACK =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT | CHANNEL_BACK_CENTER;
    const int LAYOUT_3POINT1 =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT | CHANNEL_FRONT_CENTER |
            CHANNEL_LOW_FREQUENCY;
    const int LAYOUT_2POINT0POINT2 =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_TOP_SIDE_LEFT | CHANNEL_TOP_SIDE_RIGHT;
    const int LAYOUT_2POINT1POINT2 =
            LAYOUT_2POINT0POINT2 | CHANNEL_LOW_FREQUENCY;
    const int LAYOUT_3POINT0POINT2 =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_FRONT_CENTER |
            CHANNEL_TOP_SIDE_LEFT | CHANNEL_TOP_SIDE_RIGHT;
    const int LAYOUT_3POINT1POINT2 =
            LAYOUT_3POINT0POINT2 | CHANNEL_LOW_FREQUENCY;
    const int LAYOUT_QUAD =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_BACK_LEFT | CHANNEL_BACK_RIGHT;
    const int LAYOUT_QUAD_SIDE =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_SIDE_LEFT | CHANNEL_SIDE_RIGHT;
    const int LAYOUT_SURROUND =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_FRONT_CENTER | CHANNEL_BACK_CENTER;
    const int LAYOUT_PENTA = LAYOUT_QUAD | CHANNEL_FRONT_CENTER;
    const int LAYOUT_5POINT1 =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_FRONT_CENTER | CHANNEL_LOW_FREQUENCY |
            CHANNEL_BACK_LEFT | CHANNEL_BACK_RIGHT;
    const int LAYOUT_5POINT1_SIDE =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_FRONT_CENTER | CHANNEL_LOW_FREQUENCY |
            CHANNEL_SIDE_LEFT | CHANNEL_SIDE_RIGHT;
    const int LAYOUT_5POINT1POINT2 = LAYOUT_5POINT1 |
            CHANNEL_TOP_SIDE_LEFT | CHANNEL_TOP_SIDE_RIGHT;
    const int LAYOUT_5POINT1POINT4 = LAYOUT_5POINT1 |
            CHANNEL_TOP_FRONT_LEFT | CHANNEL_TOP_FRONT_RIGHT |
            CHANNEL_TOP_BACK_LEFT | CHANNEL_TOP_BACK_RIGHT;
    const int LAYOUT_6POINT1 =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_FRONT_CENTER | CHANNEL_LOW_FREQUENCY |
            CHANNEL_BACK_LEFT | CHANNEL_BACK_RIGHT | CHANNEL_BACK_CENTER;
    const int LAYOUT_7POINT1 = LAYOUT_5POINT1 |
            CHANNEL_SIDE_LEFT | CHANNEL_SIDE_RIGHT;
    const int LAYOUT_7POINT1POINT2 = LAYOUT_7POINT1 |
            CHANNEL_TOP_SIDE_LEFT | CHANNEL_TOP_SIDE_RIGHT;
    const int LAYOUT_7POINT1POINT4 = LAYOUT_7POINT1 |
            CHANNEL_TOP_FRONT_LEFT | CHANNEL_TOP_FRONT_RIGHT |
            CHANNEL_TOP_BACK_LEFT | CHANNEL_TOP_BACK_RIGHT;
    const int LAYOUT_9POINT1POINT4 = LAYOUT_7POINT1POINT4 |
            CHANNEL_FRONT_WIDE_LEFT | CHANNEL_FRONT_WIDE_RIGHT;
    const int LAYOUT_9POINT1POINT6 = LAYOUT_9POINT1POINT4 |
            CHANNEL_TOP_SIDE_LEFT | CHANNEL_TOP_SIDE_RIGHT;
    const int LAYOUT_13POINT_360RA =
            CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT |
            CHANNEL_FRONT_CENTER |
            CHANNEL_SIDE_LEFT | CHANNEL_SIDE_RIGHT |
            CHANNEL_TOP_FRONT_LEFT | CHANNEL_TOP_FRONT_RIGHT |
            CHANNEL_TOP_FRONT_CENTER |
            CHANNEL_TOP_BACK_LEFT | CHANNEL_TOP_BACK_RIGHT |
            CHANNEL_BOTTOM_FRONT_LEFT | CHANNEL_BOTTOM_FRONT_RIGHT |
            CHANNEL_BOTTOM_FRONT_CENTER;
    const int LAYOUT_22POINT2 = LAYOUT_7POINT1POINT4 |
            CHANNEL_FRONT_LEFT_OF_CENTER | CHANNEL_FRONT_RIGHT_OF_CENTER |
            CHANNEL_BACK_CENTER | CHANNEL_TOP_CENTER |
            CHANNEL_TOP_FRONT_CENTER | CHANNEL_TOP_BACK_CENTER |
            CHANNEL_TOP_SIDE_LEFT | CHANNEL_TOP_SIDE_RIGHT |
            CHANNEL_BOTTOM_FRONT_LEFT | CHANNEL_BOTTOM_FRONT_RIGHT |
            CHANNEL_BOTTOM_FRONT_CENTER |
            CHANNEL_LOW_FREQUENCY_2;
    const int LAYOUT_MONO_HAPTIC_A =
            LAYOUT_MONO | CHANNEL_HAPTIC_A;
    const int LAYOUT_STEREO_HAPTIC_A =
            LAYOUT_STEREO | CHANNEL_HAPTIC_A;
    const int LAYOUT_HAPTIC_AB =
            CHANNEL_HAPTIC_A | CHANNEL_HAPTIC_B;
    const int LAYOUT_MONO_HAPTIC_AB =
            LAYOUT_MONO | LAYOUT_HAPTIC_AB;
    const int LAYOUT_STEREO_HAPTIC_AB =
            LAYOUT_STEREO | LAYOUT_HAPTIC_AB;
    const int LAYOUT_FRONT_BACK =
            CHANNEL_FRONT_CENTER | CHANNEL_BACK_CENTER;
    const int LAYOUT_VOICE_UPLINK_MONO =
            LAYOUT_MONO | CHANNEL_VOICE_UPLINK;
    const int LAYOUT_VOICE_DNLINK_MONO =
            LAYOUT_MONO | CHANNEL_VOICE_DNLINK;
    const int LAYOUT_VOICE_CALL_MONO =
            CHANNEL_VOICE_UPLINK | CHANNEL_VOICE_DNLINK;

    /**
     * Expresses the convention when stereo audio samples are stored interleaved
     * in an array.  This should improve readability by allowing code to use
     * symbolic indices instead of hard-coded [0] and [1].
     *
     * For multi-channel beyond stereo, the platform convention is that channels
     * are interleaved in order from least significant channel mask bit to most
     * significant channel mask bit, with unused bits skipped. Any exceptions
     * to this convention will be noted at the appropriate API.
     */
    const int INTERLEAVE_LEFT = 0;
    const int INTERLEAVE_RIGHT = 1;

    /**
     * 'CHANNEL_*' constants are used to build 'LAYOUT_*' masks.
     * Each constant must have exactly one bit set.
     */
    const int CHANNEL_FRONT_LEFT = 1 << 0;
    const int CHANNEL_FRONT_RIGHT = 1 << 1;
    const int CHANNEL_FRONT_CENTER = 1 << 2;
    const int CHANNEL_LOW_FREQUENCY = 1 << 3;
    const int CHANNEL_BACK_LEFT = 1 << 4;
    const int CHANNEL_BACK_RIGHT = 1 << 5;
    const int CHANNEL_FRONT_LEFT_OF_CENTER = 1 << 6;
    const int CHANNEL_FRONT_RIGHT_OF_CENTER = 1 << 7;
    const int CHANNEL_BACK_CENTER = 1 << 8;
    const int CHANNEL_SIDE_LEFT = 1 << 9;
    const int CHANNEL_SIDE_RIGHT = 1 << 10;
    const int CHANNEL_TOP_CENTER = 1 << 11;
    const int CHANNEL_TOP_FRONT_LEFT = 1 << 12;
    const int CHANNEL_TOP_FRONT_CENTER = 1 << 13;
    const int CHANNEL_TOP_FRONT_RIGHT = 1 << 14;
    const int CHANNEL_TOP_BACK_LEFT = 1 << 15;
    const int CHANNEL_TOP_BACK_CENTER = 1 << 16;
    const int CHANNEL_TOP_BACK_RIGHT = 1 << 17;
    const int CHANNEL_TOP_SIDE_LEFT = 1 << 18;
    const int CHANNEL_TOP_SIDE_RIGHT = 1 << 19;
    const int CHANNEL_BOTTOM_FRONT_LEFT = 1 << 20;
    const int CHANNEL_BOTTOM_FRONT_CENTER = 1 << 21;
    const int CHANNEL_BOTTOM_FRONT_RIGHT = 1 << 22;
    const int CHANNEL_LOW_FREQUENCY_2 = 1 << 23;
    const int CHANNEL_FRONT_WIDE_LEFT = 1 << 24;
    const int CHANNEL_FRONT_WIDE_RIGHT = 1 << 25;
    const int CHANNEL_VOICE_UPLINK = 1 << 26;
    const int CHANNEL_VOICE_DNLINK = 1 << 27;
    const int CHANNEL_HAPTIC_B = 1 << 28;  // B then A to match legacy const.
    const int CHANNEL_HAPTIC_A = 1 << 29;
}
