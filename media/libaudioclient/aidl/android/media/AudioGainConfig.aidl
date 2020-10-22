/*
 * Copyright (C) 2020 The Android Open Source Project
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
 * {@hide}
 */
parcelable AudioGainConfig {
    /** Index of the corresponding audio_gain in the audio_port gains[] table. */
    int index;

    /** Mode requested for this command. Bitfield indexed by AudioGainMode. */
    int mode;

    /**
     * Channels which gain value follows. N/A in joint mode.
     * Interpreted as audio_channel_mask_t.
     */
    int channelMask;

    /**
     * Gain values in millibels.
     * For each channel ordered from LSb to MSb in channel mask. The number of values is 1 in joint
     * mode, otherwise equals the number of bits implied by channelMask.
     */
    int[]  values;

    /** Ramp duration in ms. */
    int rampDurationMs;
}
