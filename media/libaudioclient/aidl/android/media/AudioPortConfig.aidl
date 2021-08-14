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

import android.media.AudioGainConfig;
import android.media.AudioIoFlags;
import android.media.AudioPortConfigExt;
import android.media.AudioPortConfigType;
import android.media.AudioPortRole;
import android.media.AudioPortType;
import android.media.audio.common.AudioFormat;

/**
 * {@hide}
 */
parcelable AudioPortConfig {
    /**
     * Port unique ID.
     * Interpreted as audio_port_handle_t.
     */
    int id;
    /** Sink or source. */
    AudioPortRole role;
    /** Device, mix ... */
    AudioPortType type;
    /** Bitmask, indexed by AudioPortConfigType. */
    int configMask;
    /** Sampling rate in Hz. */
    int sampleRate;
    /**
     * Channel mask, if applicable.
     * Interpreted as audio_channel_mask_t.
     * TODO: bitmask?
     */
    int channelMask;
    /**
     * Format, if applicable.
     */
    AudioFormat format;
    /** Gain to apply, if applicable. */
    AudioGainConfig gain;
    /** Framework only: HW_AV_SYNC, DIRECT, ... */
    AudioIoFlags flags;
    AudioPortConfigExt ext;
}
