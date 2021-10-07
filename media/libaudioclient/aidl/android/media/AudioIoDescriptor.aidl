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

import android.media.AudioPatch;
import android.media.audio.common.AudioFormat;

/**
 * {@hide}
 */
parcelable AudioIoDescriptor {
    /** Interpreted as audio_io_handle_t. */
    int ioHandle;
    AudioPatch patch;
    int samplingRate;
    AudioFormat format;
    /** Interpreted as audio_channel_mask_t. */
    int channelMask;
    long frameCount;
    long frameCountHAL;
    /** Only valid for output. */
    int latency;
    /**
     * Interpreted as audio_port_handle_t.
     * valid for event AUDIO_CLIENT_STARTED.
     */
    int portId;
}
