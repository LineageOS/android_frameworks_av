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

import android.media.AudioStreamType;
import android.media.IAudioTrack;

/**
 * CreateTrackOutput contains all output arguments returned by AudioFlinger to AudioTrack
 * when calling createTrack() including arguments that were passed as I/O for update by
 * CreateTrackRequest.
 *
 * {@hide}
 */
parcelable CreateTrackResponse {
    /** Bitmask, indexed by AudioOutputFlags. */
    int flags;
    long frameCount;
    long notificationFrameCount;
    /** Interpreted as audio_port_handle_t. */
    int selectedDeviceId;
    int sessionId;
    int sampleRate;
    AudioStreamType streamType;
    long afFrameCount;
    int afSampleRate;
    int afLatencyMs;
    /** Interpreted as audio_io_handle_t. */
    int outputId;
    /** Interpreted as audio_port_handle_t. */
    int portId;
    /** The newly created track. */
    @nullable IAudioTrack audioTrack;
}
