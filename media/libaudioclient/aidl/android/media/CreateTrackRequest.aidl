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

import android.media.audio.common.AudioAttributes;
import android.media.AudioClient;
import android.media.IAudioTrackCallback;
import android.media.SharedFileRegion;
import android.media.audio.common.AudioConfig;

/**
 * CreateTrackInput contains all input arguments sent by AudioTrack to AudioFlinger
 * when calling createTrack() including arguments that will be updated by AudioFlinger
 * and returned in CreateTrackResponse object.
 *
 * {@hide}
 */
parcelable CreateTrackRequest {
    AudioAttributes attr;
    AudioConfig config;
    AudioClient clientInfo;
    @nullable SharedFileRegion sharedBuffer;
    int notificationsPerBuffer;
    float speed;
    IAudioTrackCallback audioTrackCallback;
    @utf8InCpp String opPackageName;
    /** Bitmask, indexed by AudioOutputFlags. */
    int flags;
    long frameCount;
    long notificationFrameCount;
    /** Interpreted as audio_port_handle_t. */
    int selectedDeviceId;
    int sessionId;
}
