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

import android.media.AudioMixCallbackFlag;
import android.media.AudioMixMatchCriterion;
import android.media.AudioMixRouteFlag;
import android.media.AudioMixType;
import android.media.audio.common.AudioConfig;
import android.media.audio.common.AudioDevice;

/**
 * {@hide}
 */
parcelable AudioMix {
    AudioMixMatchCriterion[] criteria;
    AudioMixType mixType;
    AudioConfig format;
    /** Bitmask, indexed by AudioMixRouteFlag. */
    int routeFlags;
    AudioDevice device;
    /** Flags indicating which callbacks to use. Bitmask, indexed by AudioMixCallbackFlag. */
    int cbFlags;
    /** Ignore the AUDIO_FLAG_NO_MEDIA_PROJECTION */
    boolean allowPrivilegedMediaPlaybackCapture;
    /** Indicates if the caller can capture voice communication output */
    boolean voiceCommunicationCaptureAllowed;
    /** Identifies the owner of the AudioPolicy that this AudioMix belongs to */
    IBinder mToken;
}
