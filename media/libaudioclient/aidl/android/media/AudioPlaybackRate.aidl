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
 * The AudioPlaybackRate.
 *
 * See https://developer.android.com/reference/android/media/PlaybackParams.
 * TODO(b/175166815): Reconcile with framework-media-sources PlaybackParams.aidl.
 *       As this is used for native wire serialization, no need to define
 *       audio_timestretch_stretch_mode_t and audio_timestretch_fallback_mode_t enums
 *       until we attempt to unify with PlaybackParams.
 *
 * {@hide}
 */
parcelable AudioPlaybackRate {
    /** Speed of audio playback, >= 0.f, 1.f nominal (system limits are further restrictive) */
    float speed;
    /** Pitch of audio, >= 0.f, 1.f nominal (system limits are further restrictive) */
    float pitch;
    /** Interpreted as audio_timestretch_stretch_mode_t */
    int stretchMode;
    /** Interpreted as audio_timestretch_fallback_mode_t */
    int fallbackMode;
}
