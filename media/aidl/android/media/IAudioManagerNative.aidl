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
 * Native accessible interface for AudioService.
 * Note this interface has a mix of oneway and non-oneway methods. This is intentional for certain
 * calls intended to come from audioserver.
 * @hide
 */
interface IAudioManagerNative {
    enum HardeningType {
        // Restricted due to OP_CONTROL_AUDIO_PARTIAL
        // This OP is more permissive than OP_CONTROL_AUDIO, which allows apps in a foreground state
        // not associated with FGS to access audio
        PARTIAL,
        // Restricted due to OP_CONTROL_AUDIO
        FULL,
    }

    /**
     * audioserver is muting playback due to hardening.
     * Calls which aren't from uid 1041 are dropped.
     * @param uid - the uid whose playback is restricted
     * @param type - the level of playback restriction which was hit (full or partial)
     * @param bypassed - true if the client should be muted but was exempted (for example due to a
     * certain audio usage to prevent regressions)
     */
    oneway void playbackHardeningEvent(in int uid, in HardeningType type, in boolean bypassed);

    /**
     * Block until AudioService synchronizes pending permission state with audioserver.
     */
    void permissionUpdateBarrier();

    /**
     * Update mute state event for port
     * @param portId Port id to update
     * @param event the mute event containing info about the mute
     */
    oneway void portMuteEvent(in int portId, in int event);
}
