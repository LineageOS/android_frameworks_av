/*
 * Copyright (C) 2025 The Android Open Source Project
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

import android.media.TimerQueueHandle;

/**
 * The IMmapStreamCallback interface is the binder interface for AudioFlinger to notify
 * condition changes affecting the stream operation.
 *
 * @hide
 */
oneway interface IMmapStreamCallback {
    /**
     * Indicates that the stream is torn down and the client should not make any more calls on the
     * stream.
     *
     * @param portId for the stream.
     */
    void onTearDown(in int portId);

    /**
     * Indicates that the volume has changed.
     *
     * @param volume the new volume.
     */
    void onVolumeChanged(in float volume);

    /**
     * Indicates that the routing has changed.
     *
     * @param deviceIds the new device ids.
     */
    void onRoutingChanged(in int[] deviceIds);

    /**
     * Indicates that the sound dose computation requirement has changed and the
     * client needs to use the IMmapStream to reportData if active.
     *
     * @param active true if the sound dose computation is active, false otherwise.
     */
    void onSoundDoseChanged(in boolean active);

    /**
     * Indicates that the client should wake up to process data.
     *
     * @param handle the handle of the wake up task.
     */
    void onWakeUp(in TimerQueueHandle handle);
}
