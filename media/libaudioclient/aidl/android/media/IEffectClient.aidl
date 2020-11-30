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
 * A callback interface for getting effect-related notifications.
 *
 * {@hide}
 */
interface IEffectClient {
    /**
     * Called whenever the status of granting control over the effect to the application
     * has changed.
     * @param controlGranted true iff the application has the control of the effect module.
     */
    oneway void controlStatusChanged(boolean controlGranted);

    /**
     * Called whenever the effect has been enabled or disabled. Received only if the client is not
     * currently controlling the effect.
     * @param enabled true if the effect module has been activated, false if deactivated.
     */
    oneway void enableStatusChanged(boolean enabled);

    /**
     * A command has been send to the effect engine. Received only if the client is not currently
     * controlling the effect. See IEffect.command() for a description of buffer contents.
     *
     * TODO(ytai): replace opaque byte arrays with strongly typed parameters.
     */
    oneway void commandExecuted(int cmdCode, in byte[] cmdData, in byte[] replyData);
}
