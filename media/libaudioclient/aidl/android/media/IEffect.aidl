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

import android.media.SharedFileRegion;

/**
 * The IEffect interface enables control of the effect module activity and parameters.
 *
 * {@hide}
 */
interface IEffect {
    /**
     * Activates the effect module by connecting it to the audio path.
     * @return a status_t code.
     */
    int enable();

    /**
     * Deactivates the effect module by disconnecting it from the audio path.
     * @return a status_t code.
     */
    int disable();

    /**
     * Sends control, reads or writes parameters. Same behavior as the command() method in the
     * effect control interface.
     * Refer to system/audio_effect.h for a description of the valid command codes and their
     * associated parameter and return messages. The cmdData and response parameters are expected to
     * contain the respective types in a standard C memory layout.
     *
     * TODO(ytai): replace opaque byte arrays with strongly typed parameters.
     */
    int command(int cmdCode, in byte[] cmdData, int maxResponseSize, out byte[] response);

    /**
     * Disconnects the IEffect interface from the effect module.
     * This will also delete the effect module and release the effect engine in the library if this
     * is the last client disconnected. To release control of the effect module, the application can
     * disconnect or delete the IEffect interface.
     */
    void disconnect();

    /**
     * returns a pointer to a shared memory area used to pass multiple parameters to the effect
     * module without multiplying the binder calls.
     *
     * TODO(ytai): Explain how this should be used exactly.
     */
    SharedFileRegion getCblk();
}
