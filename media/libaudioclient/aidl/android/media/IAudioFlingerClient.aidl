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

import android.media.AudioIoConfigEvent;
import android.media.AudioIoDescriptor;
import android.media.LatencyMode;

/**
 * A callback interface for AudioFlinger.
 *
 * {@hide}
 */
interface IAudioFlingerClient {
    oneway void ioConfigChanged(AudioIoConfigEvent event,
                                in AudioIoDescriptor ioDesc);
    /**
     * Called when the latency modes supported on a given output stream change.
     * output is the I/O handle of the output stream for which the change is signalled.
     * latencyModes is the new list of supported latency modes (See LatencyMode.aidl).
     */
    oneway void onSupportedLatencyModesChanged(int output, in LatencyMode[] latencyModes);
}
