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

import android.media.AudioPortDeviceExtSys;
import android.media.AudioPortMixExtSys;

/**
 * {@hide}
 */
union AudioPortExtSys {
    /**
     * This represents an empty union. Value is ignored.
     */
    boolean unspecified;
    /** System-only parameters when the port is an audio device. */
    AudioPortDeviceExtSys device;
    /** System-only parameters when the port is an audio mix. */
    AudioPortMixExtSys mix;
    /** Framework audio session identifier. */
    int session;
}
