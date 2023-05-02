/*
 * Copyright (C) 2023 The Android Open Source Project
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

import android.media.audio.common.AudioFormatDescription;

/**
 * TODO(b/280077672): This is a temporary copy of the stable
 * android.hardware.audio.core.SurroundSoundConfig parcelable.
 * Interfaces from the Core API do not support the CPP backend. This copy will
 * be removed either by moving the AudioRoute from core to a.m.a.common or by
 * switching the framework internal interfaces to the NDK backend.
 * {@hide}
 */
parcelable SurroundSoundConfig {
    parcelable SurroundFormatFamily {
        /**
         * A primaryFormat shall get an entry in the Surround Settings dialog on TV
         * devices. There must be a corresponding Java ENCODING_... constant
         * defined in AudioFormat.java, and a display name defined in
         * AudioFormat.toDisplayName.
         */
        AudioFormatDescription primaryFormat;
        /**
         * List of formats that shall be equivalent to the primaryFormat from the
         * users' point of view and don't need a dedicated Surround Settings
         * dialog entry.
         */
        AudioFormatDescription[] subFormats;
    }
    SurroundFormatFamily[] formatFamilies;
}
