/*
 * Copyright (C) 2022 The Android Open Source Project
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

import android.media.audio.common.AudioConfigBase;

/**
 * Describes configuration of an audio effect. Input and output
 * audio configurations are described separately because the effect
 * can perform transformations on channel layouts, for example.
 *
 * {@hide}
 */
parcelable EffectConfig {
    /** Configuration of the audio input of the effect. */
    AudioConfigBase inputCfg;
    /** Configuration of the audio output of the effect. */
    AudioConfigBase outputCfg;
    /**
     * Specifies whether the effect is instantiated on an input stream,
     * e.g. on the input from a microphone.
     */
    boolean isOnInputStream;
}
