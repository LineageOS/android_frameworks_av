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

import android.media.AudioHwModule;
import android.media.SurroundSoundConfig;
import android.media.audio.common.AudioHalEngineConfig;
import android.media.audio.common.AudioMode;

/*
 * Audio policy configuration. Functionally replaces the APM XML file.
 * {@hide}
 */
parcelable AudioPolicyConfig {
    AudioHwModule[] modules;
    AudioMode[] supportedModes;
    SurroundSoundConfig surroundSoundConfig;
    AudioHalEngineConfig engineConfig;
}
