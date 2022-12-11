/*
 * Copyright 2022 The Android Open Source Project
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

import android.media.SoundDoseRecord;

/**
 * Interface used to push the sound dose related information from the audio
 * server to the AudioService#SoundDoseHelper.
 */
interface ISoundDoseCallback {
    /** Called whenever the momentary exposure exceeds the RS2 value. */
    oneway void onMomentaryExposure(float currentMel, int deviceId);

    /**
     * Notifies that the CSD value has changed. The currentCsd is normalized
     * with value 1 representing 100% of sound dose. SoundDoseRecord represents
     * the newest record that lead to the new currentCsd.
     */
    oneway void onNewCsdValue(float currentCsd, in SoundDoseRecord[] records);
}
