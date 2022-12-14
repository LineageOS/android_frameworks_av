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
 * Interface used to push the sound dose related information from the
 * AudioService#SoundDoseHelper to the audio server
 */
oneway interface ISoundDose {
    /** Set a new RS2 value used for momentary exposure warnings. */
    void setOutputRs2(float rs2Value);

    /**
     * Resets the native CSD values. This can happen after a crash in the
     * audio server or after booting when restoring the previous state.
     * 'currentCsd' represents the restored CSD value and 'records' contains the
     * dosage values and MELs together with their timestamps that lead to this
     * CSD.
     */
    void resetCsd(float currentCsd, in SoundDoseRecord[] records);
}
