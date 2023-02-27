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
interface ISoundDose {
    /** Set a new RS2 value used for momentary exposure warnings. */
    oneway void setOutputRs2(float rs2Value);

    /**
     * Resets the native CSD values. This can happen after a crash in the
     * audio server or after booting when restoring the previous state.
     * 'currentCsd' represents the restored CSD value and 'records' contains the
     * dosage values and MELs together with their timestamps that lead to this
     * CSD.
     */
    oneway void resetCsd(float currentCsd, in SoundDoseRecord[] records);

    /**
     * Updates the attenuation used for the MEL calculation when the volume is
     * not applied by the audio framework. This can be the case when for example
     * the absolute volume is used for a particular device.
     *
     * @param attenuationDB the attenuation as a negative value in dB that will
     *                      be applied for the internal MEL when computing CSD.
     *                      A value of 0 represents no attenuation for the MELs
     * @param device        the audio_devices_t type for which we will apply the
     *                      attenuation
     */
    oneway void updateAttenuation(float attenuationDB, int device);

    /* -------------------------- Test API methods --------------------------
    /** Get the currently used RS2 value. */
    float getOutputRs2();
    /** Get the current CSD from audioserver. */
    float getCsd();
    /** Enables/Disables MEL computations from framework. */
    oneway void forceUseFrameworkMel(boolean useFrameworkMel);
    /** Enables/Disables the computation of CSD on all devices. */
    oneway void forceComputeCsdOnAllDevices(boolean computeCsdOnAllDevices);
}
