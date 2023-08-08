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
    /** Set a new RS2 upper bound used for momentary exposure warnings. */
    oneway void setOutputRs2UpperBound(float rs2Value);

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

    /**
     * Enables/disables the calculation of sound dose. This has the effect that
     * if disabled no MEL values will be computed on the framework side. The MEL
     * returned from the IHalSoundDoseCallbacks will be ignored.
     */
    oneway void setCsdEnabled(boolean enabled);

    /**
     * Structure containing a device identifier by address and type together with
     * the categorization whether it is a headphone or not.
     */
    @JavaDerive(toString = true)
    parcelable AudioDeviceCategory {
        @utf8InCpp String address;
        int internalAudioType;
        boolean csdCompatible;
    }

    /**
     * Resets the list of stored device categories for the native layer. Should
     * only be called once at boot time after parsing the existing AudioDeviceCategories.
     */
    oneway void initCachedAudioDeviceCategories(in AudioDeviceCategory[] audioDevices);

    /**
     * Sets whether a device for a given address and type is a headphone or not.
     * This is used to determine whether we compute the CSD on the given device
     * since we can not rely completely on the device annotations.
     */
    oneway void setAudioDeviceCategory(in AudioDeviceCategory audioDevice);

    /* -------------------------- Test API methods --------------------------
    /** Get the currently used RS2 upper bound. */
    float getOutputRs2UpperBound();
    /** Get the current CSD from audioserver. */
    float getCsd();
    /**
     * Returns true if the HAL supports the ISoundDose interface. Can be either
     * as part of IModule or standalon sound dose HAL.
     */
    boolean isSoundDoseHalSupported();
    /** Enables/Disables MEL computations from framework. */
    oneway void forceUseFrameworkMel(boolean useFrameworkMel);
    /** Enables/Disables the computation of CSD on all devices. */
    oneway void forceComputeCsdOnAllDevices(boolean computeCsdOnAllDevices);
}
