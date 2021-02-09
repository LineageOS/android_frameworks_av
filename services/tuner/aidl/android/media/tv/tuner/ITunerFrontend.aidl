/**
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.media.tv.tuner;

import android.media.tv.tuner.ITunerFrontendCallback;
import android.media.tv.tuner.ITunerLnb;
import android.media.tv.tuner.TunerFrontendSettings;
import android.media.tv.tuner.TunerFrontendStatus;

/**
 * Tuner Frontend interface handles frontend related operations.
 *
 * {@hide}
 */
interface ITunerFrontend {
    /**
     * Set the frontend callback.
     *
     * @param tunerFrontendCallback the callback to receive frontend related info.
     */
    void setCallback(in ITunerFrontendCallback tunerFrontendCallback);

    /**
     * Tunes the frontend to using the settings given.
     *
     * @param settings the settings to tune with.
     */
    void tune(in TunerFrontendSettings settings);

    /**
     * Stop the previous tuning.
     */
    void stopTune();

    /**
     * Scan the frontend to use the settings given.
     *
     * @param settings the settings to scan with.
     * @param frontendScanType scan with given type.
     */
    void scan(in TunerFrontendSettings settings, in int frontendScanType);

    /**
     * Stop the previous scanning.
     */
    void stopScan();

    /**
     * Sets Low-Noise Block downconverter (LNB) for satellite frontend.
     *
     * @param tuner lnb interface.
     */
    void setLnb(in ITunerLnb lnb);

    /**
     * Enable or Disable Low Noise Amplifier (LNA).
     *
     * @param bEnable enable Lna or not.
     */
    void setLna(in boolean bEnable);

    /**
     * Link Frontend to the cicam with given id.
     *
     * @return lts id
     */
    int linkCiCamToFrontend(in int ciCamId);

    /**
     * Unink Frontend to the cicam with given id.
     */
    void unlinkCiCamToFrontend(in int ciCamId);

    /**
     * Releases the ITunerFrontend instance.
     */
    void close();

    /**
     * Gets the statuses of the frontend.
     */
    TunerFrontendStatus[] getStatus(in int[] statusTypes);

    /**
     * Gets the 1.1 extended statuses of the frontend.
     */
    TunerFrontendStatus[] getStatusExtended_1_1(in int[] statusTypes);

    /**
     * Gets the id of the frontend.
     */
    int getFrontendId();
}
