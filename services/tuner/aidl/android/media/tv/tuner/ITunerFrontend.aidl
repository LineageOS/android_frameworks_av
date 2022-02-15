/**
 * Copyright 2021, The Android Open Source Project
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

import android.hardware.tv.tuner.FrontendScanType;
import android.hardware.tv.tuner.FrontendSettings;
import android.hardware.tv.tuner.FrontendStatus;
import android.hardware.tv.tuner.FrontendStatusReadiness;
import android.hardware.tv.tuner.FrontendStatusType;
import android.media.tv.tuner.ITunerFrontendCallback;
import android.media.tv.tuner.ITunerLnb;

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
    void tune(in FrontendSettings settings);

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
    void scan(in FrontendSettings settings, in FrontendScanType frontendScanType);

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
    FrontendStatus[] getStatus(in FrontendStatusType[] statusTypes);

    /**
     * Gets the id of the frontend.
     */
    int getFrontendId();

    /**
     * Request hardware information about the frontend.
     */
    String getHardwareInfo();

    /**
     * Filter out unnecessary PID from frontend output.
     */
    void removeOutputPid(int pid);

    /**
     * Gets FrontendStatus’ readiness statuses for given status types.
     */
    FrontendStatusReadiness[] getFrontendStatusReadiness(in FrontendStatusType[] statusTypes);
}
