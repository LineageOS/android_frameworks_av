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

import android.media.tv.tuner.TunerAtsc3PlpInfo;

/**
 * TunerFrontendCallback interface handles tuner frontend related callbacks.
 *
 * {@hide}
 */
interface ITunerFrontendCallback {
    /**
     * Notify the client that a new event happened on the frontend.
     */
    void onEvent(in int frontendEventType);

    /**
     * notify locked message to client from the ongoing scan.
     */
    void onLocked();

    /**
     * notify scan stopped message to client from the ongoing scan.
     */
    void onScanStopped();

    /**
     * notify progress message to client from the ongoing scan.
     */
    void onProgress(in int percent);

    /**
     * notify Frequencies message to client from the ongoing scan.
     */
    void onFrequenciesReport(in int[] frequency);

    /**
     * notify SymbolRates message to client from the ongoing scan.
     */
    void onSymbolRates(in int[] rates);

    /**
     * notify Hierarchy message to client from the ongoing scan.
     */
    void onHierarchy(in int hierarchy);

    /**
     * notify SignalType message to client from the ongoing scan.
     */
    void onSignalType(in int signalType);

    /**
     * notify PlpIds message to client from the ongoing scan.
     */
    void onPlpIds(in int[] plpIds);

    /**
     * notify GroupIds message to client from the ongoing scan.
     */
    void onGroupIds(in int[] groupIds);

    /**
     * notify InputStreamIds message to client from the ongoing scan.
     */
    void onInputStreamIds(in int[] inputStreamIds);

    /**
     * notify DvbsStandard message to client from the ongoing scan.
     */
    void onDvbsStandard(in int dvbsStandandard);

    /**
     * notify AnalogSifStandard message to client from the ongoing scan.
     */
    void onAnalogSifStandard(in int sifStandandard);

    /**
     * notify Atsc3PlpInfos message to client from the ongoing scan.
     */
    void onAtsc3PlpInfos(in TunerAtsc3PlpInfo[] atsc3PlpInfos);
}
