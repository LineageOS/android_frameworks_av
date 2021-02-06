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

import android.media.tv.tuner.TunerFrontendStatusAtsc3PlpInfo;

/**
 * Tuner Frontend Status interface.
 *
 * {@hide}
 */
union TunerFrontendStatus {
    /**
     * Lock status for Demod in True/False.
     */
    boolean isDemodLocked;

    /**
     * SNR value measured by 0.001 dB.
     */
    int snr;

    /**
     * The number of error bits per 1 billion bits.
     */
    int ber;

    /**
     * The number of error packages per 1 billion packages.
     */
    int per;

    /**
     * The number of error bits per 1 billion bits before FEC.
     */
    int preBer;

    /**
     * Signal Quality in percent.
     */
    int signalQuality;

    /**
     * Signal Strength measured by 0.001 dBm.
     */
    int signalStrength;

    /**
     * Symbols per second
     */
    int symbolRate;

    long innerFec;

    /**
     * Check frontend type to decide the hidl type value
     */
    int modulation;

    int inversion;

    int lnbVoltage;

    byte plpId;

    boolean isEWBS;

    /**
     * AGC value is normalized from 0 to 255.
     */
    byte agc;

    boolean isLnaOn;

    boolean[] isLayerError;

    /**
     * MER value measured by 0.001 dB
     */
    int mer;

    /**
     * Frequency difference in Hertz.
     */
    int freqOffset;

    int hierarchy;

    boolean isRfLocked;

    /**
     * A list of PLP status for tuned PLPs for ATSC3 frontend.
     */
    TunerFrontendStatusAtsc3PlpInfo[] plpInfo;

    // 1.1 Extension Starting

    /**
     * Extended modulation status. Check frontend type to decide the hidl type value.
     */
    int[] modulations;

    /**
     * Extended bit error ratio status.
     */
    int[] bers;

    /**
     * Extended code rate status.
     */
    long[] codeRates;

    /**
     * Extended bandwidth status. Check frontend type to decide the hidl type value.
     */
    int bandwidth;

    /**
     * Extended guard interval status. Check frontend type to decide the hidl type value.
     */
    int interval;

    /**
     * Extended transmission mode status. Check frontend type to decide the hidl type value.
     */
    int transmissionMode;

    /**
     * Uncorrectable Error Counts of the frontend's Physical Layer Pipe (PLP)
     * since the last tune operation.
     */
    int uec;

    /**
     * The current DVB-T2 system id status.
     */
    char systemId;

    /**
     * Frontend Interleaving Modes. Check frontend type to decide the hidl type value.
     */
    int[] interleaving;

    /**
     * Segments in ISDB-T Specification of all the channels.
     */
    byte[] isdbtSegment;

    /**
     * Transport Stream Data Rate in BPS of the current channel.
     */
    int[] tsDataRate;

    /**
     * Roll Off Type status of the frontend. Check frontend type to decide the hidl type value.
     */
    int rollOff;

    /**
     * If the frontend currently supports MISO or not.
     */
    boolean isMiso;

    /**
     * If the frontend code rate is linear or not.
     */
    boolean isLinear;

    /**
     * If short frames are enabled or not.
     */
    boolean isShortFrames;
}
