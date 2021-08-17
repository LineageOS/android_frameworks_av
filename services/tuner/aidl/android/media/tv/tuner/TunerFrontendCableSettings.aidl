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

/**
 * Cable Frontend Settings interface.
 *
 * {@hide}
 */
parcelable TunerFrontendCableSettings {
    /**
     * Signal frequency in Hertz
     */
    int frequency;

    int modulation;

    /**
     * Inner Forward Error Correction type as specified in ETSI EN 300 468 V1.15.1
     * and ETSI EN 302 307-2 V1.1.1.
     */
    long innerFec;

    /**
     * Symbols per second
     */
    int symbolRate;

    /**
     * Outer Forward Error Correction (FEC) Type.
     */
    int outerFec;

    int annex;

    /**
     * Spectral Inversion Type.
     */
    int spectralInversion;

    /**
     * Fields after isExtended are only valid when isExtended is true
     */
    boolean isExtended;

    int interleaveMode;

    int bandwidth;
}
