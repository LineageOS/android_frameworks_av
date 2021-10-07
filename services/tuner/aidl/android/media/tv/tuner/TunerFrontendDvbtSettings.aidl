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
 * Dvbt Frontend Settings interface.
 *
 * {@hide}
 */
parcelable TunerFrontendDvbtSettings {
    /**
     * Signal frequency in Hertz
     */
    int frequency;

    int transmissionMode;

    int bandwidth;

    int constellation;

    int hierarchy;

    /**
     * Code Rate for High Priority level
     */
    int hpCodeRate;

    /**
     * Code Rate for Low Priority level
     */
    int lpCodeRate;

    int guardInterval;

    boolean isHighPriority;

    int standard;

    boolean isMiso;

    /**
     * Physical Layer Pipe (PLP) mode
     */
    int plpMode;

    /**
     * Physical Layer Pipe (PLP) Id
     */
    int plpId;

    /**
     * Physical Layer Pipe (PLP) Group Id
     */
    int plpGroupId;

    /**
     * Fields after isExtended are only valid when isExtended is true
     */
    boolean isExtended;
}
