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
 * DVBT Frontend Capabilities interface.
 *
 * {@hide}
 */
parcelable TunerFrontendDvbtCapabilities {
    /**
     * Transmission Mode capability
     */
    int transmissionModeCap;

    /**
     * Bandwidth capability
     */
    int bandwidthCap;

    /**
     * Constellation capability
     */
    int constellationCap;

    /**
     * Code Rate capability
     */
    int codeRateCap;

    /**
     * Hierarchy Type capability
     */
    int hierarchyCap;

    /**
     * Guard Interval capability
     */
    int guardIntervalCap;

    /**
     * T2 Support capability
     */
    boolean isT2Supported;

    /**
     * Miso Support capability
     */
    boolean isMisoSupported;
}
