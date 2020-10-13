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

import android.media.tv.tuner.TunerFrontendAnalogCapabilities;
import android.media.tv.tuner.TunerFrontendAtscCapabilities;
import android.media.tv.tuner.TunerFrontendAtsc3Capabilities;
import android.media.tv.tuner.TunerFrontendCableCapabilities;
import android.media.tv.tuner.TunerFrontendDvbsCapabilities;
import android.media.tv.tuner.TunerFrontendDvbtCapabilities;
import android.media.tv.tuner.TunerFrontendIsdbsCapabilities;
import android.media.tv.tuner.TunerFrontendIsdbs3Capabilities;
import android.media.tv.tuner.TunerFrontendIsdbtCapabilities;

/**
 * Frontend Capabilities interface.
 *
 * Use a group of vectors as the workaround for Union structure that is not fully supported
 * in AIDL currently.
 *
 * Client may use FrontendInfo.type as the discriminar to check the corresponding vector. If
 * the vector is not null, it contains valid value.
 *
 * {@hide}
 */
union TunerFrontendCapabilities {
    /**
     * Analog Frontend Capabilities
     */
    TunerFrontendAnalogCapabilities analogCaps;

    /**
     * ATSC Frontend Capabilities
     */
    TunerFrontendAtscCapabilities atscCaps;

    /**
     * ATSC3 Frontend Capabilities
     */
    TunerFrontendAtsc3Capabilities atsc3Caps;

    /**
     * Cable Frontend Capabilities
     */
    TunerFrontendCableCapabilities cableCaps;

    /**
     * DVBS Frontend Capabilities
     */
    TunerFrontendDvbsCapabilities dvbsCaps;

    /**
     * DVBT Frontend Capabilities
     */
    TunerFrontendDvbtCapabilities dvbtCaps;

    /**
     * ISDB-S Frontend Capabilities
     */
    TunerFrontendIsdbsCapabilities isdbsCaps;

    /**
     * ISDB-S3 Frontend Capabilities
     */
    TunerFrontendIsdbs3Capabilities isdbs3Caps;

    /**
     * ISDB-T Frontend Capabilities
     */
    TunerFrontendIsdbtCapabilities isdbtCaps;
}
