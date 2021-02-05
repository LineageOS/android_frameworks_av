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

import android.media.tv.tuner.TunerFrontendAnalogSettings;
import android.media.tv.tuner.TunerFrontendAtscSettings;
import android.media.tv.tuner.TunerFrontendAtsc3Settings;
import android.media.tv.tuner.TunerFrontendCableSettings;
import android.media.tv.tuner.TunerFrontendDtmbSettings;
import android.media.tv.tuner.TunerFrontendDvbsSettings;
import android.media.tv.tuner.TunerFrontendDvbtSettings;
import android.media.tv.tuner.TunerFrontendIsdbsSettings;
import android.media.tv.tuner.TunerFrontendIsdbs3Settings;
import android.media.tv.tuner.TunerFrontendIsdbtSettings;

/**
 * Frontend Settings Union interface.
 *
 * {@hide}
 */
union TunerFrontendUnionSettings {
    TunerFrontendAnalogSettings analog;

    TunerFrontendAtscSettings atsc;

    TunerFrontendAtsc3Settings atsc3;

    TunerFrontendCableSettings cable;

    TunerFrontendDvbsSettings dvbs;

    TunerFrontendDvbtSettings dvbt;

    TunerFrontendIsdbsSettings isdbs;

    TunerFrontendIsdbs3Settings isdbs3;

    TunerFrontendIsdbtSettings isdbt;

    TunerFrontendDtmbSettings dtmb;
}
