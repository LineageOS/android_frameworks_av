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

import android.media.tv.tuner.TunerFilterAvSettings;
import android.media.tv.tuner.TunerFilterDownloadSettings;
import android.media.tv.tuner.TunerFilterPesDataSettings;
import android.media.tv.tuner.TunerFilterRecordSettings;
import android.media.tv.tuner.TunerFilterSectionSettings;

/**
 * Filter Settings.
 *
 * {@hide}
 */
union TunerFilterSettings {
    boolean nothing;

    TunerFilterAvSettings av;

    TunerFilterSectionSettings section;

    TunerFilterPesDataSettings pesData;

    TunerFilterRecordSettings record;

    TunerFilterDownloadSettings download;

    boolean isPassthrough;
}
