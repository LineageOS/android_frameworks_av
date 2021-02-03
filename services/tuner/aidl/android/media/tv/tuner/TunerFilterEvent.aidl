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

import android.media.tv.tuner.TunerFilterDownloadEvent;
import android.media.tv.tuner.TunerFilterIpPayloadEvent;
import android.media.tv.tuner.TunerFilterMediaEvent;
import android.media.tv.tuner.TunerFilterMmtpRecordEvent;
import android.media.tv.tuner.TunerFilterMonitorEvent;
import android.media.tv.tuner.TunerFilterPesEvent;
import android.media.tv.tuner.TunerFilterSectionEvent;
import android.media.tv.tuner.TunerFilterTemiEvent;
import android.media.tv.tuner.TunerFilterTsRecordEvent;

/**
 * Filter events.
 *
 * {@hide}
 */
union TunerFilterEvent {
    TunerFilterMediaEvent media;

    TunerFilterSectionEvent section;

    TunerFilterPesEvent pes;

    TunerFilterTsRecordEvent tsRecord;

    TunerFilterMmtpRecordEvent mmtpRecord;

    TunerFilterDownloadEvent download;

    TunerFilterIpPayloadEvent ipPayload;

    TunerFilterTemiEvent temi;

    TunerFilterMonitorEvent monitor;

    int startId;
}
