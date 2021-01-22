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

import android.media.tv.tuner.ITunerFilter;
import android.media.tv.tuner.ITunerFilterCallback;
import android.media.tv.tuner.ITunerFrontend;

/**
 * Tuner Demux interface handles tuner related operations.
 *
 * {@hide}
 */
interface ITunerDemux {

    /**
     * Set a frontend resource as data input of the demux
     */
    void setFrontendDataSource(in ITunerFrontend frontend);

    /**
     * Open a new filter in the demux
     */
    ITunerFilter openFilter(
        in int mainType, in int subtype, in int bufferSize, in ITunerFilterCallback cb);
}
