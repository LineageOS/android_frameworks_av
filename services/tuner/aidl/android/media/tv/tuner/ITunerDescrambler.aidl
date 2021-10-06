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

import android.media.tv.tuner.ITunerDemux;
import android.media.tv.tuner.ITunerFilter;
import android.media.tv.tuner.TunerDemuxPid;

/**
 * Tuner Demux interface handles tuner related operations.
 *
 * {@hide}
 */
interface ITunerDescrambler {
    /**
     * Set a demux as source of the descrambler.
     */
    void setDemuxSource(in ITunerDemux tunerDemux);

    /**
     * Set a key token to link descrambler to a key slot.
     */
    void setKeyToken(in byte[] keyToken);

    /**
     * Add packets' PID to the descrambler for descrambling.
     */
    void addPid(in TunerDemuxPid pid, in ITunerFilter optionalSourceFilter);

    /**
     * Remove packets' PID from the descrambler.
     */
    void removePid(in TunerDemuxPid pid, in ITunerFilter optionalSourceFilter);

    /**
     * Close a new interface of ITunerDescrambler.
     */
    void close();
}
