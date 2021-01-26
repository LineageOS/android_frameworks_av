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

import android.hardware.common.fmq.MQDescriptor;
import android.hardware.common.fmq.SynchronizedReadWrite;
import android.media.tv.tuner.ITunerFilter;
import android.media.tv.tuner.TunerDvrSettings;

/**
 * Tuner Dvr interface handles tuner related operations.
 *
 * {@hide}
 */
interface ITunerDvr {
    /**
     * Get the descriptor of the DVR's FMQ.
     */
    MQDescriptor<byte, SynchronizedReadWrite> getQueueDesc();

    /**
     * Configure the DVR.
     */
    void configure(in TunerDvrSettings settings);

    /**
     * Attach one filter to DVR interface for recording.
     */
    void attachFilter(in ITunerFilter filter);

    /**
     * Detach one filter from the DVR's recording.
     */
    void detachFilter(in ITunerFilter filter);

    /**
     * Start DVR.
     */
    void start();

    /**
     * Stop DVR.
     */
    void stop();

    /**
     * Flush DVR data.
     */
    void flush();

    /**
     * close the DVR instance to release resource for DVR.
     */
    void close();
}
