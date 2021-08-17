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
import android.hardware.common.NativeHandle;
import android.media.tv.tuner.TunerFilterConfiguration;
import android.media.tv.tuner.TunerFilterSharedHandleInfo;

/**
 * Tuner Filter interface handles tuner related operations.
 *
 * {@hide}
 */
interface ITunerFilter {
    /**
     * Get the filter Id.
     */
    int getId();

    /**
     * Get the 64-bit filter Id.
     */
    long getId64Bit();

    /**
     * Get the descriptor of the Filter's FMQ.
     */
    MQDescriptor<byte, SynchronizedReadWrite> getQueueDesc();

    /**
     * Configure the filter.
     */
    void configure(in TunerFilterConfiguration config);

    /**
     * Configure the monitor event of the Filter.
     */
    void configureMonitorEvent(in int monitorEventType);

    /**
     * Configure the context id of the IP Filter.
     */
    void configureIpFilterContextId(in int cid);

    /**
     * Configure the stream type of the media Filter.
     */
    void configureAvStreamType(in int avStreamType);

    /**
     * Get the a/v shared memory handle
     */
    TunerFilterSharedHandleInfo getAvSharedHandleInfo();

    /**
     * Release the handle reported by the HAL for AV memory.
     */
    void releaseAvHandle(in NativeHandle handle, in long avDataId);

    /**
     * Set the filter's data source.
     */
    void setDataSource(ITunerFilter filter);

    /**
     * Start the filter.
     */
    void start();

    /**
     * Stop the filter.
     */
    void stop();

    /**
     * Flush the filter.
     */
    void flush();

    /**
     * Close the filter.
     */
    void close();
}
