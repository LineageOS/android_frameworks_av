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
import android.hardware.tv.tuner.DemuxFilterSettings;
import android.hardware.tv.tuner.DemuxFilterType;
import android.hardware.tv.tuner.AvStreamType;
import android.hardware.tv.tuner.DemuxFilterMonitorEventType;
import android.hardware.tv.tuner.FilterDelayHint;

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
    void configure(in DemuxFilterSettings settings);

    /**
     * Configure the monitor event of the Filter.
     */
    void configureMonitorEvent(in int monitorEventTypes);

    /**
     * Configure the context id of the IP Filter.
     */
    void configureIpFilterContextId(in int cid);

    /**
     * Configure the stream type of the media Filter.
     */
    void configureAvStreamType(in AvStreamType avStreamType);

    /**
     * Get the a/v shared memory handle
     */
    long getAvSharedHandle(out NativeHandle avMemory);

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

    /**
     * Acquire a new SharedFilter token.
     *
     * @return a token of the newly created SharedFilter instance.
     */
    String acquireSharedFilterToken();

    /**
     * Free a SharedFilter token.
     *
     * @param filterToken the SharedFilter token will be released.
     * @return a token of the newly created SharedFilter instance.
     */
    void freeSharedFilterToken(in String filterToken);

    /**
     * Get filter type.
     *
     * @return filter type.
     */
    DemuxFilterType getFilterType();

    void setDelayHint(in FilterDelayHint hint);
}
