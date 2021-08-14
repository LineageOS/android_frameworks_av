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

/**
 * Tuner Time Filter interface handles time filter related operations.
 *
 * {@hide}
 */
interface ITunerTimeFilter {
    /**
     * Set time stamp for time based filter.
     */
    void setTimeStamp(in long timeStamp);

    /**
     * Clear the time stamp in the time filter.
     */
    void clearTimeStamp();

    /**
     * Get the time from the beginning of current data source.
     */
    long getSourceTime();

    /**
     * Get the current time in the time filter.
     */
    long getTimeStamp();

    /**
     * Close the Time Filter instance.
     */
    void close();
}
