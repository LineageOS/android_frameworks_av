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

import android.media.tv.tuner.TunerFrontendCapabilities;

/**
 * FrontendInfo interface that carries tuner frontend information.
 *
 * <p>This is used to update the TunerResourceManager and pass Frontend
 * information from HAL to the client side.
 *
 * {@hide}
 */
parcelable TunerFrontendInfo {
    /**
     * Frontend Handle
     */
    int handle;

    /**
     * Frontend Type
     */
    int type;

    /**
     * Minimum Frequency in Hertz
     */
    int minFrequency;

    /**
     * Maximum Frequency in Hertz
     */
    int maxFrequency;

    /**
     * Minimum symbols per second
     */
    int minSymbolRate;

    /**
     * Maximum symbols per second
     */
    int maxSymbolRate;

    /**
     * Range in Hertz
     */
    int acquireRange;

    /**
     * Frontends are assigned with the same exclusiveGroupId if they can't
     * function at same time. For instance, they share same hardware module.
     */
    int exclusiveGroupId;

    /**
     * A list of supported status types which client can inquiry
     */
    int[] statusCaps;

    /**
     * Frontend Capabilities
     */
    TunerFrontendCapabilities caps;
}
