/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aaudio;

/**
 * This is used for offload playback when the client wants to drain data.
 * @hide
 */
@Backing(type="int")
enum DrainType {
    /**
     * Drain all written data. IAAudioClientCallback.onWakeUp will be called
     * when all data is drained.
     */
    DRAIN_ALL_DATA = 0,
    /**
     * Drain all written data. Allow wakeup even when not all data is drained.
     * This is typically used when the device wakeups from suspend for other
     * events, such as wifi, the clients allow to wake up to get more data.
     * In this case, it is possible to save some wakeup.
     */
    DRAIN_ALL_ALLOW_SOFT_WAKEUP = 1,
    /**
     * Drain all written data. IAAudioClientCallback.onWakeUp is not needed to
     * be called when all data is drained. This is typically used when the client
     * cannot provide more data at the moment and there is not big enough data to
     * drain and suspend the device. In this case, the client side is going to
     * suspend the callback thread to drain most of the data before firing more
     * callback to the apps. Use this drain type to notify the service side to
     * stop reporting position.
     */
    DRAIN_ALL_WITHOUT_WAKEUP_CALLBACK = 2,
}
