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

import android.media.tv.tuner.TunerFrontendScanMessage;

/**
 * TunerFrontendCallback interface handles tuner frontend related callbacks.
 *
 * {@hide}
 */
interface ITunerFrontendCallback {
        /**
     * Notify the client that a new event happened on the frontend.
     */
    void onEvent(in int frontendEventType);

    /**
     * notify the client of scan messages.
     */
    void onScanMessage(in int messageType, in TunerFrontendScanMessage message);
}
