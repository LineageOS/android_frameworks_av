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

import android.hardware.tv.tuner.FrontendEventType;
import android.hardware.tv.tuner.FrontendScanMessage;
import android.hardware.tv.tuner.FrontendScanMessageType;

/**
 * TunerFrontendCallback interface handles tuner frontend related callbacks.
 *
 * {@hide}
 */
interface ITunerFrontendCallback {
    /**
     * Notify the client that a new event happened on the frontend.
     */
    void onEvent(in FrontendEventType frontendEventType);

    /**
     * notify the client of scan messages.
     */
    void onScanMessage(in FrontendScanMessageType messageType,
        in FrontendScanMessage message);
}
