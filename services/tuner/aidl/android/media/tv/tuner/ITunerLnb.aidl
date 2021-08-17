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

import android.media.tv.tuner.ITunerLnbCallback;

/**
 * Tuner Lnb interface handles Lnb related operations.
 *
 * {@hide}
 */
interface ITunerLnb {
    /**
     * Set the lnb callback.
     */
    void setCallback(in ITunerLnbCallback tunerLnbCallback);

    /**
     * Set the lnb's power voltage.
     */
    void setVoltage(in int voltage);

    /**
     * Set the lnb's tone mode.
     */
    void setTone(in int tone);

    /**
     * Select the lnb's position.
     */
    void setSatellitePosition(in int position);

    /**
     * Sends DiSEqC (Digital Satellite Equipment Control) message.
     */
    void sendDiseqcMessage(in byte[] diseqcMessage);

    /**
     * Releases the LNB instance.
     */
    void close();
}
