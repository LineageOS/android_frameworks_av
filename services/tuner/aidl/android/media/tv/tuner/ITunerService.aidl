/**
 * Copyright (c) 2020, The Android Open Source Project
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
import android.hardware.common.fmq.UnsynchronizedWrite;
import android.media.tv.tuner.ITunerDemux;
import android.media.tv.tuner.ITunerDescrambler;
import android.media.tv.tuner.ITunerFrontend;
import android.media.tv.tuner.ITunerLnb;
import android.media.tv.tuner.TunerDemuxCapabilities;
import android.media.tv.tuner.TunerFrontendDtmbCapabilities;
import android.media.tv.tuner.TunerFrontendInfo;

/**
 * TunerService interface handles tuner related operations.
 *
 * {@hide}
 */
//@VintfStability
interface ITunerService {

    /**
     * Gets frontend IDs.
     */
    void getFrontendIds(out int[] ids);

    /**
     * Retrieve the frontend's information.
     *
     * @param frontendHandle the handle of the frontend granted by TRM.
     * @return the information of the frontend.
     */
    TunerFrontendInfo getFrontendInfo(in int frontendHandle);

    /**
     * Get Dtmb Frontend Capabilities.
     */
    TunerFrontendDtmbCapabilities getFrontendDtmbCapabilities(in int id);

    /**
     * Open a Tuner Frontend interface.
     *
     * @param frontendHandle the handle of the frontend granted by TRM.
     * @return the aidl interface of the frontend.
     */
    ITunerFrontend openFrontend(in int frontendHandle);

    /**
     * Open a new interface of ITunerLnb given a lnbHandle.
     *
     * @param lnbHandle the handle of the LNB granted by TRM.
     * @return a newly created ITunerLnb interface.
     */
    ITunerLnb openLnb(in int lnbHandle);

    /**
     * Open a new interface of ITunerLnb given a LNB name.
     *
     * @param lnbName the name for an external LNB to be opened.
     * @return a newly created ITunerLnb interface.
     */
    ITunerLnb openLnbByName(in String lnbName);

    /**
     * Create a new instance of Demux.
     */
    ITunerDemux openDemux(in int demuxHandle);

    /**
     * Retrieve the Tuner Demux capabilities.
     *
     * @return the demux’s capabilities.
     */
    TunerDemuxCapabilities getDemuxCaps();

    /* Open a new interface of ITunerDescrambler given a descramblerHandle.
     *
     * @param descramblerHandle the handle of the descrambler granted by TRM.
     * @return a newly created ITunerDescrambler interface.
     */
    ITunerDescrambler openDescrambler(in int descramblerHandle);

    /**
     * Get an integer that carries the Tuner HIDL version. The high 16 bits are the
     * major version number while the low 16 bits are the minor version. Default
     * value is unknown version 0.
     */
    int getTunerHalVersion();
}
