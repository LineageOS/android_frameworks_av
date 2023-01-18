/**
 * Copyright (c) 2021, The Android Open Source Project
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

import android.hardware.tv.tuner.DemuxCapabilities;
import android.hardware.tv.tuner.DemuxInfo;
import android.hardware.tv.tuner.FrontendInfo;
import android.hardware.tv.tuner.FrontendType;
import android.media.tv.tuner.ITunerDemux;
import android.media.tv.tuner.ITunerDescrambler;
import android.media.tv.tuner.ITunerFilter;
import android.media.tv.tuner.ITunerFilterCallback;
import android.media.tv.tuner.ITunerFrontend;
import android.media.tv.tuner.ITunerLnb;

/**
 * TunerService interface handles tuner related operations.
 *
 * {@hide}
 */
//@VintfStability
@SuppressWarnings(value={"out-array"})
interface ITunerService {
    /**
     * Gets frontend IDs.
     */
    void getFrontendIds(out int[] ids);

    /**
     * Retrieve the frontend's information.
     *
     * @param frontendId the ID of the frontend.
     * @return the information of the frontend.
     */
    FrontendInfo getFrontendInfo(in int frontendId);

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
     * Retrieve the supported filter main types
     *
     * @param demuxHandle the handle of the demux to query demux info for
     * @return the demux info
     */
    DemuxInfo getDemuxInfo(in int demuxHandle);

    /**
     * Retrieve the list of demux info for all the demuxes on the system
     *
     * @return the list of DemuxInfo
     */
    DemuxInfo[] getDemuxInfoList();

    /**
     * Retrieve the Tuner Demux capabilities.
     *
     * @return the demux’s capabilities.
     */
    DemuxCapabilities getDemuxCaps();

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

    /**
     * Open a new SharedFilter instance of ITunerFilter.
     *
     * @param filterToken the SharedFilter token created by ITunerFilter.
     * @param cb the ITunerFilterCallback used to receive callback events
     * @return a newly created ITunerFilter interface.
     */
    ITunerFilter openSharedFilter(in String filterToken, in ITunerFilterCallback cb);

    /**
     * Is Low Noise Amplifier (LNA) supported by the Tuner.
     *
     * @return {@code true} if supported, otherwise {@code false}.
     */
    boolean isLnaSupported();

    /**
     * Enable or Disable Low Noise Amplifier (LNA).
     *
     * @param bEnable enable Lna or not.
     */
    void setLna(in boolean bEnable);

    /**
     * Set the maximum usable frontends number of a given frontend type. It's used by client
     * to enable or disable frontends when cable connection status is changed by user.
     *
     * @param frontendType the frontend type which the maximum usable number will be set.
     * @param maxNumber the new maximum usable number.
     */
    void setMaxNumberOfFrontends(in FrontendType frontendType, in int maxNumber);

    /**
     * Get the maximum usable frontends number of a given frontend type.
     *
     * @param frontendType the frontend type which the maximum usable number will be queried.
     *
     * @return the maximum usable number of the queried frontend type.
     */
    int getMaxNumberOfFrontends(in FrontendType frontendType);
}
