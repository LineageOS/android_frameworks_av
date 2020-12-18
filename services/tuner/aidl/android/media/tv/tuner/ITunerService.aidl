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
import android.media.tv.tuner.ITunerFrontend;
import android.media.tv.tuner.TunerServiceFrontendInfo;

/**
 * TunerService interface handles tuner related operations.
 *
 * {@hide}
 */
//@VintfStability
interface ITunerService {

    /**
     * Gets frontend IDs.
     *
     * @return the result code of the operation.
     */
    int getFrontendIds(out int[] ids);

    /**
     * Retrieve the frontend's information.
     *
     * @param frontendHandle the handle of the frontend granted by TRM.
     * @return the information of the frontend.
     */
    TunerServiceFrontendInfo getFrontendInfo(in int frontendHandle);

    /**
     * Open a Tuner Frontend interface.
     *
     * @param frontendHandle the handle of the frontend granted by TRM.
     * @return the aidl interface of the frontend.
     */
    ITunerFrontend openFrontend(in int frontendHandle);

    /*
     * Gets synchronized fast message queue.
     *
     * @return true if succeeds, false otherwise.
     */
    boolean getFmqSyncReadWrite(out MQDescriptor<byte, SynchronizedReadWrite> mqDesc);
}
