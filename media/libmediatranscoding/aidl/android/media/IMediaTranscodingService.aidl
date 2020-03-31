/**
 * Copyright (c) 2019, The Android Open Source Project
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

package android.media;

import android.media.ITranscodingClient;
import android.media.ITranscodingClientCallback;
import android.media.TranscodingJobParcel;
import android.media.TranscodingRequestParcel;

/**
 * Binder interface for MediaTranscodingService.
 *
 * {@hide}
 */
interface IMediaTranscodingService {
    /**
     * All MediaTranscoding service and device Binder calls may return a
     * ServiceSpecificException with the following error codes
     */
    const int ERROR_PERMISSION_DENIED = 1;
    const int ERROR_ALREADY_EXISTS = 2;
    const int ERROR_ILLEGAL_ARGUMENT = 3;
    const int ERROR_DISCONNECTED = 4;
    const int ERROR_TIMED_OUT = 5;
    const int ERROR_DISABLED = 6;
    const int ERROR_INVALID_OPERATION = 7;

    /**
     * Default UID/PID values for non-privileged callers of
     * registerClient().
     */
    const int USE_CALLING_UID = -1;
    const int USE_CALLING_PID = -1;

    /**
     * Register the client with the MediaTranscodingService.
     *
     * Client must call this function to register itself with the service in
     * order to perform transcoding tasks. This function will return an
     * ITranscodingClient interface object. The client should save and use it
     * for all future transactions with the service.
     *
     * @param callback client interface for the MediaTranscodingService to call
     *        the client.
     * @param clientName name of the client.
     * @param opPackageName op package name of the client.
     * @param clientUid user id of the client.
     * @param clientPid process id of the client.
     * @return an ITranscodingClient interface object, with nullptr indicating
     *         failure to register.
     */
    ITranscodingClient registerClient(
            in ITranscodingClientCallback callback,
            in String clientName,
            in String opPackageName,
            in int clientUid,
            in int clientPid);

    /**
    * Returns the number of clients. This is used for debugging.
    */
    int getNumOfClients();
}
