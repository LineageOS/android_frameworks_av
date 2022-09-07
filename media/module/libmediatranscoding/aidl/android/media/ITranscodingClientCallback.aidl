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

import android.media.TranscodingErrorCode;
import android.media.TranscodingSessionParcel;
import android.media.TranscodingResultParcel;
import android.os.ParcelFileDescriptor;

/**
 * ITranscodingClientCallback
 *
 * Interface for the MediaTranscodingService to communicate with the client.
 *
 * {@hide}
 */
interface ITranscodingClientCallback {
    /**
    * Called to open a raw file descriptor to access data under a URI
    *
    * @param fileUri The path of the filename.
    * @param mode The file mode to use. Must be one of ("r, "w", "rw")
    * @return ParcelFileDescriptor if open the file successfully, null otherwise.
    */
    ParcelFileDescriptor openFileDescriptor(in @utf8InCpp String fileUri,
                                            in @utf8InCpp String mode);

    /**
    * Called when the transcoding associated with the sessionId finished.
    * This will only be called if client request to get all the status of the session.
    *
    * @param sessionId sessionId assigned by the MediaTranscodingService upon receiving request.
    */
    oneway void onTranscodingStarted(in int sessionId);

    /**
    * Called when the transcoding associated with the sessionId is paused.
    * This will only be called if client request to get all the status of the session.
    *
    * @param sessionId sessionId assigned by the MediaTranscodingService upon receiving request.
    */
    oneway void onTranscodingPaused(in int sessionId);

    /**
    * Called when the transcoding associated with the sessionId is resumed.
    * This will only be called if client request to get all the status of the session.
    *
    * @param sessionId sessionId assigned by the MediaTranscodingService upon receiving request.
    */
    oneway void onTranscodingResumed(in int sessionId);

    /**
    * Called when the transcoding associated with the sessionId finished.
    *
    * @param sessionId sessionId assigned by the MediaTranscodingService upon receiving request.
    * @param result contains the transcoded file stats and other transcoding metrics if requested.
    */
    oneway void onTranscodingFinished(in int sessionId, in TranscodingResultParcel result);

    /**
    * Called when the transcoding associated with the sessionId failed.
    *
    * @param sessionId sessionId assigned by the MediaTranscodingService upon receiving request.
    * @param errorCode error code that indicates the error.
    */
    oneway void onTranscodingFailed(in int sessionId, in TranscodingErrorCode errorCode);

    /**
    * Called when the transcoding configuration associated with the sessionId gets updated, i.e. wait
    * number in the session queue.
    *
    * <p> This will only be called if client set requestUpdate to be true in the TranscodingRequest
    * submitted to the MediaTranscodingService.
    *
    * @param sessionId sessionId assigned by the MediaTranscodingService upon receiving request.
    * @param oldAwaitNumber previous number of sessions ahead of current session.
    * @param newAwaitNumber updated number of sessions ahead of current session.
    */
    oneway void onAwaitNumberOfSessionsChanged(in int sessionId,
                                           in int oldAwaitNumber,
                                           in int newAwaitNumber);

    /**
    * Called when there is an update on the progress of the TranscodingSession.
    *
    * <p> This will only be called if client set requestUpdate to be true in the TranscodingRequest
    * submitted to the MediaTranscodingService.
    *
    * @param sessionId sessionId assigned by the MediaTranscodingService upon receiving request.
    * @param progress an integer number ranging from 0 ~ 100 inclusive.
    */
    oneway void onProgressUpdate(in int sessionId, in int progress);
}
