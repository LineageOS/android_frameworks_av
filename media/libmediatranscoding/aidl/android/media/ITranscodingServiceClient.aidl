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
import android.media.TranscodingJobParcel;
import android.media.TranscodingResultParcel;

/**
 * ITranscodingServiceClient interface for the MediaTranscodingervice to communicate with the
 * client.
 *
 * {@hide}
 */
//TODO(hkuang): Implement the interface.
interface ITranscodingServiceClient {
    /**
     * Retrieves the name of the client.
     */
    @utf8InCpp String getName();

    /**
    * Called when the transcoding associated with the jobId finished.
    *
    * @param jobId jobId assigned by the MediaTranscodingService upon receiving request.
    * @param result contains the transcoded file stats and other transcoding metrics if requested.
    */
    oneway void onTranscodingFinished(in int jobId, in TranscodingResultParcel result);

    /**
    * Called when the transcoding associated with the jobId failed.
    *
    * @param jobId jobId assigned by the MediaTranscodingService upon receiving request.
    * @param errorCode error code that indicates the error.
    */
    oneway void onTranscodingFailed(in int jobId, in TranscodingErrorCode errorCode);

    /**
    * Called when the transcoding configuration associated with the jobId gets updated, i.e. wait
    * number in the job queue.
    *
    * <p> This will only be called if client set requestUpdate to be true in the TranscodingRequest
    * submitted to the MediaTranscodingService.
    *
    * @param jobId jobId assigned by the MediaTranscodingService upon receiving request.
    * @param oldAwaitNumber previous number of jobs ahead of current job.
    * @param newAwaitNumber updated number of jobs ahead of current job.
    */
    oneway void onAwaitNumberOfJobsChanged(in int jobId,
                                           in int oldAwaitNumber,
                                           in int newAwaitNumber);

    /**
    * Called when there is an update on the progress of the TranscodingJob.
    *
    * <p> This will only be called if client set requestUpdate to be true in the TranscodingRequest
    * submitted to the MediaTranscodingService.
    *
    * @param jobId jobId assigned by the MediaTranscodingService upon receiving request.
    * @param progress an integer number ranging from 0 ~ 100 inclusive.
    */
    oneway void onProgressUpdate(in int jobId, in int progress);
}
