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

import android.media.TranscodingJobPriority;
import android.media.TranscodingType;
import android.media.TranscodingVideoTrackFormat;

/**
 * TranscodingRequest contains the desired configuration for the transcoding.
 *
 * {@hide}
 */
//TODO(hkuang): Implement the parcelable.
parcelable TranscodingRequestParcel {
    /**
     * The absolute file path of the source file.
     */
    @utf8InCpp String sourceFilePath;

    /**
     * The absolute file path of the destination file.
     */
    @utf8InCpp String destinationFilePath;

    /**
     * Type of the transcoding.
     */
    TranscodingType transcodingType;

    /**
     * Requested video track format for the transcoding.
     * Note that the transcoding service will try to fulfill the requested format as much as
     * possbile, while subject to hardware and software limitation. The final video track format
     * will be available in the TranscodingJobParcel when the job is finished.
     */
    @nullable TranscodingVideoTrackFormat requestedVideoTrackFormat;

    /**
     * Priority of this transcoding. Service will schedule the transcoding based on the priority.
     */
    TranscodingJobPriority priority;

    /**
     * Whether to receive update on progress and change of awaitNumJobs.
     */
    boolean requestUpdate;
}
