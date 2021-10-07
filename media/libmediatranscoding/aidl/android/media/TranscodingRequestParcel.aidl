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

import android.os.ParcelFileDescriptor;
import android.media.TranscodingSessionPriority;
import android.media.TranscodingTestConfig;
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

    /*
     * The filedescrptor of the sourceFilePath. If the source Fd is provided, transcoding service
     * will use this fd instead of calling back to client side to open the sourceFilePath. It is
     * client's responsibility to make sure sourceFd is opened from sourceFilePath.
     */
    @nullable ParcelFileDescriptor sourceFd;

    /**
     * The absolute file path of the destination file.
     */
    @utf8InCpp String destinationFilePath;

    /*
     * The filedescrptor of the destinationFilePath. If the destination Fd is provided, transcoding
     * service will use this fd instead of calling back to client side to open the
     * destinationFilePath. It is client's responsibility to make sure destinationFd is opened
     * from destinationFilePath.
     */
    @nullable ParcelFileDescriptor destinationFd;

    /**
     * The UID of the client that this transcoding request is for. Only privileged caller could
     * set this Uid as only they could do the transcoding on behalf of the client.
     * -1 means not available.
     */
    int clientUid = -1;

    /**
     * The PID of the client that this transcoding request is for. Only privileged caller could
     * set this Uid as only they could do the transcoding on behalf of the client.
     * -1 means not available.
     */
    int clientPid = -1;

    /**
     * The package name of the client whom this transcoding request is for.
     */
    @utf8InCpp String clientPackageName;

    /**
     * Type of the transcoding.
     */
    TranscodingType transcodingType;

    /**
     * Requested video track format for the transcoding.
     * Note that the transcoding service will try to fulfill the requested format as much as
     * possbile, while subject to hardware and software limitation. The final video track format
     * will be available in the TranscodingSessionParcel when the session is finished.
     */
    @nullable TranscodingVideoTrackFormat requestedVideoTrackFormat;

    /**
     * Priority of this transcoding. Service will schedule the transcoding based on the priority.
     */
    TranscodingSessionPriority priority;

    /**
     * Whether to receive update on progress and change of awaitNumSessions.
     * Default to false.
     */
    boolean requestProgressUpdate = false;

    /**
     * Whether to receive update on session's start/stop/pause/resume.
     * Default to false.
     */
    boolean requestSessionEventUpdate = false;

    /**
     * Whether this request is for testing.
     */
    boolean isForTesting = false;

    /**
     * Test configuration. This will be available only when isForTesting is set to true.
     */
    @nullable TranscodingTestConfig testConfig;

     /**
      * Whether to get the stats of the transcoding.
      * If this is enabled, the TranscodingSessionStats will be returned in TranscodingResultParcel
      * upon transcoding finishes.
      */
    boolean enableStats = false;
}
