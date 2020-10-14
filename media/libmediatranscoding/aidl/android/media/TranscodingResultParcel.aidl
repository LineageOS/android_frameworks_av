/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.media;

import android.media.TranscodingSessionStats;

/**
 * Result of the transcoding.
 *
 * {@hide}
 */
//TODO(hkuang): Implement the parcelable.
parcelable TranscodingResultParcel {
    /**
     * The sessionId associated with the TranscodingResult.
     */
    int sessionId;

    /**
     * Actual bitrate of the transcoded video in bits per second. This will only present for video
     * transcoding. -1 means not available.
     */
    int actualBitrateBps;

    /**
     * Stats of the transcoding session. This will only be available when client requests to get the
     * stats in TranscodingRequestParcel.
     */
    @nullable TranscodingSessionStats sessionStats;
}