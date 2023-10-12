/**
 * Copyright (c) 2023, The Android Open Source Project
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

import android.media.ClientInfoParcel;
import android.media.MediaResourceSubType;

/**
 * Description of a Client(codec) configuration.
 *
 * {@hide}
 */
parcelable ClientConfigParcel {
    /**
     * Client info.
     */
    ClientInfoParcel clientInfo;

    /**
     * Type of codec (Audio/Video/Image).
     */
    MediaResourceSubType codecType = MediaResourceSubType.kUnspecifiedSubType;

    /**
     * true if this is an encoder, false if this is a decoder.
     */
    boolean isEncoder = false;

    /*
     * Video Resolution of the codec when it was configured, as width and height (in pixels).
     */
    int width = 0;
    int height = 0;

    /*
     * Timestamp (in microseconds) when this configuration is created.
     */
    long timeStamp = 0;

    /*
     * ID associated with the Codec.
     * This will be used by the metrics:
     * - Associate MediaCodecStarted with MediaCodecStopped Atom.
     * - Correlate MediaCodecReported Atom for codec configuration parameters.
     */
    long id = 0;
}
