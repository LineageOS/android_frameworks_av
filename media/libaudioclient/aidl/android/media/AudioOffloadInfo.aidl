/*
 * Copyright (C) 2020 The Android Open Source Project
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

import android.media.AudioConfigBase;
import android.media.AudioEncapsulationMode;
import android.media.AudioStreamType;
import android.media.AudioUsage;
import android.media.audio.common.AudioFormat;

/**
 * {@hide}
 */
parcelable AudioOffloadInfo {
    /** Version of the info structure. Interpreted as a uint16_t version constant. */
    int version;
    /** Audio configuration. */
    AudioConfigBase config;
    /** Stream type. */
    AudioStreamType streamType;
    /** Bit rate in bits per second. */
    int bitRate;
    /** Duration in microseconds, -1 if unknown. */
    long durationUs;
    /** true if stream is tied to a video stream. */
    boolean hasVideo;
    /** true if streaming, false if local playback. */
    boolean isStreaming;
    int bitWidth;
    /** Offload fragment size. */
    int offloadBufferSize;
    AudioUsage usage;
    AudioEncapsulationMode encapsulationMode;
    /** Content id from tuner HAL (0 if none). */
    int contentId;
    /** Sync id from tuner HAL (0 if none). */
    int syncId;
}
