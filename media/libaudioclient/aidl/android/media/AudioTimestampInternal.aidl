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

/**
 * The "Internal" timestamp is intended to disambiguate from the android.media.AudioTimestamp type.
 *
 * {@hide}
 */
parcelable AudioTimestampInternal {
    /**
     * A frame position in AudioTrack::getPosition() units. Use 'long' to accommodate
     * all values from 'uint32_t'.
     */
    long position;
    /** corresponding CLOCK_MONOTONIC when frame is expected to present. */
    long sec;
    int nsec;
}
