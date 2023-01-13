/*
 * Copyright 2022 The Android Open Source Project
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

/** Record containing information about the computed sound dose. */
@JavaDerive(toString = true)
parcelable SoundDoseRecord {
    /**
     * Corresponds to the time in seconds when the CSD value is calculated from.
     * Values should be consistent and referenced from the same clock (e.g.: monotonic)
     */
    long timestamp;
    /** Corresponds to the duration that leads to the CSD value. */
    int duration;
    /** The actual contribution to the CSD computation normalized: 1.f is 100%CSD. */
    float value;
    /** The average MEL value in this time frame that lead to this CSD value. */
    float averageMel;
}
