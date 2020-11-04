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
 * {@hide}
 */
parcelable VolumeShaperOperation {
    /** Operations to do. Bitmask of VolumeShaperOperationFlag. */
    int flags;
    /** If >= 0 the id to remove in a replace operation. */
    int replaceId;
    /** Position in the curve to set if a valid number (not nan). */
    float xOffset;
}
