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
// TODO(b/150948558): This should be a union. In the meantime, we require
// that exactly one of the below arrays has a single element and the rest
// are empty.
parcelable AudioIoFlags {
    /** Bitmask indexed by AudioInputFlags. */
    int[] input;
    /** Bitmask indexed by AudioOutputFlags. */
    int[] output;
}
