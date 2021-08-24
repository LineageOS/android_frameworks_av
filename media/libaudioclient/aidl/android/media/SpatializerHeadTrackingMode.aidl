/*
 * Copyright 2021 The Android Open Source Project
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
 * The head tracking mode supported by the spatializer effect implementation.
 * Used by methods of the ISpatializer interface.
 * {@hide}
 */
@Backing(type="byte")
enum SpatializerHeadTrackingMode {
    /** Head tracking is active in a mode not listed below (forward compatibility) */
    OTHER = 0,
    /** Head tracking is disabled */
    DISABLED = 1,
    /** Head tracking is performed relative to the real work environment */
    RELATIVE_WORLD = 2,
    /** Head tracking is performed relative to the device's screen */
    RELATIVE_SCREEN = 3,
}
