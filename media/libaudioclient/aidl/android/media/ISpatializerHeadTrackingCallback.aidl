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

import android.media.SpatializationLevel;
import android.media.SpatializerHeadTrackingMode;

/**
 * The ISpatializerHeadTrackingCallback interface is a callback associated to the
 * Spatializer head tracking function. It can be registered via the ISpatializer
 * interface to monitor head tracking related states.
 * {@hide}
 */
oneway interface ISpatializerHeadTrackingCallback {
    /** Called when the head tracking mode has changed
     */
    void onHeadTrackingModeChanged(SpatializerHeadTrackingMode mode);

    /** Called when the head to stage pose hase been updated
     * The head to stage pose is conveyed as a vector of 6 elements,
     * where the first three are a translation vector and
     * the last three are a rotation vector.
     */
    void onHeadToSoundStagePoseUpdated(in float[] headToStage);
}
