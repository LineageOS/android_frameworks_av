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
 * The INativeSpatializerCallback interface is a callback associated to the
 * ISpatializer interface. The callback is used by the spatializer
 * implementation in native audio server to communicate state changes to the
 * client controlling the spatializer with the ISpatializer interface.
 * {@hide}
 */
oneway interface INativeSpatializerCallback {
    /** Called when the spatialization level applied by the spatializer changes
     * (e.g. when the spatializer is enabled or disabled)
     */
    void onLevelChanged(SpatializationLevel level);

    /** Called when the output stream the Spatializer is attached to changes.
     * Indicates the IO Handle of the new output.
     */
    void onOutputChanged(int output);
}
