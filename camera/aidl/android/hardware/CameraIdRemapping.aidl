/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.hardware;

/**
 * Specifies a remapping of Camera Ids.
 *
 * Example: For a given package, a remapping of camera id0 to id1 specifies
 * that any operation to perform on id0 should instead be performed on id1.
 *
 * @hide
 */
parcelable CameraIdRemapping {
    /**
     * Specifies remapping of Camera Ids per package.
     */
    parcelable PackageIdRemapping {
        /** Package Name (e.g. com.android.xyz). */
        String packageName;
        /**
         * Ordered list of Camera Ids to replace. Only Camera Ids present in this list will be
         * affected.
         */
        List<String> cameraIdsToReplace;
        /**
         *  Ordered list of updated Camera Ids, where updatedCameraIds[i] corresponds to
         *  the updated camera id for cameraIdsToReplace[i].
         */
        List<String> updatedCameraIds;
    }

    /**
     * List of Camera Id remappings to perform.
     */
    List<PackageIdRemapping> packageIdRemappings;
}
