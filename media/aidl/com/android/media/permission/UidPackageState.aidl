/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.media.permission;

/**
 * Entity representing the packages associated with a particular app-id. Multiple packages can be
 * assigned a specific app-id.
 * @hide
 */
@JavaDerive(equals = true, toString = true)
parcelable UidPackageState {
    /**
     * State we retain for an individual package
     * @hide
     */
    @JavaDerive(equals = true, toString = true)
    parcelable PackageState {
        @utf8InCpp String packageName;
        int targetSdk;
        boolean isPlaybackCaptureAllowed;
    }
    // Technically, an app-id for real packages, since the package is associated with an appId,
    // which is associated with a uid per user.
    int uid;
    List<PackageState> packageStates;
}
