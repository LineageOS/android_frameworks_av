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

package android.hardware;

/**
 * {@hide}
 */
parcelable CameraFeatureCombinationStats {
    /**
     * Values for feature combination queries
     */
    const long CAMERA_FEATURE_UNKNOWN = 0;
    const long CAMERA_FEATURE_60_FPS = 1 << 0;
    const long CAMERA_FEATURE_STABILIZATION = 1 << 1;
    const long CAMERA_FEATURE_HLG10 = 1 << 2;
    const long CAMERA_FEATURE_JPEG = 1 << 3;
    const long CAMERA_FEATURE_JPEG_R = 1 << 4;
    const long CAMERA_FEATURE_4K = 1 << 5;

    /**
     * Values for notifyFeatureCombinationStats type
     */
    enum QueryType {
        QUERY_FEATURE_COMBINATION = 0,
        QUERY_SESSION_CHARACTERISTICS = 1,
    }

    @utf8InCpp String mCameraId;
    int mUid;
    long mFeatureCombination;
    int mQueryType;
    int mStatus;
}
