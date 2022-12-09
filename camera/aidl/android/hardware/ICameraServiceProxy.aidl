/*
 * Copyright (C) 2015 The Android Open Source Project
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

import android.hardware.CameraSessionStats;

/**
 * Binder interface for the camera service proxy running in system_server.
 *
 * @hide
 */
interface ICameraServiceProxy
{
    /**
     * Ping the service proxy to update the valid users for the camera service.
     */
    oneway void pingForUserUpdate();


    /**
     * Update the status of a camera device.
     */
    oneway void notifyCameraState(in CameraSessionStats cameraSessionStats);

    /**
     * Returns the necessary rotate and crop override for the top activity which
     * will be one of ({@link android.hardware.camera2.CameraMetadata#SCALER_ROTATE_AND_CROP_NONE},
     * {@link android.hardware.camera2.CameraMetadata#SCALER_ROTATE_AND_CROP_90},
     * {@link android.hardware.camera2.CameraMetadata#SCALER_ROTATE_AND_CROP_180},
     * {@link android.hardware.camera2.CameraMetadata#SCALER_ROTATE_AND_CROP_270}).
     */
    int getRotateAndCropOverride(String packageName, int lensFacing, int userId);

    /**
     * Checks if the camera has been disabled via device policy.
     */
    boolean isCameraDisabled(int userId);
}
